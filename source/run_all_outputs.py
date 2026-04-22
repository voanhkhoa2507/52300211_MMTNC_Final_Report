#!/usr/bin/env python3
"""
Chạy 1 lệnh để sinh hầu hết output cần nộp vào thư mục logs/.

Yêu cầu chung:
- Topology đang chạy (đã tạo netns: core/dist1/dist2/internet/dmz_web1/dmz_web2...)
- Chạy bằng root: sudo python3 source/run_all_outputs.py

Output tạo ra (theo các script đã có):
- logs/acl/acl_heatmap_live.png + csv
- logs/nat/nat_snapshot_*.txt + nat_static_table_*.csv + nat_pat_rules_*.txt
- logs/nat/incident_conntrack_*.csv (nếu bật capture incident)
- logs/perf/perf_table.png (benchmark 4 case)
- logs/loadbalancer/* (tuỳ chọn: chạy nhanh để cập nhật chart/event/csv)
"""

from __future__ import annotations

import argparse
import os
import subprocess
import time
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC = PROJECT_ROOT / "source"


def sh(cmd: str, timeout_s: int | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(["bash", "-lc", cmd], text=True, capture_output=True, timeout=timeout_s, check=False)


def netns_exists(ns: str) -> bool:
    p = sh(f"ip netns list | awk '{{print $1}}' | grep -x {ns} >/dev/null 2>&1; echo $?")
    return (p.stdout or "").strip().endswith("0")


def require_netns(names: list[str]) -> None:
    missing = [n for n in names if not netns_exists(n)]
    if missing:
        raise SystemExit(f"[LỖI] Thiếu namespace: {', '.join(missing)}. Hãy chạy topology.py trước (sudo python3 source/topology.py).")


def run_py(path: Path, args: str, timeout_s: int | None = None) -> None:
    p = sh(f"python3 {path} {args}", timeout_s=timeout_s)
    if p.returncode != 0:
        raise SystemExit(f"[LỖI] Chạy fail: python3 {path.name} {args}\nSTDOUT:\n{p.stdout}\nSTDERR:\n{p.stderr}")


def ensure_dmz_http() -> None:
    """
    Bật http.server cho dmz_web1/dmz_web2, tách folder riêng để phân biệt WEB1/WEB2.
    Dùng PID file để không kill nhầm.
    """
    cmds = [
        r"""ip netns exec dmz_web1 bash -lc 'mkdir -p /tmp/web_web1; echo WEB1 > /tmp/web_web1/index.html; test -f /tmp/web_web1/http.pid && kill $(cat /tmp/web_web1/http.pid) 2>/dev/null || true; cd /tmp/web_web1; nohup python3 -m http.server 80 >/tmp/web_web1/http.log 2>&1 & echo $! > /tmp/web_web1/http.pid; sleep 0.3; ss -ltnp | grep ":80" >/dev/null'""",
        r"""ip netns exec dmz_web2 bash -lc 'mkdir -p /tmp/web_web2; echo WEB2 > /tmp/web_web2/index.html; test -f /tmp/web_web2/http.pid && kill $(cat /tmp/web_web2/http.pid) 2>/dev/null || true; cd /tmp/web_web2; nohup python3 -m http.server 80 >/tmp/web_web2/http.log 2>&1 & echo $! > /tmp/web_web2/http.pid; sleep 0.3; ss -ltnp | grep ":80" >/dev/null'""",
    ]
    for c in cmds:
        p = sh(c, timeout_s=5)
        if p.returncode != 0:
            raise SystemExit(f"[LỖI] Không bật được HTTP DMZ.\nCMD:\n{c}\nSTDOUT:\n{p.stdout}\nSTDERR:\n{p.stderr}")


def generate_some_traffic(vip: str, seconds: int) -> None:
    """
    Tạo traffic ngắn từ internet -> VIP để:
    - incident conntrack có data
    - load balancer có tx bytes tăng
    """
    # cố dùng curl; nếu thiếu thì dùng wget
    p = sh("ip netns exec internet bash -lc 'command -v curl >/dev/null 2>&1; echo $?'")
    has_curl = (p.stdout or "").strip().endswith("0")
    if has_curl:
        sh(
            f"ip netns exec internet bash -lc 't_end=$((SECONDS+{seconds})); "
            f"while [ $SECONDS -lt $t_end ]; do curl -m 2 -s --header \"Connection: close\" http://{vip}/ -o /dev/null; done'",
            timeout_s=seconds + 5,
        )
    else:
        sh(
            f"ip netns exec internet bash -lc 't_end=$((SECONDS+{seconds})); "
            f"while [ $SECONDS -lt $t_end ]; do wget -qO- http://{vip}/ >/dev/null 2>&1; done'",
            timeout_s=seconds + 5,
        )


def main() -> int:
    if os.geteuid() != 0:
        raise SystemExit("Hãy chạy với quyền root: sudo python3 source/run_all_outputs.py")

    ap = argparse.ArgumentParser()
    ap.add_argument("--vip", default="203.0.113.11", help="VIP web để tạo traffic (mặc định 203.0.113.11)")
    ap.add_argument("--incident-seconds", type=int, default=15, help="Thời gian capture incident conntrack (mặc định 15s)")
    ap.add_argument("--skip-incident", action="store_true", help="Bỏ qua capture incident")
    ap.add_argument("--skip-loadbalancer", action="store_true", help="Bỏ qua chạy nhanh load balancer")
    ap.add_argument("--lb-seconds", type=int, default=20, help="Chạy load balancer trong bao lâu để cập nhật chart (mặc định 20s)")
    ap.add_argument("--lb-capacity", type=float, default=2000.0, help="capacity-mbps cho load balancer (mặc định 2000)")
    ap.add_argument("--perf-repeat", type=int, default=3, help="repeat cho perf benchmark (mặc định 3)")
    args = ap.parse_args()

    require_netns(["core", "dist1", "internet", "dmz_web1", "dmz_web2"])

    print("[1/5] ACL heatmap live...")
    run_py(SRC / "heatmap_acl.py", "--mode live", timeout_s=30)

    print("[2/5] NAT snapshot...")
    run_py(SRC / "nat_audit.py", "snapshot", timeout_s=30)

    print("[3/5] Incident (conntrack)...")
    if not args.skip_incident:
        ensure_dmz_http()
        # Chạy capture ở background bằng timeout bên trong script => chỉ cần tạo traffic trong thời gian đó.
        cap_cmd = f"python3 {SRC/'nat_audit.py'} capture-incident --seconds {args.incident_seconds} --vip {args.vip}"
        cap = subprocess.Popen(["bash", "-lc", cap_cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        # tạo traffic trong cửa sổ capture
        time.sleep(1)
        generate_some_traffic(args.vip, seconds=max(5, args.incident_seconds - 2))
        out, err = cap.communicate(timeout=args.incident_seconds + 10)
        if cap.returncode != 0:
            raise SystemExit(f"[LỖI] capture-incident fail\nSTDOUT:\n{out}\nSTDERR:\n{err}")
        print(out.strip())
    else:
        print("  (skip)")

    print("[4/5] Performance benchmark + render table PNG...")
    run_py(
        SRC / "perf_benchmark.py",
        f"--fail-soft --render-table --no-csv --repeat {args.perf_repeat}",
        timeout_s=600,
    )

    print("[5/5] Load balancer (quick run) ...")
    if not args.skip_loadbalancer:
        ensure_dmz_http()
        # chạy load balancer nhanh trong nền; trong lúc đó tạo traffic để có tx bytes
        lb_cmd = (
            f"timeout {max(5, args.lb_seconds)} "
            f"python3 {SRC/'load_balancer.py'} --interval 1 --plot-interval 0.1 "
            f"--capacity-mbps {args.lb_capacity} --save-every 2"
        )
        lb = subprocess.Popen(["bash", "-lc", lb_cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        time.sleep(1)
        generate_some_traffic(args.vip, seconds=max(5, args.lb_seconds - 2))
        out, err = lb.communicate(timeout=args.lb_seconds + 10)
        # timeout returncode !=0 là bình thường; ignore
        if err.strip():
            print("(lb stderr) " + err.strip().splitlines()[-1])
        print("[OK] Load balancer chart/log đã được cập nhật trong logs/loadbalancer/")
    else:
        print("  (skip)")

    print("\n[OK] Hoàn tất. Mở thư mục logs/ để lấy hình + bảng.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

