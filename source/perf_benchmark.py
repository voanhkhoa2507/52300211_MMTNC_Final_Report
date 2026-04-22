#!/usr/bin/env python3
"""
Benchmark hiệu năng (Throughput + Latency) cho 4 case:
1) no_nat_no_acl
2) nat_only
3) acl_only
4) nat_and_acl

Thiết kế đo:
- Throughput: iperf3 TCP từ inside host (ad_pc1) -> internet host (203.0.113.1)
- Latency   : ping từ inside host -> internet host

Yêu cầu:
- Mininet topology đã chạy và đã tạo netns symlink (/var/run/netns/<node>) từ topology.py
- Có iperf3 trong các host namespace (thường đã cài: sudo apt-get install -y iperf3)
"""

from __future__ import annotations

import argparse
import csv
import json
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
LOG_DIR = PROJECT_ROOT / "logs" / "perf"
LOG_DIR.mkdir(parents=True, exist_ok=True)


def sh(cmd: list[str], check: bool = False, timeout_s: int | None = None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(cmd, text=True, capture_output=True, check=check, timeout=timeout_s)
    except subprocess.TimeoutExpired as e:
        # Chuẩn hoá để caller không bị crash
        return subprocess.CompletedProcess(cmd, returncode=124, stdout=e.stdout or "", stderr=(e.stderr or "") + "\nTIMEOUT\n")


def netns_exec(ns: str, cmd: str, timeout_s: int | None = None) -> subprocess.CompletedProcess:
    # Bọc timeout ở cấp shell để tránh trường hợp subprocess timeout vẫn kẹt.
    if timeout_s is not None:
        wrapped = f"timeout {int(timeout_s)} ip netns exec {ns} bash -lc {json.dumps(cmd)}"
        return sh(["bash", "-lc", wrapped], check=False, timeout_s=timeout_s + 3)
    return sh(["ip", "netns", "exec", ns, "bash", "-lc", cmd], check=False, timeout_s=None)


def ensure_netns(ns: str) -> None:
    p = sh(["bash", "-lc", f"ip netns list | awk '{{print $1}}' | grep -x {ns} >/dev/null 2>&1; echo $?"])
    if not (p.stdout or "").strip().endswith("0"):
        raise RuntimeError(f"Không thấy namespace '{ns}'. Hãy chạy topology.py trước để tạo netns symlink.")


def run_acl(mode: str) -> None:
    """
    mode: apply | drop
    """
    script = PROJECT_ROOT / "source" / "acl.sh"
    if mode == "drop":
        sh(["bash", "-lc", f"sudo bash {script} dropacl >/dev/null 2>&1 || true"])
    else:
        sh(["bash", "-lc", f"sudo bash {script} >/dev/null 2>&1 || true"])


def nat_disable(core_ns: str) -> None:
    # Chỉ gỡ rule NAT, không flush filter
    netns_exec(core_ns, "iptables -t nat -F >/dev/null 2>&1 || true")


def nat_enable_basic(core_ns: str) -> None:
    """
    Bật PAT tương tự topology.py cho inside -> core-out.
    """
    # Flush nat rồi add lại PAT
    netns_exec(core_ns, "iptables -t nat -F >/dev/null 2>&1 || true")
    netns_exec(core_ns, "iptables -t nat -A POSTROUTING -s 10.10.0.0/16 -o core-out -j MASQUERADE")


def prepare_case(case: str, core_ns: str) -> None:
    """
    Chuẩn hoá trạng thái iptables trước khi test.
    """
    if case == "no_nat_no_acl":
        run_acl("drop")
        nat_disable(core_ns)
    elif case == "nat_only":
        run_acl("drop")
        nat_enable_basic(core_ns)
    elif case == "acl_only":
        run_acl("apply")
        nat_disable(core_ns)
    elif case == "nat_and_acl":
        run_acl("apply")
        nat_enable_basic(core_ns)
    else:
        raise ValueError(case)


def iperf3_server_once(server_ns: str, port: int) -> None:
    # -1: serve one client then exit
    netns_exec(server_ns, "command -v iperf3 >/dev/null 2>&1 || echo NO_IPERF3", timeout_s=2)
    netns_exec(server_ns, f"pkill -f 'iperf3 -s' 2>/dev/null || true", timeout_s=2)
    netns_exec(server_ns, f"nohup iperf3 -s -p {port} -1 >/tmp/iperf3_server.log 2>&1 &", timeout_s=2)
    # wait until LISTEN (max ~2s)
    for _ in range(6):
        p = netns_exec(server_ns, f"ss -ltn 2>/dev/null | grep -q ':{port} ' ; echo $?", timeout_s=2)
        if (p.stdout or "").strip().endswith("0"):
            return
        time.sleep(0.3)
    # server may still be ok; don't hard fail here


def iperf3_client_json(client_ns: str, server_ip: str, port: int, seconds: int) -> dict:
    # timeout buffer: iperf time + 5s
    # Dùng `timeout` bên trong namespace để chắc chắn không bị treo.
    p = netns_exec(
        client_ns,
        f"command -v iperf3 >/dev/null 2>&1 || echo NO_IPERF3; timeout {seconds + 6} iperf3 -c {server_ip} -p {port} -t {seconds} -J 2>/dev/null",
        timeout_s=seconds + 10,
    )
    if p.returncode != 0 or not (p.stdout or "").strip():
        raise RuntimeError(f"iperf3 client lỗi (ns={client_ns}):\n{p.stdout}\n{p.stderr}")
    try:
        return json.loads(p.stdout)
    except Exception as e:
        raise RuntimeError(f"Không parse được JSON từ iperf3:\n{p.stdout}") from e


def ping_avg_ms(client_ns: str, dst_ip: str, count: int) -> float:
    # -w: deadline tổng (giây) để không treo khi route/ACL lỗi
    deadline = max(2, count * 2)
    p = netns_exec(client_ns, f"ping -c {count} -w {deadline} -n {dst_ip} 2>/dev/null | tail -n 1 || true", timeout_s=deadline + 3)
    line = (p.stdout or "").strip()
    # rtt min/avg/max/mdev = 0.172/0.439/0.905/0.330 ms
    if "min/avg" not in line:
        return -1.0
    try:
        avg = line.split("=")[1].strip().split(" ")[0].split("/")[1]
        return float(avg)
    except Exception:
        return -1.0


@dataclass(frozen=True)
class ResultRow:
    case: str
    throughput_mbps: float
    ping_avg_ms: float


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--client-ns", default="ad_pc1", help="Namespace client inside (mặc định ad_pc1)")
    ap.add_argument("--server-ns", default="internet", help="Namespace server (mặc định internet)")
    ap.add_argument("--server-ip", default="203.0.113.1", help="IP server internet (mặc định 203.0.113.1)")
    ap.add_argument("--core-ns", default="core", help="Namespace core (mặc định core)")
    ap.add_argument("--iperf-port", type=int, default=5201)
    ap.add_argument("--iperf-seconds", type=int, default=5)
    ap.add_argument("--ping-count", type=int, default=5)
    ap.add_argument("--repeat", type=int, default=2, help="Mỗi case lặp N lần, lấy trung bình (mặc định 2)")
    ap.add_argument("--fail-soft", action="store_true", help="Không dừng khi 1 case lỗi; ghi -1 và chạy tiếp")
    args = ap.parse_args()

    for ns in [args.client_ns, args.server_ns, args.core_ns]:
        ensure_netns(ns)

    cases = ["no_nat_no_acl", "nat_only", "acl_only", "nat_and_acl"]
    ts = time.strftime("%Y%m%d_%H%M%S")
    out_csv = LOG_DIR / f"perf_table_{ts}.csv"
    out_raw = LOG_DIR / f"perf_raw_{ts}.json"

    all_raw: dict[str, list[dict]] = {c: [] for c in cases}
    rows: list[ResultRow] = []

    for case in cases:
        prepare_case(case, core_ns=args.core_ns)
        time.sleep(0.5)

        thr_list: list[float] = []
        ping_list: list[float] = []

        for _ in range(max(1, args.repeat)):
            try:
                iperf3_server_once(args.server_ns, args.iperf_port)
                raw = iperf3_client_json(args.client_ns, args.server_ip, args.iperf_port, args.iperf_seconds)
                all_raw[case].append(raw)
                bps = raw.get("end", {}).get("sum_sent", {}).get("bits_per_second", 0.0)
                thr_list.append(float(bps) / 1_000_000.0)
            except Exception as e:
                if not args.fail_soft:
                    raise
                all_raw[case].append({"error": str(e)})
                thr_list.append(-1.0)

            # ping không bắt buộc phải thành công; lỗi -> -1
            ping_list.append(ping_avg_ms(args.client_ns, args.server_ip, args.ping_count))
            time.sleep(0.3)

        ok_thr = [t for t in thr_list if t >= 0]
        ok_ping = [p for p in ping_list if p >= 0]
        thr_avg = (sum(ok_thr) / len(ok_thr)) if ok_thr else -1.0
        ping_avg = (sum(ok_ping) / len(ok_ping)) if ok_ping else -1.0
        rows.append(ResultRow(case=case, throughput_mbps=thr_avg, ping_avg_ms=ping_avg))

    # Export
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["case", "throughput_mbps_tcp", "ping_avg_ms"])
        for r in rows:
            w.writerow([r.case, f"{r.throughput_mbps:.3f}", f"{r.ping_avg_ms:.3f}"])

    out_raw.write_text(json.dumps(all_raw, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"[OK] Perf table CSV: {out_csv}")
    print(f"[OK] Perf raw JSON : {out_raw}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

