#!/usr/bin/env python3
"""
Load Balancer theo ngưỡng (80/20) cho DMZ Web.

Yêu cầu bài:
- Giám sát tải trên từng DMZ server liên tục
- Khi tải > 80% -> chuyển hướng sang server dự phòng
- Khi tải < 20% -> khôi phục về server chính
- Vẽ biểu đồ đường (Matplotlib Line Chart) Mbps theo thời gian thực

Cách triển khai trong Mininet:
- Đọc counter bytes trong namespace dmz_web1/dmz_web2 (/sys/class/net/*/statistics/*_bytes)
- Điều hướng bằng iptables DNAT:
  - Trên core: VIP public 203.0.113.11:80/443 -> dmz_web1 hoặc dmz_web2
  - (Tuỳ chọn) Trên dist1: inside -> 172.16.200.11:80/443 -> 172.16.200.12

File output (trong 52300211_Final_Report/logs):
- load_balancing_timeseries.csv
- load_balancing_line_chart.png
- load_balancer_events.log
"""

from __future__ import annotations

import argparse
import csv
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import matplotlib


PROJECT_ROOT = Path(__file__).resolve().parents[1]
LOG_DIR = PROJECT_ROOT / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

CSV_PATH = LOG_DIR / "load_balancing_timeseries.csv"
PNG_PATH = LOG_DIR / "load_balancing_line_chart.png"
EVENT_LOG_PATH = LOG_DIR / "load_balancer_events.log"


def sh(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, text=True, capture_output=True, check=check)


def netns_exec(ns: str, cmd: str) -> str:
    # cmd chạy trong bash -lc để dùng pipe/for/awk nếu cần
    p = sh(["ip", "netns", "exec", ns, "bash", "-lc", cmd], check=False)
    return (p.stdout or "") + (p.stderr or "")


def read_int_from_ns(ns: str, path: str) -> int:
    out = netns_exec(ns, f"cat {path} 2>/dev/null | tr -d '\\n'").strip()
    try:
        return int(out)
    except Exception:
        return 0


def detect_data_intf(ns: str) -> str:
    """
    Tự tìm interface "data" trong namespace:
    - Bỏ qua lo
    - Ưu tiên interface có default route
    - Nếu không có, lấy interface đầu tiên khác lo
    """
    # Try default route interface
    out = netns_exec(ns, "ip route show default 2>/dev/null | awk '{print $5}' | head -n 1").strip()
    if out and out != "lo":
        return out

    out = netns_exec(ns, "ls /sys/class/net 2>/dev/null | tr ' ' '\\n' | grep -v '^lo$' | head -n 1").strip()
    return out if out else "eth0"


def iptables_nat_replace_dnat(ns: str, vip: str, ports: str, to_ip: str, comment: str) -> None:
    """
    Đảm bảo đúng 1 rule DNAT cho VIP:ports -> to_ip (trong PREROUTING).
    Xoá rule DNAT cũ (nếu có) rồi add rule mới.
    """
    # Liệt kê rule hiện tại có comment
    cur = netns_exec(ns, "iptables -t nat -S PREROUTING 2>/dev/null || true")
    lines = [l for l in cur.splitlines() if comment in l and "-j DNAT" in l]
    for l in lines:
        # Convert -A to -D
        del_line = l.replace("-A", "-D", 1)
        netns_exec(ns, f"iptables -t nat {del_line} 2>/dev/null || true")

    # Add new DNAT
    netns_exec(
        ns,
        (
            "iptables -t nat -A PREROUTING "
            f"-p tcp -d {vip} -m multiport --dports {ports} "
            f"-j DNAT --to-destination {to_ip} "
            f"-m comment --comment \"{comment}\""
        ),
    )


def iptables_filter_ensure_forward_accept(ns: str, in_if: str, out_if: str, dst_ip: str, ports: str, comment: str) -> None:
    """
    Đảm bảo có rule FORWARD accept đến dst_ip:ports (để DNAT đi qua).
    """
    # Check exists
    check_cmd = (
        "iptables -C FORWARD "
        f"-i {in_if} -o {out_if} -p tcp -d {dst_ip} -m multiport --dports {ports} "
        f"-j ACCEPT -m comment --comment \"{comment}\""
    )
    ok = netns_exec(ns, f"{check_cmd} 2>/dev/null; echo $?").strip().endswith("0")
    if ok:
        return
    netns_exec(ns, check_cmd.replace("-C", "-A", 1))


def log_event(msg: str) -> None:
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    EVENT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with EVENT_LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(f"[{ts}] {msg}\n")


@dataclass
class ServerStat:
    name: str
    ip: str
    ns: str
    intf: str
    last_tx: int = 0
    last_ts: float = 0.0

    def sample_mbps_tx(self) -> float:
        now = time.time()
        tx = read_int_from_ns(self.ns, f"/sys/class/net/{self.intf}/statistics/tx_bytes")
        if self.last_ts == 0.0:
            self.last_ts = now
            self.last_tx = tx
            return 0.0
        dt = max(0.001, now - self.last_ts)
        mbps = ((tx - self.last_tx) * 8.0) / dt / 1_000_000.0
        self.last_ts = now
        self.last_tx = tx
        return max(0.0, mbps)


def main() -> int:
    if os.geteuid() != 0:
        print("Hãy chạy với quyền root: sudo python3 source/load_balancer.py")
        return 1

    ap = argparse.ArgumentParser()
    ap.add_argument("--interval", type=float, default=5.0, help="Chu kỳ giám sát (giây). Mặc định 5s")
    ap.add_argument("--capacity-mbps", type=float, default=100.0, help="Dung lượng giả lập để quy đổi %% tải. Mặc định 100 Mbps")
    ap.add_argument("--failover", type=float, default=80.0, help="Ngưỡng %% kích hoạt failover. Mặc định 80")
    ap.add_argument("--restore", type=float, default=20.0, help="Ngưỡng %% khôi phục. Mặc định 20")

    ap.add_argument("--vip", default="203.0.113.11", help="VIP public cho web service (Static NAT). Mặc định 203.0.113.11")
    ap.add_argument("--ports", default="80,443", help="Các port web cần điều hướng. Mặc định 80,443")

    ap.add_argument("--primary-ns", default="dmz_web1", help="Namespace server chính. Mặc định dmz_web1")
    ap.add_argument("--primary-ip", default="172.16.200.11", help="IP DMZ server chính. Mặc định 172.16.200.11")
    ap.add_argument("--backup-ns", default="dmz_web2", help="Namespace server dự phòng. Mặc định dmz_web2")
    ap.add_argument("--backup-ip", default="172.16.200.12", help="IP DMZ server dự phòng. Mặc định 172.16.200.12")

    ap.add_argument("--core-ns", default="core", help="Namespace router core. Mặc định core")
    ap.add_argument("--dist-ns", default="dist1", help="Namespace dist nối DMZ. Mặc định dist1")
    ap.add_argument("--also-redirect-inside", action="store_true", help="Ngoài VIP, redirect cả inside -> dmz_web1 (172.16.200.11) sang web2 khi failover")

    args = ap.parse_args()

    # Matplotlib: realtime nếu có DISPLAY, nếu không thì chỉ lưu PNG
    has_display = bool(os.environ.get("DISPLAY"))
    if not has_display:
        matplotlib.use("Agg")
    import matplotlib.pyplot as plt  # noqa: WPS433 (local import for backend)

    primary_intf = detect_data_intf(args.primary_ns)
    backup_intf = detect_data_intf(args.backup_ns)

    primary = ServerStat("primary", args.primary_ip, args.primary_ns, primary_intf)
    backup = ServerStat("backup", args.backup_ip, args.backup_ns, backup_intf)

    # CSV header
    if not CSV_PATH.exists():
        with CSV_PATH.open("w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["timestamp", "primary_mbps_tx", "backup_mbps_tx", "active_target"])

    # Plot init
    plt.ion()
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.set_title("Load Balancing DMZ Web (Mbps theo thời gian)")
    ax.set_xlabel("Thời gian (s)")
    ax.set_ylabel("Mbps (TX)")
    ax.grid(True, linestyle="--", alpha=0.4)

    t0 = time.time()
    xs: list[float] = []
    y1: list[float] = []
    y2: list[float] = []

    (l1,) = ax.plot([], [], label=f"Primary {args.primary_ip}", linewidth=2)
    (l2,) = ax.plot([], [], label=f"Backup  {args.backup_ip}", linewidth=2)
    ax.axhline(args.capacity_mbps * (args.failover / 100.0), linestyle=":", linewidth=1.5, label=f"Failover {args.failover}%")
    ax.axhline(args.capacity_mbps * (args.restore / 100.0), linestyle="--", linewidth=1.5, label=f"Restore {args.restore}%")
    ax.legend(loc="upper right")

    # State
    active = "primary"  # primary hoặc backup

    def apply_redirect(to_ip: str, target_label: str) -> None:
        nonlocal active
        # VIP redirect on core (public inbound)
        iptables_nat_replace_dnat(
            args.core_ns,
            args.vip,
            args.ports,
            to_ip,
            comment="LB:VIP203.0.113.11",
        )
        # Ensure FORWARD allows VIP->DMZ for port 80/443
        iptables_filter_ensure_forward_accept(
            args.core_ns,
            in_if="core-out",
            out_if="core-d1",
            dst_ip=to_ip,
            ports=args.ports,
            comment="LB:ALLOW_VIP_TO_DMZ",
        )

        # Optional: inside redirect at dist1 (inside -> dmz_web1)
        if args.also_redirect_inside:
            if target_label == "backup":
                # redirect inside tcp 80/443 to dmz_web1 -> dmz_web2
                netns_exec(
                    args.dist_ns,
                    (
                        "iptables -t nat -D PREROUTING "
                        "-p tcp -d 172.16.200.11 -m multiport --dports 80,443 "
                        "-j DNAT --to-destination 172.16.200.12 "
                        "-m comment --comment \"LB:INSIDE_TO_DMZ_WEB\" 2>/dev/null || true"
                    ),
                )
                netns_exec(
                    args.dist_ns,
                    (
                        "iptables -t nat -A PREROUTING "
                        "-p tcp -d 172.16.200.11 -m multiport --dports 80,443 "
                        "-j DNAT --to-destination 172.16.200.12 "
                        "-m comment --comment \"LB:INSIDE_TO_DMZ_WEB\""
                    ),
                )
            else:
                # remove inside redirect
                netns_exec(
                    args.dist_ns,
                    (
                        "iptables -t nat -D PREROUTING "
                        "-p tcp -d 172.16.200.11 -m multiport --dports 80,443 "
                        "-j DNAT --to-destination 172.16.200.12 "
                        "-m comment --comment \"LB:INSIDE_TO_DMZ_WEB\" 2>/dev/null || true"
                    ),
                )

        active = target_label
        log_event(f"Chuyển hướng VIP {args.vip}:{args.ports} -> {to_ip} (active={active})")

    # Set initial to primary
    apply_redirect(args.primary_ip, "primary")

    log_event(
        f"Start LB: interval={args.interval}s capacity={args.capacity_mbps}Mbps failover={args.failover}% restore={args.restore}% "
        f"primary={args.primary_ns}({args.primary_ip}) backup={args.backup_ns}({args.backup_ip})"
    )

    try:
        while True:
            p_mbps = primary.sample_mbps_tx()
            b_mbps = backup.sample_mbps_tx()
            p_load = (p_mbps / args.capacity_mbps) * 100.0 if args.capacity_mbps > 0 else 0.0
            b_load = (b_mbps / args.capacity_mbps) * 100.0 if args.capacity_mbps > 0 else 0.0

            # Threshold logic:
            # - Nếu đang primary và primary vượt failover -> chuyển backup
            # - Nếu đang backup và backup xuống dưới restore -> trả primary
            if active == "primary" and p_load > args.failover:
                apply_redirect(args.backup_ip, "backup")
            elif active == "backup" and b_load < args.restore:
                apply_redirect(args.primary_ip, "primary")

            # Append CSV
            ts = time.time()
            with CSV_PATH.open("a", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow([ts, f"{p_mbps:.3f}", f"{b_mbps:.3f}", active])

            # Update plot
            x = ts - t0
            xs.append(x)
            y1.append(p_mbps)
            y2.append(b_mbps)
            # Keep last 120 points
            if len(xs) > 120:
                xs[:] = xs[-120:]
                y1[:] = y1[-120:]
                y2[:] = y2[-120:]

            l1.set_data(xs, y1)
            l2.set_data(xs, y2)
            ax.relim()
            ax.autoscale_view()

            fig.tight_layout()
            fig.canvas.draw_idle()
            if has_display:
                plt.pause(0.001)
            fig.savefig(PNG_PATH, dpi=140)

            time.sleep(args.interval)
    except KeyboardInterrupt:
        log_event("Stop LB: KeyboardInterrupt")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())

