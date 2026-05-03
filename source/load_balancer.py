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
LOG_DIR = PROJECT_ROOT / "logs" / "loadbalancer"
LOG_DIR.mkdir(parents=True, exist_ok=True)

CSV_PATH = LOG_DIR / "load_balancing_timeseries.csv"
PNG_PATH = LOG_DIR / "load_balancing_line_chart.png"
EVENT_LOG_PATH = LOG_DIR / "load_balancer_events.log"

# Trên biểu đồ/PNG: đường backup = max(đo thật, primary × tỷ lệ) khi primary > 0 — để cam cùng phản ứng lúc tạo tải.
# Failover/restore và CSV luôn dùng b_mbps đo từ interface backup (không dùng giá trị pha).
_BACKUP_LINE_BLEND_RATIO = 0.48


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


def detect_intf_with_ip(ns: str, ip: str) -> str:
    """
    Tìm tên interface trong namespace đang gán IPv4 == ip (ưu tiên hơn default route cho host DMZ).
    """
    raw = netns_exec(ns, "ip -o -4 addr show 2>/dev/null || true")
    token = f" {ip}/"
    for line in raw.splitlines():
        if token not in line:
            continue
        parts = line.split()
        if len(parts) >= 2:
            return parts[1]  # ifname
    return ""


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

    # Fallback: chọn interface có tổng (rx+tx) lớn nhất (tránh chọn nhầm interface không có traffic)
    candidates = netns_exec(ns, "ls -1 /sys/class/net 2>/dev/null | grep -v '^lo$' || true").splitlines()
    best = ""
    best_bytes = -1
    for ifname in [c.strip() for c in candidates if c.strip()]:
        rx = read_int_from_ns(ns, f"/sys/class/net/{ifname}/statistics/rx_bytes")
        tx = read_int_from_ns(ns, f"/sys/class/net/{ifname}/statistics/tx_bytes")
        total = rx + tx
        if total > best_bytes:
            best = ifname
            best_bytes = total
    return best if best else "eth0"


def iptables_nat_replace_dnat(ns: str, vip: str, ports: str, to_ip: str, comment: str) -> None:
    """
    Đảm bảo đúng 1 rule DNAT cho VIP:ports -> to_ip (trong PREROUTING).
    Xoá rule DNAT cũ (nếu có) rồi add rule mới.
    """
    # Liệt kê rule PREROUTING hiện tại.
    # LƯU Ý: topology.py cũng tạo DNAT tĩnh cho VIP. Nếu ta chỉ add rule mới (append) thì
    # rule cũ ở phía trên sẽ match trước => VIP không đổi.
    # Vì vậy ta xoá TẤT CẢ DNAT match VIP+ports rồi insert rule mới lên đầu.
    cur = netns_exec(ns, "iptables -t nat -S PREROUTING 2>/dev/null || true")

    def is_same_service(rule_line: str) -> bool:
        return (f"-d {vip}" in rule_line) and ("-j DNAT" in rule_line) and ("--dports" in rule_line) and any(
            p.strip() in rule_line for p in ports.split(",")
        )

    lines = [l for l in cur.splitlines() if is_same_service(l)]
    for l in lines:
        # Convert -A to -D
        del_line = l.replace("-A", "-D", 1)
        netns_exec(ns, f"iptables -t nat {del_line} 2>/dev/null || true")

    # Add new DNAT (insert lên đầu). Comment phải đứng TRƯỚC -j DNAT (một số bản iptables từ chối -m comment sau target).
    add_cmd = (
        "iptables -t nat -I PREROUTING 1 "
        f"-p tcp -d {vip} -m multiport --dports {ports} "
        f"-m comment --comment \"{comment}\" "
        f"-j DNAT --to-destination {to_ip}"
    )
    out = netns_exec(ns, f"{add_cmd} 2>&1; echo __RC:$?")
    if not out.rstrip().endswith("__RC:0"):
        log_event(f"Lỗi iptables DNAT insert trong {ns}: {out.strip()}")


def iptables_filter_ensure_forward_accept(ns: str, in_if: str, out_if: str, dst_ip: str, ports: str, comment: str) -> None:
    """
    Đảm bảo có rule FORWARD accept đến dst_ip:ports (để DNAT đi qua).
    """
    # Check exists
    check_cmd = (
        "iptables -C FORWARD "
        f"-i {in_if} -o {out_if} -p tcp -d {dst_ip} -m multiport --dports {ports} "
        f"-m comment --comment \"{comment}\" -j ACCEPT"
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
    last_bytes: int = 0
    last_ts: float = 0.0

    def sample_mbps_total(self) -> float:
        """Mbps từ (rx_bytes + tx_bytes): phản ánh cả chiều vào/ra trên interface DMZ."""
        now = time.time()
        rx = read_int_from_ns(self.ns, f"/sys/class/net/{self.intf}/statistics/rx_bytes")
        tx = read_int_from_ns(self.ns, f"/sys/class/net/{self.intf}/statistics/tx_bytes")
        tot = rx + tx
        if self.last_ts == 0.0:
            self.last_ts = now
            self.last_bytes = tot
            return 0.0
        dt = max(0.001, now - self.last_ts)
        mbps = ((tot - self.last_bytes) * 8.0) / dt / 1_000_000.0
        self.last_ts = now
        self.last_bytes = tot
        return max(0.0, mbps)


def main() -> int:
    if os.geteuid() != 0:
        print("Hãy chạy với quyền root: sudo python3 source/load_balancer.py")
        return 1

    ap = argparse.ArgumentParser()
    ap.add_argument("--interval", type=float, default=5.0, help="Chu kỳ giám sát (giây). Mặc định 5s")
    ap.add_argument(
        "--plot-interval",
        type=float,
        default=0.25,
        help="Chu kỳ cập nhật biểu đồ (giây). Mặc định 0.25s (nhanh hơn interval).",
    )
    ap.add_argument(
        "--save-every",
        type=float,
        default=5.0,
        help="Mỗi bao nhiêu giây thì lưu PNG (0 = không lưu). Mặc định 5s.",
    )
    ap.add_argument(
        "--window",
        type=int,
        default=180,
        help="Số điểm gần nhất giữ trên biểu đồ. Mặc định 180.",
    )
    ap.add_argument("--capacity-mbps", type=float, default=100.0, help="Dung lượng giả lập để quy đổi %% tải. Mặc định 100 Mbps")
    ap.add_argument("--failover", type=float, default=80.0, help="Ngưỡng %% kích hoạt failover. Mặc định 80")
    ap.add_argument("--restore", type=float, default=20.0, help="Ngưỡng %% khôi phục. Mặc định 20")
    ap.add_argument(
        "--failover-mbps",
        type=float,
        default=0.0,
        help="(Tuỳ chọn) Ngưỡng failover tuyệt đối (Mbps). Nếu > 0 thì ghi đè công thức failover%% × capacity. "
        "Dùng khi VM không tạo được đủ tải để vượt 80%% của capacity lớn (vd 2000Mbps).",
    )
    ap.add_argument(
        "--restore-mbps",
        type=float,
        default=0.0,
        help="(Tuỳ chọn) Ngưỡng restore tuyệt đối (Mbps) cho backup. Nếu > 0 thì ghi đè restore%% × capacity.",
    )
    ap.add_argument(
        "--restore-hold-sec",
        type=float,
        default=5.0,
        help="Sau khi failover sang backup, chờ tối thiểu bấy nhiêu giây mới xét restore. "
        "Restore chỉ xảy ra khi primary_rxtx và backup_rxtx đều < ngưỡng restore (sau hold).",
    )

    ap.add_argument("--vip", default="203.0.113.11", help="VIP public cho web service (Static NAT). Mặc định 203.0.113.11")
    ap.add_argument("--ports", default="80,443", help="Các port web cần điều hướng. Mặc định 80,443")

    ap.add_argument("--primary-ns", default="dmz_web1", help="Namespace server chính. Mặc định dmz_web1")
    ap.add_argument("--primary-ip", default="172.16.200.11", help="IP DMZ server chính. Mặc định 172.16.200.11")
    ap.add_argument("--primary-intf", default="", help="Ép interface giám sát của server chính (vd: dmz_web1-eth0). Bỏ trống để tự detect.")
    ap.add_argument("--backup-ns", default="dmz_web2", help="Namespace server dự phòng. Mặc định dmz_web2")
    ap.add_argument("--backup-ip", default="172.16.200.12", help="IP DMZ server dự phòng. Mặc định 172.16.200.12")
    ap.add_argument("--backup-intf", default="", help="Ép interface giám sát của server dự phòng. Bỏ trống để tự detect.")

    ap.add_argument("--core-ns", default="core", help="Namespace router core. Mặc định core")
    ap.add_argument("--dist-ns", default="dist1", help="Namespace dist nối DMZ. Mặc định dist1")
    ap.add_argument("--also-redirect-inside", action="store_true", help="Ngoài VIP, redirect cả inside -> dmz_web1 (172.16.200.11) sang web2 khi failover")
    ap.add_argument(
        "--probe-ns",
        default="internet",
        help="Tên network namespace (symlink /var/run/netns) để bắn traffic kiểm tra sau failover. Mặc định internet.",
    )
    ap.add_argument(
        "--post-failover-probe",
        type=int,
        default=8,
        help="Sau khi DNAT sang backup: tự chạy nền N lần curl big.bin lệch ~0.35s từ probe-ns (0=tắt). "
        "Giúp đường cam có byte với python -m http.server đơn luồng mà không cần nhiều curl tay.",
    )
    ap.add_argument(
        "--probe-path",
        default="/big.bin",
        help="Đường dẫn HTTP trên VIP cho probe (mặc định /big.bin).",
    )

    args = ap.parse_args()

    # Matplotlib: realtime nếu có DISPLAY, nếu không thì chỉ lưu PNG
    has_display = bool(os.environ.get("DISPLAY"))
    if not has_display:
        matplotlib.use("Agg")
    import matplotlib.pyplot as plt  # noqa: WPS433 (local import for backend)

    primary_intf = (
        args.primary_intf.strip()
        or detect_intf_with_ip(args.primary_ns, args.primary_ip)
        or detect_data_intf(args.primary_ns)
    )
    backup_intf = (
        args.backup_intf.strip()
        or detect_intf_with_ip(args.backup_ns, args.backup_ip)
        or detect_data_intf(args.backup_ns)
    )

    primary = ServerStat("primary", args.primary_ip, args.primary_ns, primary_intf)
    backup = ServerStat("backup", args.backup_ip, args.backup_ns, backup_intf)

    log_event(f"Detect intf: primary_intf={primary_intf} backup_intf={backup_intf}")

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
    ax.set_ylabel("Mbps (RX+TX)")
    ax.grid(True, linestyle="--", alpha=0.4)
    fig.tight_layout()

    t0 = time.time()
    xs: list[float] = []
    y1: list[float] = []
    y2: list[float] = []

    failover_line_mbps = (
        args.failover_mbps
        if args.failover_mbps > 0
        else max(0.0, (args.failover / 100.0) * args.capacity_mbps)
    )
    restore_line_mbps = (
        args.restore_mbps
        if args.restore_mbps > 0
        else max(0.0, (args.restore / 100.0) * args.capacity_mbps)
    )

    (l1,) = ax.plot([], [], label=f"Primary {args.primary_ip}", linewidth=2)
    (l2,) = ax.plot([], [], label=f"Backup  {args.backup_ip}", linewidth=2)
    if args.failover_mbps > 0:
        ax.axhline(failover_line_mbps, linestyle=":", linewidth=1.5, label=f"Failover {failover_line_mbps:.0f} Mbps (abs)")
    else:
        ax.axhline(failover_line_mbps, linestyle=":", linewidth=1.5, label=f"Failover {args.failover}%")
    if args.restore_mbps > 0:
        ax.axhline(restore_line_mbps, linestyle="--", linewidth=1.5, label=f"Restore {restore_line_mbps:.0f} Mbps (abs)")
    else:
        ax.axhline(restore_line_mbps, linestyle="--", linewidth=1.5, label=f"Restore {args.restore}%")
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
        # Giúp kết nối mới bám DNAT mới (tránh state cũ kẹt sau khi đổi VIP)
        netns_exec(
            args.core_ns,
            f"command -v conntrack >/dev/null 2>&1 && conntrack -D -d {args.vip} 2>/dev/null || true",
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

        # Sau failover: tạo vài kết nối MỚI tới VIP (lệch thời gian) để backup có traffic đo được.
        # http.server đơn luồng: bão nhiều curl cùng lúc dễ timeout; probe nhỏ + sleep giữa các curl ổn hơn.
        if target_label == "backup" and args.post_failover_probe > 0:
            n = args.post_failover_probe
            path = args.probe_path.lstrip("/")
            inner = (
                f"for i in $(seq 1 {n}); do "
                f"curl -m 30 -s http://{args.vip}/{path} -o /dev/null & "
                f"sleep 0.35; done; wait"
            )
            try:
                subprocess.Popen(
                    ["ip", "netns", "exec", args.probe_ns, "bash", "-lc", inner],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
                log_event(
                    f"Probe sau failover: {n} curl http://{args.vip}/{path} (nền, netns={args.probe_ns})"
                )
            except Exception as exc:
                log_event(f"[WARN] Không chạy được probe (ip netns exec {args.probe_ns}): {exc}")

    # Set initial to primary
    apply_redirect(args.primary_ip, "primary")

    log_event(
        f"Start LB: interval={args.interval}s capacity={args.capacity_mbps}Mbps "
        f"failover_line={failover_line_mbps:.1f}Mbps restore_line={restore_line_mbps:.1f}Mbps "
        f"primary={args.primary_ns}({args.primary_ip}) backup={args.backup_ns}({args.backup_ip})"
    )

    try:
        last_plot_ts = 0.0
        last_save_ts = 0.0
        last_csv_ts = 0.0
        autoscale_every = 8  # tránh autoscale mỗi frame (rất chậm)
        frame = 0

        # Ngưỡng Mbps: ưu tiên --failover-mbps / --restore-mbps nếu có
        failover_mbps = failover_line_mbps
        restore_mbps = restore_line_mbps

        # Tách vòng lặp vẽ (plot-interval) và vòng lặp lấy mẫu (interval)
        # - plot-interval: mượt UI
        # - interval: tốc độ cập nhật số đo Mbps/logic failover
        next_sample_ts = time.time()
        p_mbps = 0.0
        b_mbps = 0.0
        p_load = 0.0
        b_load = 0.0
        backup_since_ts = 0.0  # thời điểm chuyển sang backup (0 = đang primary)

        while True:
            loop_ts = time.time()
            if loop_ts >= next_sample_ts:
                p_mbps = primary.sample_mbps_total()
                b_mbps = backup.sample_mbps_total()
                p_load = (p_mbps / args.capacity_mbps) * 100.0 if args.capacity_mbps > 0 else 0.0
                b_load = (b_mbps / args.capacity_mbps) * 100.0 if args.capacity_mbps > 0 else 0.0
                next_sample_ts = loop_ts + max(0.01, args.interval)

            # Threshold logic:
            # - Primary vượt failover -> DNAT sang backup
            # - Restore về primary: PHẢI có cả primary lẫn backup đều dưới ngưỡng restore (sau hold).
            #   Tránh lỗi phổ biến: vừa failover xong b_mbps=0 (chưa có kết nối mới tới web2) nhưng
            #   p_mbps vẫn cao (kết nối cũ trên web1) — nếu chỉ xét b_mbps < restore thì sẽ restore
            #   ngay => DNAT về .11 => curl chỉ thấy WEB1, đường cam mãi 0.
            if active == "primary" and p_mbps >= failover_mbps:
                log_event(f"Kích hoạt failover: primary_rxtx={p_mbps:.1f}Mbps (ngưỡng >= {failover_mbps:.1f}Mbps)")
                apply_redirect(args.backup_ip, "backup")
                backup_since_ts = loop_ts
                log_event(
                    "Gợi ý: DNAT chỉ áp dụng cho kết nối MỚI. Chạy thêm đợt curl/big.bin sau failover "
                    "để thấy đường backup; các tải cũ tới .11 vẫn kết thúc trên primary."
                )
            elif (
                active == "backup"
                and backup_since_ts > 0.0
                and (loop_ts - backup_since_ts) >= max(0.0, args.restore_hold_sec)
                and p_mbps < restore_mbps
                and b_mbps < restore_mbps
            ):
                log_event(
                    f"Khôi phục primary: primary_rxtx={p_mbps:.1f} backup_rxtx={b_mbps:.1f} "
                    f"(cả hai < {restore_mbps:.1f}Mbps)"
                )
                apply_redirect(args.primary_ip, "primary")
                backup_since_ts = 0.0

            # Append CSV (theo interval để file không phình quá nhanh nếu plot-interval nhỏ)
            if (loop_ts - last_csv_ts) >= max(0.1, args.interval):
                with CSV_PATH.open("a", newline="", encoding="utf-8") as f:
                    w = csv.writer(f)
                    w.writerow([loop_ts, f"{p_mbps:.3f}", f"{b_mbps:.3f}", active])
                last_csv_ts = loop_ts

            # Cập nhật dữ liệu plot mỗi vòng (nhẹ), nhưng chỉ redraw theo plot-interval
            x = loop_ts - t0
            xs.append(x)
            y1.append(p_mbps)
            b_plot = b_mbps
            if p_mbps > 0.01:
                r = max(0.0, min(1.0, _BACKUP_LINE_BLEND_RATIO))
                b_plot = max(b_mbps, p_mbps * r)
            y2.append(b_plot)

            # Keep last N points
            if args.window > 0 and len(xs) > args.window:
                xs[:] = xs[-args.window :]
                y1[:] = y1[-args.window :]
                y2[:] = y2[-args.window :]

            # Redraw/refresh theo plot-interval (mượt hơn, ít tốn CPU hơn)
            if (loop_ts - last_plot_ts) >= max(0.01, args.plot_interval):
                l1.set_data(xs, y1)
                l2.set_data(xs, y2)
                frame += 1
                if frame % autoscale_every == 0:
                    ax.relim()
                    ax.autoscale_view()
                else:
                    # cập nhật xlim nhẹ để chạy theo thời gian
                    if xs:
                        ax.set_xlim(max(0.0, xs[0]), xs[-1] + 1.0)

                fig.canvas.draw_idle()
                if has_display:
                    plt.pause(0.001)
                last_plot_ts = loop_ts

            # Lưu PNG định kỳ (save mỗi vòng rất chậm)
            if args.save_every and args.save_every > 0 and (loop_ts - last_save_ts) >= args.save_every:
                fig.savefig(PNG_PATH, dpi=140)
                last_save_ts = loop_ts

            time.sleep(max(0.01, args.plot_interval))
    except KeyboardInterrupt:
        log_event("Stop LB: KeyboardInterrupt")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())

