#!/usr/bin/env python3
"""
Thu thập output NAT/PAT + Incident log (traceability) cho báo cáo.

Yêu cầu output liên quan NAT:
- Static NAT table: VIP public -> DMZ server (service/port)
- PAT (overload) rule: inside -> internet (MASQUERADE) + DMZ -> internet (nếu có)
- Incident log: truy vết lưu lượng đi qua core (VIP inbound + inside outbound)

Cách dùng gợi ý:
1) Snapshot NAT rules (không can thiệp):
   sudo python3 source/nat_audit.py snapshot

2) Bật logging (trace) rồi tạo traffic test, sau đó xuất incident:
   sudo python3 source/nat_audit.py enable-trace
   # tạo traffic (curl VIP, ping, curl internet...)
   sudo python3 source/nat_audit.py export-incident
   sudo python3 source/nat_audit.py disable-trace
"""

from __future__ import annotations

import argparse
import csv
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
LOG_DIR = PROJECT_ROOT / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)


def sh(cmd: list[str], check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, text=True, capture_output=True, check=check)


def netns_exec(ns: str, cmd: str) -> str:
    p = sh(["ip", "netns", "exec", ns, "bash", "-lc", cmd], check=False)
    return (p.stdout or "") + (p.stderr or "")


def have_cmd(cmd: str) -> bool:
    p = sh(["bash", "-lc", f"command -v {cmd} >/dev/null 2>&1; echo $?"])
    return (p.stdout or "").strip().endswith("0")


@dataclass(frozen=True)
class StaticNatRow:
    vip: str
    proto: str
    dports: str
    to_ip: str
    comment: str


MASQ_RE = re.compile(r"-A POSTROUTING .* -j MASQUERADE")


def parse_static_nat_from_iptables_s(nat_s: str) -> list[StaticNatRow]:
    rows: list[StaticNatRow] = []
    for line in nat_s.splitlines():
        line = line.strip()
        if not line.startswith("-A PREROUTING"):
            continue
        if "-j DNAT" not in line:
            continue
        # proto
        proto = "?"
        m = re.search(r"\s-p\s+(\w+)\b", line)
        if m:
            proto = m.group(1)
        # vip
        vip = "?"
        m = re.search(r"\s-d\s+([0-9.]+)(?:/\d+)?\b", line)
        if m:
            vip = m.group(1)
        # ports
        dports = ""
        m = re.search(r"--dports\s+([0-9,]+)", line)
        if m:
            dports = m.group(1)
        else:
            m = re.search(r"--dport\s+(\d+)", line)
            if m:
                dports = m.group(1)
        # to
        to_ip = "?"
        m = re.search(r"--to-destination\s+([0-9.]+)", line)
        if m:
            to_ip = m.group(1)
        # comment
        comment = ""
        m = re.search(r'--comment\s+"([^"]+)"', line)
        if m:
            comment = m.group(1)
        rows.append(StaticNatRow(vip=vip, proto=proto, dports=dports, to_ip=to_ip, comment=comment))
    return rows


def snapshot(core_ns: str) -> None:
    ts = time.strftime("%Y%m%d_%H%M%S")
    snap_path = LOG_DIR / f"nat_snapshot_{ts}.txt"
    nat_s = netns_exec(core_ns, "iptables -t nat -S 2>/dev/null || true")
    flt_s = netns_exec(core_ns, "iptables -S FORWARD 2>/dev/null || true")
    nat_l = netns_exec(core_ns, "iptables -t nat -nvL 2>/dev/null || true")
    flt_l = netns_exec(core_ns, "iptables -nvL FORWARD 2>/dev/null || true")
    conntrack = ""
    if have_cmd("conntrack"):
        conntrack = netns_exec(core_ns, "conntrack -L 2>/dev/null | head -n 200 || true")

    snap_path.write_text(
        "\n".join(
            [
                f"=== NAT SNAPSHOT {ts} (ns={core_ns}) ===",
                "",
                "## iptables -t nat -S",
                nat_s,
                "",
                "## iptables -S FORWARD",
                flt_s,
                "",
                "## iptables -t nat -nvL",
                nat_l,
                "",
                "## iptables -nvL FORWARD",
                flt_l,
                "",
                "## conntrack (first 200 lines)" if conntrack else "## conntrack (not installed)",
                conntrack or "",
                "",
            ]
        ),
        encoding="utf-8",
        errors="replace",
    )

    # Static NAT table CSV
    static_rows = parse_static_nat_from_iptables_s(nat_s)
    static_csv = LOG_DIR / f"nat_static_table_{ts}.csv"
    with static_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["VIP(public)", "Proto", "Ports", "To(DMZ)", "Comment"])
        for r in static_rows:
            w.writerow([r.vip, r.proto, r.dports, r.to_ip, r.comment])

    # PAT/MASQ rules (text)
    masq_txt = LOG_DIR / f"nat_pat_rules_{ts}.txt"
    masq_lines = [l for l in nat_s.splitlines() if MASQ_RE.search(l)]
    masq_txt.write_text("\n".join(masq_lines) + ("\n" if masq_lines else ""), encoding="utf-8")

    print(f"[OK] Snapshot NAT: {snap_path}")
    print(f"[OK] Static NAT CSV: {static_csv}")
    print(f"[OK] PAT rules txt : {masq_txt}")


TRACE_PREFIX = "NATTRACE "
TRACE_TAG = "NATTRACE:rule"


def enable_trace(core_ns: str, vip: str = "203.0.113.11") -> None:
    """
    Bật iptables LOG ở FORWARD để truy vết:
    - NEW inbound từ Internet (core-out -> core-d1) tới DMZ (bắt theo dải 172.16.200.0/24)
    - NEW outbound từ Inside (10.10.0.0/16) ra core-out
    """
    # Insert lên đầu FORWARD để log trước khi ACCEPT/DROP
    netns_exec(
        core_ns,
        (
            "iptables -C FORWARD -m conntrack --ctstate NEW -i core-out -o core-d1 -d 172.16.200.0/24 "
            f'-j LOG --log-prefix "{TRACE_PREFIX}IN_DMZ " -m comment --comment "{TRACE_TAG}" 2>/dev/null || '
            "iptables -I FORWARD 1 -m conntrack --ctstate NEW -i core-out -o core-d1 -d 172.16.200.0/24 "
            f'-j LOG --log-prefix "{TRACE_PREFIX}IN_DMZ " -m comment --comment "{TRACE_TAG}"'
        ),
    )
    netns_exec(
        core_ns,
        (
            "iptables -C FORWARD -m conntrack --ctstate NEW -i core-d1 -o core-out -s 10.10.0.0/16 "
            f'-j LOG --log-prefix "{TRACE_PREFIX}OUT_INSIDE " -m comment --comment "{TRACE_TAG}" 2>/dev/null || '
            "iptables -I FORWARD 1 -m conntrack --ctstate NEW -i core-d1 -o core-out -s 10.10.0.0/16 "
            f'-j LOG --log-prefix "{TRACE_PREFIX}OUT_INSIDE " -m comment --comment "{TRACE_TAG}"'
        ),
    )
    netns_exec(
        core_ns,
        (
            "iptables -C FORWARD -m conntrack --ctstate NEW -i core-d2 -o core-out -s 10.10.0.0/16 "
            f'-j LOG --log-prefix "{TRACE_PREFIX}OUT_INSIDE " -m comment --comment "{TRACE_TAG}" 2>/dev/null || '
            "iptables -I FORWARD 1 -m conntrack --ctstate NEW -i core-d2 -o core-out -s 10.10.0.0/16 "
            f'-j LOG --log-prefix "{TRACE_PREFIX}OUT_INSIDE " -m comment --comment "{TRACE_TAG}"'
        ),
    )

    # Khuyến nghị dmesg timestamp để xuất incident có thời gian
    sh(["bash", "-lc", "dmesg -T >/dev/null 2>&1 || true"])
    print("[OK] Đã bật trace (iptables LOG). Tạo traffic rồi chạy export-incident.")


def disable_trace(core_ns: str) -> None:
    """
    Gỡ toàn bộ rule LOG của NATTRACE trong FORWARD.
    """
    rules = netns_exec(core_ns, "iptables -S FORWARD 2>/dev/null || true").splitlines()
    for r in rules:
        if TRACE_TAG in r and r.startswith("-A FORWARD "):
            del_line = r.replace("-A", "-D", 1)
            netns_exec(core_ns, f"iptables {del_line} 2>/dev/null || true")
    print("[OK] Đã tắt trace.")


DMESG_RE = re.compile(
    r"^(?P<ts>\\[[^\\]]+\\]|\\w{3}\\s+\\d+\\s[\\d:]+).*?NATTRACE\\s+(?P<dir>IN_DMZ|OUT_INSIDE)\\s+(?P<rest>.*)$"
)


def export_incident(out_csv: Path) -> None:
    """
    Trích incident từ dmesg theo prefix NATTRACE.
    """
    # -T có thể không luôn có, nên lấy raw rồi parse mềm.
    out = sh(["bash", "-lc", "dmesg --color=never 2>/dev/null | tail -n 5000 || true"]).stdout or ""
    rows: list[list[str]] = []
    for line in out.splitlines():
        if "NATTRACE" not in line:
            continue
        m = DMESG_RE.search(line)
        if not m:
            continue
        ts = m.group("ts")
        direction = m.group("dir")
        rest = m.group("rest")
        # Parse SRC/DST/SPT/DPT/PROTO nếu có
        src = dst = spt = dpt = proto = ""
        mm = re.search(r"\bSRC=([0-9.]+)\b", rest)
        if mm:
            src = mm.group(1)
        mm = re.search(r"\bDST=([0-9.]+)\b", rest)
        if mm:
            dst = mm.group(1)
        mm = re.search(r"\bSPT=(\d+)\b", rest)
        if mm:
            spt = mm.group(1)
        mm = re.search(r"\bDPT=(\d+)\b", rest)
        if mm:
            dpt = mm.group(1)
        mm = re.search(r"\bPROTO=(\w+)\b", rest)
        if mm:
            proto = mm.group(1)
        rows.append([ts, direction, proto, src, spt, dst, dpt, rest])

    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["timestamp", "direction", "proto", "src_ip", "src_port", "dst_ip", "dst_port", "raw"])
        w.writerows(rows)

    print(f"[OK] Đã xuất incident log CSV: {out_csv} (rows={len(rows)})")


def build_argparser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser()
    ap.add_argument("action", choices=["snapshot", "enable-trace", "disable-trace", "export-incident"])
    ap.add_argument("--core-ns", default="core", help="Namespace core (mặc định core)")
    ap.add_argument("--vip", default="203.0.113.11", help="VIP web chính để tham khảo (mặc định 203.0.113.11)")
    ap.add_argument("--out", default="", help="Đường dẫn output CSV (chỉ dùng cho export-incident)")
    return ap


def main() -> int:
    args = build_argparser().parse_args()
    if args.action == "snapshot":
        snapshot(args.core_ns)
        return 0
    if args.action == "enable-trace":
        enable_trace(args.core_ns, vip=args.vip)
        return 0
    if args.action == "disable-trace":
        disable_trace(args.core_ns)
        return 0
    if args.action == "export-incident":
        ts = time.strftime("%Y%m%d_%H%M%S")
        out = Path(args.out) if args.out else (LOG_DIR / f"incident_nattrace_{ts}.csv")
        export_incident(out)
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

