#!/usr/bin/env python3
"""
Sinh heatmap ACL (multi-layer) từ các rule trong source/acl.sh.

Mục tiêu:
- Tạo 1 hình heatmap dễ đưa vào báo cáo: cho phép/chặn theo từng "luồng" (source zone -> dịch vụ/đích).

- Script này KHÔNG đọc iptables live để tránh phụ thuộc vào trạng thái runtime.

- Có thể đọc trực tiếp `iptables -S FORWARD` trong namespace (core/dist1),
  rồi mô phỏng quyết định ALLOW/DENY theo đúng thứ tự rule + default policy.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import subprocess
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import matplotlib


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIR = PROJECT_ROOT / "source"
LOG_DIR = PROJECT_ROOT / "logs" / "acl"
LOG_DIR.mkdir(parents=True, exist_ok=True)


Decision = Literal["ALLOW", "DENY", "N/A"]


@dataclass(frozen=True)
class FlowCell:
    src: str
    dst_service: str
    decision: Decision
    layer: str  # STD / EXT / FW / ROUTE
    note: str


def _read_acl_sh(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _sh(cmd: list[str]) -> str:
    p = subprocess.run(cmd, text=True, capture_output=True, check=False)
    return (p.stdout or "") + (p.stderr or "")


def _netns_iptables_s(ns: str, chain: str = "FORWARD", table: str | None = None) -> list[str]:
    """
    Trả về output iptables -S cho chain (kèm -P policy) trong namespace.
    """
    base = ["ip", "netns", "exec", ns, "iptables"]
    if table:
        base += ["-t", table]
    base += ["-S", chain]
    out = _sh(base)
    return [l.strip() for l in out.splitlines() if l.strip()]


@dataclass(frozen=True)
class IptRule:
    chain: str
    target: str  # ACCEPT/DROP/...
    proto: str | None
    src: str | None
    dst: str | None
    in_if: str | None
    out_if: str | None
    dports: set[int] | None
    ctstate: set[str] | None
    comment: str | None
    raw: str


def _parse_iptables_s(lines: list[str], chain: str = "FORWARD") -> tuple[str, list[IptRule]]:
    """
    Parse iptables -S CHAIN:
    - Tách policy (-P CHAIN <POLICY>)
    - Tách rules (-A CHAIN ...)
    """
    policy = "ACCEPT"
    rules: list[IptRule] = []

    for line in lines:
        if line.startswith(f"-P {chain} "):
            policy = line.split()[-1].strip()
            continue
        if not line.startswith(f"-A {chain} "):
            continue

        toks = line.split()
        proto = src = dst = in_if = out_if = comment = None
        dports: set[int] | None = None
        ctstate: set[str] | None = None
        target = ""

        i = 0
        while i < len(toks):
            t = toks[i]
            if t == "-p" and i + 1 < len(toks):
                proto = toks[i + 1]
                i += 2
                continue
            if t == "-s" and i + 1 < len(toks):
                src = toks[i + 1]
                i += 2
                continue
            if t == "-d" and i + 1 < len(toks):
                dst = toks[i + 1]
                i += 2
                continue
            if t == "-i" and i + 1 < len(toks):
                in_if = toks[i + 1]
                i += 2
                continue
            if t == "-o" and i + 1 < len(toks):
                out_if = toks[i + 1]
                i += 2
                continue
            if t == "--dport" and i + 1 < len(toks):
                try:
                    dports = {int(toks[i + 1])}
                except Exception:
                    dports = None
                i += 2
                continue
            if t == "--dports" and i + 1 < len(toks):
                try:
                    dports = {int(x) for x in toks[i + 1].split(",") if x.strip().isdigit()}
                except Exception:
                    dports = None
                i += 2
                continue
            if t == "--ctstate" and i + 1 < len(toks):
                ctstate = {x.strip() for x in toks[i + 1].split(",") if x.strip()}
                i += 2
                continue
            if t == "--comment" and i + 1 < len(toks):
                comment = toks[i + 1].strip('"')
                i += 2
                continue
            if t == "-j" and i + 1 < len(toks):
                target = toks[i + 1]
                i += 2
                continue
            i += 1

        rules.append(
            IptRule(
                chain=chain,
                target=target,
                proto=proto,
                src=src,
                dst=dst,
                in_if=in_if,
                out_if=out_if,
                dports=dports,
                ctstate=ctstate,
                comment=comment,
                raw=line,
            )
        )

    return policy, rules


def _ip_in_cidr(ip: str, cidr: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        net = ipaddress.ip_network(cidr, strict=False)
        return ip_obj in net
    except Exception:
        return False


@dataclass(frozen=True)
class FlowSpec:
    src_ip: str
    dst_ip: str
    proto: str
    dst_port: int | None  # None = any


def _match_rule(rule: IptRule, flow: FlowSpec) -> bool:
    # mô phỏng NEW connection => bỏ qua ESTABLISHED,RELATED
    if rule.ctstate and ("ESTABLISHED" in rule.ctstate or "RELATED" in rule.ctstate):
        return False
    if rule.proto and rule.proto != flow.proto:
        return False
    if rule.src and not _ip_in_cidr(flow.src_ip, rule.src):
        return False
    if rule.dst and not _ip_in_cidr(flow.dst_ip, rule.dst):
        return False
    if flow.dst_port is not None and rule.dports is not None and flow.dst_port not in rule.dports:
        return False
    return True


def _decide_from_rules(policy: str, rules: list[IptRule], flow: FlowSpec) -> tuple[Decision, str, str]:
    for r in rules:
        if _match_rule(r, flow):
            decision: Decision = "ALLOW" if r.target == "ACCEPT" else "DENY" if r.target == "DROP" else "N/A"
            layer = ""
            note = r.comment or r.raw
            if r.comment:
                if r.comment.startswith("STD:"):
                    layer = "STD"
                elif r.comment.startswith("EXT:"):
                    layer = "EXT"
                elif r.comment.startswith("FW:"):
                    layer = "FW"
                elif r.comment.startswith("LB:"):
                    layer = "LB"
            return decision, layer, note

    if policy == "DROP":
        return "DENY", "POLICY", f"Default policy {policy}"
    if policy == "ACCEPT":
        return "ALLOW", "POLICY", f"Default policy {policy}"
    return "N/A", "POLICY", f"Default policy {policy}"


def _policy_from_acl_sh(acl_text: str) -> list[FlowCell]:
    """
    Trích policy ở mức "báo cáo" từ các comment trong acl.sh.

    Hiện tại acl.sh có các rule cốt lõi:
    - EXT: Allow Inside -> dmz_web1/2 tcp 80/443; Allow Inside -> dmz_dns 53; Deny Inside -> DMZ other
    - FW : Allow Internet -> dmz_web1/2 tcp 80/443; Allow Internet -> dmz_dns 53; Deny Internet -> DMZ other
    - FW : Allow Inside -> Internet; Allow DMZ -> Internet

    Ưu tiên bền vững: nếu sau này bạn đổi subnet/IP, chỉ cần sửa map dưới đây cho đúng.
    """
    # Nếu pattern thay đổi, ta vẫn dùng "policy design" làm nguồn chân lý.
    # Các nhãn luồng trong báo cáo:
    sources = ["Sales (VLAN20)", "Inside (VLAN khác)", "Internet", "DMZ"]
    services = [
        "DMZ Web1 (80/443)",
        "DMZ Web2 (80/443)",
        "DMZ DNS (53)",
        "DMZ (dịch vụ khác)",
        "Internet",
    ]

    # Mặc định: N/A (không áp dụng/không xét)
    matrix: dict[tuple[str, str], FlowCell] = {}
    for s in sources:
        for d in services:
            matrix[(s, d)] = FlowCell(s, d, "N/A", layer="", note="")

    def set_cell(src: str, dst: str, decision: Decision, layer: str, note: str) -> None:
        matrix[(src, dst)] = FlowCell(src, dst, decision, layer, note)

    # --- Extended ACL (Inside -> DMZ) ---
    # Sales cũng là 1 phần Inside => được phép dùng các dịch vụ DMZ hợp lệ (web/dns).
    for src in ["Sales (VLAN20)", "Inside (VLAN khác)"]:
        for dst in ["DMZ Web1 (80/443)", "DMZ Web2 (80/443)"]:
            set_cell(
                src,
                dst,
                "ALLOW",
                "EXT",
                "Chỉ cho TCP 80/443 tới Web DMZ",
            )
    set_cell(
        "Sales (VLAN20)",
        "DMZ DNS (53)",
        "ALLOW",
        "EXT",
        "Chỉ cho DNS (UDP/TCP 53) tới DMZ DNS",
    )
    set_cell(
        "Inside (VLAN khác)",
        "DMZ DNS (53)",
        "ALLOW",
        "EXT",
        "Chỉ cho DNS (UDP/TCP 53) tới DMZ DNS",
    )
    for src in ["Sales (VLAN20)", "Inside (VLAN khác)"]:
        set_cell(
            src,
            "DMZ (dịch vụ khác)",
            "DENY",
            "EXT",
            "Mặc định chặn inside -> DMZ dịch vụ khác",
        )

    # --- Boundary firewall (Internet -> DMZ) ---
    for dst in ["DMZ Web1 (80/443)", "DMZ Web2 (80/443)"]:
        set_cell(
            "Internet",
            dst,
            "ALLOW",
            "FW",
            "Cho phép inbound web qua Static NAT (VIP)",
        )
    set_cell(
        "Internet",
        "DMZ DNS (53)",
        "ALLOW",
        "FW",
        "Cho phép inbound DNS qua Static NAT (VIP)",
    )
    set_cell(
        "Internet",
        "DMZ (dịch vụ khác)",
        "DENY",
        "FW",
        "Chặn inbound khác vào DMZ",
    )

    # --- Outbound ---
    set_cell(
        "Inside (VLAN khác)",
        "Internet",
        "ALLOW",
        "FW",
        "Inside đi Internet qua PAT (core)",
    )
    set_cell(
        "DMZ",
        "Internet",
        "ALLOW",
        "FW",
        "DMZ đi Internet (tuỳ chọn cho lab)",
    )

    # Nếu muốn minh hoạ “Internet -> Inside” là bị chặn theo mặc định (FORWARD DROP),
    # ta đặt rõ ở đây để heatmap đẹp hơn.
    set_cell(
        "Internet",
        "Internet",
        "N/A",
        "",
        "",
    )
    # Internet -> Inside không nằm trong list services; giữ đơn giản cho bài.

    # Giữ đúng thứ tự hàng/cột
    cells: list[FlowCell] = []
    for s in sources:
        for d in services:
            cells.append(matrix[(s, d)])

    return cells


def _decision_to_value(decision: Decision) -> float:
    # map để tô màu: DENY=-1, N/A=0, ALLOW=+1
    return {"DENY": -1.0, "N/A": 0.0, "ALLOW": 1.0}[decision]


def _render_heatmap(cells: list[FlowCell], out_png: Path, out_csv: Path, extra_csv: Path | None = None) -> None:
    # Tách cảnh báo (nếu có) ra khỏi ma trận
    core_cells = [c for c in cells if not c.src.startswith("(")]
    sources = sorted({c.src for c in core_cells}, key=lambda s: ["Sales (VLAN20)", "Inside (VLAN khác)", "Internet", "DMZ"].index(s))
    services = sorted(
        {c.dst_service for c in core_cells},
        key=lambda s: ["DMZ Web1 (80/443)", "DMZ Web2 (80/443)", "DMZ DNS (53)", "DMZ (dịch vụ khác)", "Internet"].index(s),
    )

    # Build matrix
    cell_map = {(c.src, c.dst_service): c for c in core_cells}
    values = [[_decision_to_value(cell_map[(s, d)].decision) for d in services] for s in sources]
    ann = [[cell_map[(s, d)].decision for d in services] for s in sources]
    layers = [[cell_map[(s, d)].layer for d in services] for s in sources]

    # CSV output
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Nguồn", *services])
        for i, s in enumerate(sources):
            w.writerow([s, *ann[i]])

    # CSV chi tiết (layer + note)
    if extra_csv is not None:
        with extra_csv.open("w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["Nguồn", "Đích/Dịch vụ", "Kết quả", "Lớp", "Note(rule match/policy)"])
            for c in cells:
                if c.src.startswith("("):
                    continue
                w.writerow([c.src, c.dst_service, c.decision, c.layer, c.note])

    # Plot
    has_display = True
    try:
        import os

        has_display = bool(os.environ.get("DISPLAY"))
    except Exception:
        has_display = True

    if not has_display:
        matplotlib.use("Agg")
    import matplotlib.pyplot as plt  # noqa: WPS433
    import numpy as np  # noqa: WPS433

    arr = np.array(values, dtype=float)

    fig, ax = plt.subplots(figsize=(12, 4.8))
    ax.set_title("Heatmap ACL đa lớp (ALLOW / DENY) theo luồng")
    im = ax.imshow(arr, aspect="auto", vmin=-1.0, vmax=1.0, cmap="RdYlGn")

    # Ticks
    ax.set_xticks(range(len(services)))
    ax.set_xticklabels(services, rotation=25, ha="right")
    ax.set_yticks(range(len(sources)))
    ax.set_yticklabels(sources)

    # Annotate each cell with decision + layer
    for r in range(len(sources)):
        for c in range(len(services)):
            text = ann[r][c]
            layer = layers[r][c]
            label = text if text != "N/A" else ""
            if layer:
                label = f"{label}\n{layer}" if label else layer
            ax.text(c, r, label, ha="center", va="center", fontsize=9, color="black")

    # Colorbar
    cbar = fig.colorbar(im, ax=ax, fraction=0.025, pad=0.03)
    cbar.set_ticks([-1, 0, 1])
    cbar.set_ticklabels(["DENY", "N/A", "ALLOW"])

    # Footnote từ comment trong script
    foot = (
        "STD=Standard (lọc theo nguồn, dist1) | EXT=Extended (dịch vụ, dist1) | FW=Firewall biên (core)\n"
        f"Xuất CSV: {out_csv.name} | Xuất PNG: {out_png.name}"
    )
    fig.text(0.5, 0.01, foot, ha="center", fontsize=9)
    fig.tight_layout(rect=(0, 0.05, 1, 1))

    fig.savefig(out_png, dpi=160)
    plt.close(fig)


def _policy_from_live_iptables(core_ns: str, dist_ns: str) -> list[FlowCell]:
    """
    Xây policy từ iptables live.

    Quy ước mô phỏng (đúng với mô hình bài):
    - Sales/Inside -> DMZ: xét iptables FORWARD ở dist_ns (dist1 là biên DMZ)
    - Internet -> DMZ và (Inside/DMZ) -> Internet: xét iptables FORWARD ở core_ns (firewall biên)
    """
    dist_lines = _netns_iptables_s(dist_ns, "FORWARD")
    core_lines = _netns_iptables_s(core_ns, "FORWARD")
    dist_policy, dist_rules = _parse_iptables_s(dist_lines, "FORWARD")
    core_policy, core_rules = _parse_iptables_s(core_lines, "FORWARD")

    sources = ["Sales (VLAN20)", "Inside (VLAN khác)", "Internet", "DMZ"]
    services = [
        "DMZ Web1 (80/443)",
        "DMZ Web2 (80/443)",
        "DMZ DNS (53)",
        "DMZ (dịch vụ khác)",
        "Internet",
    ]

    # IP đại diện để mô phỏng (NEW connection)
    SALES_IP = "10.10.20.11"
    INSIDE_IP = "10.10.10.11"
    INTERNET_IP = "203.0.113.1"
    DMZ_WEB1 = "172.16.200.11"
    DMZ_WEB2 = "172.16.200.12"
    DMZ_DNS = "172.16.200.53"
    DMZ_OTHER = "172.16.200.99"
    INTERNET_DST = "1.1.1.1"

    def decide(src_zone: str, dst_service: str) -> FlowCell:
        proto = "tcp"
        port: int | None = 80
        dst_ip = DMZ_WEB1

        if dst_service == "DMZ Web1 (80/443)":
            dst_ip, proto, port = DMZ_WEB1, "tcp", 80
        elif dst_service == "DMZ Web2 (80/443)":
            dst_ip, proto, port = DMZ_WEB2, "tcp", 80
        elif dst_service == "DMZ DNS (53)":
            dst_ip, proto, port = DMZ_DNS, "udp", 53
        elif dst_service == "DMZ (dịch vụ khác)":
            dst_ip, proto, port = DMZ_OTHER, "tcp", 22
        elif dst_service == "Internet":
            dst_ip, proto, port = INTERNET_DST, "tcp", 443

        if src_zone == "Sales (VLAN20)":
            src_ip = SALES_IP
        elif src_zone == "Inside (VLAN khác)":
            src_ip = INSIDE_IP
        elif src_zone == "Internet":
            src_ip = INTERNET_IP
        elif src_zone == "DMZ":
            src_ip = DMZ_WEB1
        else:
            src_ip = INSIDE_IP

        # chọn rule-set
        use_policy, use_rules = dist_policy, dist_rules
        if src_zone in ("Internet", "DMZ") or dst_service == "Internet":
            use_policy, use_rules = core_policy, core_rules

        decision, layer, note = _decide_from_rules(use_policy, use_rules, FlowSpec(src_ip=src_ip, dst_ip=dst_ip, proto=proto, dst_port=port))
        return FlowCell(src=src_zone, dst_service=dst_service, decision=decision, layer=layer, note=note)

    cells: list[FlowCell] = []
    for s in sources:
        for d in services:
            if s == "Internet" and d == "Internet":
                cells.append(FlowCell(s, d, "N/A", "", ""))
            else:
                cells.append(decide(s, d))
    return cells


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["design", "live"], default="design", help="design=theo acl.sh, live=đọc iptables runtime")
    ap.add_argument("--acl-sh", default=str(SOURCE_DIR / "acl.sh"), help="Đường dẫn acl.sh (mặc định: source/acl.sh)")
    ap.add_argument("--core-ns", default="core", help="Namespace core (mặc định: core)")
    ap.add_argument("--dist-ns", default="dist1", help="Namespace dist nối DMZ (mặc định: dist1)")
    ap.add_argument("--out-png", default="", help="File PNG output (mặc định theo mode)")
    ap.add_argument("--out-csv", default="", help="File CSV output (mặc định theo mode)")
    args = ap.parse_args()

    if args.mode == "design":
        out_png = Path(args.out_png) if args.out_png else (LOG_DIR / "acl_heatmap.png")
        out_csv = Path(args.out_csv) if args.out_csv else (LOG_DIR / "acl_heatmap.csv")
        extra_csv = LOG_DIR / "acl_heatmap_detail.csv"
        acl_text = _read_acl_sh(Path(args.acl_sh))
        cells = _policy_from_acl_sh(acl_text)
        _render_heatmap(cells, out_png=out_png, out_csv=out_csv, extra_csv=extra_csv)
        print(f"[OK] (design) PNG: {out_png}")
        print(f"[OK] (design) CSV: {out_csv}")
        print(f"[OK] (design) Detail CSV: {extra_csv}")
    else:
        out_png = Path(args.out_png) if args.out_png else (LOG_DIR / "acl_heatmap_live.png")
        out_csv = Path(args.out_csv) if args.out_csv else (LOG_DIR / "acl_heatmap_live.csv")
        extra_csv = LOG_DIR / "acl_heatmap_live_detail.csv"
        cells = _policy_from_live_iptables(core_ns=args.core_ns, dist_ns=args.dist_ns)
        _render_heatmap(cells, out_png=out_png, out_csv=out_csv, extra_csv=extra_csv)
        print(f"[OK] (live) PNG: {out_png}")
        print(f"[OK] (live) CSV: {out_csv}")
        print(f"[OK] (live) Detail CSV: {extra_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

