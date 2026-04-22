#!/usr/bin/env python3
"""
Sinh heatmap ACL (multi-layer) từ các rule trong source/acl.sh.

Mục tiêu:
- Tạo 1 hình heatmap dễ đưa vào báo cáo: cho phép/chặn theo từng "luồng" (source zone -> dịch vụ/đích).
- Xuất kèm bảng CSV để làm minh chứng.

Lưu ý:
- Script này KHÔNG đọc iptables live để tránh phụ thuộc vào trạng thái runtime.
- Nó đọc/diễn giải policy theo đúng thiết kế của acl.sh (STD/EXT/FW).
"""

from __future__ import annotations

import argparse
import csv
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import matplotlib


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIR = PROJECT_ROOT / "source"
LOG_DIR = PROJECT_ROOT / "logs"
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


def _policy_from_acl_sh(acl_text: str) -> list[FlowCell]:
    """
    Trích policy ở mức "báo cáo" từ các comment trong acl.sh.

    Hiện tại acl.sh có các rule cốt lõi:
    - STD: Deny Sales VLAN20 -> DMZ (mọi dịch vụ)
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

    # --- Standard ACL ---
    set_cell(
        "Sales (VLAN20)",
        "DMZ Web1 (80/443)",
        "DENY",
        "STD",
        "Chặn theo nguồn: Sales -> DMZ",
    )
    set_cell(
        "Sales (VLAN20)",
        "DMZ Web2 (80/443)",
        "DENY",
        "STD",
        "Chặn theo nguồn: Sales -> DMZ",
    )
    set_cell(
        "Sales (VLAN20)",
        "DMZ DNS (53)",
        "DENY",
        "STD",
        "Chặn theo nguồn: Sales -> DMZ",
    )
    set_cell(
        "Sales (VLAN20)",
        "DMZ (dịch vụ khác)",
        "DENY",
        "STD",
        "Chặn theo nguồn: Sales -> DMZ",
    )

    # --- Extended ACL (Inside -> DMZ) ---
    for dst in ["DMZ Web1 (80/443)", "DMZ Web2 (80/443)"]:
        set_cell(
            "Inside (VLAN khác)",
            dst,
            "ALLOW",
            "EXT",
            "Chỉ cho TCP 80/443 tới Web DMZ",
        )
    set_cell(
        "Inside (VLAN khác)",
        "DMZ DNS (53)",
        "ALLOW",
        "EXT",
        "Chỉ cho DNS (UDP/TCP 53) tới DMZ DNS",
    )
    set_cell(
        "Inside (VLAN khác)",
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

    # Thêm ghi chú nhắc: policy sync với acl.sh
    if not re.search(r"STD:\s*Deny\s*Sales", acl_text):
        # không fail; chỉ để người dùng biết nếu acl.sh đã đổi lớn.
        cells.append(
            FlowCell(
                src="(Cảnh báo)",
                dst_service="acl.sh",
                decision="N/A",
                layer="",
                note="Không tìm thấy comment 'STD: Deny Sales' trong acl.sh (có thể bạn đã chỉnh script).",
            )
        )
    return cells


def _decision_to_value(decision: Decision) -> float:
    # map để tô màu: DENY=-1, N/A=0, ALLOW=+1
    return {"DENY": -1.0, "N/A": 0.0, "ALLOW": 1.0}[decision]


def _render_heatmap(cells: list[FlowCell], out_png: Path, out_csv: Path) -> None:
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


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--acl-sh", default=str(SOURCE_DIR / "acl.sh"), help="Đường dẫn acl.sh (mặc định: source/acl.sh)")
    ap.add_argument("--out-png", default=str(LOG_DIR / "acl_heatmap.png"), help="File PNG output (mặc định: logs/acl_heatmap.png)")
    ap.add_argument("--out-csv", default=str(LOG_DIR / "acl_heatmap.csv"), help="File CSV output (mặc định: logs/acl_heatmap.csv)")
    args = ap.parse_args()

    acl_path = Path(args.acl_sh)
    out_png = Path(args.out_png)
    out_csv = Path(args.out_csv)
    acl_text = _read_acl_sh(acl_path)
    cells = _policy_from_acl_sh(acl_text)
    _render_heatmap(cells, out_png=out_png, out_csv=out_csv)
    print(f"[OK] Đã tạo heatmap ACL: {out_png}")
    print(f"[OK] Đã tạo bảng ACL CSV  : {out_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

