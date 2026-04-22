#!/usr/bin/env python3
"""
Vẽ bảng Performance (Throughput/Latency) dạng ảnh giống style bảng ở TKM/Baitap4/image/case5.jpg.

Input: một file CSV do perf_benchmark.py sinh ra (cột: case, throughput_mbps_tcp, ping_avg_ms)
Output: PNG trong logs/perf/
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

import matplotlib


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PERF_DIR = PROJECT_ROOT / "logs" / "perf"
PERF_DIR.mkdir(parents=True, exist_ok=True)


CASE_LABELS = {
    "no_nat_no_acl": "No NAT / No ACL",
    "nat_only": "NAT only",
    "acl_only": "ACL only",
    "nat_and_acl": "NAT + ACL",
}


def read_perf_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8") as f:
        r = csv.DictReader(f)
        return [row for row in r]


def latest_perf_csv() -> Path | None:
    cands = sorted(PERF_DIR.glob("perf_table_*.csv"), key=lambda p: p.stat().st_mtime, reverse=True)
    return cands[0] if cands else None


def fmt_num(s: str, digits: int = 3) -> str:
    try:
        v = float(s)
    except Exception:
        return s
    if v < 0:
        return "N/A"
    return f"{v:.{digits}f}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in-csv", default="", help="CSV input. Nếu bỏ trống sẽ lấy perf_table_*.csv mới nhất trong logs/perf/")
    ap.add_argument("--out-png", default="", help="PNG output (mặc định logs/perf/perf_table.png)")
    ap.add_argument("--title", default="BẢNG SO SÁNH HIỆU NĂNG (NAT / ACL)", help="Tiêu đề bảng")
    args = ap.parse_args()

    in_csv = Path(args.in_csv) if args.in_csv else (latest_perf_csv() or Path(""))
    if not in_csv or not in_csv.exists():
        raise SystemExit("Không tìm thấy CSV. Hãy chạy: sudo python3 source/perf_benchmark.py --fail-soft")

    out_png = Path(args.out_png) if args.out_png else (PERF_DIR / "perf_table.png")

    rows = read_perf_csv(in_csv)
    # Giữ thứ tự quen thuộc
    rows.sort(key=lambda r: ["no_nat_no_acl", "nat_only", "acl_only", "nat_and_acl"].index(r["case"]))

    # Build table data (2 hàng: Throughput, Latency) và nhiều cột theo case
    col_labels = ["Path"] + [CASE_LABELS.get(r["case"], r["case"]) for r in rows]
    throughput = ["Throughput (Mbps)"] + [fmt_num(r.get("throughput_mbps_tcp", ""), 3) for r in rows]
    latency = ["Latency avg (ms)"] + [fmt_num(r.get("ping_avg_ms", ""), 3) for r in rows]
    cell_text = [throughput, latency]

    has_display = bool(__import__("os").environ.get("DISPLAY"))
    if not has_display:
        matplotlib.use("Agg")
    import matplotlib.pyplot as plt  # noqa: WPS433

    fig, ax = plt.subplots(figsize=(12.5, 3.2))
    ax.axis("off")

    # Title (2 dòng giống style case5)
    fig.text(0.5, 0.95, args.title, ha="center", va="top", fontsize=16, fontweight="bold")
    fig.text(0.5, 0.88, f"TỪ [ad_pc1] ĐẾN [internet]  (CSV: {in_csv.name})", ha="center", va="top", fontsize=12, fontweight="bold")

    table = ax.table(
        cellText=cell_text,
        colLabels=col_labels,
        cellLoc="center",
        colLoc="center",
        loc="center",
    )

    table.auto_set_font_size(False)
    table.set_fontsize(11)
    table.scale(1.0, 2.0)

    # Style giống case5: cột trái màu cam, header xanh nhạt
    header_color = "#d9edf7"
    left_color = "#f4b183"
    edge_color = "#111111"

    for (r, c), cell in table.get_celld().items():
        cell.set_edgecolor(edge_color)
        cell.set_linewidth(1.5)
        if r == 0:  # header row
            cell.set_facecolor(header_color)
            cell.set_text_props(fontweight="bold")
        if c == 0:  # left labels column (bao gồm header "Path")
            cell.set_facecolor(left_color)
            cell.set_text_props(fontweight="bold")

    fig.tight_layout(rect=(0.02, 0.02, 0.98, 0.84))
    fig.savefig(out_png, dpi=170)
    plt.close(fig)

    print(f"[OK] Đã vẽ bảng PNG: {out_png}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

