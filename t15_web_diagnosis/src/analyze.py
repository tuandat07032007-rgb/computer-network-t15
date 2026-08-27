"""
T15 - Bước 4: PHÂN TÍCH (Analyze) + BIỂU ĐỒ.

Sinh 3 biểu đồ EDA bắt buộc (mỗi biểu đồ có SỐ, TÊN và phần diễn giải in ra màn hình
để nhóm chép vào báo cáo):
    Hình 1 - Cơ cấu thời gian trung bình của 4 pha theo từng nhóm nguyên nhân
    Hình 2 - Quan hệ giữa thời gian DNS và TTFB (thang log) theo nhãn
    Hình 3 - Ảnh hưởng của giờ trong ngày và của cache/tái dùng kết nối

Chạy: python src/analyze.py
"""

from __future__ import annotations

from pathlib import Path
import matplotlib
matplotlib.use("Agg")            # backend không cần màn hình -> chạy được trên server
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

DATA = Path("data/processed/dataset.csv")
FIG = Path("figures")
PHASES = ["dns_ms", "tcp_ms", "tls_ms", "server_ms", "transfer_ms"]
PHASE_VN = ["DNS", "TCP", "TLS", "Server (TTFB)", "Transfer"]
ORDER = ["NORMAL", "DNS_PROBLEM", "CONNECT_PROBLEM", "TLS_PROBLEM", "HTTP_PROBLEM"]


def describe(df: pd.DataFrame) -> None:
    """In thống kê mô tả cơ bản - phần 'Analyze' của pipeline."""
    print("=" * 70)
    print("THỐNG KÊ MÔ TẢ (ms)")
    print(df[PHASES + ["total_ms"]].describe().T[["count", "mean", "50%", "std", "max"]].round(1))
    print("\nThời gian trung vị từng pha theo nhãn:")
    print(df.groupby("label")[PHASES + ["total_ms"]].median().round(1).reindex(ORDER))
    print("\nTỉ lệ request thất bại theo nhãn:")
    print((1 - df.groupby("label")["success"].mean()).round(3).reindex(ORDER))


def fig1(df: pd.DataFrame) -> None:
    """Hình 1: biểu đồ cột chồng - trung bình mỗi pha theo nhãn."""
    m = df[df["source"] == "synthetic"].groupby("label")[PHASES].mean().reindex(ORDER)
    fig, ax = plt.subplots(figsize=(9, 5))
    bottom = np.zeros(len(m))
    for col, name in zip(PHASES, PHASE_VN):
        ax.bar(m.index, m[col], bottom=bottom, label=name)   # cột chồng: cộng dồn bottom
        bottom += m[col].to_numpy()
    ax.set_ylabel("Thời gian trung bình (ms)")
    ax.set_title("Hình 1. Cơ cấu thời gian DNS/TCP/TLS/HTTP theo nhóm nguyên nhân")
    ax.legend(title="Pha")
    ax.tick_params(axis="x", rotation=15)
    fig.tight_layout()
    fig.savefig(FIG / "hinh1_co_cau_thoi_gian.png", dpi=150)
    plt.close(fig)
    print("\n[Hình 1] Diễn giải: mỗi nhóm sự cố có một pha phình to rõ rệt đúng với tên nhãn; "
          "riêng nhóm NORMAL thì tổng thời gian nhỏ và không pha nào chiếm ưu thế tuyệt đối. "
          "Đây là bằng chứng trực quan cho thấy chuỗi DNS→TCP→TLS→HTTP đủ sức phân biệt nguyên nhân.")


def fig2(df: pd.DataFrame) -> None:
    """Hình 2: scatter dns_ms vs server_ms (thang log) - tách nhóm DNS và HTTP."""
    d = df[(df["source"] == "synthetic") & (df["success"] == 1)]
    fig, ax = plt.subplots(figsize=(8, 6))
    for lab in ORDER:
        s = d[d["label"] == lab]
        ax.scatter(s["dns_ms"] + 1, s["server_ms"] + 1, s=8, alpha=0.5, label=lab)
    ax.set_xscale("log")            # độ trễ lệch phải mạnh -> dùng thang log cho dễ đọc
    ax.set_yscale("log")
    ax.set_xlabel("DNS time + 1 (ms, thang log)")
    ax.set_ylabel("TTFB / server time + 1 (ms, thang log)")
    ax.set_title("Hình 2. Quan hệ DNS time - TTFB theo nhóm nguyên nhân")
    ax.legend(markerscale=2, fontsize=8)
    fig.tight_layout()
    fig.savefig(FIG / "hinh2_dns_vs_ttfb.png", dpi=150)
    plt.close(fig)
    print("\n[Hình 2] Diễn giải: nhóm DNS_PROBLEM dạt hẳn sang phải, nhóm HTTP_PROBLEM dạt lên trên, "
          "nhưng hai đám mây vẫn CHỒNG LẤN ở vùng giữa - đó chính là phần mà luật ngưỡng cố định "
          "hay chẩn đoán sai và là lý do cần mô hình học máy.")


def fig3(df: pd.DataFrame) -> None:
    """Hình 3: hai panel - (a) tổng thời gian theo giờ, (b) DNS/handshake theo cache & reuse."""
    d = df[df["source"] == "synthetic"]
    fig, axes = plt.subplots(1, 2, figsize=(12, 4.5))

    by_hour = d.groupby("hour")["total_ms"].median()
    axes[0].plot(by_hour.index, by_hour.to_numpy(), marker="o")
    axes[0].set_xlabel("Giờ trong ngày")
    axes[0].set_ylabel("Tổng thời gian - trung vị (ms)")
    axes[0].set_title("(a) Ảnh hưởng của giờ cao điểm")

    grp = pd.DataFrame({
        "DNS": [d.loc[d["cache_warm"] == 0, "dns_ms"].median(),
                d.loc[d["cache_warm"] == 1, "dns_ms"].median()],
        "TCP+TLS": [d.loc[d["conn_reuse"] == 0, "handshake_ms"].median(),
                    d.loc[d["conn_reuse"] == 1, "handshake_ms"].median()],
    }, index=["cold / kết nối mới", "warm / tái dùng kết nối"])
    grp.plot(kind="bar", ax=axes[1], rot=0)
    axes[1].set_ylabel("Trung vị (ms)")
    axes[1].set_title("(b) Tác động của cache DNS và connection reuse")

    fig.suptitle("Hình 3. Yếu tố ngữ cảnh: thời điểm đo, cache DNS và tái dùng kết nối")
    fig.tight_layout()
    fig.savefig(FIG / "hinh3_ngu_canh.png", dpi=150)
    plt.close(fig)
    print("\n[Hình 3] Diễn giải: (a) giờ cao điểm đẩy trung vị tổng thời gian lên rõ rệt, nên "
          "time_of_day là feature có ý nghĩa; (b) khi cache DNS hit thì dns_ms ≈ 0 và khi tái dùng "
          "kết nối thì TCP+TLS ≈ 0. Vì vậy mọi kết luận 'DNS chậm' chỉ có giá trị trên các phép đo "
          "cold-cache; nếu trộn lẫn cold/warm mà không ghi cờ cache thì phân tích sẽ bị lệch.")


def main() -> None:
    FIG.mkdir(exist_ok=True)
    df = pd.read_csv(DATA)
    describe(df)
    fig1(df)
    fig2(df)
    fig3(df)
    print(f"\nĐã lưu biểu đồ vào {FIG}/")


if __name__ == "__main__":
    main()
