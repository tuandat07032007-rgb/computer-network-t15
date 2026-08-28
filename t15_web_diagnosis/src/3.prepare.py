"""
T15 - Bước 3: LÀM SẠCH (Clean) + GÁN NHÃN + TẠO FEATURE (Feature Engineering).

Đầu vào : data/raw/synthetic.csv (bắt buộc), data/raw/measurements.csv (nếu có)
Đầu ra  : data/processed/dataset.csv

Hai nguồn nhãn khác nhau, phải phân biệt rõ trong báo cáo:
  - source = "synthetic" -> nhãn là `cause` do quá trình tiêm lỗi sinh ra (ground truth).
  - source = "real"      -> không ai biết nguyên nhân thật, nên dùng LUẬT THÍCH NGHI
                            THEO HOST (so với trung vị của chính host đó) để gán
                            "nhãn yếu" (weak label), chỉ dùng để đối chiếu định tính.

Chạy: python src/prepare.py
"""

from __future__ import annotations

from pathlib import Path
import numpy as np
import pandas as pd

RAW = Path("data/raw")
OUT = Path("data/processed/dataset.csv")

PHASES = ["dns_ms", "tcp_ms", "tls_ms", "server_ms", "transfer_ms"]
# Ánh xạ từ pha bị lỗi/chậm nhất sang tên nhãn theo đúng đề bài T15.
PHASE2LABEL = {"dns_ms": "DNS_PROBLEM", "tcp_ms": "CONNECT_PROBLEM",
               "tls_ms": "TLS_PROBLEM", "server_ms": "HTTP_PROBLEM",
               "transfer_ms": "HTTP_PROBLEM"}
STAGE2LABEL = {"DNS": "DNS_PROBLEM", "CONNECT": "CONNECT_PROBLEM",
               "TLS": "TLS_PROBLEM", "HTTP": "HTTP_PROBLEM"}


def load_raw() -> pd.DataFrame:
    """Đọc tất cả file CSV thô có trong data/raw và nối lại thành một bảng."""
    frames = []
    for name in ["synthetic.csv", "measurements.csv"]:
        p = RAW / name
        if p.exists():
            df = pd.read_csv(p)
            frames.append(df)
            print(f"  đọc {p} -> {len(df)} dòng")
    if not frames:
        raise SystemExit("Không tìm thấy dữ liệu trong data/raw/. Chạy make_synthetic.py trước.")
    return pd.concat(frames, ignore_index=True)


def clean(df: pd.DataFrame) -> pd.DataFrame:
    """Ép kiểu số, điền khuyết, loại dòng vô nghĩa. Đây là bước Clean của pipeline."""
    n0 = len(df)
    for c in PHASES + ["total_ms", "response_size", "hour", "success", "conn_reuse"]:
        df[c] = pd.to_numeric(df[c], errors="coerce")   # chuỗi rỗng/hỏng -> NaN

    df[PHASES] = df[PHASES].fillna(0.0)                 # pha không được thực hiện = 0 ms
    df["response_size"] = df["response_size"].fillna(0)
    df["error_stage"] = df["error_stage"].fillna("").astype(str)
    df["cache_state"] = df["cache_state"].fillna("cold")

    # total_ms bị thiếu -> tính lại bằng tổng các pha (đảm bảo tính nhất quán).
    recomputed = df[PHASES].sum(axis=1)
    df["total_ms"] = df["total_ms"].fillna(recomputed)
    df.loc[df["total_ms"] <= 0, "total_ms"] = recomputed

    df = df[df["total_ms"] > 0]                         # bỏ bản ghi hỏng hoàn toàn
    df = df.drop_duplicates()
    df = df[df["hour"].between(0, 23)]
    print(f"  clean: {n0} -> {len(df)} dòng")
    return df.reset_index(drop=True)


def weak_label_real(df: pd.DataFrame) -> pd.Series:
    """
    Gán nhãn yếu cho dữ liệu ĐO THẬT bằng luật thích nghi theo host.

    Ý tưởng: một pha bị coi là "thủ phạm" khi nó vượt xa TRUNG VỊ của chính pha đó
    trên cùng host, và phần vượt đó chiếm phần lớn tổng phần vượt. Dùng trung vị
    (median) vì nó chịu được ngoại lai tốt hơn trung bình.
    """
    labels = pd.Series("NORMAL", index=df.index, dtype=object)
    ok = df["success"] == 1

    # Bảng trung vị của từng host, tính trên các lần đo THÀNH CÔNG.
    med = df[ok].groupby("host")[PHASES + ["total_ms"]].median()

    for i, row in df.iterrows():
        if row["error_stage"] in STAGE2LABEL:           # có lỗi rõ ràng -> nhãn theo pha lỗi
            labels[i] = STAGE2LABEL[row["error_stage"]]
            continue
        if row["host"] not in med.index:
            continue
        base = med.loc[row["host"]]
        # Chậm hơn 60% so với trung vị VÀ chậm hơn ít nhất 120 ms thì mới xét là bất thường.
        if row["total_ms"] < base["total_ms"] * 1.6 or row["total_ms"] - base["total_ms"] < 120:
            continue
        excess = {p: max(0.0, row[p] - base[p]) for p in PHASES}
        tot = sum(excess.values())
        if tot <= 0:
            continue
        worst = max(excess, key=excess.get)             # pha đóng góp nhiều nhất vào phần vượt
        labels[i] = PHASE2LABEL[worst]
    return labels


def add_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Feature Engineering: tạo biến phái sinh giàu thông tin hơn số đo thô.
    - *_share : tỉ trọng của từng pha trong tổng thời gian (giúp mô hình so sánh
                giữa các host nhanh/chậm khác nhau, không phụ thuộc đơn vị tuyệt đối).
    - log_*   : nén thang đo lệch phải của độ trễ mạng.
    """
    for p in PHASES:
        df[p.replace("_ms", "_share")] = df[p] / df["total_ms"]
    df["log_total"] = np.log1p(df["total_ms"])
    df["log_size"] = np.log1p(df["response_size"])
    df["is_peak_hour"] = df["hour"].isin([8, 9, 19, 20, 21, 22, 23]).astype(int)
    df["cache_warm"] = (df["cache_state"] == "warm").astype(int)
    df["handshake_ms"] = df["tcp_ms"] + df["tls_ms"]        # tổng chi phí thiết lập kết nối
    df["tls_over_tcp"] = df["tls_ms"] / (df["tcp_ms"] + 1)  # TLS thường ~ 2 RTT
    return df


def main() -> None:
    print("Đọc dữ liệu thô:")
    df = load_raw()
    df = clean(df)
    df = add_features(df)

    # --- Gán nhãn ---
    df["label"] = ""                      # khởi tạo kiểu chuỗi (pandas 3 không cho gán chuỗi vào cột float)
    is_syn = df["source"] == "synthetic"
    if "cause" in df.columns:
        df.loc[is_syn, "label"] = df.loc[is_syn, "cause"]
    if (~is_syn).any():
        df.loc[~is_syn, "label"] = weak_label_real(df[~is_syn].copy())
    df["label_source"] = np.where(is_syn, "ground_truth", "weak_rule")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUT, index=False)
    print("\nPhân bố nhãn:")
    print(df.groupby(["source", "label"]).size())
    print(f"\nĐã ghi {len(df)} dòng x {df.shape[1]} cột -> {OUT}")


if __name__ == "__main__":
    main()
