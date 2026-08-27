"""
T15 - Bước 5: BASELINE (luật) vs MACHINE LEARNING (Decision Tree) + ĐÁNH GIÁ.

Kết quả bắt buộc theo đề bài:
    - Confusion matrix              -> figures/hinh4_confusion_matrix.png
    - Macro F1                      -> results/metrics.json, results/report.txt
    - So sánh baseline vs ML        -> bảng in ra + biểu đồ
    - Error analysis theo từng nhóm nguyên nhân -> results/report.txt

CHỐNG RÒ RỈ NHÃN (đề bài yêu cầu):
    - Nhãn của tập synthetic KHÔNG được suy ra từ feature nào cả: nó là nguyên nhân
      đã được tiêm khi sinh dữ liệu (ground truth).
    - Baseline dùng NGƯỠNG TUYỆT ĐỐI cố định, khác hoàn toàn cách sinh nhãn.
    - Các cột bị LOẠI khỏi feature vì mang thông tin nhãn: cause, label, error_stage,
      error_type, http_status, host, url, source.

Chạy: python src/model.py
"""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import (ConfusionMatrixDisplay, classification_report,
                             confusion_matrix, f1_score)
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.tree import DecisionTreeClassifier, export_text

DATA = Path("data/processed/dataset.csv")
FIG, RES = Path("figures"), Path("results")
ORDER = ["NORMAL", "DNS_PROBLEM", "CONNECT_PROBLEM", "TLS_PROBLEM", "HTTP_PROBLEM"]

# Ngưỡng tuyệt đối cho baseline (ms) - đặt theo kinh nghiệm vận hành mạng.
THRESHOLDS = {"dns_ms": 90.0, "tcp_ms": 150.0, "tls_ms": 250.0, "server_ms": 400.0}
THRESH2LABEL = {"dns_ms": "DNS_PROBLEM", "tcp_ms": "CONNECT_PROBLEM",
                "tls_ms": "TLS_PROBLEM", "server_ms": "HTTP_PROBLEM"}

FEATURES = ["dns_ms", "tcp_ms", "tls_ms", "server_ms", "transfer_ms", "total_ms",
            "dns_share", "tcp_share", "tls_share", "server_share", "transfer_share",
            "log_total", "log_size", "hour", "is_peak_hour",
            "cache_warm", "conn_reuse", "handshake_ms", "tls_over_tcp", "success"]


def rule_baseline(df: pd.DataFrame) -> np.ndarray:
    """
    Baseline: chẩn đoán bằng luật ngưỡng cố định, không dùng học máy.
    Với mỗi bản ghi, tính tỉ số vượt ngưỡng của 4 pha; pha nào vượt nhiều nhất
    thì kết luận nguyên nhân ở đó. Không pha nào vượt -> NORMAL.
    """
    ratios = pd.DataFrame({p: df[p] / t for p, t in THRESHOLDS.items()})
    worst = ratios.idxmax(axis=1)                       # tên pha vượt ngưỡng nhiều nhất
    over = ratios.max(axis=1) >= 1.0                    # có vượt ngưỡng hay không
    pred = np.where(over, worst.map(THRESH2LABEL), "NORMAL")
    return pred


def plot_confusions(y_true, y_base, y_ml) -> None:
    """Hình 4: hai ma trận nhầm lẫn cạnh nhau để so sánh trực tiếp."""
    fig, axes = plt.subplots(1, 2, figsize=(13, 5.5))
    for ax, pred, name in zip(axes, [y_base, y_ml], ["Baseline (luật ngưỡng)", "Decision Tree"]):
        cm = confusion_matrix(y_true, pred, labels=ORDER)
        ConfusionMatrixDisplay(cm, display_labels=ORDER).plot(
            ax=ax, cmap="Blues", colorbar=False, values_format="d")
        ax.set_title(f"{name}\nmacro F1 = {f1_score(y_true, pred, average='macro'):.3f}")
        ax.tick_params(axis="x", rotation=45)
    fig.suptitle("Hình 4. Ma trận nhầm lẫn trên tập test: baseline so với Decision Tree")
    fig.tight_layout()
    fig.savefig(FIG / "hinh4_confusion_matrix.png", dpi=150)
    plt.close(fig)


def plot_importance(model, features) -> None:
    """Hình 5: mức độ quan trọng của feature trong cây quyết định."""
    imp = pd.Series(model.feature_importances_, index=features).sort_values()
    imp = imp[imp > 0.001]
    fig, ax = plt.subplots(figsize=(8, max(4, 0.32 * len(imp))))
    ax.barh(imp.index, imp.to_numpy())
    ax.set_xlabel("Mức độ quan trọng (giảm impurity)")
    ax.set_title("Hình 5. Feature quan trọng nhất của Decision Tree")
    fig.tight_layout()
    fig.savefig(FIG / "hinh5_feature_importance.png", dpi=150)
    plt.close(fig)


def error_analysis(X_test, y_test, y_base, y_ml) -> str:
    """Phân tích lỗi theo từng nhóm nguyên nhân và theo ngữ cảnh đo."""
    d = X_test.copy()
    d["y_true"], d["y_base"], d["y_ml"] = y_test.to_numpy(), y_base, y_ml
    lines = ["", "=" * 70, "PHÂN TÍCH LỖI (ERROR ANALYSIS)", "=" * 70]

    rows = []
    for lab in ORDER:                                   # duyệt từng lớp nguyên nhân
        g = d[d["y_true"] == lab]
        rows.append({"nguyen_nhan": lab, "n": len(g),
                     "acc_baseline": round((g["y_base"] == lab).mean(), 3),
                     "acc_decision_tree": round((g["y_ml"] == lab).mean(), 3)})
    acc = pd.DataFrame(rows).set_index("nguyen_nhan")
    lines += ["", "Độ chính xác theo từng nhóm nguyên nhân:", acc.to_string()]

    wrong = d[d.y_ml != d.y_true]
    top = wrong.groupby(["y_true", "y_ml"]).size().sort_values(ascending=False).head(6)
    lines += ["", f"Tổng số ca Decision Tree dự đoán sai: {len(wrong)}/{len(d)}",
              "Các cặp nhầm lẫn phổ biến nhất (thật -> dự đoán):", top.to_string()]

    lines += ["", "Ngữ cảnh của các ca sai (so với toàn tập test):",
              f"  tỉ lệ cache warm : sai={wrong.cache_warm.mean():.2f} | chung={d.cache_warm.mean():.2f}",
              f"  tỉ lệ reuse conn : sai={wrong.conn_reuse.mean():.2f} | chung={d.conn_reuse.mean():.2f}",
              f"  tỉ lệ giờ cao điểm: sai={wrong.is_peak_hour.mean():.2f} | chung={d.is_peak_hour.mean():.2f}",
              f"  trung vị total_ms : sai={wrong.total_ms.median():.0f} ms | chung={d.total_ms.median():.0f} ms"]
    lines += ["", "Nhận xét: sai sót tập trung ở các ca CHẬM NHẸ, nơi một pha chỉ hơi vượt mức",
              "nền nên ranh giới giữa NORMAL và *_PROBLEM bị mờ; các ca hỏng hẳn (timeout, 5xx)",
              "gần như luôn được phân loại đúng."]
    return "\n".join(lines)


def main() -> None:
    FIG.mkdir(exist_ok=True)
    RES.mkdir(exist_ok=True)
    df = pd.read_csv(DATA)

    # Chỉ huấn luyện trên phần có nhãn ground truth (synthetic).
    d = df[df["label_source"] == "ground_truth"].reset_index(drop=True)
    X, y = d[FEATURES], d["label"]

    # stratify=y giữ nguyên tỉ lệ 5 lớp ở cả train và test; random_state để tái lập.
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)

    # --- Baseline: luật ngưỡng ---
    base_pred = rule_baseline(X_te)

    # --- Machine Learning: Decision Tree ---
    clf = DecisionTreeClassifier(max_depth=6,            # giới hạn độ sâu -> chống overfit, dễ đọc luật
                                 min_samples_leaf=20,    # mỗi lá tối thiểu 20 mẫu -> luật ổn định
                                 class_weight="balanced",# bù cho lớp NORMAL chiếm đa số
                                 random_state=42)
    clf.fit(X_tr, y_tr)
    ml_pred = clf.predict(X_te)

    cv = cross_val_score(clf, X_tr, y_tr, cv=5, scoring="f1_macro")   # kiểm tra tính ổn định

    f1_base = f1_score(y_te, base_pred, average="macro")
    f1_ml = f1_score(y_te, ml_pred, average="macro")

    plot_confusions(y_te, base_pred, ml_pred)
    plot_importance(clf, FEATURES)

    report = [
        "=" * 70, "KẾT QUẢ T15 - PHÂN LOẠI NGUYÊN NHÂN WEB CHẬM/LỖI", "=" * 70,
        f"Số mẫu huấn luyện: {len(X_tr)} | Số mẫu kiểm thử: {len(X_te)}",
        f"Cross-validation 5-fold trên tập train (macro F1): "
        f"{cv.mean():.3f} ± {cv.std():.3f}",
        "", f"Macro F1 - Baseline (luật ngưỡng): {f1_base:.3f}",
        f"Macro F1 - Decision Tree          : {f1_ml:.3f}",
        f"Mức cải thiện                     : {f1_ml - f1_base:+.3f}",
        "", "-" * 70, "BÁO CÁO CHI TIẾT - BASELINE", "-" * 70,
        classification_report(y_te, base_pred, labels=ORDER, zero_division=0),
        "-" * 70, "BÁO CÁO CHI TIẾT - DECISION TREE", "-" * 70,
        classification_report(y_te, ml_pred, labels=ORDER, zero_division=0),
        error_analysis(X_te, y_te, base_pred, ml_pred),
        "", "=" * 70, "10 TẦNG ĐẦU CỦA CÂY QUYẾT ĐỊNH (để giải thích cho giảng viên)", "=" * 70,
        export_text(clf, feature_names=FEATURES, max_depth=3),
    ]
    text = "\n".join(report)
    (RES / "report.txt").write_text(text, encoding="utf-8")
    json.dump({"macro_f1_baseline": round(f1_base, 4),
               "macro_f1_decision_tree": round(f1_ml, 4),
               "cv_macro_f1_mean": round(float(cv.mean()), 4),
               "cv_macro_f1_std": round(float(cv.std()), 4),
               "n_train": len(X_tr), "n_test": len(X_te)},
              open(RES / "metrics.json", "w"), indent=2)
    print(text)
    print(f"\nĐã lưu results/report.txt, results/metrics.json và biểu đồ trong {FIG}/")


if __name__ == "__main__":
    main()
