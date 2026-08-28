"""
T15 - Bước 2: SINH DỮ LIỆU SYNTHETIC có nhãn nguyên nhân "ground truth".

VÌ SAO CẦN SYNTHETIC?
  - Đo thật trên mạng nhà/trường thì hầu hết request đều BÌNH THƯỜNG. Muốn có đủ
    mẫu cho 5 lớp (NORMAL, DNS, CONNECT, TLS, HTTP) thì phải chờ rất lâu, hoặc phải
    tự gây lỗi lên hệ thống -> điều này bị Phần IV của đề bài CẤM.
  - Cách hợp lệ: mô phỏng lại quá trình sinh dữ liệu, TIÊM lỗi vào đúng một pha,
    và lấy chính pha bị tiêm làm nhãn. Nhãn KHÔNG suy ra từ feature -> tránh
    hoàn toàn lỗi "tạo target từ đúng một feature rồi dùng lại feature đó".

GIẢ ĐỊNH (phải ghi rõ trong báo cáo):
  1. Mỗi host có một "hồ sơ" độ trễ nền riêng (resolver, RTT, tải server, kích thước trang).
  2. Nhiễu đo nhân tính theo phân phối log-normal (độ trễ mạng lệch phải, không âm).
  3. Giờ cao điểm (8-9h và 19-23h) làm tăng RTT và thời gian xử lý của server.
  4. Cache DNS: nếu warm thì dns_ms ~ 0-2 ms; tái dùng kết nối thì tcp_ms = tls_ms = 0.
  5. Sự cố ở một pha làm thời gian pha đó tăng theo hệ số ngẫu nhiên, đôi khi timeout.

GIỚI HẠN: đây KHÔNG phải dữ liệu thật. Không được diễn giải kết quả như đo thực tế.
Dùng data/raw/measurements.csv (đo thật) để đối chiếu định tính.

Chạy: python src/make_synthetic.py --n 4000 --seed 42 --out data/raw/synthetic.csv
"""

from __future__ import annotations

import argparse
import numpy as np
import pandas as pd

# Hồ sơ độ trễ nền của từng host giả lập (đơn vị ms; size tính theo KB).
HOST_PROFILES = {
    "cdn-near.example":   dict(dns=12, rtt=8,   server=45,  size=90),
    "cdn-far.example":    dict(dns=25, rtt=95,  server=70,  size=140),
    "shop.example":       dict(dns=18, rtt=35,  server=210, size=520),
    "api.example":        dict(dns=15, rtt=20,  server=95,  size=25),
    "legacy.example":     dict(dns=40, rtt=60,  server=320, size=300),
    "media.example":      dict(dns=20, rtt=45,  server=80,  size=1800),
}

CAUSES = ["NORMAL", "DNS_PROBLEM", "CONNECT_PROBLEM", "TLS_PROBLEM", "HTTP_PROBLEM"]
CAUSE_P = [0.52, 0.12, 0.11, 0.10, 0.15]     # tỉ lệ lớp: lệch nhẹ, giống thực tế


def lognorm(rng, mean: float, sigma: float = 0.35) -> float:
    """Sinh 1 giá trị dương quanh `mean` theo log-normal (mô phỏng nhiễu độ trễ mạng)."""
    return float(mean * rng.lognormal(mean=0.0, sigma=sigma))


def generate(n: int, seed: int = 42) -> pd.DataFrame:
    rng = np.random.default_rng(seed)         # bộ sinh số ngẫu nhiên có seed -> tái lập được
    hosts = list(HOST_PROFILES)
    rows = []

    for _ in range(n):
        host = hosts[rng.integers(len(hosts))]
        prof = HOST_PROFILES[host]

        hour = int(rng.integers(0, 24))
        peak = 1.0 + (0.55 if hour in (8, 9) or 19 <= hour <= 23 else 0.0)   # hệ số giờ cao điểm
        congestion = peak * lognorm(rng, 1.0, 0.18)                          # nhiễu tắc nghẽn chung

        cache_state = "warm" if rng.random() < 0.55 else "cold"
        conn_reuse = 1 if rng.random() < 0.25 else 0
        cause = str(rng.choice(CAUSES, p=CAUSE_P))

        # --- Ràng buộc logic: sự cố phải xảy ra ở pha thực sự được thực hiện ---
        if cause == "DNS_PROBLEM":
            cache_state, conn_reuse = "cold", 0      # cache hit thì không có truy vấn DNS
        if cause in ("CONNECT_PROBLEM", "TLS_PROBLEM"):
            conn_reuse = 0                           # tái dùng kết nối thì không bắt tay lại

        # --- Giá trị nền của từng pha khi mọi thứ bình thường ---
        dns = 0.0 if cache_state == "warm" else lognorm(rng, prof["dns"])
        tcp = 0.0 if conn_reuse else lognorm(rng, prof["rtt"] * 1.0) * congestion
        tls = 0.0 if conn_reuse else lognorm(rng, prof["rtt"] * 2.0 + 15) * congestion
        server = lognorm(rng, prof["server"]) * congestion
        size_kb = max(3.0, lognorm(rng, prof["size"], 0.5))
        bandwidth_kbps = lognorm(rng, 9000, 0.3) / congestion       # KB/s
        transfer = size_kb / bandwidth_kbps * 1000

        success, error_stage, status = 1, "", 200

        # --- Tiêm sự cố vào đúng MỘT pha ---
        if cause == "DNS_PROBLEM":
            if rng.random() < 0.25:                       # 25% là hỏng hẳn (NXDOMAIN/timeout)
                dns = lognorm(rng, 5000, 0.2)
                success, error_stage = 0, "DNS"
                tcp = tls = server = transfer = 0.0
                size_kb, status = 0.0, np.nan
            else:
                dns = lognorm(rng, prof["dns"]) * rng.uniform(4, 15)

        elif cause == "CONNECT_PROBLEM":
            if rng.random() < 0.25:
                tcp = lognorm(rng, 6000, 0.2)
                success, error_stage = 0, "CONNECT"
                tls = server = transfer = 0.0
                size_kb, status = 0.0, np.nan
            else:
                tcp *= rng.uniform(4, 12)                 # mất gói -> SYN phải truyền lại
                transfer *= rng.uniform(1.2, 2.0)         # mất gói cũng làm chậm tải dữ liệu

        elif cause == "TLS_PROBLEM":
            if rng.random() < 0.22:
                tls = lognorm(rng, 3000, 0.25)
                success, error_stage = 0, "TLS"
                server = transfer = 0.0
                size_kb, status = 0.0, np.nan
            else:
                tls *= rng.uniform(3.5, 11)               # chain dài, OCSP, renegotiation...

        elif cause == "HTTP_PROBLEM":
            if rng.random() < 0.3:
                server = lognorm(rng, 900, 0.4)
                success, error_stage, status = 0, "HTTP", int(rng.choice([500, 502, 503]))
                size_kb = lognorm(rng, 2, 0.3)
                transfer = size_kb / bandwidth_kbps * 1000
            else:
                server *= rng.uniform(4, 14)              # backend/DB chậm

        total = dns + tcp + tls + server + transfer
        rows.append(dict(
            ts="", host=host, url=f"https://{host}/", hour=hour,
            dns_ms=round(dns, 3), tcp_ms=round(tcp, 3), tls_ms=round(tls, 3),
            server_ms=round(server, 3), transfer_ms=round(transfer, 3),
            total_ms=round(total, 3), response_size=int(size_kb * 1024),
            http_status=status, cache_state=cache_state, conn_reuse=conn_reuse,
            success=success, error_stage=error_stage, error_type="",
            source="synthetic", cause=cause,
        ))

    return pd.DataFrame(rows)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=4000, help="số quan sát cần sinh")
    ap.add_argument("--seed", type=int, default=42, help="seed để kết quả tái lập được")
    ap.add_argument("--out", default="data/raw/synthetic.csv")
    args = ap.parse_args()

    df = generate(args.n, args.seed)
    df.to_csv(args.out, index=False)
    print(df["cause"].value_counts(), "\n")
    print(f"Đã sinh {len(df)} dòng -> {args.out}")


if __name__ == "__main__":
    main()
