# computer-network-t15

Bài tập cuối kỳ môn **Mạng máy tính** — chủ đề **T15: Phân loại nguyên nhân truy cập Web chậm/lỗi** dựa trên timing 4 pha **DNS → TCP → TLS → HTTP**.

Chương trình đo/đo mô phỏng thời gian từng pha của một lượt truy cập web, gán nhãn nguyên nhân (DNS_PROBLEM, CONNECT_PROBLEM, TLS_PROBLEM, HTTP_PROBLEM, NORMAL...), rồi so sánh cách chẩn đoán bằng **luật ngưỡng (baseline)** với **Decision Tree**.

> Code toàn bộ nằm trong thư mục [`t15_web_diagnosis/`](./t15_web_diagnosis). README này chỉ tóm tắt nhanh cách chạy — chi tiết đầy đủ (dataset, chống rò rỉ nhãn, giới hạn phép đo, nguyên tắc an toàn...) xem tại [`t15_web_diagnosis/README.md`](./t15_web_diagnosis/README.md).

---

## Cấu trúc repo

```
computer-network-t15/
└── t15_web_diagnosis/
    ├── local_server/          # server Node.js giả lập lỗi (slow, 500/503, drop connection)
    ├── src/
    │   ├── 1.1 measure_local.py   # đo timing với local_server (an toàn, không cần Internet)
    │   ├── 1.2 measure_real.py    # đo timing với site thật ngoài Internet
    │   ├── 2. make_synthetic.py   # sinh dataset mô phỏng có ground-truth
    │   ├── 3.prepare.py           # làm sạch + gán nhãn + feature engineering
    │   ├── 4.analyze.py           # thống kê mô tả + vẽ Hình 1, 2, 3
    │   └── 5. model.py            # baseline luật + Decision Tree + Hình 4, 5
    ├── data/                  # raw + processed dataset
    ├── figures/                # 5 biểu đồ PNG kết quả
    ├── results/                 # report.txt + metrics.json
    ├── run_all.py              # chạy nhanh toàn bộ pipeline synthetic → model
    └── requirements.txt
```

---

## Yêu cầu môi trường

| Thành phần | Phiên bản |
|---|---|
| Python | 3.12 |
| Node.js | để chạy `local_server` (dùng Express) |
| pandas, numpy, matplotlib, scikit-learn | xem `requirements.txt` |

Cài Python packages:

```bash
cd t15_web_diagnosis
pip install -r requirements.txt
```

Cài server giả lập:

```bash
cd t15_web_diagnosis/local_server
npm install
```

---

## Cách chạy (đúng thứ tự)

Nếu chỉ cần dataset synthetic + huấn luyện model nhanh, chạy thẳng:

```bash
cd t15_web_diagnosis
python run_all.py
```

Còn nếu muốn chạy **đầy đủ pipeline kể cả phần đo thật** (local + real), làm theo thứ tự dưới đây:

1. **Mở server ảo** (giả lập các tình huống lỗi HTTP: chậm, 500/503, drop connection)
   ```bash
   cd t15_web_diagnosis/local_server
   node server.js
   ```
   Giữ cửa sổ này chạy, mở terminal khác cho các bước sau.

2. **Chạy đo local** (đo timing với server ảo vừa mở ở bước 1)
   ```bash
   cd t15_web_diagnosis
   python "src/1.1 measure_local.py"
   ```

3. **Chạy đo real** (đo timing với các site thật trên Internet)
   ```bash
   python "src/1.2 measure_real.py"
   ```

4. **Làm synthetic** (sinh dataset mô phỏng có nhãn — dùng để train/test model)
   ```bash
   python "src/2. make_synthetic.py" --n 4000 --seed 42
   ```

5. **Prepare** (làm sạch dữ liệu, gán nhãn, tạo feature, gộp cả 3 nguồn dữ liệu trên)
   ```bash
   python "src/3.prepare.py"
   ```

6. **Analyze** (thống kê mô tả, xuất Hình 1–3 vào `figures/`)
   ```bash
   python "src/4.analyze.py"
   ```

7. **Model** (baseline luật ngưỡng vs Decision Tree, xuất Hình 4–5, `results/report.txt`, `results/metrics.json`)
   ```bash
   python "src/5. model.py"
   ```

---

## Kết quả tham chiếu (seed 42, 4.000 mẫu)

```
Macro F1 - Baseline (luật ngưỡng): 0.848
Macro F1 - Decision Tree         : 0.917   (+0.069)
Cross-validation 5-fold          : 0.910 ± 0.010
```

Biểu đồ nằm trong `figures/`, báo cáo chi tiết nằm trong `results/report.txt`.

---

## Lưu ý

- Toàn bộ đo thật chỉ gửi request GET bình thường tới site công khai, có giới hạn tốc độ (`--delay ≥ 1s`), không quét port, không khai thác lỗ hổng, không thu thập dữ liệu cá nhân.
- Dữ liệu synthetic **không phải dữ liệu thật** — chỉ dùng để kiểm chứng tính khả thi của phương pháp phân loại.
- Chi tiết về giả định mô phỏng, chống rò rỉ nhãn (label leakage), và giới hạn phép đo (cache DNS, connection reuse...) xem mục 4–7 của [README trong `t15_web_diagnosis/`](./t15_web_diagnosis/README.md).
