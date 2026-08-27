# T15 — Phân loại nguyên nhân truy cập Web chậm hoặc lỗi dựa trên DNS–TCP–TLS–HTTP

Bài tập hết môn Mạng máy tính. Chương trình phân tách một lần truy cập Web thành 4 pha
(DNS → TCP → TLS → HTTP), xác định pha nào gây chậm/lỗi, và so sánh **chẩn đoán bằng luật**
với **mô hình Decision Tree**.

---

## 1. Môi trường chạy

| Thành phần | Phiên bản đã kiểm thử |
|---|---|
| Hệ điều hành | Ubuntu 24.04 (chạy được trên Windows/macOS) |
| Python | 3.12 |
| pandas | 3.0 (≥2.0 là chạy được) |
| numpy | 2.4 |
| matplotlib | 3.10 |
| scikit-learn | 1.8 |

Cài thư viện:

```bash
pip install -r requirements.txt
```

Không cần GPU, không cần Deep Learning. Toàn bộ pipeline chạy dưới 1 phút.

---

## 2. Cấu trúc thư mục

```
t15_web_diagnosis/
├── README.md                 # file này
├── requirements.txt          # thư viện cần cài
├── run_all.py                # chạy toàn bộ pipeline theo thứ tự
├── src/
│   ├── measure.py            # (tuỳ chọn) ĐO THẬT timing DNS/TCP/TLS/HTTP
│   ├── make_synthetic.py     # sinh dataset synthetic có ground truth
│   ├── prepare.py            # Clean + gán nhãn + Feature Engineering
│   ├── analyze.py            # thống kê mô tả + Hình 1, 2, 3
│   └── model.py              # baseline luật + Decision Tree + Hình 4, 5
├── data/
│   ├── raw/measurements.csv  # dữ liệu đo thật (nếu có chạy measure.py)
│   ├── raw/synthetic.csv     # dữ liệu mô phỏng
│   └── processed/dataset.csv # dataset đã làm sạch + feature + nhãn
├── figures/                  # 5 biểu đồ PNG
└── results/                  # report.txt và metrics.json
```

---

## 3. Cách chạy

**Chạy toàn bộ (khuyến nghị):**

```bash
python run_all.py
```

**Hoặc chạy từng bước:**

```bash
python src/make_synthetic.py --n 4000 --seed 42   # sinh dữ liệu mô phỏng
python src/prepare.py                              # làm sạch, gán nhãn, tạo feature
python src/analyze.py                              # thống kê + Hình 1,2,3
python src/model.py                                # baseline + Decision Tree + Hình 4,5
```

**Đo thật (tuỳ chọn, cần Internet):**

```bash
python src/measure.py --rounds 20 --delay 2 --second-request
```

Sau khi có `data/raw/measurements.csv`, chạy lại `prepare.py` để dữ liệu thật được
gộp vào dataset và gán "nhãn yếu".

---

## 4. Dataset

Đề tài dùng **hai nguồn dữ liệu**, ghi rõ trong cột `source` và `label_source`.

### (A) Dữ liệu đo thật — `data/raw/measurements.csv`
Do nhóm tự thu bằng `src/measure.py`, chỉ gửi request GET bình thường tới các site công
khai, có nghỉ ≥ 1 giây giữa hai request. Mỗi dòng là một lần truy cập, đo tách bạch
`dns_ms`, `tcp_ms`, `tls_ms`, `server_ms` (TTFB), `transfer_ms`.

Vì không ai biết nguyên nhân thật của một lần truy cập chậm, dữ liệu này chỉ được gán
**nhãn yếu (weak label)** bằng luật thích nghi theo host và **không dùng để huấn luyện**;
nó dùng để kiểm chứng định tính rằng phân bố thời gian mô phỏng là hợp lý.

### (B) Dữ liệu synthetic — `data/raw/synthetic.csv`
**Đây không phải dữ liệu thật.** Được sinh bằng `src/make_synthetic.py`.

*Cách tạo:* mô phỏng 6 host với hồ sơ độ trễ nền khác nhau; sinh thời gian từng pha theo
phân phối log-normal; nhân thêm hệ số tắc nghẽn theo giờ; áp dụng cache DNS và tái dùng
kết nối; sau đó **tiêm sự cố vào đúng một pha** và lấy chính pha bị tiêm làm nhãn.

*Giả định:* độ trễ mạng lệch phải và không âm (log-normal); giờ cao điểm 8–9h và 19–23h
làm tăng RTT ~55%; cache hit ⇒ `dns_ms ≈ 0`; tái dùng kết nối ⇒ `tcp_ms = tls_ms = 0`;
mỗi lần truy cập chỉ có tối đa một nguyên nhân chính.

*Giới hạn:* không mô phỏng mất gói ở mức gói tin, không mô phỏng HTTP/2–HTTP/3, không có
tương quan thời gian giữa các lần đo liên tiếp (mỗi mẫu độc lập). Kết quả chỉ chứng minh
tính khả thi của phương pháp, không phải số liệu vận hành thực tế.

### Quy mô mẫu
4.000 quan sát, tỉ lệ lớp ~52% NORMAL và 10–15% cho mỗi loại sự cố. Với 5 lớp và 20
feature, chia 70/30 cho ra ~1.200 mẫu test (≈120–620 mẫu mỗi lớp) — đủ để precision/recall
theo lớp ổn định, được kiểm chứng thêm bằng cross-validation 5-fold (độ lệch chuẩn macro F1
chỉ ±0.010).

---

## 5. Output mong đợi

Sau khi chạy `run_all.py`:

**Biểu đồ (`figures/`)**

| File | Nội dung |
|---|---|
| `hinh1_co_cau_thoi_gian.png` | Cột chồng: thời gian trung bình mỗi pha theo nhóm nguyên nhân |
| `hinh2_dns_vs_ttfb.png` | Scatter log–log DNS time vs TTFB, tô màu theo nhãn |
| `hinh3_ngu_canh.png` | (a) tổng thời gian theo giờ; (b) tác động cache DNS & connection reuse |
| `hinh4_confusion_matrix.png` | Hai ma trận nhầm lẫn: baseline và Decision Tree |
| `hinh5_feature_importance.png` | Mức độ quan trọng của feature trong cây |

**Kết quả số (`results/`)**

- `report.txt` — classification report đầy đủ, phân tích lỗi, 3 tầng đầu của cây.
- `metrics.json` — macro F1 của baseline và Decision Tree, kết quả cross-validation.

**Kết quả tham chiếu (seed 42, 4.000 mẫu):**

```
Macro F1 - Baseline (luật ngưỡng): 0.848
Macro F1 - Decision Tree         : 0.917   (+0.069)
Cross-validation 5-fold          : 0.910 ± 0.010
```

---

## 6. Chống rò rỉ nhãn (label leakage)

Đề bài yêu cầu tránh việc tạo target từ đúng một feature rồi dùng lại feature đó. Ba biện pháp:

1. **Nhãn không sinh ra từ feature.** Nhãn của tập huấn luyện là nguyên nhân đã tiêm khi
   sinh dữ liệu, tồn tại *trước* khi các con số thời gian được tạo ra — không phải kết quả
   của một phép so sánh ngưỡng nào.
2. **Baseline khác cơ chế sinh nhãn.** Baseline dùng ngưỡng tuyệt đối cố định
   (DNS 90 ms, TCP 150 ms, TLS 250 ms, server 400 ms); nếu baseline chính là bộ sinh nhãn
   thì nó đã đạt F1 = 1.0. Nó chỉ đạt 0.848, chứng tỏ bài toán không tầm thường.
3. **Loại bỏ cột mang thông tin nhãn.** `cause`, `error_stage`, `error_type`,
   `http_status`, `host`, `url`, `source` đều **không** được đưa vào feature. Mô hình chỉ
   thấy số đo thời gian, tỉ trọng các pha, kích thước response và ngữ cảnh đo.

---

## 7. Thảo luận bắt buộc: cache, connection reuse và giới hạn phép đo

- **Cache DNS.** `dns_ms` chỉ phản ánh chi phí phân giải tên khi cache miss. Khi cache hit
  (ở OS, ở stub resolver hoặc ở trình duyệt), giá trị này gần bằng 0 và **không** có nghĩa
  là DNS đang khoẻ. Vì vậy dataset có cột `cache_state`, và kết luận "DNS chậm" chỉ được
  phát biểu trên các phép đo cold-cache.
- **Connection reuse.** Với keep-alive/HTTP2, request thứ hai trở đi không lặp lại bắt tay
  TCP và TLS, nên `tcp_ms = tls_ms = 0`. Phép đo thật đã xác nhận điều này: cùng một trang,
  request đầu mất ~108 ms còn request tái dùng kết nối chỉ mất ~22 ms. Cột `conn_reuse` ghi
  lại trạng thái này để mô hình không hiểu nhầm "0 ms" là "không có vấn đề".
- **Giới hạn phép đo.** Công cụ đo ở tầng ứng dụng nên chỉ thấy được thời gian, không thấy
  được nguyên nhân gốc bên trong mạng (mất gói, định tuyến, tải backend). `server_ms` (TTFB)
  gộp cả thời gian truyền request đi và thời gian server xử lý. Ngoài ra mỗi lần đo chỉ lấy
  bản ghi A đầu tiên từ `getaddrinfo`, chưa xét IPv6, CDN anycast hay Happy Eyeballs.

---

## 8. Nguyên tắc an toàn đã tuân thủ (Phần IV đề bài)

- Chỉ đo các request do chính nhóm tạo ra, tới site công khai, bằng phương thức GET thông thường.
- Có giới hạn tốc độ cứng trong code (`--delay` phải ≥ 1 giây) để không gây tải cho dịch vụ bên ngoài.
- Không quét port, không khai thác lỗ hổng, không ARP poisoning, không SYN flood/DoS, không DNS tunneling.
- Không bắt traffic Wi-Fi của người khác, không dùng monitor mode.
- Không thu thập credential, cookie hay payload cá nhân; script chỉ đếm **số byte** của
  response chứ không lưu nội dung.
- Các trường hợp lỗi (timeout, 5xx, lỗi TLS) trong tập huấn luyện là **mô phỏng**, không
  phải do nhóm gây ra trên hệ thống thật.
