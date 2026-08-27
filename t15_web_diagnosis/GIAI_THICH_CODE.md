# Giải thích chi tiết mã nguồn — T15

Tài liệu này giải thích **chức năng của từng dòng/khối lệnh**, kèm lý do chọn cách làm đó.
Đọc theo đúng thứ tự pipeline: `measure.py` → `make_synthetic.py` → `prepare.py` →
`analyze.py` → `model.py`.

---

## Phần 0. Kiến thức mạng nằm sau mã nguồn

Một lần gõ URL rồi Enter, trình duyệt phải đi qua 4 pha tuần tự. Toàn bộ đề tài là việc
**bấm giờ từng pha** rồi đoán xem pha nào là thủ phạm.

| Pha | Điều gì xảy ra | Biến trong code | Chậm bất thường nghĩa là |
|---|---|---|---|
| 1. DNS | Máy hỏi resolver: tên miền này ứng với IP nào? | `dns_ms` | Resolver chậm/xa, cache miss, tên miền cấu hình sai |
| 2. TCP | Bắt tay 3 bước SYN → SYN/ACK → ACK | `tcp_ms` | RTT lớn, mất gói (SYN phải truyền lại), server quá tải hàng đợi |
| 3. TLS | ClientHello → chứng chỉ → khoá phiên → Finished | `tls_ms` | Chuỗi chứng chỉ dài, kiểm tra OCSP, thiếu session resumption |
| 4. HTTP | Gửi GET, chờ byte đầu tiên (TTFB), rồi tải nốt body | `server_ms`, `transfer_ms` | Backend/CSDL chậm (TTFB lớn) hoặc trang quá nặng/băng thông thấp (transfer lớn) |

Điểm mấu chốt: `tcp_ms` ≈ 1 RTT, `tls_ms` ≈ 2 RTT (TLS 1.2) hoặc 1 RTT (TLS 1.3). Nếu
`tls_ms` lớn hơn `tcp_ms` **rất nhiều lần** thì vấn đề nằm ở chính TLS chứ không phải ở
độ trễ đường truyền — đây là lý do code có feature `tls_over_tcp`.

---

## Phần 1. `src/measure.py` — đo thật

### 1.1 Các thư viện

```python
import socket   # cung cấp cả getaddrinfo (DNS) lẫn socket TCP
import ssl      # bọc socket TCP thành socket TLS
import time     # time.perf_counter() = đồng hồ đơn điệu, độ phân giải nano giây
```

Dùng `time.perf_counter()` chứ **không** dùng `time.time()`: `time.time()` lấy giờ hệ
thống, có thể bị NTP chỉnh lùi giữa chừng làm khoảng đo bị âm. `perf_counter()` chỉ tăng.

### 1.2 Hàm `_ms(t0)`

```python
def _ms(t0):
    return round((time.perf_counter() - t0) * 1000, 3)
```

Lấy thời điểm hiện tại trừ mốc `t0` (giây), nhân 1000 ra mili-giây, làm tròn 3 chữ số.
Viết thành hàm để 5 pha đều dùng chung một cách đo — tránh lặp code và tránh sai lệch.

### 1.3 Pha 1 — đo DNS

```python
t0 = time.perf_counter()
infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
rec["dns_ms"] = _ms(t0)
family, socktype, proto, _canon, sockaddr = infos[0]
```

- `getaddrinfo` là hàm chuẩn POSIX thực hiện phân giải tên; nó chính là bước gửi truy vấn
  DNS (hoặc đọc từ cache).
- `socket.AF_INET` ép chỉ lấy IPv4 để phép đo nhất quán (nếu để mặc định, máy có thể chọn
  IPv6 lúc này, IPv4 lúc khác, làm thời gian nhảy loạn).
- `socket.SOCK_STREAM` nghĩa là ta cần TCP, không phải UDP.
- `infos[0]` lấy bản ghi đầu tiên; `sockaddr` là cặp (IP, port) dùng để `connect`.
- Bọc trong `try`, nếu ném `socket.gaierror` thì đây là **lỗi ở pha DNS** → gán
  `error_stage = "DNS"`.

### 1.4 Pha 2 — đo bắt tay TCP

```python
sock = socket.socket(family, socktype, proto)
sock.settimeout(timeout)
sock.connect(sockaddr)
rec["tcp_ms"] = _ms(t0)
```

- Tạo socket đúng họ địa chỉ vừa phân giải được.
- `settimeout(10)` bắt buộc phải có: nếu không, một server im lặng sẽ treo script mãi mãi.
- `connect()` chính là gửi SYN và chờ SYN/ACK. Thời gian hàm này trả về ≈ 1 RTT.
- Cố tình **không** dùng `socket.create_connection(host, port)` vì hàm tiện lợi đó gộp cả
  DNS lẫn TCP vào một lời gọi — ta sẽ không tách được hai pha nữa.

### 1.5 Pha 3 — đo bắt tay TLS

```python
ctx = ssl.create_default_context()
sock = ctx.wrap_socket(sock, server_hostname=host)
rec["tls_ms"] = _ms(t0)
```

- `create_default_context()` bật sẵn kiểm tra chứng chỉ và hostname, giống trình duyệt.
  (Tuyệt đối không tắt kiểm tra — chứng chỉ sai là một *nguyên nhân lỗi hợp lệ* cần ghi nhận,
  không phải thứ để bỏ qua.)
- `wrap_socket` thực hiện toàn bộ bắt tay TLS ngay tại dòng này.
- `server_hostname=host` gửi **SNI** — bắt buộc với server dùng chung IP cho nhiều tên miền.
- Nếu ném `ssl.SSLError` → `error_stage = "TLS"`.

### 1.6 Pha 4 — HTTP và TTFB

```python
req = (f"GET {path} HTTP/1.1\r\n"
       f"Host: {host}\r\n"
       ... f"Connection: {conn_hdr}\r\n\r\n").encode()
sock.sendall(req)
first = sock.recv(1)        # <-- chờ đúng 1 byte
rec["server_ms"] = _ms(t0)
```

- Viết request HTTP thủ công thay vì dùng `requests` để **nhìn thấy** cấu trúc bản tin và
  kiểm soát được thời điểm bắt đầu bấm giờ.
- Mỗi dòng header kết thúc bằng `\r\n`, và một dòng trống `\r\n\r\n` báo hết header — đúng
  chuẩn RFC 7230.
- `Host:` là bắt buộc trong HTTP/1.1 (virtual hosting).
- `Accept-Encoding: identity` yêu cầu **không nén**, để `response_size` phản ánh số byte
  thật trên dây và so sánh được giữa các site.
- `sock.recv(1)` chỉ đọc **một byte**. Đây là mẹo chính: hàm chỉ trả về khi byte đầu tiên
  của response đã tới nơi ⇒ đo được đúng **TTFB**, tức thời gian server nghĩ + 1 chiều truyền.

```python
head, rest = _read_headers(sock)
status, headers = _parse_headers(first + head)
size = _read_body(sock, headers, rest, max_bytes)
rec["transfer_ms"] = _ms(t0)
```

- `_read_headers` đọc tiếp tới khi gặp `\r\n\r\n`, tách phần header và phần body đã lỡ đọc kèm.
- `_parse_headers` cắt dòng đầu `HTTP/1.1 200 OK` để lấy status code, rồi tách các header
  thành dictionary (khoá đổi thành chữ thường vì tên header không phân biệt hoa/thường).
- `_read_body` xử lý 3 trường hợp: có `Content-Length`, `Transfer-Encoding: chunked`, hoặc
  server đóng kết nối. Hàm chỉ **cộng dồn số byte** chứ không lưu nội dung — đúng yêu cầu
  không thu thập payload.
- `max_bytes = 512KB` chặn việc vô tình tải một file khổng lồ.

### 1.7 Request thứ hai — chứng minh connection reuse

```python
r2.update(dns_ms=0.0, tcp_ms=0.0, tls_ms=0.0, conn_reuse=1, cache_state="warm")
sock.sendall(req)              # gửi lại trên CHÍNH socket cũ
```

Không đóng socket mà gửi tiếp request thứ hai (nhờ `Connection: keep-alive`). Vì không phải
phân giải DNS, không bắt tay lại, ba pha đầu bằng 0 theo đúng định nghĩa. Kết quả đo thật:
108 ms → 22 ms. Đây là bằng chứng cho phần thảo luận connection reuse trong báo cáo.

### 1.8 Bắt lỗi theo pha

```python
except (socket.timeout, TimeoutError) as e:
    stage = "DNS" if rec["dns_ms"] == "" else ("CONNECT" if rec["tcp_ms"] == "" else ...)
```

Timeout có thể xảy ra ở bất kỳ pha nào. Cách xác định: **pha nào chưa kịp ghi số đo thì
chính pha đó đang bị treo**. Đây là logic chẩn đoán cốt lõi của đề tài, viết dưới dạng
biểu thức điều kiện lồng nhau.

### 1.9 Giới hạn tốc độ

```python
if args.delay < 1.0:
    raise SystemExit("delay phải >= 1.0 giây ...")
time.sleep(args.delay)
random.shuffle(targets)
```

- Chặn cứng ở mức code, không cho phép người dùng đặt delay quá nhỏ → tuân thủ quy định
  "không tạo tần suất request gây tải đáng kể".
- `random.shuffle` đảo thứ tự site mỗi vòng để site đứng đầu danh sách không luôn hưởng lợi
  (hoặc chịu thiệt) từ trạng thái mạng tại một thời điểm cố định.

---

## Phần 2. `src/make_synthetic.py` — sinh dữ liệu mô phỏng

### 2.1 Vì sao phải mô phỏng

Muốn huấn luyện mô hình 5 lớp thì cần đủ mẫu cho cả 4 loại sự cố. Nhưng gây lỗi DNS/TCP/TLS
trên hệ thống thật là hành vi bị đề bài cấm. Giải pháp hợp lệ: mô phỏng, và **ghi rõ đây là
synthetic**.

### 2.2 Hồ sơ host

```python
HOST_PROFILES = {
    "cdn-near.example": dict(dns=12, rtt=8,  server=45,  size=90),
    "cdn-far.example":  dict(dns=25, rtt=95, server=70,  size=140),
    ...
}
```

Mỗi host có RTT nền, thời gian xử lý nền và kích thước trang khác nhau. Mục đích: buộc mô
hình phải học được rằng **"chậm" là khái niệm tương đối**. 95 ms TCP với `cdn-far` là bình
thường, nhưng với `cdn-near` thì đó là sự cố.

### 2.3 Nhiễu log-normal

```python
def lognorm(rng, mean, sigma=0.35):
    return float(mean * rng.lognormal(mean=0.0, sigma=sigma))
```

Độ trễ mạng không phân phối chuẩn: nó luôn dương và có đuôi phải dài (đa số nhanh, thỉnh
thoảng rất chậm). Log-normal tái hiện đúng hình dạng đó. Phân phối chuẩn sẽ sinh ra thời
gian âm — vô nghĩa về mặt vật lý.

`rng = np.random.default_rng(seed)` tạo bộ sinh số ngẫu nhiên có seed cố định ⇒ chạy lại
cho kết quả y hệt, thoả yêu cầu **khả năng tái lập**.

### 2.4 Hệ số giờ cao điểm

```python
peak = 1.0 + (0.55 if hour in (8, 9) or 19 <= hour <= 23 else 0.0)
congestion = peak * lognorm(rng, 1.0, 0.18)
```

Nhân vào `tcp`, `tls`, `server` và chia vào băng thông. Nhờ vậy feature `hour` /
`is_peak_hour` mới thật sự mang thông tin, đúng như đề bài gợi ý `time_of_day`.

### 2.5 Ràng buộc logic — phần quan trọng nhất

```python
if cause == "DNS_PROBLEM":
    cache_state, conn_reuse = "cold", 0
if cause in ("CONNECT_PROBLEM", "TLS_PROBLEM"):
    conn_reuse = 0
```

Nếu bỏ qua mấy dòng này, dataset sẽ chứa những bản ghi **bất khả thi về mặt vật lý**: một
request cache hit (không truy vấn DNS) mà lại bị "lỗi DNS". Mô hình học trên dữ liệu mâu
thuẫn sẽ cho kết luận vô nghĩa, và giảng viên chắc chắn sẽ hỏi đúng chỗ này.

### 2.6 Tiêm sự cố

```python
if cause == "DNS_PROBLEM":
    if rng.random() < 0.25:
        dns = lognorm(rng, 5000, 0.2); success, error_stage = 0, "DNS"
        tcp = tls = server = transfer = 0.0
    else:
        dns = lognorm(rng, prof["dns"]) * rng.uniform(4, 15)
```

- Nhánh 25%: hỏng hẳn (timeout) ⇒ các pha **sau** bằng 0 vì chúng không bao giờ được thực
  hiện. Đây lại là một ràng buộc nhân quả: pha sau chỉ tồn tại nếu pha trước thành công.
- Nhánh 75%: chỉ chậm, hệ số nhân ngẫu nhiên 4–15 lần. Khoảng này cố ý **chồng lấn** với
  đuôi phải của phân phối bình thường ⇒ bài toán không tầm thường, mô hình buộc phải học
  ranh giới thay vì đọc một ngưỡng hiển nhiên.
- `CONNECT_PROBLEM` còn nhân thêm `transfer` lên 1.2–2.0 lần, vì mất gói làm chậm cả pha
  truyền dữ liệu chứ không riêng bắt tay — chi tiết này khiến dữ liệu thật hơn.

**Điểm cần nhấn trong báo cáo:** nhãn `cause` được chọn **trước**, rồi mới sinh ra các con
số. Nghĩa là nhãn không phải hàm của bất kỳ feature nào ⇒ không thể có rò rỉ nhãn.

---

## Phần 3. `src/prepare.py` — làm sạch, gán nhãn, tạo feature

### 3.1 Clean

```python
df[c] = pd.to_numeric(df[c], errors="coerce")
```

Ép về kiểu số; `errors="coerce"` biến mọi giá trị không parse được (ô rỗng khi request lỗi)
thành `NaN` thay vì làm sập chương trình.

```python
df[PHASES] = df[PHASES].fillna(0.0)
```

`NaN` ở đây có nghĩa rõ ràng: **pha đó không được thực hiện**, nên điền 0 là đúng ngữ nghĩa
(khác với "thiếu dữ liệu ngẫu nhiên").

```python
recomputed = df[PHASES].sum(axis=1)
df["total_ms"] = df["total_ms"].fillna(recomputed)
df = df[df["total_ms"] > 0].drop_duplicates()
```

Kiểm tra tính nhất quán: tổng phải bằng tổng các pha. Bỏ bản ghi tổng ≤ 0 (hỏng hoàn toàn)
và bỏ dòng trùng lặp.

### 3.2 Gán nhãn yếu cho dữ liệu thật

```python
med = df[ok].groupby("host")[PHASES + ["total_ms"]].median()
```

Tính **trung vị** từng pha cho từng host, chỉ trên các lần đo thành công. Dùng median chứ
không dùng mean vì một lần đo 8 giây sẽ kéo lệch trung bình, còn trung vị thì không.

```python
if row["total_ms"] < base["total_ms"] * 1.6 or row["total_ms"] - base["total_ms"] < 120:
    continue                       # -> giữ nhãn NORMAL
```

Điều kiện **kép**: phải chậm hơn 60% *và* chậm hơn ít nhất 120 ms. Chỉ dùng tỉ lệ thì một
site nhanh (30 ms → 50 ms) sẽ bị báo động giả; chỉ dùng ms tuyệt đối thì site chậm sẵn không
bao giờ bị phát hiện.

```python
excess = {p: max(0.0, row[p] - base[p]) for p in PHASES}
worst = max(excess, key=excess.get)
labels[i] = PHASE2LABEL[worst]
```

Tính phần **vượt trội** của từng pha so với mức nền của chính host đó, rồi quy tội cho pha
đóng góp nhiều nhất. `max(dict, key=dict.get)` trả về **khoá** có giá trị lớn nhất.

### 3.3 Feature Engineering

```python
df[p.replace("_ms", "_share")] = df[p] / df["total_ms"]
```

Tỉ trọng mỗi pha trong tổng thời gian. Đây là feature mạnh nhất của bài: nó **không phụ
thuộc đơn vị tuyệt đối**, nên một luật học được từ site nhanh vẫn áp dụng được cho site chậm.

```python
df["log_total"] = np.log1p(df["total_ms"])
```

`log1p(x) = log(1+x)`, nén đuôi phải và xử lý an toàn giá trị 0 (`log(0)` = âm vô cùng).

```python
df["tls_over_tcp"] = df["tls_ms"] / (df["tcp_ms"] + 1)
```

Tỉ số TLS/TCP. Về lý thuyết tỉ số này nên ≈ 1–2 (số RTT). Cộng 1 vào mẫu để tránh chia cho 0
khi tái dùng kết nối.

```python
df["label_source"] = np.where(is_syn, "ground_truth", "weak_rule")
```

Đánh dấu rõ nguồn nhãn để bước sau chỉ huấn luyện trên phần có ground truth — minh bạch về
mặt phương pháp.

---

## Phần 4. `src/analyze.py` — thống kê và biểu đồ

```python
matplotlib.use("Agg")
```

Chọn backend không cần màn hình. Thiếu dòng này, script sẽ lỗi khi chạy qua SSH hoặc trong
container.

```python
bottom = np.zeros(len(m))
for col, name in zip(PHASES, PHASE_VN):
    ax.bar(m.index, m[col], bottom=bottom, label=name)
    bottom += m[col].to_numpy()
```

Vẽ **cột chồng** thủ công: mỗi pha vẽ đè lên trên tổng các pha trước, nên phải cộng dồn
biến `bottom`. Cột chồng cho thấy đồng thời tổng thời gian *và* cơ cấu bên trong.

```python
ax.set_xscale("log"); ax.set_yscale("log")
ax.scatter(s["dns_ms"] + 1, s["server_ms"] + 1, ...)
```

Thang log cho cả hai trục vì độ trễ trải dài từ 1 ms tới 8000 ms. Cộng 1 để các giá trị 0
(cache hit) vẫn vẽ được trên thang log.

Ba biểu đồ đều có **số hiệu, tên và phần diễn giải** in ra màn hình để chép thẳng vào báo
cáo — đúng yêu cầu "mỗi biểu đồ có số, tên và phần diễn giải".

---

## Phần 5. `src/model.py` — baseline và Decision Tree

### 5.1 Baseline luật ngưỡng

```python
ratios = pd.DataFrame({p: df[p] / t for p, t in THRESHOLDS.items()})
worst = ratios.idxmax(axis=1)
over = ratios.max(axis=1) >= 1.0
pred = np.where(over, worst.map(THRESH2LABEL), "NORMAL")
```

- Chia mỗi pha cho ngưỡng của nó ⇒ đưa 4 pha về **cùng một thang so sánh** (tỉ số vượt ngưỡng).
- `idxmax(axis=1)` trả về *tên cột* lớn nhất trên mỗi dòng.
- `np.where(điều_kiện, giá_trị_nếu_đúng, giá_trị_nếu_sai)` chạy vector hoá trên toàn bảng —
  nhanh hơn nhiều so với vòng lặp `for`.

Đây đúng là cách một kỹ sư vận hành chẩn đoán bằng tay, nên nó là baseline công bằng.

### 5.2 Tách tập train/test

```python
X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.3,
                                          random_state=42, stratify=y)
```

- `test_size=0.3`: 70% học, 30% kiểm thử.
- `stratify=y`: giữ nguyên tỉ lệ 5 lớp ở cả hai tập. Không có tham số này, tập test có thể
  thiếu hẳn lớp hiếm.
- `random_state=42`: cố định phép chia ⇒ tái lập được kết quả.

### 5.3 Decision Tree

```python
clf = DecisionTreeClassifier(max_depth=6, min_samples_leaf=20,
                             class_weight="balanced", random_state=42)
```

- `max_depth=6`: nếu để cây mọc tự do, nó sẽ thuộc lòng nhiễu (overfit) và cây in ra không
  ai đọc nổi. Độ sâu 6 vừa đủ cho 5 lớp và vẫn giải thích được cho giảng viên.
- `min_samples_leaf=20`: mỗi lá phải dựa trên ít nhất 20 mẫu ⇒ luật ổn định, không phải quy
  tắc rút ra từ 1–2 trường hợp cá biệt.
- `class_weight="balanced"`: lớp NORMAL chiếm 52%; nếu không cân bằng trọng số, mô hình có
  thể đoán bừa NORMAL cho mọi thứ mà vẫn được accuracy cao trong khi recall lớp hiếm rất tệ.
- Chọn Decision Tree vì đúng yêu cầu đề bài T15, và vì nó cho ra **luật đọc được** —
  hợp với bài toán chẩn đoán (`export_text` in ra cây để bảo vệ trước giảng viên).

```python
cv = cross_val_score(clf, X_tr, y_tr, cv=5, scoring="f1_macro")
```

Cắt tập train thành 5 phần, luân phiên học 4 – kiểm 1. Độ lệch chuẩn nhỏ (±0.010) chứng minh
kết quả không phải may mắn từ một lần chia dữ liệu.

### 5.4 Vì sao dùng macro F1

`f1_score(..., average="macro")` tính F1 riêng cho từng lớp rồi lấy **trung bình không trọng
số**. Mỗi loại nguyên nhân có tầm quan trọng ngang nhau, dù DNS_PROBLEM hiếm hơn NORMAL bốn
lần. Nếu dùng accuracy hoặc weighted F1, lớp NORMAL sẽ chi phối toàn bộ con số.

### 5.5 Ma trận nhầm lẫn

```python
cm = confusion_matrix(y_true, pred, labels=ORDER)
ConfusionMatrixDisplay(cm, display_labels=ORDER).plot(ax=ax, cmap="Blues", values_format="d")
```

`labels=ORDER` ép thứ tự lớp giống nhau ở cả hai ma trận để so sánh trực quan. Hàng = nhãn
thật, cột = dự đoán; đường chéo là số ca đúng.

### 5.6 Phân tích lỗi

```python
wrong = d[d.y_ml != d.y_true]
top = wrong.groupby(["y_true", "y_ml"]).size().sort_values(ascending=False).head(6)
```

Đếm các cặp (thật → dự đoán sai) phổ biến nhất. Kết quả cho thấy phần lớn lỗi là
NORMAL ↔ *_PROBLEM, tức nhầm ở **ranh giới mức độ**, chứ mô hình gần như không bao giờ nhầm
DNS thành TLS — nghĩa là nó đã học đúng cấu trúc chuỗi 4 pha.

```python
f"tỉ lệ cache warm : sai={wrong.cache_warm.mean():.2f} | chung={d.cache_warm.mean():.2f}"
```

So sánh đặc điểm ngữ cảnh của nhóm bị dự đoán sai với toàn bộ tập test. Nếu một tỉ lệ lệch
hẳn, đó là manh mối về điểm yếu của mô hình.

---

## Phần 6. Những câu giảng viên có thể hỏi

**"Sao không dùng Random Forest cho chính xác hơn?"**
Đề bài chỉ yêu cầu một kỹ thuật ML cơ bản và gợi ý Decision Tree cho T15. Quan trọng hơn:
bài toán này cần **giải thích được nguyên nhân**, mà một cây duy nhất in ra luật rõ ràng.
Nhóm có thể thêm Random Forest như phần mở rộng để so sánh.

**"Machine Learning có thay thế kiến thức mạng không?"**
Không, và đề bài nói rõ điều đó. ML chỉ học ranh giới giữa các vùng thời gian. Việc **chia
một lần truy cập thành 4 pha, biết pha nào ứng với nguyên nhân gì, biết cache và
connection reuse làm sai lệch số đo ra sao** — đó hoàn toàn là kiến thức mạng, và nó quyết
định feature nào tồn tại để mô hình học.

**"Dữ liệu synthetic thì kết luận có giá trị gì?"**
Nó chứng minh **phương pháp** hoạt động: với bộ feature 4 pha, một Decision Tree khôi phục
được nguyên nhân đã tiêm ở mức macro F1 ≈ 0.92, cao hơn luật ngưỡng cố định 0.85. Dữ liệu đo
thật kèm theo cho thấy phân bố thời gian mô phỏng nằm cùng bậc độ lớn với thực tế.

**"Làm sao chắc chắn không rò rỉ nhãn?"**
Ba lớp bảo vệ, xem mục 6 của README: nhãn có trước feature; baseline khác cơ chế sinh nhãn
(nếu trùng thì F1 đã bằng 1.0); và các cột `cause`, `error_stage`, `http_status`, `host` đều
bị loại khỏi feature.
