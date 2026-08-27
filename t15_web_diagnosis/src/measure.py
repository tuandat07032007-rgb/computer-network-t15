"""
T15 - Bước 1 (tuỳ chọn): ĐO THẬT chuỗi DNS -> TCP -> TLS -> HTTP.

Script tách riêng thời gian của từng pha trong MỘT lần truy cập Web:
    dns_ms      : thời gian phân giải tên miền (resolver trả về IP)
    tcp_ms      : thời gian bắt tay 3 bước TCP (SYN -> SYN/ACK -> ACK)
    tls_ms      : thời gian bắt tay TLS (ClientHello ... Finished)
    server_ms   : TTFB tính từ lúc gửi xong request đến khi nhận byte đầu tiên
    transfer_ms : thời gian tải phần thân còn lại của response

AN TOÀN / HỢP PHÁP (theo Phần IV của đề bài):
  - Chỉ gửi request GET bình thường tới các site công khai, giống hệt trình duyệt.
  - Có --delay giữa các request (mặc định 2 giây) để KHÔNG gây tải cho dịch vụ.
  - Không quét port, không khai thác lỗ hổng, không bắt traffic của người khác,
    không thu thập credential/cookie. Chỉ đọc timing của chính request mình tạo ra.

Cách chạy:
    python src/measure.py --rounds 5 --delay 2 --out data/raw/measurements.csv
"""

from __future__ import annotations

import argparse          # đọc tham số dòng lệnh (--rounds, --delay, ...)
import csv               # ghi kết quả ra file CSV
import random            # xáo trộn thứ tự site để tránh thiên lệch theo thời gian
import socket            # DNS (getaddrinfo) + TCP socket
import ssl               # bắt tay TLS
import time              # đo thời gian (perf_counter) và ngủ giữa các lần đo
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit   # tách URL thành scheme/host/port/path

# Danh sách site mặc định. Nhóm có thể sửa lại cho phù hợp đề tài.
DEFAULT_TARGETS = [
    "https://pypi.org/",
    "https://github.com/",
    "https://api.github.com/",
    "https://www.npmjs.com/",
]

# Thứ tự cột trong file CSV đầu ra (giữ cố định để các script sau đọc được).
FIELDS = [
    "ts", "host", "url", "hour",
    "dns_ms", "tcp_ms", "tls_ms", "server_ms", "transfer_ms", "total_ms",
    "response_size", "http_status",
    "cache_state", "conn_reuse", "success", "error_stage", "error_type",
    "source",
]


def _ms(t0: float) -> float:
    """Đổi khoảng thời gian từ giây (perf_counter) sang mili-giây, làm tròn 3 số."""
    return round((time.perf_counter() - t0) * 1000, 3)


def _read_headers(sock: socket.socket) -> tuple[bytes, bytes]:
    """Đọc dữ liệu tới khi gặp dòng trống CRLFCRLF -> trả về (header, phần dư của body)."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:                       # server đóng kết nối sớm
            break
        buf += chunk
        if len(buf) > 64 * 1024:            # chặn header bất thường quá lớn
            break
    head, _, rest = buf.partition(b"\r\n\r\n")
    return head, rest


def _parse_headers(head: bytes) -> tuple[int | None, dict]:
    """Tách status code và dictionary header từ khối header thô."""
    lines = head.decode("iso-8859-1", errors="replace").split("\r\n")
    status = None
    if lines and lines[0].startswith("HTTP/"):
        parts = lines[0].split()
        if len(parts) >= 2 and parts[1].isdigit():
            status = int(parts[1])
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return status, headers


def _read_body(sock, headers: dict, rest: bytes, max_bytes: int) -> int:
    """Đọc phần thân response, trả về TỔNG SỐ BYTE đã nhận (không lưu nội dung)."""
    size = len(rest)
    if "content-length" in headers:                       # trường hợp phổ biến nhất
        try:
            total = int(headers["content-length"])
        except ValueError:
            total = 0
        while size < total and size < max_bytes:
            chunk = sock.recv(8192)
            if not chunk:
                break
            size += len(chunk)
    elif headers.get("transfer-encoding", "").lower() == "chunked":
        # Với chunked, đọc tới khi gặp chunk kết thúc "0\r\n\r\n".
        buf = rest
        while b"0\r\n\r\n" not in buf[-16:] and size < max_bytes:
            chunk = sock.recv(8192)
            if not chunk:
                break
            buf = chunk
            size += len(chunk)
    else:
        # Không có Content-Length -> đọc tới khi server đóng kết nối (Connection: close).
        while size < max_bytes:
            chunk = sock.recv(8192)
            if not chunk:
                break
            size += len(chunk)
    return size


def measure_once(url: str, timeout: float = 10.0, cache_state: str = "cold",
                 second_request: bool = False, max_bytes: int = 512 * 1024) -> list[dict]:
    """
    Đo MỘT lần truy cập url và (tuỳ chọn) một request thứ hai tái dùng kết nối.
    Trả về danh sách bản ghi dict (1 hoặc 2 dòng dữ liệu).
    """
    parts = urlsplit(url)
    host = parts.hostname
    port = parts.port or (443 if parts.scheme == "https" else 80)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query

    now = datetime.now()
    rec = {f: "" for f in FIELDS}
    rec.update(ts=now.isoformat(timespec="seconds"), host=host, url=url, hour=now.hour,
               response_size=0, cache_state=cache_state, conn_reuse=0,
               success=0, source="real")

    t_start = time.perf_counter()
    sock = None
    try:
        # ---------- PHA 1: DNS ----------
        t0 = time.perf_counter()
        infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
        rec["dns_ms"] = _ms(t0)
        family, socktype, proto, _canon, sockaddr = infos[0]

        # ---------- PHA 2: TCP handshake ----------
        t0 = time.perf_counter()
        sock = socket.socket(family, socktype, proto)
        sock.settimeout(timeout)
        sock.connect(sockaddr)
        rec["tcp_ms"] = _ms(t0)

        # ---------- PHA 3: TLS handshake ----------
        if parts.scheme == "https":
            ctx = ssl.create_default_context()          # kiểm tra chứng chỉ như trình duyệt
            t0 = time.perf_counter()
            sock = ctx.wrap_socket(sock, server_hostname=host)   # SNI
            rec["tls_ms"] = _ms(t0)
        else:
            rec["tls_ms"] = 0.0

        # ---------- PHA 4: HTTP request/response ----------
        conn_hdr = "keep-alive" if second_request else "close"
        req = (f"GET {path} HTTP/1.1\r\n"
               f"Host: {host}\r\n"
               f"User-Agent: T15-Edu-Measure/1.0\r\n"
               f"Accept: */*\r\n"
               f"Accept-Encoding: identity\r\n"
               f"Connection: {conn_hdr}\r\n\r\n").encode()

        t0 = time.perf_counter()
        sock.sendall(req)
        first = sock.recv(1)                 # chờ BYTE ĐẦU TIÊN -> đây chính là TTFB
        rec["server_ms"] = _ms(t0)
        if not first:
            raise ConnectionError("server đóng kết nối trước khi trả dữ liệu")

        t0 = time.perf_counter()
        head, rest = _read_headers(sock)
        head = first + head
        status, headers = _parse_headers(head)
        size = _read_body(sock, headers, rest, max_bytes)
        rec["transfer_ms"] = _ms(t0)
        rec["http_status"] = status
        rec["response_size"] = size + len(head)
        rec["total_ms"] = _ms(t_start)
        rec["success"] = 1
        if status is not None and status >= 500:
            rec.update(success=0, error_stage="HTTP", error_type=f"status_{status}")

        out = [rec]

        # ---------- (tuỳ chọn) Request thứ 2: TÁI DÙNG kết nối ----------
        if second_request and rec["success"] == 1 and headers.get("connection", "") != "close":
            r2 = dict(rec)
            r2.update(dns_ms=0.0, tcp_ms=0.0, tls_ms=0.0, conn_reuse=1,
                      cache_state="warm", error_stage="", error_type="")
            t_start2 = time.perf_counter()
            t0 = time.perf_counter()
            sock.sendall(req)
            first2 = sock.recv(1)
            r2["server_ms"] = _ms(t0)
            t0 = time.perf_counter()
            head2, rest2 = _read_headers(sock)
            status2, headers2 = _parse_headers(first2 + head2)
            size2 = _read_body(sock, headers2, rest2, max_bytes)
            r2["transfer_ms"] = _ms(t0)
            r2["total_ms"] = _ms(t_start2)
            r2["http_status"] = status2
            r2["response_size"] = size2 + len(head2)
            out.append(r2)
        return out

    # ---------- Bắt lỗi theo ĐÚNG PHA đang thực hiện ----------
    except socket.gaierror as e:                        # lỗi phân giải tên miền
        rec.update(error_stage="DNS", error_type=type(e).__name__)
    except ssl.SSLError as e:                           # lỗi bắt tay/chứng chỉ TLS
        rec.update(error_stage="TLS", error_type=type(e).__name__)
    except (socket.timeout, TimeoutError) as e:
        # Hết thời gian: pha nào chưa có số đo thì pha đó là nơi bị treo.
        stage = "DNS" if rec["dns_ms"] == "" else ("CONNECT" if rec["tcp_ms"] == "" else
                ("TLS" if rec["tls_ms"] == "" else "HTTP"))
        rec.update(error_stage=stage, error_type=type(e).__name__)
    except OSError as e:                                # refused, unreachable, reset...
        stage = "CONNECT" if rec["tcp_ms"] == "" else "HTTP"
        rec.update(error_stage=stage, error_type=type(e).__name__)
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    rec["total_ms"] = _ms(t_start)
    return [rec]


def main() -> None:
    ap = argparse.ArgumentParser(description="Đo timing DNS/TCP/TLS/HTTP (an toàn, có giới hạn tốc độ)")
    ap.add_argument("--targets", nargs="*", default=DEFAULT_TARGETS, help="danh sách URL cần đo")
    ap.add_argument("--rounds", type=int, default=5, help="số vòng lặp qua toàn bộ danh sách")
    ap.add_argument("--delay", type=float, default=2.0, help="giây nghỉ giữa 2 request liên tiếp")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--second-request", action="store_true",
                    help="gửi thêm 1 request tái dùng kết nối để so sánh connection reuse")
    ap.add_argument("--out", default="data/raw/measurements.csv")
    args = ap.parse_args()

    if args.delay < 1.0:                     # chặn cứng: không cho phép bắn dồn dập
        raise SystemExit("delay phải >= 1.0 giây để không gây tải lên dịch vụ bên ngoài.")

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    rows: list[dict] = []
    seen_hosts: set[str] = set()             # để đánh dấu lần đo đầu tiên là "cold" (chưa có cache DNS)

    for r in range(args.rounds):
        targets = args.targets[:]
        random.shuffle(targets)              # xáo trộn để không cố định thứ tự đo
        for url in targets:
            host = urlsplit(url).hostname
            state = "warm" if host in seen_hosts else "cold"
            seen_hosts.add(host)
            recs = measure_once(url, timeout=args.timeout, cache_state=state,
                                second_request=args.second_request)
            rows.extend(recs)
            print(f"[vòng {r+1}] {host:<20} "
                  f"dns={recs[0]['dns_ms']} tcp={recs[0]['tcp_ms']} "
                  f"tls={recs[0]['tls_ms']} ttfb={recs[0]['server_ms']} "
                  f"ok={recs[0]['success']} {recs[0]['error_stage']}")
            time.sleep(args.delay)

    with out_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)
    print(f"\nĐã ghi {len(rows)} dòng vào {out_path}")


if __name__ == "__main__":
    main()
