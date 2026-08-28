from __future__ import annotations

import argparse
import csv
import socket
import ssl
import time
import urllib.parse
from datetime import datetime
from pathlib import Path

FIELDS = [
    "ts", "host", "url", "hour",
    "dns_ms", "tcp_ms", "tls_ms", "server_ms", "transfer_ms", "total_ms",
    "response_size", "http_status",
    "cache_state", "conn_reuse", "success", "error_stage", "error_type",
    "source",
]

REAL_TEST_CASES = [
    {"url": "https://google.com/", "expected": "NORMAL"},
    {"url": "https://cloudflare.com/", "expected": "NORMAL"},
    {"url": "https://expired.badssl.com/", "expected": "TLS_PROBLEM"},
    {"url": "https://wrong.host.badssl.com/", "expected": "TLS_PROBLEM"},
    {"url": "https://github.com/duong-dan-loi-404-test", "expected": "HTTP_PROBLEM"},
    {"url": "https://httpbin.org/status/500", "expected": "HTTP_PROBLEM"},
    {"url": "http://domain-khong-ton-tai-123456789.com/", "expected": "DNS_PROBLEM"},
]


def _ms(t0: float) -> float:
    return round((time.perf_counter() - t0) * 1000, 3)


def _read_headers(sock: socket.socket) -> tuple[bytes, bytes]:
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
        if len(buf) > 64 * 1024:
            break
    head, _, rest = buf.partition(b"\r\n\r\n")
    return head, rest


def _parse_headers(head: bytes) -> tuple[int | None, dict]:
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


def _read_body(sock: socket.socket, headers: dict, rest: bytes, max_bytes: int) -> int:
    size = len(rest)
    if "content-length" in headers:
        try:
            total = int(headers["content-length"])
        except ValueError:
            total = 0
        while size < total and size < max_bytes:
            chunk = sock.recv(8192)
            if not chunk:
                break
            size += len(chunk)
    else:
        while size < max_bytes:
            chunk = sock.recv(8192)
            if not chunk:
                break
            size += len(chunk)
    return size


def measure_real_once(url: str, timeout: float = 8.0) -> dict:
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname
    port = parts.port or (443 if parts.scheme == "https" else 80)
    path = parts.path or "/"

    now = datetime.now()
    rec = {f: "" for f in FIELDS}
    rec.update(
        ts=now.isoformat(timespec="seconds"), host=host, url=url, hour=now.hour,
        response_size=0, cache_state="cold", conn_reuse=0,
        success=0, source="real"
    )

    t_start = time.perf_counter()
    sock = None
    try:
        t0 = time.perf_counter()
        infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
        rec["dns_ms"] = _ms(t0)
        family, socktype, proto, _, sockaddr = infos[0]

        t0 = time.perf_counter()
        sock = socket.socket(family, socktype, proto)
        sock.settimeout(timeout)
        sock.connect(sockaddr)
        rec["tcp_ms"] = _ms(t0)

        if parts.scheme == "https":
            ctx = ssl.create_default_context()
            t0 = time.perf_counter()
            sock = ctx.wrap_socket(sock, server_hostname=host)
            rec["tls_ms"] = _ms(t0)
        else:
            rec["tls_ms"] = 0.0

        req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
               f"User-Agent: DataCollector/2.0\r\nConnection: close\r\n\r\n").encode()
        t0 = time.perf_counter()
        sock.sendall(req)
        first = sock.recv(1)
        rec["server_ms"] = _ms(t0)
        if not first:
            raise ConnectionError("Server early close")

        t0 = time.perf_counter()
        head, rest = _read_headers(sock)
        status, headers = _parse_headers(first + head)
        size = _read_body(sock, headers, rest, 512 * 1024)
        rec["transfer_ms"] = _ms(t0)
        rec["http_status"] = status
        rec["response_size"] = size + len(first + head)
        rec["total_ms"] = _ms(t_start)

        if status and status < 400:
            rec["success"] = 1
        else:
            rec["success"] = 0
            rec.update(error_stage="HTTP", error_type=f"status_{status}")

    except socket.gaierror as e:
        rec.update(error_stage="DNS", error_type=type(e).__name__)
    except ssl.SSLError as e:
        rec.update(error_stage="TLS", error_type=type(e).__name__)
    except (socket.timeout, TimeoutError) as e:
        stage = "DNS" if rec["dns_ms"] == "" else ("CONNECT" if rec["tcp_ms"] == "" else ("TLS" if rec["tls_ms"] == "" else "HTTP"))
        rec.update(error_stage=stage, error_type=type(e).__name__)
    except OSError as e:
        stage = "CONNECT" if rec["tcp_ms"] == "" else "HTTP"
        rec.update(error_stage=stage, error_type=type(e).__name__)
    finally:
        if sock:
            sock.close()

    if rec["total_ms"] == "":
        rec["total_ms"] = _ms(t_start)
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=50, help="Số lần lặp lại quét các site")
    ap.add_argument("--delay", type=float, default=1.0, help="Trễ nghỉ tránh bị rate limit (giây)")
    ap.add_argument("--out", default="data/raw/measurements_real.csv")
    args = ap.parse_args()

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    rows = []

    total_requests = args.rounds * len(REAL_TEST_CASES)
    print(f"=== BẮT ĐẦU ĐO SITE REAL: {args.rounds} ROUNDS ({total_requests} REQUESTS) ===")

    counter = 0
    for r in range(args.rounds):
        for item in REAL_TEST_CASES:
            counter += 1
            rec = measure_real_once(item["url"])
            rows.append(rec)
            print(f"[{counter}/{total_requests}] R{r+1:02d} | {item['expected']:<12} | {rec['host']:<25} | Stage={rec['error_stage'] or 'NONE'}")
            time.sleep(args.delay)

    with out_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)
    print(f"\n[THÀNH CÔNG] Đã xuất {len(rows)} bản ghi vào {out_path}")


if __name__ == "__main__":
    main()