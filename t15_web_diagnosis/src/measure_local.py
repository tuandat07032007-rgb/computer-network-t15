from __future__ import annotations

import argparse
import csv
import socket
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

LOCAL_TEST_CASES = [
    {"url": "http://localhost:3000/normal", "target_cause": "NORMAL"},
    {"url": "http://localhost:3000/slow-server", "target_cause": "HTTP_PROBLEM (TTFB)"},
    {"url": "http://localhost:3000/error-500", "target_cause": "HTTP_PROBLEM (Status 500)"},
    {"url": "http://localhost:3000/drop-connection", "target_cause": "HTTP_PROBLEM (Drop Connection)"},
    {"url": "http://127.0.0.1:59999/", "target_cause": "CONNECT_PROBLEM (Port Closed)"},
    {"url": "http://invalid-dns-local-test.invalid:3000/", "target_cause": "DNS_PROBLEM (Bad Host)"},
]


def _ms(t0: float) -> float:
    return round((time.perf_counter() - t0) * 1000, 3)


def measure_local_once(url: str, timeout: float = 2.0) -> dict:
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname
    port = parts.port or 80
    path = parts.path or "/"

    now = datetime.now()
    rec = {f: "" for f in FIELDS}
    rec.update(
        ts=now.isoformat(timespec="seconds"), host=host, url=url, hour=now.hour,
        response_size=0, cache_state="cold", conn_reuse=0,
        success=0, source="local_fault"
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
        rec["tls_ms"] = 0.0

        req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
        t0 = time.perf_counter()
        sock.sendall(req)
        first = sock.recv(1)
        rec["server_ms"] = _ms(t0)

        if not first:
            raise ConnectionError("Server reset socket")

        t0 = time.perf_counter()
        buf = first + sock.recv(4096)
        rec["transfer_ms"] = _ms(t0)

        head_text = buf.decode("iso-8859-1", errors="replace")
        lines = head_text.split("\r\n")
        if lines and lines[0].startswith("HTTP/"):
            parts_st = lines[0].split()
            if len(parts_st) >= 2 and parts_st[1].isdigit():
                rec["http_status"] = int(parts_st[1])

        rec["response_size"] = len(buf)
        rec["total_ms"] = _ms(t_start)

        if rec["http_status"] and rec["http_status"] >= 500:
            rec.update(success=0, error_stage="HTTP", error_type=f"status_{rec['http_status']}")
        else:
            rec["success"] = 1

    except socket.gaierror as e:
        rec.update(error_stage="DNS", error_type=type(e).__name__)
    except (socket.timeout, TimeoutError) as e:
        stage = "DNS" if rec["dns_ms"] == "" else ("CONNECT" if rec["tcp_ms"] == "" else "HTTP")
        rec.update(error_stage=stage, error_type=type(e).__name__)
    except (socket.error, ConnectionError, OSError) as e:
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
    ap.add_argument("--rounds", type=int, default=200, help="Số lần lặp lại danh sách test case")
    ap.add_argument("--delay", type=float, default=0.05, help="Thời gian nghỉ giữa các request (giây)")
    ap.add_argument("--out", default="data/raw/measurements_local.csv")
    args = ap.parse_args()

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    rows = []

    total_requests = args.rounds * len(LOCAL_TEST_CASES)
    print(f"=== BẮT ĐẦU ĐO LOCAL: {args.rounds} ROUNDS ({total_requests} REQUESTS) ===")

    counter = 0
    for r in range(args.rounds):
        for item in LOCAL_TEST_CASES:
            counter += 1
            rec = measure_local_once(item["url"])
            rows.append(rec)
            if counter % 50 == 0 or counter == total_requests:
                print(f" Tiến độ: [{counter}/{total_requests}] mẫu | Round {r+1}/{args.rounds}")
            time.sleep(args.delay)

    with out_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)
    print(f"\n[THÀNH CÔNG] Đã xuất {len(rows)} bản ghi vào {out_path}")


if __name__ == "__main__":
    main()