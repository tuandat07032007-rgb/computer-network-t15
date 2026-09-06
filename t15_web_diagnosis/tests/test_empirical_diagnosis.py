"""
Unit tests cho module empirical_diagnosis.py
Kiểm tra các trường hợp biên, các kịch bản mạng và tính độc lập logic với bước B.
"""

from __future__ import annotations

import unittest
import numpy as np
import pandas as pd
import sys
from pathlib import Path

# Thêm src vào sys.path để import trực tiếp
SRC_PATH = Path(__file__).resolve().parent.parent / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

from empirical_diagnosis import (
    EmpiricalThresholds,
    EmpiricalWebDiagnoser,
    DiagnosisResult,
    empirical_diagnose,
)


class TestEmpiricalDiagnosis(unittest.TestCase):
    def setUp(self):
        self.diagnoser = EmpiricalWebDiagnoser()

    def test_normal_traffic(self):
        """Mẫu truy cập bình thường với độ trễ các pha thấp."""
        sample = {
            "dns_ms": 15.0,
            "tcp_ms": 25.0,
            "tls_ms": 50.0,
            "server_ms": 120.0,
            "transfer_ms": 20.0,
            "http_status": 200,
            "cache_state": "cold",
            "conn_reuse": 0,
            "success": 1,
        }
        res = self.diagnoser.diagnose_single(sample)
        self.assertEqual(res.label, "NORMAL")
        self.assertFalse(res.is_hard_failure)
        self.assertIsNone(res.bottleneck_phase)

    def test_http_500_fast_response(self):
        """
        Server trả về lỗi HTTP 500 cực nhanh (30ms).
        Luật ngưỡng truyền thống sẽ nhầm là NORMAL vì thời gian không vượt ngưỡng.
        Hàm kinh nghiệm phân tầng phải nhận diện ngay là HTTP_PROBLEM.
        """
        sample = {
            "dns_ms": 5.0,
            "tcp_ms": 10.0,
            "tls_ms": 20.0,
            "server_ms": 30.0,
            "transfer_ms": 5.0,
            "http_status": 500,
            "success": 0,
            "error_stage": "HTTP",
        }
        res = self.diagnoser.diagnose_single(sample)
        self.assertEqual(res.label, "HTTP_PROBLEM")
        self.assertTrue(res.is_hard_failure)
        self.assertIn("500", res.primary_reason)

    def test_dns_slow_and_timeout(self):
        """Trường hợp DNS chậm (>90ms) và DNS timeout (>2000ms)."""
        slow_dns = {
            "dns_ms": 250.0,
            "tcp_ms": 25.0,
            "tls_ms": 50.0,
            "server_ms": 90.0,
            "transfer_ms": 10.0,
            "cache_state": "cold",
            "conn_reuse": 0,
            "http_status": 200,
            "success": 1,
        }
        res_slow = self.diagnoser.diagnose_single(slow_dns)
        self.assertEqual(res_slow.label, "DNS_PROBLEM")
        self.assertEqual(res_slow.bottleneck_phase, "dns_ms")

        timeout_dns = {
            "dns_ms": 5000.0,
            "tcp_ms": 0.0,
            "tls_ms": 0.0,
            "server_ms": 0.0,
            "transfer_ms": 0.0,
            "success": 0,
            "error_stage": "DNS",
        }
        res_timeout = self.diagnoser.diagnose_single(timeout_dns)
        self.assertEqual(res_timeout.label, "DNS_PROBLEM")
        self.assertTrue(res_timeout.is_hard_failure)

    def test_tcp_connect_slow_and_timeout(self):
        """Trường hợp bắt tay TCP chậm do mất gói SYN (RTO) và timeout."""
        slow_tcp = {
            "dns_ms": 10.0,
            "tcp_ms": 380.0,
            "tls_ms": 60.0,
            "server_ms": 90.0,
            "transfer_ms": 15.0,
            "conn_reuse": 0,
            "success": 1,
        }
        res_slow = self.diagnoser.diagnose_single(slow_tcp)
        self.assertEqual(res_slow.label, "CONNECT_PROBLEM")
        self.assertEqual(res_slow.bottleneck_phase, "tcp_ms")

        timeout_tcp = {
            "dns_ms": 15.0,
            "tcp_ms": 6000.0,
            "tls_ms": 0.0,
            "server_ms": 0.0,
            "transfer_ms": 0.0,
            "success": 0,
            "error_stage": "CONNECT",
        }
        res_timeout = self.diagnoser.diagnose_single(timeout_tcp)
        self.assertEqual(res_timeout.label, "CONNECT_PROBLEM")
        self.assertTrue(res_timeout.is_hard_failure)

    def test_tls_handshake_slow(self):
        """Trường hợp bắt tay TLS phình to do chuỗi chứng chỉ hoặc OCSP."""
        slow_tls = {
            "dns_ms": 12.0,
            "tcp_ms": 30.0,
            "tls_ms": 650.0,
            "server_ms": 110.0,
            "transfer_ms": 20.0,
            "conn_reuse": 0,
            "success": 1,
        }
        res = self.diagnoser.diagnose_single(slow_tls)
        self.assertEqual(res.label, "TLS_PROBLEM")
        self.assertEqual(res.bottleneck_phase, "tls_ms")

    def test_cache_warm_semantics(self):
        """
        Khi cache warm, dns_ms ~ 0.
        Không được phán đoán sai, và nếu các pha khác bình thường thì nhãn phải là NORMAL.
        """
        sample = {
            "dns_ms": 0.5,
            "tcp_ms": 20.0,
            "tls_ms": 45.0,
            "server_ms": 100.0,
            "transfer_ms": 10.0,
            "cache_state": "warm",
            "conn_reuse": 0,
            "success": 1,
        }
        res = self.diagnoser.diagnose_single(sample)
        self.assertEqual(res.label, "NORMAL")

    def test_connection_reuse_semantics(self):
        """
        Khi tái dùng kết nối (keep-alive/HTTP2), tcp_ms = tls_ms = 0.
        Không được phán đoán sai là lỗi kết nối.
        """
        sample = {
            "dns_ms": 0.0,
            "tcp_ms": 0.0,
            "tls_ms": 0.0,
            "server_ms": 150.0,
            "transfer_ms": 25.0,
            "cache_state": "warm",
            "conn_reuse": 1,
            "success": 1,
        }
        res = self.diagnoser.diagnose_single(sample)
        self.assertEqual(res.label, "NORMAL")

    def test_independence_from_b_no_host_needed(self):
        """
        Kiểm tra tính độc lập: Hàm chẩn đoán chạy hoàn hảo khi KHÔNG CÓ cột 'host',
        trong khi bước B (weak_label_real) bắt buộc phải có host để groupby.
        """
        sample_no_host = {
            "dns_ms": 15.0,
            "tcp_ms": 20.0,
            "tls_ms": 40.0,
            "server_ms": 950.0,
            "transfer_ms": 30.0,
            "success": 1,
        }
        res = self.diagnoser.diagnose_single(sample_no_host)
        self.assertEqual(res.label, "HTTP_PROBLEM")

    def test_batch_dataframe_diagnosis(self):
        """Kiểm tra chẩn đoán hàng loạt qua DataFrame."""
        df = pd.DataFrame([
            {"dns_ms": 10.0, "tcp_ms": 20.0, "tls_ms": 40.0, "server_ms": 100.0, "transfer_ms": 10.0},
            {"dns_ms": 300.0, "tcp_ms": 20.0, "tls_ms": 40.0, "server_ms": 100.0, "transfer_ms": 10.0},
            {"dns_ms": 10.0, "tcp_ms": 500.0, "tls_ms": 40.0, "server_ms": 100.0, "transfer_ms": 10.0},
            {"dns_ms": 10.0, "tcp_ms": 20.0, "tls_ms": 800.0, "server_ms": 100.0, "transfer_ms": 10.0},
            {"dns_ms": 10.0, "tcp_ms": 20.0, "tls_ms": 40.0, "server_ms": 900.0, "transfer_ms": 10.0},
        ])
        labels = empirical_diagnose(df)
        self.assertEqual(len(labels), 5)
        self.assertEqual(list(labels), [
            "NORMAL", "DNS_PROBLEM", "CONNECT_PROBLEM", "TLS_PROBLEM", "HTTP_PROBLEM"
        ])


if __name__ == "__main__":
    unittest.main()
