"""
test_new_architecture.py - Kiểm thử tích hợp toàn bộ 3 thành phần (Attacker, NIDS, HIPS, Web Server)
"""
import sys
import unittest
from pathlib import Path

# Thiết lập encoding
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from part3_webserver.server import app, hips, nids


class TestFullSecurityArchitecture(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        # Reset trạng thái
        hips.set_enabled(False)
        nids.set_enabled(False)

    def test_01_attacks_succeed_when_no_defense(self):
        """KHI CHƯA BẬT BẢO VỆ: SQLi và XSS phải thành công (200 OK)"""
        self.assertFalse(hips.enabled)
        self.assertFalse(nids.enabled)

        # 1. SQL Injection
        resp = self.client.get("/api/login?user=admin' OR '1'='1&pass=123")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "PWNED_WITHOUT_HIPS")
        self.assertTrue(len(data["leaked_data"]) > 0)

        # 2. XSS
        resp = self.client.get("/api/comment?author=Attacker&content=<script>alert('pwned')</script>")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "PWNED_WITHOUT_HIPS")

    def test_02_attacks_blocked_when_defense_enabled(self):
        """KHI BẬT HỆ THỐNG PHÒNG THỦ: HIPS phải chặn đứng (403 Forbidden)"""
        # Bật phòng thủ
        hips.set_enabled(True)
        nids.set_enabled(True)
        self.assertTrue(hips.enabled)
        self.assertTrue(nids.enabled)

        # 1. SQL Injection phải bị chặn
        resp = self.client.get("/api/login?user=admin' OR '1'='1&pass=123")
        self.assertEqual(resp.status_code, 403)
        data = resp.get_json()
        self.assertEqual(data["status"], "BLOCKED_BY_HIPS")
        self.assertEqual(data["category"], "SQL_INJECTION")

        # Xóa quarantine để test XSS độc lập
        hips.quarantine_ips.clear()

        # 2. XSS phải bị chặn
        resp = self.client.get("/api/comment?author=Attacker&content=<script>alert('pwned')</script>")
        self.assertEqual(resp.status_code, 403)
        data = resp.get_json()
        self.assertEqual(data["status"], "BLOCKED_BY_HIPS")
        self.assertEqual(data["category"], "XSS")

        # 3. DoS Rate-limiting phải chặn khi vượt ngưỡng
        blocked_count = 0
        for _ in range(20):
            r = self.client.get("/api/search?q=flood_attack")
            if r.status_code == 403:
                blocked_count += 1
        self.assertGreater(blocked_count, 0)


if __name__ == "__main__":
    unittest.main()
