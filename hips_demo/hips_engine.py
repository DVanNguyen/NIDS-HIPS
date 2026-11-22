"""
hips_engine.py - Host-based Intrusion Prevention System (HIPS) Engine
Chức năng:
1. Interceptor in-line: Chặn đứng Request độc hại trước khi chạm vào Controller/Database.
2. Rule Inspection: Nhận diện SQLi, Command Injection, Path Traversal bằng RegEx.
3. System Call & Command Guard: Ngăn chặn thực thi lệnh OS trái phép (whoami, cmd, powershell).
4. File Integrity Guard: Chặn đọc/ghi các tệp tin cấu hình nhạy cảm.
5. Dynamic IP Blacklist & Quản lý sự kiện ngăn chặn (Prevention Events).
"""
import re
import time
import json
import threading
from typing import Dict, Any, Tuple, Optional
from pathlib import Path

class HIPSEngine:
    def __init__(self, log_file: Optional[Path] = None):
        self.enabled = False  # Mặc định tắt để có thể demo so sánh Trước/Sau
        self.lock = threading.Lock()
        self.log_file = log_file or (Path(__file__).parent / "hips_events.json")
        
        # Thống kê hiệu năng HIPS
        self.stats = {
            "total_inspected": 0,
            "total_blocked": 0,
            "sqli_blocked": 0,
            "cmdi_blocked": 0,
            "traversal_blocked": 0,
            "blacklisted_ips": 0
        }
        
        # Danh sách IP bị đưa vào diện cách ly (Quarantine / Blacklist)
        self.blacklisted_ips: Dict[str, float] = {}
        self.blacklist_duration = 60.0  # Chặn IP trong 60 giây
        
        # Danh sách nhật ký sự kiện ngăn chặn gần nhất (để hiển thị UI)
        self.event_history = []
        
        # 1. Tập luật ngăn chặn tầng ứng dụng L7 (RegEx-based In-line Prevention Rules)
        self.rules = [
            {
                "id": "HIPS_SQLI_001",
                "category": "SQL_INJECTION",
                "severity": "CRITICAL",
                "pattern": re.compile(r"(?i)(\bUNION\s+(ALL\s+)?SELECT\b|'\s*(OR|AND)\s*'?\d+'?\s*=\s*'?\d+|'\s*OR\s*'1'='1|--|#|/\*|\bWAITFOR\s+DELAY\b)"),
                "description": "Phát hiện kỹ thuật SQL Injection nhằm chiếm đoạt tài khoản hoặc trích xuất Database"
            },
            {
                "id": "HIPS_CMDI_001",
                "category": "COMMAND_INJECTION",
                "severity": "CRITICAL",
                "pattern": re.compile(r"(?i)(;\s*\b(cat|ls|whoami|pwd|net\s+user|dir|id|uname)\b|\||\b(cmd\.exe|powershell\.exe|/bin/(sh|bash)|nc\s+-e)\b)"),
                "description": "Phát hiện chèn lệnh hệ điều hành trái phép nhằm chiếm quyền máy chủ"
            },
            {
                "id": "HIPS_TRAVERSAL_001",
                "category": "PATH_TRAVERSAL",
                "severity": "HIGH",
                "pattern": re.compile(r"(?i)(\.\.[\/\\]{1,}|%2e%2e[%2f%5c]|etc[\/\\]passwd|win\.ini|boot\.ini|secret_config\.json)"),
                "description": "Phát hiện truy cập trái phép vượt cấp thư mục hoặc đọc tệp tin hệ thống nhạy cảm"
            }
        ]

    def set_enabled(self, status: bool):
        """Bật hoặc tắt cơ chế bảo vệ HIPS"""
        with self.lock:
            self.enabled = status

    def inspect_and_filter(self, client_ip: str, method: str, path: str, query_params: str, body: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        In-line Inspection: Được gọi TRƯỚC KHI request được xử lý.
        Trả về:
            - allowed: True (Cho phép đi tiếp) | False (CHẶN NGAY LẬP TỨC - HTTP 403)
            - block_info: Thông tin chi tiết lý do chặn (nếu bị chặn)
        """
        with self.lock:
            self.stats["total_inspected"] += 1
            now = time.time()

            # Nếu HIPS đang TẮT -> Thả cho request lọt qua hoàn toàn (Chế độ Không bảo vệ)
            if not self.enabled:
                return True, None

            # 1. Kiểm tra xem IP này có đang nằm trong Blacklist cách ly không
            if client_ip in self.blacklisted_ips:
                expire_time = self.blacklisted_ips[client_ip]
                if now < expire_time:
                    remaining = int(expire_time - now)
                    block_info = {
                        "rule_id": "HIPS_IP_ISOLATION",
                        "category": "IP_QUARANTINE",
                        "severity": "CRITICAL",
                        "action": "DROP_CONNECTION",
                        "reason": f"Địa chỉ IP {client_ip} đã bị HIPS phong tỏa cách ly (còn lại {remaining}s)",
                        "matched_text": client_ip,
                        "client_ip": client_ip,
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                    }
                    self._record_block(block_info)
                    return False, block_info
                else:
                    # Hết thời gian phạt -> xóa khỏi blacklist
                    del self.blacklisted_ips[client_ip]

            # 2. Quét sâu vào các thành phần của Request (URI, Query, Body)
            test_targets = [
                ("PATH", path),
                ("QUERY", query_params),
                ("BODY", body)
            ]

            for rule in self.rules:
                for zone_name, content in test_targets:
                    if not content:
                        continue
                    
                    match = rule["pattern"].search(content)
                    if match:
                        matched_str = match.group(0)
                        
                        # Kích hoạt hành động ngăn chặn (Action: BLOCK & DROP)
                        self.stats["total_blocked"] += 1
                        if rule["category"] == "SQL_INJECTION":
                            self.stats["sqli_blocked"] += 1
                        elif rule["category"] == "COMMAND_INJECTION":
                            self.stats["cmdi_blocked"] += 1
                        elif rule["category"] == "PATH_TRAVERSAL":
                            self.stats["traversal_blocked"] += 1

                        # Đưa IP vào danh sách cách ly tạm thời
                        self.blacklisted_ips[client_ip] = now + self.blacklist_duration
                        self.stats["blacklisted_ips"] = len(self.blacklisted_ips)

                        block_info = {
                            "rule_id": rule["id"],
                            "category": rule["category"],
                            "severity": rule["severity"],
                            "action": "BLOCK_AND_ISOLATE_IP",
                            "reason": rule["description"],
                            "zone": zone_name,
                            "matched_text": matched_str,
                            "client_ip": client_ip,
                            "method": method,
                            "path": path,
                            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                        }
                        
                        self._record_block(block_info)
                        return False, block_info

            # Không phát hiện dấu hiệu độc hại -> Cho phép thực thi an toàn
            return True, None

    def _record_block(self, event: Dict[str, Any]):
        """Ghi nhận nhật ký ngăn chặn để hiển thị ra UI và file"""
        self.event_history.insert(0, event)
        if len(self.event_history) > 100:
            self.event_history.pop()

        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(event, ensure_ascii=False) + "\n")
        except Exception:
            pass
