"""
Alert Manager for Multi-threaded NIDS.
Handles deduplication, storage, JSON logging, and real-time dashboard notification callbacks.
"""
import json
import time
import uuid
import threading
from typing import Dict, List, Any, Optional, Callable
from collections import deque
from config.settings import ALERT_LOG_FILE


class AlertManager:
    def __init__(self, max_history: int = 1000, enable_console: bool = True, enable_file_log: bool = True):
        self._lock = threading.Lock()
        self._alerts: deque = deque(maxlen=max_history)
        self._listeners: List[Callable[[Dict[str, Any]], None]] = []
        self._log_file = ALERT_LOG_FILE
        self.enable_console = enable_console
        self.enable_file_log = enable_file_log

    def register_listener(self, callback: Callable[[Dict[str, Any]], None]):
        """Register a callback for real-time WebSocket broadcasting."""
        with self._lock:
            self._listeners.append(callback)

    def trigger_alert(
        self,
        category: str,
        severity: str,
        rule_id: str,
        rule_name: str,
        src_ip: str,
        dst_ip: str,
        direction: str = "UNKNOWN",
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None,
        protocol: str = "TCP",
        evidence: str = "",
        evidence_slice: str = "",
        details: str = "",
        payload_sample: str = ""
    ) -> Dict[str, Any]:
        """
        Record a security alert, print colorful ANSI log to console, notify dashboard, and save to JSON.
        """
        slice_display = evidence_slice if evidence_slice else evidence

        alert = {
            "alert_id": str(uuid.uuid4())[:8],
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "unix_time": time.time(),
            "category": category,
            "severity": severity.upper(),
            "direction": direction.upper(),
            "rule_id": rule_id,
            "rule_name": rule_name,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "evidence": evidence,
            "evidence_slice": slice_display,
            "details": details,
            "payload_sample": payload_sample[:500]  # First 500 chars for preview
        }

        # 1. Luôn lưu vào bộ nhớ deque và danh sách trước tiên
        with self._lock:
            self._alerts.appendleft(alert)
            listeners_copy = list(self._listeners)

        # 2. Ghi ra file log JSONL
        if self.enable_file_log:
            try:
                with open(self._log_file, "a", encoding="utf-8") as f:
                    f.write(json.dumps(alert, ensure_ascii=False) + "\n")
            except Exception as e:
                print(f"[AlertManager] Error logging alert to file: {e}")

        # 3. In log màu ra Terminal (Bọc an toàn chống lỗi charmap)
        if self.enable_console:
            try:
                self._print_terminal_alert(alert)
            except Exception:
                try:
                    print(f"[{alert['severity']}] [{alert['direction']}] {alert['category']} ({alert['src_ip']} -> {alert['dst_ip']})")
                except Exception:
                    pass

        # 4. Gửi thông báo tới các client Dashboard qua WebSocket
        for listener in listeners_copy:
            try:
                listener(alert)
            except Exception as e:
                print(f"[AlertManager] Error notifying listener: {e}")

        return alert

    def _print_terminal_alert(self, alert: Dict[str, Any]):
        """Render stylish, high-contrast ANSI colored alerts in terminal."""
        sev = alert["severity"]
        cat = alert["category"]
        dir_tag = alert["direction"]
        time_str = time.strftime("%H:%M:%S")

        # Color badges
        if sev == "CRITICAL":
            sev_badge = "\033[1;97;41m CRITICAL \033[0m"
        elif sev == "HIGH":
            sev_badge = "\033[1;30;43m   HIGH   \033[0m"
        elif sev == "MEDIUM":
            sev_badge = "\033[1;33;40m  MEDIUM  \033[0m"
        else:
            sev_badge = "\033[1;34;40m   LOW    \033[0m"

        # Direction badges
        if dir_tag == "INBOUND":
            dir_badge = "\033[1;36m[INBOUND -> LAN]\033[0m"
        elif dir_tag == "OUTBOUND":
            dir_badge = "\033[1;32m[OUTBOUND -> WAN]\033[0m"
        elif dir_tag == "INTERNAL":
            dir_badge = "\033[1;35m[INTERNAL (EAST-WEST)]\033[0m"
        else:
            dir_badge = f"\033[90m[{dir_tag}]\033[0m"

        src_str = f"{alert['src_ip']}:{alert['src_port'] or '*'}"
        dst_str = f"{alert['dst_ip']}:{alert['dst_port'] or '*'}"
        proto = alert["protocol"]

        print(f"\n\033[90m[{time_str}]\033[0m {sev_badge} {dir_badge} \033[1;37m{cat}\033[0m \033[90m({alert['rule_id']})\033[0m")
        print(f"  \033[90m|-> Flow:\033[0m    \033[33m{src_str}\033[0m -> \033[36m{dst_str}\033[0m ({proto})")
        print(f"  \033[90m|-> Rule:\033[0m    {alert['rule_name']}")
        if alert.get("evidence_slice"):
            print(f"  \033[90m\\-> Slice:\033[0m   \033[1;91m{alert['evidence_slice']}\033[0m")
        elif alert.get("evidence"):
            print(f"  \033[90m\\-> Evid:\033[0m    \033[1;91m{alert['evidence']}\033[0m")

    def get_recent_alerts(self, count: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._alerts)[:count]

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            total = len(self._alerts)
            categories: Dict[str, int] = {}
            severities: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            for a in self._alerts:
                cat = a.get("category", "OTHER")
                sev = a.get("severity", "LOW")
                categories[cat] = categories.get(cat, 0) + 1
                severities[sev] = severities.get(sev, 0) + 1

            return {
                "total_alerts": total,
                "severities": severities,
                "categories": categories
            }
