"""
nids_engine.py - Network Intrusion Detection System (NIDS Engine)
TIẾN TRÌNH GIÁM SÁT THỤ ĐỘNG & BẮT GÓI TIN ĐA TẦNG (L4 + L7)

Chức năng:
1. Bắt gói tin qua Scapy trên Card mạng thật (Tự động giám sát đồng thời Wi-Fi, Ethernet, VMware, VPN, Loopback).
2. Tầng 4: Sliding Window đếm tần suất gói tin phát hiện DoS (TCP SYN Flood, HTTP Flood).
3. Tầng 7: Deep Packet Inspection (DPI) quét RegEx phát hiện SQL Injection và Stored XSS.
4. Gửi bản tin cảnh báo qua UDP IPC ký số HMAC-SHA256 sang HIPS Guard và Bảng điều khiển SOC GUI.
5. Hỗ trợ Callback trực tiếp và đo lường lưu lượng thực tế (Packets/Second) cho Desktop Tkinter.
"""
import sys
import time
import json
import socket
import threading
import hmac
import hashlib
import re
from urllib.parse import unquote_plus
from collections import defaultdict, deque
from pathlib import Path

# Thiết lập encoding UTF-8
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Thư mục logs
LOG_DIR = Path(__file__).resolve().parent.parent / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
ALERT_LOG_FILE = LOG_DIR / "nids_alerts.json"

# Cổng IPC UDP
HIPS_IPC_HOST = "127.0.0.1"
HIPS_IPC_PORT = 9999
GUI_IPC_PORT = 9988
IPC_HMAC_SECRET = b"NIDS_HIPS_SECURE_TOKEN_KEY_2026"

# ANSI Colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def get_active_capture_interfaces() -> list[str]:
    """Tự động phát hiện toàn bộ các card mạng IPv4 đang hoạt động trên máy chủ"""
    if sys.platform == "win32":
        try:
            from scapy.arch.windows import get_windows_if_list
            skip_tokens = (
                "Npcap Packet Driver",
                "Filter",
                "Packet Scheduler",
                "LightWeight",
                "Light-Weight",
                "Kernel Debugger",
                "6to4",
                "Teredo",
                "IP-HTTPS",
            )
            active = []
            for item in get_windows_if_list():
                name = item.get("name", "")
                if not name or any(tok in name for tok in skip_tokens):
                    continue
                valid_ips = [
                    ip for ip in item.get("ips", [])
                    if ":" not in ip and not ip.startswith(("fe80", "169.254"))
                ]
                if valid_ips:
                    active.append(name)
            if active:
                return active
        except Exception:
            pass
    return []


class NIDSEngine:
    def __init__(self, interface=None, target_port: int = 8080, on_alert_cb=None, on_stats_cb=None):
        self.interface = interface
        self.target_port = target_port
        self.on_alert_cb = on_alert_cb
        self.on_stats_cb = on_stats_cb
        self.running = False
        self.stop_event = threading.Event()

        # Bộ đếm lưu lượng gói tin thực tế mỗi giây (PPS)
        self._pkt_counter = 0
        self._pkt_lock = threading.Lock()

        # Socket gửi tín hiệu cảnh báo qua IPC
        self.ipc_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Cửa sổ trượt 2.0s theo dõi tần suất gói tin DoS
        self.time_window = 2.0
        self.syn_window = defaultdict(deque)
        self.http_window = defaultdict(deque)
        self.syn_threshold = 20    # Quá 20 gói SYN/2s -> SYN Flood
        self.http_threshold = 15   # Quá 15 requests/2s -> HTTP Flood

        # Biểu thức chính quy L7 DPI chuẩn xác (loại trừ dương tính giả trên mật khẩu có # hoặc boundary --)
        self.sqli_pattern = re.compile(
            r"(?i)(\bUNION\s+(ALL\s+)?SELECT\b"
            r"|'\s*(OR|AND)\s*'?\w+'?\s*=\s*'?\w+"
            r"|\b(OR|AND)\s+1\s*=\s*1\b"
            r"|'\s*(--|#)"
            r"|;\s*(DROP|SELECT|INSERT|UPDATE|DELETE)\b)",
            re.IGNORECASE
        )
        self.xss_pattern = re.compile(
            r"(?i)(<script\b[^>]*>|onerror\s*=|onload\s*=|onclick\s*=|javascript\s*:)",
            re.IGNORECASE
        )
        self.xff_pattern = re.compile(r"(?im)^X-Forwarded-For:\s*([^\r\n,]+)")

        # Cooldown chống spam cảnh báo cho cùng 1 IP
        self.alert_cooldowns = {}

    def pop_pps_count(self) -> int:
        """Lấy số lượng gói tin thực tế bắt được trong chu kỳ 1 giây vừa qua"""
        with self._pkt_lock:
            val = self._pkt_counter
            self._pkt_counter = 0
            return val

    def _send_ipc(self, msg_type: str, payload: dict):
        """Gửi gói tin IPC có ký số HMAC sang HIPS và GUI"""
        try:
            body = json.dumps({"type": msg_type, "data": payload}, ensure_ascii=False).encode("utf-8")
            sig = hmac.new(IPC_HMAC_SECRET, body, hashlib.sha256).hexdigest().encode("utf-8")
            packet = sig + b"|" + body

            self.ipc_sock.sendto(packet, (HIPS_IPC_HOST, HIPS_IPC_PORT))
            self.ipc_sock.sendto(packet, (HIPS_IPC_HOST, GUI_IPC_PORT))
        except Exception:
            pass

    def _record_alert(self, category: str, severity: str, src_ip: str, dst_ip: str, dst_port: int, evidence: str):
        now_ts = time.time()
        cooldown_key = (src_ip, category)
        if now_ts - self.alert_cooldowns.get(cooldown_key, 0.0) < 1.2:
            return  # Tránh spam cùng 1 cảnh báo trong 1.2s
        self.alert_cooldowns[cooldown_key] = now_ts

        timestamp_str = time.strftime("%H:%M:%S")
        alert = {
            "source": "NIDS",
            "timestamp": timestamp_str,
            "category": category,
            "severity": severity,
            "attacker_ip": src_ip,
            "src_ip": src_ip,
            "target_ip": dst_ip,
            "dst_port": dst_port,
            "evidence": evidence,
            "details": f"{category}: {evidence}"
        }

        # 1. In cảnh báo ra Terminal
        color = RED if severity == "CRITICAL" else YELLOW
        print(f"\n{color}{BOLD}[🚨 NIDS ALERT DETECTED]{RESET}")
        print(f"  ├─ Loại tấn công: {BOLD}{category}{RESET} (Mức độ: {severity})")
        print(f"  ├─ IP Máy Tấn Công: {YELLOW}{src_ip}{RESET} ➔ Đích: {dst_ip}:{dst_port}")
        print(f"  └─ Bằng chứng: {evidence}")

        # 2. Ghi nhật ký vào file JSONL
        try:
            with open(ALERT_LOG_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(alert, ensure_ascii=False) + "\n")
        except Exception:
            pass

        # 3. Gửi IPC sang HIPS & GUI
        self._send_ipc("ALERT", alert)

        # 4. Gọi Callback nếu có
        if self.on_alert_cb:
            try:
                self.on_alert_cb(alert)
            except Exception:
                pass

    def _clean_window(self, dq: deque, now: float):
        while dq and (now - dq[0]) > self.time_window:
            dq.popleft()

    def inspect_packet(self, pkt):
        """Hàm phân tích từng gói tin Scapy bắt được"""
        try:
            if not pkt.haslayer("IP") or not pkt.haslayer("TCP"):
                return

            ip_layer = pkt["IP"]
            tcp_layer = pkt["TCP"]

            # Chỉ giám sát các gói tin đến port dịch vụ
            if tcp_layer.dport != self.target_port:
                return

            with self._pkt_lock:
                self._pkt_counter += 1

            now = time.time()
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            flags = str(tcp_layer.flags)

            raw_payload = ""
            if pkt.haslayer("Raw"):
                raw_payload = pkt["Raw"].load.decode("utf-8", errors="ignore")
                # Nếu gói tin đi qua Ngrok Tunnel trên Loopback, bóc tách IP thật từ X-Forwarded-For
                if src_ip == "127.0.0.1":
                    xff_match = self.xff_pattern.search(raw_payload)
                    if xff_match:
                        real_ip = xff_match.group(1).strip()
                        if real_ip:
                            src_ip = real_ip

            # 1. Phát hiện TCP SYN Flood (L4)
            if flags == "S":
                dq = self.syn_window[src_ip]
                self._clean_window(dq, now)
                dq.append(now)
                if len(dq) >= self.syn_threshold:
                    self._record_alert(
                        category="DoS (TCP SYN Flood)",
                        severity="CRITICAL",
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        dst_port=tcp_layer.dport,
                        evidence=f"Tần suất dội {len(dq)} gói SYN/{self.time_window}s"
                    )

            # 2. Phân tích Deep Packet Inspection (L7 HTTP)
            if raw_payload:
                first_line = raw_payload.split("\r\n", 1)[0]
                parts = first_line.split(" ")
                req_path = parts[1].split("?", 1)[0] if len(parts) >= 2 else ""
                if req_path.startswith(("/api/xss/exfiltrate", "/api/xss/stolen_cookies", "/api/hips/", "/api/reset")):
                    return

                decoded_payload = unquote_plus(raw_payload)

                # HTTP Flood Detection (L7 DoS)
                if raw_payload.startswith(("GET ", "POST ", "PUT ", "DELETE ")):
                    hdq = self.http_window[src_ip]
                    self._clean_window(hdq, now)
                    hdq.append(now)
                    if len(hdq) >= self.http_threshold:
                        self._record_alert(
                            category="DoS (HTTP Flood)",
                            severity="CRITICAL",
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            dst_port=tcp_layer.dport,
                            evidence=f"Dội tải dồn dập {len(hdq)} requests/{self.time_window}s"
                        )

                # SQL Injection Signature Matching
                sqli_match = self.sqli_pattern.search(decoded_payload)
                if sqli_match:
                    self._record_alert(
                        category="SQL Injection (SQLi)",
                        severity="CRITICAL",
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        dst_port=tcp_layer.dport,
                        evidence=f"Khớp chữ ký: '{sqli_match.group(0)[:60]}'"
                    )

                # XSS Signature Matching
                xss_match = self.xss_pattern.search(decoded_payload)
                if xss_match:
                    self._record_alert(
                        category="Cross-Site Scripting (XSS)",
                        severity="WARNING",
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        dst_port=tcp_layer.dport,
                        evidence=f"Khớp mã Script: '{xss_match.group(0)[:60]}'"
                    )

        except Exception:
            pass

    def start_sniffing(self):
        """Khởi chạy Scapy Sniffer trên một hoặc nhiều card mạng đồng thời"""
        from scapy.all import sniff
        self.running = True

        target_iface = self.interface
        if not target_iface or target_iface == "ALL":
            detected = get_active_capture_interfaces()
            target_iface = detected if detected else None

        print(f"[+] NIDS Sensor bắt đầu lắng nghe lưu lượng trên cổng {self.target_port} (Card mạng: {target_iface})...")
        try:
            sniff(
                iface=target_iface,
                filter=f"tcp port {self.target_port}",
                prn=self.inspect_packet,
                store=False,
                stop_filter=lambda _: self.stop_event.is_set()
            )
        except Exception as e:
            print(f"[!] Scapy Sniff lỗi trên {target_iface}: {e}. Thử fallback mặc định...")
            try:
                sniff(
                    filter=f"tcp port {self.target_port}",
                    prn=self.inspect_packet,
                    store=False,
                    stop_filter=lambda _: self.stop_event.is_set()
                )
            except Exception as e2:
                print(f"[!] Lỗi nghiêm trọng Scapy: {e2}")

    def stop(self):
        self.stop_event.set()
        self.running = False


if __name__ == "__main__":
    sensor = NIDSEngine(interface="ALL", target_port=8080)
    print("=" * 65)
    print("   📡 NIDS PACKET SNIFFER & DPI ENGINE ĐANG CHẠY   ")
    print("=" * 65)
    sensor.start_sniffing()
