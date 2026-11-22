"""
nids_engine.py - Network Intrusion Detection System (NIDS Engine)
TIẾN TRÌNH ĐỘC LẬP - VAI TRÒ: "MẮT THẦN" PHÁT HIỆN THỤ ĐỘNG
1. Sử dụng Scapy bắt gói tin thô trên Card mạng thật (Promiscuous / Monitor mode).
2. Tự động nhận diện Card mạng Wi-Fi/LAN có địa chỉ IP thật (Không dùng loopback 127.0.0.1 vì Npcap không bắt được).
3. Phân tích đa tầng:
   - Tầng 4: Thuật toán Sliding Window (1.0s) phát hiện tần suất dội gói DoS Flood (> 12 pkts/s).
   - Tầng 7: So khớp RegEx với Payload thô (SQL Injection, XSS).
4. Khi phát hiện:
   - In cảnh báo màu ANSI đỏ rực ra Console.
   - Ghi nhật ký chuẩn EVE JSONL vào logs/nids_alerts.json.
   - Ký số HMAC-SHA256 và gửi tin báo qua kênh UDP IPC (127.0.0.1:9999) tới hips_guard.py.
5. TUYỆT ĐỐI KHÔNG CAN THIỆP CHẶN GÓI TIN (Chỉ quan sát và báo cáo).
"""
import sys
import time
import json
import socket
import argparse
import threading
import hmac
import hashlib
from pathlib import Path
from collections import defaultdict, deque

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

# Cổng IPC UDP để gửi tin báo cho HIPS
HIPS_IPC_HOST = "127.0.0.1"
HIPS_IPC_PORT = 9999
IPC_HMAC_SECRET = b"NIDS_HIPS_SECURE_TOKEN_KEY_2026"

# Nạp thư viện Scapy
try:
    from scapy.all import sniff, IP, TCP, Raw, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def auto_detect_active_interfaces(prefer_loopback=False):
    """Tự động tìm kiếm tất cả Card mạng khả dụng: Wi-Fi, VMware, VirtualBox, LAN"""
    if prefer_loopback and sys.platform == "win32":
        try:
            from scapy.all import conf
            for iface in conf.ifaces.values():
                name = getattr(iface, "name", "").lower()
                desc = getattr(iface, "description", "").lower()
                if "npf_loopback" in name or "loopback" in desc:
                    return [iface], ["127.0.0.1"]
        except Exception:
            pass

    found_ifaces = []
    found_ips = []
    if sys.platform == "win32":
        try:
            from scapy.arch.windows import get_windows_if_list
            interfaces = get_windows_if_list()
            filter_keywords = ["npcap", "lightweight", "filter", "packet driver", "qos", "loopback", "bluetooth"]
            
            for iface in interfaces:
                name = iface.get("name", "")
                desc = iface.get("description", "")
                full_desc = (name + " " + desc).lower()
                
                # Bỏ qua các filter phụ của Npcap/NDIS
                if any(k in full_desc for k in filter_keywords):
                    continue

                ips = [ip for ip in iface.get("ips", []) if not ip.startswith("fe80") and not ip.startswith("169.254") and ":" not in ip]
                for ip in ips:
                    if ip.startswith(("10.", "192.168.", "172.")):
                        if name not in found_ifaces:
                            found_ifaces.append(name)
                            found_ips.append(ip)
        except Exception:
            pass
            
    if not found_ifaces:
        found_ifaces = [None]
        found_ips = ["0.0.0.0"]
    return found_ifaces, found_ips


class NIDSEngine:
    def __init__(self, interface: str = None, target_port: int = 8080, prefer_loopback: bool = False):
        self.interface = interface
        self.target_port = target_port
        self.prefer_loopback = prefer_loopback
        self.running = False
        
        # Socket gửi tín hiệu cảnh báo sang HIPS
        self.ipc_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Cửa sổ trượt 1.0s theo dõi tần suất gói tin DoS: {src_ip: deque([t1, t2, ...])}
        self.dos_windows = defaultdict(deque)
        self.dos_threshold = 12  # Quá 12 gói/giây -> Báo động DoS
        
        # Biểu thức chính quy L7
        import re
        self.sqli_pattern = re.compile(r"(?i)(\bUNION\s+(ALL\s+)?SELECT\b|'\s*(OR|AND)\s*'?\d+'?\s*=\s*'?\d+|'\s*OR\s*'1'='1|--|#)")
        self.xss_pattern = re.compile(r"(?i)(<script\b[^>]*>|onerror\s*=|onload\s*=|onclick\s*=|javascript\s*:)")

        # Cooldown chống spam cảnh báo cho cùng 1 IP
        self.alert_cooldowns = {}

    def _send_alert_to_hips(self, alert_data: dict):
        """Gửi sự kiện cảnh báo qua UDP IPC có ký số HMAC sang HIPS Guard"""
        try:
            payload_str = json.dumps(alert_data)
            signature = hmac.new(IPC_HMAC_SECRET, payload_str.encode("utf-8"), hashlib.sha256).hexdigest()
            packet = {
                "payload": payload_str,
                "signature": signature
            }
            msg = json.dumps(packet).encode("utf-8")
            self.ipc_sock.sendto(msg, (HIPS_IPC_HOST, HIPS_IPC_PORT))
        except Exception as e:
            print(f"[NIDS Warning] Không thể gửi cảnh báo sang HIPS IPC: {e}")

    def _record_alert(self, category: str, severity: str, src_ip: str, dst_ip: str, dst_port: int, evidence: str):
        now_ts = time.time()
        cooldown_key = (src_ip, category)
        if now_ts - self.alert_cooldowns.get(cooldown_key, 0.0) < 1.5:
            return  # Đang trong thời gian cooldown
        self.alert_cooldowns[cooldown_key] = now_ts

        timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S")
        alert = {
            "source": "NIDS",
            "timestamp": timestamp_str,
            "category": category,
            "severity": severity,
            "attacker_ip": src_ip,
            "target_ip": dst_ip,
            "target_port": dst_port,
            "evidence": evidence
        }

        # 1. In ra Console với màu ANSI
        color = "\033[91m\033[1m" if severity == "CRITICAL" else "\033[93m\033[1m"
        print(f"\n{color}[!] [NIDS PHÁT HIỆN XÂM NHẬP - {severity}] {timestamp_str}\033[0m")
        print(f"    ├─ Loại tấn công: {category}")
        print(f"    ├─ Attacker IP: \033[91m{src_ip}\033[0m ──► Mục tiêu: {dst_ip}:{dst_port}")
        print(f"    ├─ Bằng chứng trên Packet: \033[93m{evidence}\033[0m")
        print(f"    └─ \033[96m[Hành động NIDS]\033[0m Đã ký số HMAC & Gửi tin báo động sang HIPS (UDP Port {HIPS_IPC_PORT})...")

        # 2. Ghi ra file Log EVE JSONL
        try:
            with open(ALERT_LOG_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(alert, ensure_ascii=False) + "\n")
        except Exception:
            pass

        # 3. Gửi ngay sang HIPS để HIPS thi hành án (thêm firewall rule)
        self._send_alert_to_hips(alert)

    def packet_callback(self, pkt):
        """Hàm callback xử lý từng gói tin mạng thô tóm được từ Scapy"""
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            return

        ip_layer = pkt[IP]
        tcp_layer = pkt[TCP]

        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        dst_port = tcp_layer.dport

        # Chỉ theo dõi các gói tin hướng tới cổng dịch vụ của Web Server
        if dst_port != self.target_port:
            return

        now = time.time()

        # 1. Phân tích Tầng 4: DoS Flood Detection (Sliding Window 1s)
        q = self.dos_windows[src_ip]
        q.append(now)
        while q and (now - q[0]) > 1.0:
            q.popleft()

        packet_rate = len(q)
        if packet_rate > self.dos_threshold:
            self._record_alert(
                category="DOS_FLOOD_ATTACK",
                severity="CRITICAL",
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                evidence=f"Lưu lượng dội gói bất thường: {packet_rate} pkts/s (Vượt ngưỡng {self.dos_threshold})"
            )

        # 2. Phân tích Tầng 7: Deep Packet Inspection trên Payload HTTP (Hỗ trợ URL-Decode)
        if pkt.haslayer(Raw):
            try:
                import urllib.parse
                raw_payload = pkt[Raw].load.decode("utf-8", errors="replace")
                decoded_payload = urllib.parse.unquote(raw_payload)
                # Kiểm tra cả chuỗi thô và chuỗi đã giải mã URL (%27 -> ', %20 -> space)
                payload_to_check = raw_payload + " " + decoded_payload
                
                # So khớp SQLi
                sqli_match = self.sqli_pattern.search(payload_to_check)
                if sqli_match:
                    self._record_alert(
                        category="SQL_INJECTION",
                        severity="CRITICAL",
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                        evidence=f"SQLi Payload: {sqli_match.group(0)}"
                    )

                # So khớp XSS
                xss_match = self.xss_pattern.search(payload_to_check)
                if xss_match:
                    self._record_alert(
                        category="CROSS_SITE_SCRIPTING",
                        severity="HIGH",
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                        evidence=f"XSS Payload: {xss_match.group(0)}"
                    )
            except Exception:
                pass

    def start(self):
        if not SCAPY_AVAILABLE:
            print("[NIDS Error] Thư viện Scapy chưa sẵn sàng! Hãy cài đặt qua 'pip install scapy'.")
            return

        # Tự động phát hiện interface nếu chưa chỉ định hoặc chọn loopback cho 1 máy
        if self.interface in ["loopback", "local"] or self.prefer_loopback:
            loop_ifaces, _ = auto_detect_active_interfaces(prefer_loopback=True)
            if loop_ifaces and loop_ifaces[0]:
                self.interface = loop_ifaces[0]
                print(f"[*] [CHẾ ĐỘ 1 MÁY] Đang sử dụng Npcap Loopback Adapter: '{self.interface}'")
            else:
                print("[-] Không tìm thấy Npcap Loopback Adapter. Chuyển sang Card mạng vật lý.")

        if not self.interface:
            detected_ifaces, detected_ips = auto_detect_active_interfaces(prefer_loopback=False)
            self.interface = detected_ifaces
            print(f"[*] Đã tự động nhận diện {len(detected_ifaces)} Card mạng khả dụng:")
            for ifn, ip in zip(detected_ifaces, detected_ips):
                print(f"    ├─ '{ifn}' (IP: {ip})")

        print("=" * 75)
        print("   📡 NIDS ENGINE ĐANG LẮNG NGHE THỤ ĐỘNG TRÊN TẦNG MẠNG (PASSIVE SNIFFER)   ")
        print(f"   ├─ Card mạng (Interface): {self.interface or 'Mặc định (Scapy conf.iface)'}")
        print(f"   ├─ Cổng mục tiêu giám sát: Port {self.target_port}")
        print(f"   ├─ Xác thực tin báo sang HIPS: HMAC-SHA256 qua UDP {HIPS_IPC_HOST}:{HIPS_IPC_PORT}")
        print("   └─ Vai trò: CHỈ PHÁT HIỆN & BÁO ĐỘNG (Không can thiệp chặn gói tin)")
        print("=" * 75)
        if "loopback" in str(self.interface).lower():
            print("\033[92m[✓] Đang hoạt động ở Chế độ 1 Máy (Local Loopback Sniffing qua Npcap Adapter)!\033[0m")
        else:
            print("\033[92m[✓] Đang lắng nghe đồng thời tất cả lưu lượng tấn công trên các card mạng!\033[0m")
        print("=" * 75 + "\n")

        bpf_filter = f"tcp dst port {self.target_port}"
        try:
            sniff(
                iface=self.interface,
                filter=bpf_filter,
                prn=self.packet_callback,
                store=False
            )
        except KeyboardInterrupt:
            print("\n[NIDS] Đã dừng tiến trình bắt gói tin.")
        except Exception as e:
            print(f"[NIDS Error] Lỗi khi sniff mạng: {e}")
            print("[NIDS Gợi ý] Chạy bằng quyền Administrator để Scapy truy cập được driver Npcap!")


def check_or_request_admin():
    """Kiểm tra quyền Administrator trên Windows, tự động kích hoạt UAC nếu đang ở user thường"""
    if sys.platform == "win32":
        import ctypes
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            is_admin = False
        if not is_admin:
            print("\033[93m[!] NIDS bắt buộc cần quyền Administrator để Scapy mở Raw Socket trên Card mạng (Npcap).\033[0m")
            print("[*] Đang tự động kích hoạt hộp thoại nâng quyền UAC...")
            try:
                params = f'"{__file__}" ' + " ".join(f'"{arg}"' for arg in sys.argv[1:])
                ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
                if ret > 32:
                    sys.exit(0)
            except Exception as e:
                print(f"[-] Không thể tự động xin quyền: {e}")
                print("[!] Vui lòng mở CMD bằng 'Run as administrator' để khởi chạy!")
                sys.exit(1)


if __name__ == "__main__":
    check_or_request_admin()
    parser = argparse.ArgumentParser(description="NIDS Passive Sniffer Engine")
    parser.add_argument("--interface", "-i", type=str, default=None, help="Tên card mạng để lắng nghe (Ví dụ: 'Wi-Fi')")
    parser.add_argument("--port", "-p", type=int, default=8080, help="Cổng Web Server cần giám sát (Mặc định 8080)")
    parser.add_argument("--local", "--loopback", action="store_true", help="Chế độ 1 Máy: Tự động dùng Npcap Loopback Adapter để bắt traffic 127.0.0.1")
    args = parser.parse_args()

    nids = NIDSEngine(interface=args.interface, target_port=args.port, prefer_loopback=args.local)
    nids.start()
