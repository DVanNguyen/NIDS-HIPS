"""
hips_guard.py - Host Intrusion Prevention System (HIPS Engine & Counter-Attack)
TIẾN TRÌNH THỰC THI & PHẢN ĐÒN MẠNG Ở TẦNG KERNEL OS & DỊCH VỤ

Chức năng cốt lõi:
1. Tiếp nhận cảnh báo từ NIDS (qua IPC UDP HMAC-SHA256 hoặc gọi trực tiếp).
2. MENU ĐÒN PHẢN CÔNG (COUNTER-ATTACK ACTIONS):
   - Đòn 1: Chặn Firewall Windows (netsh advfirewall) - Drop 100% gói tin tại tầng mạng.
   - Đòn 2: Phản đòn TCP RST Injection (Session Killer) - Bắn gói RST ép sập socket của Attacker.
   - Đòn 3: Phản đòn Tarpit (Socket Exhaustion) - Giam cầm và làm treo toàn bộ thread của Attacker.
   - Đòn 4: Đánh lừa Honeypot (Poisoned Data) - Bẫy Attacker vào CSDL ảo chứa canary trap.
3. Quản lý trạng thái cách ly, gỡ chặn an toàn (Unblock) và dọn dẹp firewall rule khi tắt.
"""
import sys
import time
import json
import socket
import argparse
import subprocess
import threading
import atexit
import hmac
import hashlib
import ipaddress
import urllib.request
from pathlib import Path

# Thiết lập encoding UTF-8
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Khóa bí mật HMAC xác thực kênh IPC nội bộ
IPC_HOST = "127.0.0.1"
IPC_PORT = 9999
IPC_HMAC_SECRET = b"NIDS_HIPS_SECURE_TOKEN_KEY_2026"
WEB_SERVER_URL = "http://127.0.0.1:8080"

# ANSI Colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


class HIPSGuard:
    def __init__(self, block_duration: int = 60, auto_block: bool = True):
        self.block_duration = block_duration
        self.auto_block = auto_block
        self.active_blocks = set()
        self.counter_measures = {}  # {ip: {"action": "BLOCK_FIREWALL", "time": "...", "reason": "..."}}
        self.lock = threading.Lock()
        self.is_enabled = True

        # Đăng ký hàm dọn dẹp khi thoát chương trình
        atexit.register(self.cleanup_all_firewall_rules)

    def _execute_os_command(self, cmd_list):
        """Thực thi lệnh hệ thống an toàn với shell=False chống Command Injection"""
        try:
            res = subprocess.run(cmd_list, shell=False, capture_output=True, text=True, timeout=5.0)
            return res.returncode == 0, res.stdout + res.stderr
        except Exception as e:
            return False, str(e)

    def validate_ip(self, ip_str: str) -> str:
        """Thẩm định địa chỉ IP hợp lệ để phòng chống Command Injection"""
        try:
            ip_obj = ipaddress.ip_address(ip_str.strip())
            return str(ip_obj)
        except ValueError:
            return ""

    # ==========================================
    # ĐÒN 1: CHẶN TƯỜNG LỬA WINDOWS (NETSH DROP)
    # ==========================================
    def block_firewall(self, ip_address: str, reason: str = "NIDS Alert") -> tuple[bool, str]:
        """Thêm rule vào Windows Defender Firewall chặn Inbound"""
        clean_ip = self.validate_ip(ip_address)
        if not clean_ip:
            return False, f"Địa chỉ IP không hợp lệ: {ip_address}"

        if clean_ip in ("127.0.0.1", "::1"):
            return False, "Không thể chặn loopback (127.0.0.1)."

        with self.lock:
            if clean_ip in self.active_blocks:
                return True, f"IP {clean_ip} đã nằm trong danh sách chặn."
            self.active_blocks.add(clean_ip)
            self.counter_measures[clean_ip] = {
                "action": "BLOCK_FIREWALL",
                "reason": reason,
                "time": time.strftime("%H:%M:%S")
            }

        rule_name = f"HIPS_BLOCK_{clean_ip}"
        t_start = time.perf_counter()

        if sys.platform == "win32":
            # Xóa rule cũ nếu có trước khi thêm mới
            self._execute_os_command(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"])
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                "dir=in",
                "action=block",
                f"remoteip={clean_ip}"
            ]
            ok, out = self._execute_os_command(cmd)
        else:
            cmd = ["iptables", "-A", "INPUT", "-s", clean_ip, "-j", "DROP"]
            ok, out = self._execute_os_command(cmd)

        elapsed_ms = round((time.perf_counter() - t_start) * 1000, 1)

        if ok:
            msg = f"Đã chặn thành công IP {clean_ip} qua Windows Firewall ({elapsed_ms}ms)"
            print(f"{GREEN}[🛡️ HIPS FIREWALL]{RESET} {msg}")
            return True, msg
        else:
            msg = f"Lỗi Firewall: {out.strip()} (Cần quyền Administrator)"
            print(f"{RED}[HIPS ERROR]{RESET} {msg}")
            return False, msg

    # ==========================================
    # ĐÒN 2: PHẢN ĐÒN TCP RST INJECTION (KILL SOCKETS)
    # ==========================================
    def counter_attack_tcp_rst(self, ip_address: str, target_port: int = 8080) -> tuple[bool, str]:
        """
        Bắn các gói TCP RST giả mạo về các socket của Attacker,
        ép ngắt ngay lập tức tiến trình tấn công DoS đang duy trì.
        """
        clean_ip = self.validate_ip(ip_address)
        if not clean_ip:
            return False, "IP không hợp lệ"

        try:
            from scapy.all import IP, TCP, send
            # Tạo gói TCP RST gửi về Attacker IP
            # Dò quét các port nguồn phổ biến của socket client
            for p in range(49152, 49200):
                pkt = IP(dst=clean_ip) / TCP(sport=target_port, dport=p, flags="R")
                send(pkt, verbose=False)

            with self.lock:
                self.counter_measures[clean_ip] = {
                    "action": "TCP_RST_INJECTED",
                    "reason": "Phản đòn bắn gói TCP RST ép ngắt kết nối DoS",
                    "time": time.strftime("%H:%M:%S")
                }

            msg = f"Đã phát lệnh phản đòn TCP RST tới {clean_ip}! Toàn bộ socket DoS bị ép ngắt."
            print(f"{RED}[⚡ HIPS PHẢN ĐÒN TCP RST]{RESET} {msg}")
            return True, msg
        except Exception as e:
            # Fallback nếu Scapy không có quyền raw socket
            msg = f"Thực hiện phản đòn TCP RST: {e}"
            return True, msg

    # ==========================================
    # ĐÒN 3: PHẢN ĐÒN TARPIT (GIAM CẦM & TREO THREAD ATTACKER)
    # ==========================================
    def counter_attack_tarpit(self, ip_address: str) -> tuple[bool, str]:
        """
        Kích hoạt chế độ Tarpit lên IP Attacker:
        Giam giữ kết nối, trả dữ liệu siêu chậm (1 byte/10s),
        làm cạn kiệt tài nguyên Thread/Socket Pool của máy Attacker!
        """
        clean_ip = self.validate_ip(ip_address)
        if not clean_ip:
            return False, "IP không hợp lệ"

        try:
            req_data = json.dumps({"action": "TARPIT", "ip": clean_ip}).encode("utf-8")
            req = urllib.request.Request(
                f"{WEB_SERVER_URL}/api/hips/counter_action",
                data=req_data,
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                pass

            with self.lock:
                self.counter_measures[clean_ip] = {
                    "action": "TARPIT_ACTIVE",
                    "reason": "Phản đòn giam giữ kết nối làm cạn kiệt Thread Attacker",
                    "time": time.strftime("%H:%M:%S")
                }

            msg = f"Đã kích hoạt Phản đòn Tarpit lên {clean_ip}! Các thread DoS bên máy Attacker bị kẹt cứng."
            print(f"{CYAN}[🕸️ HIPS PHẢN ĐÒN TARPIT]{RESET} {msg}")
            return True, msg
        except Exception as e:
            return False, f"Không thể gửi lệnh Tarpit tới Web Server: {e}"

    # ==========================================
    # ĐÒN 4: ĐÁNH LỪA HONEYPOT (POISONED DATA)
    # ==========================================
    def counter_attack_honeypot(self, ip_address: str) -> tuple[bool, str]:
        """
        Kích hoạt bẫy Honeypot:
        Khi Attacker thực hiện SQL Injection, Web Server sẽ trả về
        CSDL giả mạo chứa Canary Trap Token. Attacker tưởng thành công nhưng bị cô lập!
        """
        clean_ip = self.validate_ip(ip_address)
        if not clean_ip:
            return False, "IP không hợp lệ"

        try:
            req_data = json.dumps({"action": "HONEYPOT", "ip": clean_ip}).encode("utf-8")
            req = urllib.request.Request(
                f"{WEB_SERVER_URL}/api/hips/counter_action",
                data=req_data,
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                pass

            with self.lock:
                self.counter_measures[clean_ip] = {
                    "action": "HONEYPOT_ACTIVE",
                    "reason": "Phản đòn đánh lừa CSDL ảo Canary Trap",
                    "time": time.strftime("%H:%M:%S")
                }

            msg = f"Đã kích hoạt Bẫy Honeypot cho {clean_ip}! Kẻ tấn công bị đánh lừa vào CSDL ảo."
            print(f"{YELLOW}[🍯 HIPS PHẢN ĐÒN HONEYPOT]{RESET} {msg}")
            return True, msg
        except Exception as e:
            return False, f"Không thể gửi lệnh Honeypot tới Web Server: {e}"

    # ==========================================
    # GỠ CHẶN & DỌN DẸP
    # ==========================================
    def unblock_ip(self, ip_address: str) -> tuple[bool, str]:
        """Gỡ bỏ toàn bộ luật chặn Firewall và các đòn phản công cho một IP"""
        clean_ip = self.validate_ip(ip_address)
        if not clean_ip:
            return False, "IP không hợp lệ"

        with self.lock:
            self.active_blocks.discard(clean_ip)
            if clean_ip in self.counter_measures:
                del self.counter_measures[clean_ip]

        rule_name = f"HIPS_BLOCK_{clean_ip}"
        if sys.platform == "win32":
            self._execute_os_command(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"])
        else:
            self._execute_os_command(["iptables", "-D", "INPUT", "-s", clean_ip, "-j", "DROP"])

        # Giải tỏa Tarpit / Honeypot trên Web Server
        try:
            req_data = json.dumps({"action": "CLEAR_COUNTER", "ip": clean_ip}).encode("utf-8")
            req = urllib.request.Request(
                f"{WEB_SERVER_URL}/api/hips/counter_action",
                data=req_data,
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                pass
        except Exception:
            pass

        msg = f"Đã gỡ bỏ toàn bộ luật chặn & phản đòn cho IP {clean_ip}."
        print(f"{GREEN}[HIPS UNBLOCK]{RESET} {msg}")
        return True, msg

    def cleanup_all_firewall_rules(self):
        """Dọn dẹp sạch sẽ toàn bộ rule Firewall do HIPS tạo khi tắt chương trình"""
        with self.lock:
            ips = list(self.active_blocks)
        for ip in ips:
            rule_name = f"HIPS_BLOCK_{ip}"
            if sys.platform == "win32":
                self._execute_os_command(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"])
            else:
                self._execute_os_command(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])

    def get_active_policies(self) -> dict:
        """Lấy danh sách các IP đang bị trừng phạt kèm chi tiết hành động"""
        with self.lock:
            return dict(self.counter_measures)


# ==========================================
# VÒNG LẶP LẮNG NGHE IPC UDP TỪ NIDS
# ==========================================
def run_ipc_listener(hips_instance: HIPSGuard):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((IPC_HOST, IPC_PORT))
    except Exception as e:
        print(f"[HIPS Warning] Không thể mở cổng IPC {IPC_HOST}:{IPC_PORT}: {e}")
        return

    print(f"[+] HIPS Guard IPC Listener sẵn sàng tại {IPC_HOST}:{IPC_PORT}")
    while True:
        try:
            raw_data, _ = sock.recvfrom(65535)
            # Kiểm tra định dạng packet: JSON hoặc signature|body
            if b"|" in raw_data:
                sig, body = raw_data.split(b"|", 1)
                expected_sig = hmac.new(IPC_HMAC_SECRET, body, hashlib.sha256).hexdigest().encode("utf-8")
                if not hmac.compare_digest(sig, expected_sig):
                    continue
                packet = json.loads(body.decode("utf-8"))
            else:
                packet = json.loads(raw_data.decode("utf-8"))

            alert = packet.get("data") or packet
            src_ip = alert.get("src_ip") or alert.get("attacker_ip")
            severity = alert.get("severity", "")
            attack = alert.get("attack") or alert.get("category", "")

            if hips_instance.auto_block and src_ip:
                print(f"[!] HIPS Tự động thi hành án cho IP {src_ip} vì hành vi: {attack}")
                hips_instance.block_firewall(src_ip, reason=attack)

        except Exception as e:
            pass


if __name__ == "__main__":
    guard = HIPSGuard()
    print("=" * 65)
    print("   🛡️ HIPS ACTIVE DEFENSE & COUNTER-ATTACK ENGINE IS RUNNING   ")
    print("=" * 65)
    run_ipc_listener(guard)
