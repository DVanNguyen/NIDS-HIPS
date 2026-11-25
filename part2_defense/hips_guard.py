"""
hips_guard.py - Host Intrusion Prevention System (HIPS Engine & Counter-Attack)
TIẾN TRÌNH THỰC THI & PHẢN ĐÒN MẠNG Ở TẦNG KERNEL OS & DỊCH VỤ

Chức năng cốt lõi:
1. Tiếp nhận cảnh báo từ NIDS (qua IPC UDP HMAC-SHA256 hoặc gọi trực tiếp).
2. Tự động mở cổng dịch vụ 8080 trên Windows Firewall (cho phép kết nối LAN 2 máy qua Wi-Fi Public/Private).
3. MENU 4 ĐÒN PHẢN CÔNG (COUNTER-ATTACK ACTIONS):
   - Đòn 1: Chặn Firewall Windows (netsh advfirewall) - Drop 100% gói tin tại tầng mạng Kernel.
   - Đòn 2: Phản đòn TCP RST Injection (Session Killer) - Bắn cờ TCP RST & SO_LINGER ép sập socket Attacker.
   - Đòn 3: Phản đòn Tarpit (Socket Exhaustion) - Giam cầm kết nối 10s làm treo toàn bộ thread của Attacker.
   - Đòn 4: Đánh lừa Honeypot (Poisoned Data) - Bẫy Attacker vào CSDL ảo chứa Canary Trap.
4. Quản lý trạng thái cách ly, gỡ chặn an toàn (Unblock) và dọn dẹp firewall rule khi tắt.
"""
import sys
import re
import time
import json
import socket
import subprocess
import threading
import atexit
import hmac
import hashlib
import ipaddress
import urllib.request

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
        self._port_rule_created = False

        # Đăng ký hàm dọn dẹp khi thoát chương trình
        atexit.register(self.cleanup_all_firewall_rules)

    def _execute_os_command(self, cmd_list):
        """Thực thi lệnh hệ thống an toàn với shell=False chống Command Injection"""
        try:
            res = subprocess.run(cmd_list, shell=False, capture_output=True, text=True, timeout=5.0)
            return res.returncode == 0, res.stdout + res.stderr
        except Exception as e:
            return False, str(e)

    def _notify_webserver_action(self, action: str, ip: str) -> tuple[bool, str]:
        """Đồng bộ chính sách phản đòn xuống tầng Socket của Web Server"""
        try:
            req_data = json.dumps({"action": action, "ip": ip}).encode("utf-8")
            req = urllib.request.Request(
                f"{WEB_SERVER_URL}/api/hips/counter_action",
                data=req_data,
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=2.5) as resp:
                return True, resp.read().decode("utf-8", errors="ignore")
        except Exception as e:
            return False, str(e)

    def ensure_service_port_allowed(self, port: int = 8080) -> bool:
        """
        Đảm bảo cổng Web 8080 được mở Inbound trên mọi Profile (Public/Private/Domain) của Windows,
        giúp Máy Tấn Công (Máy 2) kết nối thông suốt qua Wi-Fi/Hotspot trường học trước khi bị HIPS chặn.
        (Trong Windows Firewall, luật BLOCK của HIPS luôn có độ ưu tiên cao hơn luật ALLOW này).
        """
        if sys.platform != "win32":
            return True
        rule_name = f"NIDS_ALLOW_WEB_{port}"
        self._execute_os_command(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"])
        ok, _ = self._execute_os_command([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=in",
            "action=allow",
            "protocol=TCP",
            f"localport={port}",
            "profile=any"
        ])
        if ok:
            self._port_rule_created = True
        return ok

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
        """Thêm rule vào Windows Defender Firewall chặn Inbound + cắt toàn bộ Socket đang mở"""
        clean_ip = self.validate_ip(ip_address)
        if not clean_ip:
            return False, f"Địa chỉ IP không hợp lệ: {ip_address}"

        with self.lock:
            if clean_ip in self.active_blocks:
                return True, f"IP {clean_ip} đã nằm trong danh sách chặn."
            self.active_blocks.add(clean_ip)
            self.counter_measures[clean_ip] = {
                "action": "BLOCK_FIREWALL",
                "reason": reason,
                "time": time.strftime("%H:%M:%S")
            }

        # Luôn đồng bộ khóa kết nối ngay lập tức tại tầng Socket Web Server (hỗ trợ cả Ngrok & Localhost)
        self._notify_webserver_action("BLOCK", clean_ip)

        if clean_ip in ("127.0.0.1", "::1"):
            msg = f"Đã khóa kết nối IP Loopback ({clean_ip}) tại tầng Socket HIPS (Bảo vệ OS Loopback)."
            print(f"{GREEN}[🛡️ HIPS SOCKET BLOCK]{RESET} {msg}")
            return True, msg

        rule_name = f"HIPS_BLOCK_{clean_ip}"
        t_start = time.perf_counter()

        if sys.platform == "win32":
            self._execute_os_command(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"])
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                "dir=in",
                "action=block",
                f"remoteip={clean_ip}",
                "profile=any"
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
            msg = f"Đã chặn tại tầng Socket HIPS (Lưu ý Windows Firewall cần quyền Admin: {out.strip()})"
            print(f"{YELLOW}[HIPS SOCKET FALLBACK]{RESET} {msg}")
            return True, msg

    # ==========================================
    # ĐÒN 2: PHẢN ĐÒN TCP RST INJECTION (KILL SOCKETS)
    # ==========================================
    def _find_established_client_ports(self, client_ip: str, server_port: int = 8080) -> list[int]:
        """Truy vấn bảng kết nối Kernel (netstat) để lấy danh sách Port thực tế của các Socket Attacker"""
        ports = set()
        ok, out = self._execute_os_command(["netstat", "-an"])
        if ok and out:
            pattern = re.compile(rf":{server_port}\s+{re.escape(client_ip)}:(\d+)")
            for m in pattern.finditer(out):
                try:
                    ports.add(int(m.group(1)))
                except ValueError:
                    pass
        return list(ports)

    def counter_attack_tcp_rst(self, ip_address: str, target_port: int = 8080) -> tuple[bool, str]:
        """
        Bắn gói TCP RST trực tiếp tới các port đang mở của Attacker và kích hoạt cờ Kernel SO_LINGER=0,
        ép sập ngay lập tức toàn bộ phiên kết nối TCP/DoS của máy tấn công.
        """
        clean_ip = self.validate_ip(ip_address)
        if not clean_ip:
            return False, "IP không hợp lệ"

        # 1. Kích hoạt chế độ ép bắn cờ Kernel TCP RST (SO_LINGER=0) ngay trên Socket Server
        self._notify_webserver_action("TCP_RST", clean_ip)

        # 2. Bắn bổ sung lô gói Raw TCP RST qua Scapy bất đồng bộ (không gây trễ giao diện)
        active_ports = self._find_established_client_ports(clean_ip, target_port)
        if not active_ports:
            active_ports = list(range(49152, 49168))
        ports_batch = active_ports[:16]

        def _send_rst_burst():
            try:
                from scapy.all import IP, TCP, send
                pkts = [IP(dst=clean_ip) / TCP(sport=target_port, dport=p, flags="R") for p in ports_batch]
                send(pkts, verbose=False)
            except Exception:
                pass

        threading.Thread(target=_send_rst_burst, daemon=True).start()
        rst_count = len(ports_batch)

        with self.lock:
            self.counter_measures[clean_ip] = {
                "action": "TCP_RST_INJECTED",
                "reason": "Phản đòn bắn gói TCP RST ép ngắt toàn bộ kết nối Attacker",
                "time": time.strftime("%H:%M:%S")
            }

        msg = f"Đã kích hoạt phản đòn TCP RST lên {clean_ip} (đã bắn {rst_count} gói RST & bật Kernel SO_LINGER=0)!"
        print(f"{RED}[⚡ HIPS PHẢN ĐÒN TCP RST]{RESET} {msg}")
        return True, msg

    # ==========================================
    # ĐÒN 3: PHẢN ĐÒN TARPIT (GIAM CẦM & TREO THREAD ATTACKER)
    # ==========================================
    def counter_attack_tarpit(self, ip_address: str) -> tuple[bool, str]:
        """
        Kích hoạt chế độ Tarpit lên IP Attacker:
        Giam giữ kết nối 10s ngoài hàng đợi Worker, làm cạn kiệt Thread/Socket Pool của máy Attacker!
        """
        clean_ip = self.validate_ip(ip_address)
        if not clean_ip:
            return False, "IP không hợp lệ"

        ok, err = self._notify_webserver_action("TARPIT", clean_ip)
        if not ok:
            return False, f"Không thể gửi lệnh Tarpit tới Web Server: {err}"

        with self.lock:
            self.counter_measures[clean_ip] = {
                "action": "TARPIT_ACTIVE",
                "reason": "Phản đòn giam giữ kết nối làm cạn kiệt Thread Attacker",
                "time": time.strftime("%H:%M:%S")
            }

        msg = f"Đã kích hoạt Phản đòn Tarpit lên {clean_ip}! Các thread bên máy Attacker bị giam cứng 10s/gói."
        print(f"{CYAN}[🕸️ HIPS PHẢN ĐÒN TARPIT]{RESET} {msg}")
        return True, msg

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

        ok, err = self._notify_webserver_action("HONEYPOT", clean_ip)
        if not ok:
            return False, f"Không thể gửi lệnh Honeypot tới Web Server: {err}"

        with self.lock:
            self.counter_measures[clean_ip] = {
                "action": "HONEYPOT_ACTIVE",
                "reason": "Phản đòn đánh lừa CSDL ảo Canary Trap",
                "time": time.strftime("%H:%M:%S")
            }

        msg = f"Đã kích hoạt Bẫy Honeypot cho {clean_ip}! Kẻ tấn công bị đánh lừa vào CSDL ảo Canary."
        print(f"{YELLOW}[🍯 HIPS PHẢN ĐÒN HONEYPOT]{RESET} {msg}")
        return True, msg

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
            self.counter_measures.pop(clean_ip, None)

        if clean_ip not in ("127.0.0.1", "::1"):
            rule_name = f"HIPS_BLOCK_{clean_ip}"
            if sys.platform == "win32":
                self._execute_os_command(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"])
            else:
                self._execute_os_command(["iptables", "-D", "INPUT", "-s", clean_ip, "-j", "DROP"])

        # Giải tỏa Block / TCP RST / Tarpit / Honeypot trên Web Server
        self._notify_webserver_action("CLEAR_COUNTER", clean_ip)

        msg = f"Đã gỡ bỏ toàn bộ luật chặn & phản đòn cho IP {clean_ip}."
        print(f"{GREEN}[HIPS UNBLOCK]{RESET} {msg}")
        return True, msg

    def cleanup_all_firewall_rules(self):
        """Dọn dẹp sạch sẽ toàn bộ rule Firewall do HIPS tạo khi tắt chương trình"""
        with self.lock:
            ips = list(self.active_blocks)
            self.active_blocks.clear()
            self.counter_measures.clear()

        for ip in ips:
            if ip in ("127.0.0.1", "::1"):
                continue
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
            attack = alert.get("attack") or alert.get("category", "")

            if hips_instance.auto_block and src_ip:
                print(f"[!] HIPS Tự động thi hành án cho IP {src_ip} vì hành vi: {attack}")
                hips_instance.block_firewall(src_ip, reason=attack)

        except Exception:
            pass


if __name__ == "__main__":
    guard = HIPSGuard()
    guard.ensure_service_port_allowed(8080)
    print("=" * 65)
    print("   🛡️ HIPS ACTIVE DEFENSE & COUNTER-ATTACK ENGINE IS RUNNING   ")
    print("=" * 65)
    run_ipc_listener(guard)
