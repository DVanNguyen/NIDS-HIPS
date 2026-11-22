"""
hips_guard.py - Host Intrusion Prevention System (HIPS Engine)
TIẾN TRÌNH ĐỘC LẬP - VAI TRÒ: "BÀN TAY THỰC THI" NGĂN CHẶN Ở TẦNG KERNEL OS
1. Lắng nghe tín hiệu cảnh báo từ nids_engine.py qua kênh UDP IPC (127.0.0.1:9999).
2. XÁC THỰC KÊNH IPC: Kiểm tra chữ ký HMAC-SHA256 để chống giả mạo tin báo động (Anti-Spoofing).
3. PHÒNG CHỐNG COMMAND INJECTION: Thẩm định IP bằng `ipaddress.ip_address()`, gọi `shell=False`.
4. THI HÀNH ÁN NGĂN CHẶN BẰNG TƯỜNG LỬA HỆ ĐIỀU HÀNH (OS FIREWALL):
   - Windows: Gọi lệnh `netsh advfirewall firewall add rule name="HIPS_BLOCK_<IP>" dir=in action=block remoteip=<IP>`
   - Linux: Gọi lệnh `iptables -A INPUT -s <IP> -j DROP`
5. ĐO ĐẠC ĐỘ TRỄ THỰC THI (Detection-to-Prevention Latency): Tính chính xác thời gian netsh hoàn tất.
6. Tự động đếm ngược 60 giây để gỡ bỏ rule cách ly và dọn dẹp khi tắt tiến trình (Ctrl+C).
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
from pathlib import Path

# Thiết lập encoding UTF-8
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Cổng IPC UDP tiếp nhận cảnh báo từ NIDS
IPC_HOST = "127.0.0.1"
IPC_PORT = 9999

# Khóa bí mật HMAC xác thực kênh IPC nội bộ (Chống giả mạo cảnh báo)
IPC_HMAC_SECRET = b"NIDS_HIPS_SECURE_TOKEN_KEY_2026"

# ANSI Colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


class HIPSGuard:
    def __init__(self, block_duration: int = 60):
        self.block_duration = block_duration
        self.active_blocks = set()
        self.lock = threading.Lock()
        self.is_enabled = True  # Cờ bật/tắt HIPS (Cho phép demo A/B test)
        
        # Đăng ký hàm dọn dẹp khi thoát chương trình
        atexit.register(self.cleanup_all_firewall_rules)

    def _execute_os_command(self, cmd_list):
        """Thực thi lệnh hệ thống an toàn với shell=False chống Command Injection"""
        try:
            res = subprocess.run(cmd_list, shell=False, capture_output=True, text=True, timeout=5.0)
            return res.returncode == 0, res.stdout + res.stderr
        except Exception as e:
            return False, str(e)

    def block_ip_at_os_level(self, ip_address: str, reason: str = ""):
        """Kích hoạt chặn IP ở tầng Hệ điều hành (Kernel Firewall)"""
        if not self.is_enabled:
            print(f"{YELLOW}[HIPS ĐÃ TẮT]{RESET} Bỏ qua chặn IP {ip_address} (Chế độ Server trần để thực nghiệm bị tấn công)!")
            return
        # 1. BẢO MẬT: Thẩm định IP hợp lệ tuyệt đối bằng ipaddress module (Chống Command Injection)
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            if ip_obj.is_loopback:
                print(f"{YELLOW}[HIPS Chú ý]{RESET} IP {ip_address} là Loopback (127.0.0.1). Windows Firewall chỉ lọc được IP LAN thật qua Card mạng!")
                return
            if ip_obj.is_multicast or ip_obj.is_unspecified:
                return
            clean_ip = str(ip_obj)
        except ValueError:
            print(f"{RED}[HIPS Báo Động An Ninh]{RESET} Phát hiện chuỗi IP không hợp lệ! Nghi vấn Command Injection: {ip_address}")
            return

        with self.lock:
            if clean_ip in self.active_blocks:
                return  # Đã bị chặn rồi, không cần add rule trùng lặp
            self.active_blocks.add(clean_ip)

        rule_name = f"HIPS_BLOCK_{clean_ip}"
        print(f"\n{RED}{BOLD}[🛡️ HIPS THI HÀNH ÁN - ACTIVE PREVENTION]{RESET}")
        print(f"  ├─ Đối tượng vi phạm: {YELLOW}{clean_ip}{RESET}")
        print(f"  ├─ Lý do ngăn chặn: {reason}")
        print(f"  ├─ Thao tác hệ thống: {CYAN}Thêm Rule vào Windows Defender Firewall (action=block){RESET}")

        # 2. Đo đạc độ trễ thực thi (OS Firewall Reaction Latency)
        t_start = time.perf_counter()
        success = False
        output = ""

        if sys.platform == "win32":
            # Lệnh chặn thật của Windows Firewall
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                "dir=in",
                "action=block",
                f"remoteip={clean_ip}"
            ]
            success, output = self._execute_os_command(cmd)
        else:
            # Fallback trên Linux / Ubuntu
            cmd = ["iptables", "-A", "INPUT", "-s", clean_ip, "-j", "DROP"]
            success, output = self._execute_os_command(cmd)

        elapsed_ms = round((time.perf_counter() - t_start) * 1000, 1)

        if success:
            print(f"  ├─ {GREEN}TRẠNG THÁI: ĐÃ CHẶN THÀNH CÔNG TẠI KERNEL OS!{RESET}")
            print(f"  ├─ Tên Rule tạo ra: {BOLD}{rule_name}{RESET}")
            print(f"  ├─ {BOLD}Độ trễ thực thi OS Firewall (Reaction Latency):{RESET} {CYAN}{elapsed_ms}ms{RESET}")
            print(f"  └─ Hẹn giờ tự động mở khóa sau: {self.block_duration} giây...")
            
            # Khởi tạo luồng đếm ngược tự động mở khóa
            threading.Thread(target=self._unblock_timer, args=(clean_ip, rule_name), daemon=True).start()
        else:
            print(f"  └─ {RED}Lỗi khi tạo Firewall Rule: {output.strip()}{RESET}")
            print(f"     👉 {YELLOW}Lưu ý: HIPS cần quyền Administrator để thao tác Windows Firewall!{RESET}")

    def _unblock_timer(self, ip_address: str, rule_name: str):
        """Đếm ngược thời gian cách ly rồi tự động xóa rule"""
        time.sleep(self.block_duration)
        self.unblock_ip_at_os_level(ip_address, rule_name)

    def unblock_ip_at_os_level(self, ip_address: str, rule_name: str):
        with self.lock:
            if ip_address in self.active_blocks:
                self.active_blocks.remove(ip_address)

        if sys.platform == "win32":
            cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
            self._execute_os_command(cmd)
        else:
            cmd = ["iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"]
            self._execute_os_command(cmd)

        print(f"\n{GREEN}[🛡️ HIPS THÔNG BÁO]{RESET} Đã hết thời hạn phạt {self.block_duration}s. Đã xóa Rule {rule_name}, mở khóa cho IP {ip_address}.")

    def cleanup_all_firewall_rules(self):
        """Dọn dẹp sạch sẽ toàn bộ rule do HIPS tạo khi tắt chương trình"""
        with self.lock:
            ips = list(self.active_blocks)
        for ip in ips:
            rule_name = f"HIPS_BLOCK_{ip}"
            if sys.platform == "win32":
                self._execute_os_command(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"])
            else:
                self._execute_os_command(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
        print("\n[HIPS Cleanup] Đã dọn dẹp sạch sẽ toàn bộ Firewall Rules trước khi thoát.")

    def start_listening(self):
        """Khởi động Socket UDP nhận tin báo động từ NIDS Engine có kèm xác thực HMAC"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind((IPC_HOST, IPC_PORT))
        except Exception as e:
            print(f"[HIPS Error] Không thể mở cổng IPC {IPC_PORT}: {e}")
            return

        print("=" * 75)
        print("   🛡️ HIPS GUARD ĐANG HOẠT ĐỘNG (HOST INTRUSION PREVENTION SYSTEM)   ")
        print(f"   ├─ Cơ chế chặn: Tương tác trực tiếp Windows Defender Firewall (netsh)")
        print(f"   ├─ Cổng tiếp nhận báo động từ NIDS: UDP {IPC_HOST}:{IPC_PORT}")
        print(f"   ├─ Xác thực kênh IPC: {GREEN}HMAC-SHA256 (Chống giả mạo tin báo động){RESET}")
        print(f"   ├─ Chống Command Injection: {GREEN}ipaddress module + shell=False{RESET}")
        print(f"   ├─ Thời gian cách ly mỗi đợt: {self.block_duration} giây")
        print("   └─ Vai trò: THỰC THI NGĂN CHẶN THẬT Ở TẦNG KERNEL OS (Không phải if-else)")
        print("=" * 75)

        while True:
            try:
                data, addr = sock.recvfrom(4096)
                if not data:
                    continue

                packet = json.loads(data.decode("utf-8"))
                payload_str = packet.get("payload", "")
                received_signature = packet.get("signature", "")

                # 2. XÁC THỰC HMAC CHỐNG GIẢ MẠO TIN BÁO ĐỘNG IPC
                expected_sig = hmac.new(IPC_HMAC_SECRET, payload_str.encode("utf-8"), hashlib.sha256).hexdigest()
                if not hmac.compare_digest(received_signature, expected_sig):
                    print(f"\n{RED}[HIPS CẢNH BÁO AN NINH] Từ chối tin báo động IPC không hợp lệ (Sai chữ ký HMAC)!{RESET}")
                    continue

                alert = json.loads(payload_str)
                attacker_ip = alert.get("attacker_ip")
                category = alert.get("category", "INTRUSION")
                evidence = alert.get("evidence", "")

                if attacker_ip:
                    # Ra quyết định thi hành án
                    self.block_ip_at_os_level(attacker_ip, reason=f"{category} ({evidence})")

            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"[HIPS Warning] Lỗi xử lý tin báo: {e}")

        self.cleanup_all_firewall_rules()


def check_or_request_admin():
    """Kiểm tra quyền Administrator trên Windows, tự động kích hoạt UAC nếu đang ở user thường"""
    if sys.platform == "win32":
        import ctypes
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            is_admin = False
        if not is_admin:
            print("\033[93m[!] HIPS bắt buộc cần quyền Administrator để ra lệnh netsh can thiệp Tường lửa Kernel OS.\033[0m")
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
    parser = argparse.ArgumentParser(description="HIPS Guard (OS-Level Prevention Engine)")
    parser.add_argument("--duration", "-d", type=int, default=60, help="Thời gian cách ly IP vi phạm (giây, mặc định 60)")
    args = parser.parse_args()

    hips = HIPSGuard(block_duration=args.duration)
    try:
        hips.start_listening()
    except KeyboardInterrupt:
        print("\n[HIPS] Đang tắt tiến trình phòng thủ...")
