"""
run_system.py - Trình Điều Khiển Trung Tâm Hệ Thống NIDS + HIPS
Hỗ trợ mở nhanh từng tiến trình độc lập trong kiến trúc 3 phần:
  python run_system.py --server    -> Chạy Web Server Mục Tiêu (Pure Victim)
  python run_system.py --nids      -> Chạy NIDS Engine (Passive Sniffer bằng Scapy)
  python run_system.py --hips      -> Chạy HIPS Guard (OS Kernel Firewall Controller)
  python run_system.py --attacker  -> Chạy Attacker Client
"""
import sys
import socket
import subprocess
import argparse
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

def get_lan_ip():
    """Lấy địa chỉ IP LAN thật của máy tính"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def run_script(rel_path, extra_args=None):
    full_path = BASE_DIR / rel_path
    cmd = [sys.executable, str(full_path)]
    if extra_args:
        cmd.extend(extra_args)
    subprocess.run(cmd)

def main():
    lan_ip = get_lan_ip()

    parser = argparse.ArgumentParser(description="Launcher cho Hệ thống NIDS + HIPS Độc Lập")
    parser.add_argument("--server", action="store_true", help="Chạy Web Server Nạn Nhân (Port 8080)")
    parser.add_argument("--nids", action="store_true", help="Chạy NIDS Engine (Scapy Sniffer)")
    parser.add_argument("--hips", action="store_true", help="Chạy HIPS Guard (Thao tác Windows Firewall)")
    parser.add_argument("--attacker", action="store_true", help="Chạy Attacker Client Suite")
    parser.add_argument("--ip", type=str, default=lan_ip, help="IP máy mục tiêu")
    parser.add_argument("--port", type=int, default=8080, help="Cổng máy mục tiêu")
    parser.add_argument("--iface", type=str, default=None, help="Tên card mạng cho NIDS")

    args = parser.parse_args()

    if args.server:
        run_script("part3_webserver/server.py")
    elif args.nids:
        extra = []
        if args.iface: extra.extend(["--interface", args.iface])
        if args.port: extra.extend(["--port", str(args.port)])
        run_script("part2_defense/nids_engine.py", extra)
    elif args.hips:
        run_script("part2_defense/hips_guard.py")
    elif args.attacker:
        run_script("part1_attacker/attacker.py", ["--ip", args.ip, "--port", str(args.port)])
    else:
        print("\n" + "=" * 75)
        print("      🛡️ HỆ THỐNG PHÒNG THỦ MẠNG ĐA TẦNG: NIDS (SNIFF) + HIPS (OS FIREWALL) 🛡️      ")
        print("=" * 75)
        print(f"  📌 ĐỊA CHỈ IP LAN CỦA MÁY NÀY LÀ: \033[92m\033[1m{lan_ip}\033[0m")
        print("     (Dùng IP này làm mục tiêu khi cấu hình bên máy Attacker)")
        print("-" * 75)
        print("  [1] Chạy Web Server Mục Tiêu (Nạn nhân thuần túy - Port 8080)")
        print("  [2] Chạy NIDS Engine (Mắt thần: Passive Sniffing trên card mạng bằng Scapy)")
        print("  [3] Chạy HIPS Guard (Bàn tay: Thao tác chặn thật qua Windows Defender Firewall)")
        print("  [4] Chạy Attacker Client (Kẻ tấn công: Bắn DoS, SQLi, XSS theo IP)")
        print("  [0] Thoát")
        print("=" * 75)
        choice = input("\n👉 Bạn muốn khởi chạy thành phần nào (1-4): ").strip()
        if choice == "1":
            run_script("part3_webserver/server.py")
        elif choice == "2":
            run_script("part2_defense/nids_engine.py")
        elif choice == "3":
            run_script("part2_defense/hips_guard.py")
        elif choice == "4":
            target_ip = input(f"👉 Nhập IP của Web Server (Mặc định {lan_ip}): ").strip() or lan_ip
            run_script("part1_attacker/attacker.py", ["--ip", target_ip, "--port", "8080"])
        else:
            print("Đã thoát.")

if __name__ == "__main__":
    main()
