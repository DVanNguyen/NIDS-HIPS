"""
run_web.py - Khởi Động Máy Chủ Web Dịch Vụ Nạn Nhân (Port 8080)
Chạy độc lập, cung cấp giao diện tương tác ngân hàng để người khác bấm vào được:
- Tra cứu danh bạ khách hàng
- Nạp / Chuyển tiền (Thay đổi số dư trực tiếp trên CSDL)
- Bình luận diễn đàn
- Mô phỏng sập khi bị DoS và lộ dữ liệu khi bị SQLi
"""
import sys
import os
import socket
import webbrowser
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

# Thiết lập UTF-8
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def get_lan_ip():
    """Lấy địa chỉ IP mạng thật của máy"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def main():
    lan_ip = get_lan_ip()
    port = 8080

    print("=" * 75)
    print("   🏦 MÁY CHỦ WEB DỊCH VỤ NGÂN HÀNG (TARGET WEB SERVER - PORT 8080)   ")
    print("=" * 75)
    print(f"  📌 Địa chỉ cho người khác trên mạng bấm vào: \033[92m\033[1mhttp://{lan_ip}:{port}/\033[0m")
    print(f"  📌 Địa chỉ trên máy này:                     \033[96mhttp://127.0.0.1:{port}/\033[0m")
    print("-" * 75)
    print("  ⚠️  ĐẶC ĐIỂM: Ứng dụng này hoàn toàn thuần túy, không có logic bảo mật.")
    print("     Mọi người có thể mở trình duyệt bấm tra cứu, nạp tiền, bình luận.")
    print("     Được bảo vệ từ bên ngoài bằng NIDS + HIPS (run_defense.py).")
    print("=" * 75)
    print("[*] Đang khởi động Flask Web Server trên 0.0.0.0:8080...")

    # Tự động mở trình duyệt sau 1 giây
    import threading
    threading.Timer(1.0, lambda: webbrowser.open(f"http://127.0.0.1:{port}/")).start()

    from part3_webserver.server import app
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
