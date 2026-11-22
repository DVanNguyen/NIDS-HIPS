"""
run_defense.py - Giao Diện Phòng Thủ Độc Lập (NIDS + HIPS)
TỰ ĐỘNG BẬT SẴN 100% KHI CHẠY (ZERO-CONFIG):
- Tự động tìm Card mạng thật (Wi-Fi / LAN / Radmin).
- Tự động kích hoạt NIDS (Bắt gói Scapy đa tầng).
- Tự động kích hoạt HIPS (Windows Defender Firewall Controller).
- Có công tắc BẬT / TẮT HIPS để demo đối chứng (Trước & Sau khi phòng vệ).
"""
import sys
import os
import time
import socket
import threading
import subprocess
import webbrowser
import urllib.request
from pathlib import Path
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

# Thiết lập UTF-8
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from part2_defense.nids_engine import NIDSEngine, auto_detect_active_interface
from part2_defense.hips_guard import HIPSGuard


class DefenseApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ HỆ THỐNG PHÒNG THỦ MẠNG: NIDS + HIPS (WINDOWS FIREWALL)")
        self.root.geometry("1000x680")
        self.root.minsize(880, 580)

        # 1. Tự động nhận diện Card mạng
        self.iface_name, self.local_ip = auto_detect_active_interface()
        if not self.iface_name:
            self.iface_name = "Wi-Fi"
            self.local_ip = "127.0.0.1"

        # 2. Khởi tạo Động cơ HIPS
        self.hips = HIPSGuard(block_duration=60)
        self.hips.is_enabled = True  # Mặc định BẬT

        # 3. Khởi tạo Động cơ NIDS
        self.nids = NIDSEngine(interface=self.iface_name, target_port=8080)

        # 4. Khởi động Web Server nạn nhân ngầm nếu chưa có
        self._ensure_target_web_running()

        self._build_ui()

        # 5. TỰ ĐỘNG KÍCH HOẠT PHÒNG THỦ NGAY KHI MỞ
        self._auto_start_defense()

    def _ensure_target_web_running(self):
        """Đảm bảo Web Server :8080 đã chạy ngầm"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.3)
                in_use = (s.connect_ex(("127.0.0.1", 8080)) == 0)
            if not in_use:
                subprocess.Popen(
                    [sys.executable, str(BASE_DIR / "part3_webserver" / "server.py")],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
        except Exception:
            pass

    def _build_ui(self):
        # Header
        header = tk.Frame(self.root, bg="#0f172a", height=60)
        header.pack(fill=tk.X)

        title = tk.Label(header, text="🛡️ TRUNG TÂM GIÁM SÁT & PHÒNG VỆ CHỦ ĐỘNG (NIDS & HIPS)",
                         font=("Segoe UI", 13, "bold"), fg="#38bdf8", bg="#0f172a")
        title.pack(side=tk.LEFT, padx=15, pady=10)

        ip_badge = tk.Label(header, text=f"Card: {self.iface_name} | IP: {self.local_ip}",
                            font=("Segoe UI", 10, "bold"), fg="#a7f3d0", bg="#064e3b", padx=10, pady=4)
        ip_badge.pack(side=tk.RIGHT, padx=15, pady=10)

        container = tk.Frame(self.root, padx=15, pady=10)
        container.pack(fill=tk.BOTH, expand=True)

        # Khung Điều Khiển Trạng Thái (Thanh công cụ nhanh)
        toolbar = tk.Frame(container, pady=5)
        toolbar.pack(fill=tk.X)

        # CÔNG TẮC BẬT/TẮT HIPS ĐỂ DEMO
        self.btn_toggle_hips = tk.Button(
            toolbar, text="🛡️ TƯỜNG LỬA HIPS: ĐANG BẬT (CHẶN IP THẬT)",
            font=("Segoe UI", 11, "bold"), bg="#15803d", fg="white", activebackground="#166534",
            activeforeground="white", padx=16, pady=8, cursor="hand2", command=self._toggle_hips
        )
        self.btn_toggle_hips.pack(side=tk.LEFT, padx=5)

        # NÚT RESET TRẠNG THÁI SERVER
        btn_reset = tk.Button(
            toolbar, text="🔄 RESET TRẠNG THÁI SERVER", font=("Segoe UI", 10, "bold"),
            bg="#d97706", fg="white", activebackground="#b45309", activeforeground="white",
            padx=12, pady=8, cursor="hand2", command=self._reset_server_state
        )
        btn_reset.pack(side=tk.LEFT, padx=5)

        # NÚT MỞ WEB MỤC TIÊU
        btn_web = tk.Button(
            toolbar, text="🌐 MỞ WEB MỤC TIÊU (:8080)", font=("Segoe UI", 10, "bold"),
            bg="#0284c7", fg="white", activebackground="#0369a1", activeforeground="white",
            padx=12, pady=8, cursor="hand2", command=lambda: webbrowser.open("http://127.0.0.1:8080/")
        )
        btn_web.pack(side=tk.RIGHT, padx=5)

        # Trạng thái tổng quát
        self.lbl_status = tk.Label(
            container, text=f"Trạng thái: 🟢 NIDS & HIPS ĐÃ BẬT SẴN - Đang bảo vệ máy chủ Web http://{self.local_ip}:8080/",
            font=("Segoe UI", 10, "bold"), fg="#16a34a", anchor=tk.W
        )
        self.lbl_status.pack(fill=tk.X, pady=6)

        # Bảng danh sách IP đang bị Tường lửa phong tỏa
        self.block_frame = ttk.LabelFrame(container, text=" Danh Sách IP Bị Windows Firewall Phong Tỏa (Active HIPS Blocks) ", padding=5)
        self.block_frame.pack(fill=tk.X, pady=5)

        self.lbl_blocked_ips = tk.Label(self.block_frame, text="Chưa có IP nào bị phong tỏa. Hệ thống an toàn!",
                                        font=("Segoe UI", 10), fg="#64748b")
        self.lbl_blocked_ips.pack(side=tk.LEFT, padx=10, pady=5)

        self.btn_unblock = tk.Button(self.block_frame, text="🔓 Tha Bổng / Mở Khóa Tất Cả IP", font=("Segoe UI", 9, "bold"),
                                     bg="#e2e8f0", fg="#334155", state=tk.DISABLED, command=self._unblock_all)
        self.btn_unblock.pack(side=tk.RIGHT, padx=10, pady=5)

        # Khung Nhật ký Nhận diện Tấn công Trực tiếp
        log_frame = ttk.LabelFrame(container, text=" Nhật Ký Phát Hiện & Tường Lửa Ngăn Chặn (Live Alert Feed) ", padding=5)
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.log_text = scrolledtext.ScrolledText(log_frame, bg="#0b1329", fg="#e2e8f0",
                                                 insertbackground="white", font=("Consolas", 10), wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True)

        self.log_text.tag_config("CRITICAL", foreground="#f87171", font=("Consolas", 10, "bold"))
        self.log_text.tag_config("HIGH", foreground="#fbbf24", font=("Consolas", 10, "bold"))
        self.log_text.tag_config("SUCCESS", foreground="#34d399", font=("Consolas", 10, "bold"))
        self.log_text.tag_config("INFO", foreground="#38bdf8")

    def _auto_start_defense(self):
        """Tự động kích hoạt phòng thủ ngầm"""
        self.log_text.insert(tk.END, "=" * 75 + "\n", "INFO")
        self.log_text.insert(tk.END, f"[*] HỆ THỐNG PHÒNG THỦ NIDS + HIPS ĐÃ TỰ ĐỘNG BẬT SẴN 100%!\n", "SUCCESS")
        self.log_text.insert(tk.END, f"[*] Card Mạng: {self.iface_name} | Địa Chỉ IP: {self.local_ip}\n", "INFO")
        self.log_text.insert(tk.END, f"[*] Mục tiêu bảo vệ: Cổng Dịch vụ Web http://{self.local_ip}:8080/\n", "INFO")
        self.log_text.insert(tk.END, "=" * 75 + "\n\n", "INFO")
        self.log_text.see(tk.END)

        # Luồng nhận IPC từ NIDS sang HIPS
        def hips_ipc_listener():
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(("127.0.0.1", 9999))
            while True:
                try:
                    data, _ = sock.recvfrom(4096)
                    import json
                    packet = json.loads(data.decode("utf-8"))
                    alert = json.loads(packet.get("payload", "{}"))
                    attacker_ip = alert.get("attacker_ip")
                    category = alert.get("category", "Tấn công")
                    sev = alert.get("severity", "CRITICAL")

                    # Ghi ra giao diện GUI
                    ts = alert.get("timestamp", time.strftime("%H:%M:%S"))
                    self.log_text.insert(tk.END, f"[{ts}] [PHÁT HIỆN] {category} từ {attacker_ip} ➔ Mục tiêu: :8080\n", sev)
                    self.log_text.insert(tk.END, f"       Evidence: {alert.get('evidence')}\n", "INFO")

                    # Gọi HIPS xử lý chặn
                    if self.hips.is_enabled:
                        self.hips.block_ip_at_os_level(attacker_ip, reason=category)
                        self.log_text.insert(tk.END, f"  [HIPS FIREWALL] ĐÃ THÊM LUẬT DROP IP {attacker_ip} VÀO WINDOWS DEFENDER FIREWALL!\n\n", "SUCCESS")
                    else:
                        self.log_text.insert(tk.END, f"  [HIPS ĐÃ TẮT] Bỏ qua, không chặn IP {attacker_ip} (Server trần chịu tải)!\n\n", "HIGH")
                    self.log_text.see(tk.END)
                    self._update_blocked_list_ui()
                except Exception:
                    pass

        threading.Thread(target=hips_ipc_listener, daemon=True).start()

        # Luồng chạy Scapy Sniffer của NIDS
        def run_nids_sniffer():
            try:
                self.nids.start()
            except Exception as e:
                self.log_text.insert(tk.END, f"[Lỗi NIDS Sniffer] {e}\n", "CRITICAL")

        threading.Thread(target=run_nids_sniffer, daemon=True).start()

    def _toggle_hips(self):
        """Bật/Tắt HIPS để thực hiện A/B Test"""
        self.hips.is_enabled = not self.hips.is_enabled
        if self.hips.is_enabled:
            self.btn_toggle_hips.config(
                text="🛡️ TƯỜNG LỬA HIPS: ĐANG BẬT (CHẶN IP THẬT)",
                bg="#15803d", activebackground="#166534"
            )
            self.lbl_status.config(
                text=f"Trạng thái: 🟢 HIPS ĐANG BẬT - Tự động gọi Windows Defender Firewall DROP IP tấn công!",
                fg="#16a34a"
            )
            self.log_text.insert(tk.END, "[*] [CHẾ ĐỘ] HIPS TƯỜNG LỬA ĐÃ BẬT: Mọi đòn tấn công sẽ bị khóa IP ngay tức thì!\n\n", "SUCCESS")
        else:
            self.btn_toggle_hips.config(
                text="⚠️ TƯỜNG LỬA HIPS: ĐÃ TẮT (SERVER TRẦN ĐỂ DEMO BỊ TẤN CÔNG)",
                bg="#b91c1c", activebackground="#991b1b"
            )
            self.lbl_status.config(
                text=f"Trạng thái: 🔴 HIPS ĐÃ TẮT - Máy chủ đang ở trạng thái trần, Attacker có thể làm sập web và cướp CSDL!",
                fg="#dc2626"
            )
            self.log_text.insert(tk.END, "[*] [CHẾ ĐỘ] HIPS TƯỜNG LỬA ĐÃ TẮT: Chuẩn bị demo Attacker làm sập web và cướp CSDL!\n\n", "HIGH")
            # Gỡ bỏ các IP đang bị chặn để Attacker tấn công được
            self._unblock_all()
        self.log_text.see(tk.END)

    def _update_blocked_list_ui(self):
        with self.hips.lock:
            blocks = list(self.hips.active_blocks)
        if blocks:
            self.lbl_blocked_ips.config(text=f"🚨 ĐANG PHONG TỎA: {', '.join(blocks)} (Gói tin bị Windows Firewall DROP sạch)", fg="#ef4444")
            self.btn_unblock.config(state=tk.NORMAL)
        else:
            self.lbl_blocked_ips.config(text="Chưa có IP nào bị phong tỏa. Hệ thống an toàn!", fg="#64748b")
            self.btn_unblock.config(state=tk.DISABLED)

    def _unblock_all(self):
        """Gỡ bỏ toàn bộ luật Firewall"""
        self.hips.cleanup_all_firewall_rules()
        self._update_blocked_list_ui()
        self.log_text.insert(tk.END, "[✓] ĐÃ GỠ BỎ TOÀN BỘ LUẬT PHONG TỎA TRÊN WINDOWS FIREWALL!\n\n", "INFO")
        self.log_text.see(tk.END)

    def _reset_server_state(self):
        """Khôi phục trạng thái Web Server"""
        try:
            req = urllib.request.Request("http://127.0.0.1:8080/api/reset", headers={"User-Agent": "DefenseGUI/1.0"})
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                self.log_text.insert(tk.END, "[✓] ĐÃ KHÔI PHỤC TRẠNG THÁI MÁY CHỦ WEB (:8080) VỀ BÌNH THƯỜNG!\n\n", "SUCCESS")
                self.log_text.see(tk.END)
                messagebox.showinfo("Reset Server", "Đã khôi phục trạng thái Web Server thành công!")
        except Exception as e:
            messagebox.showwarning("Reset Server", f"Không thể reset (Máy chủ web có đang chạy không?): {e}")

    def on_closing(self):
        self.hips.cleanup_all_firewall_rules()
        self.root.destroy()


def main():
    root = tk.Tk()
    app = DefenseApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()


if __name__ == "__main__":
    main()
