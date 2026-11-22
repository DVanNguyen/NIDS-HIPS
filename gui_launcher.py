"""
gui_launcher.py - Trung Tâm Điều Khiển Phòng Thủ Mạng (NIDS & HIPS Controller)
Giao diện Desktop GUI tối giản, tự động hóa 100%, loại bỏ mọi thao tác dư thừa.
Chỉ 1 click:
1. Tự động chạy Web Server Mục Tiêu (:8080) có CSDL và cơ chế sập DoS.
2. Tự động kích hoạt HIPS Guard (Tường lửa Windows Defender).
3. Tự động kích hoạt NIDS Engine (Bắt gói tin Scapy).
4. Tự động mở trình duyệt xem trực tiếp Web :8080.
"""
import sys
import os
import time
import threading
import subprocess
import webbrowser
import urllib.request
from pathlib import Path
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

# Thiết lập encoding UTF-8
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def get_network_interfaces():
    """Lấy danh sách các card mạng khả dụng kèm địa chỉ IP IPv4"""
    ifaces_info = []
    default_selection = ""
    
    if sys.platform == "win32":
        try:
            from scapy.arch.windows import get_windows_if_list
            raw_list = get_windows_if_list()
            for item in raw_list:
                name = item.get("name", "Unknown")
                ips = [ip for ip in item.get("ips", []) if not ip.startswith("fe80") and not ip.startswith("169.254") and ":" not in ip]
                if any(x in name for x in ["Filter Driver", "Packet Scheduler", "LightWeight"]):
                    continue
                ip_str = ips[0] if ips else "N/A"
                display_label = f"{name} (IP: {ip_str})"
                ifaces_info.append((name, ip_str, display_label))
                if not default_selection and ip_str != "N/A" and not ip_str.startswith("127."):
                    default_selection = display_label
        except Exception:
            pass

    if not ifaces_info:
        ifaces_info = [("Wi-Fi", "127.0.0.1", "Wi-Fi (Default)"), ("Ethernet", "127.0.0.1", "Ethernet (Default)")]
        default_selection = "Wi-Fi (Default)"
        
    return ifaces_info, default_selection


class NIDSDefenseGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ TRUNG TÂM PHÒNG THỦ MẠNG: NIDS & HIPS CONTROLLER")
        self.root.geometry("980x680")
        self.root.minsize(850, 580)
        
        # Danh sách tiến trình đang chạy
        self.server_process = None
        self.hips_process = None
        self.nids_process = None
        self.is_running = False

        self.ifaces_info, self.default_iface = get_network_interfaces()
        self._setup_styles()
        self._build_ui()

    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(".", font=("Segoe UI", 10))
        style.configure("Header.TLabel", font=("Segoe UI", 13, "bold"), foreground="#1a365d")

    def _build_ui(self):
        # 1. Header
        header_frame = tk.Frame(self.root, bg="#0f172a", height=55)
        header_frame.pack(fill=tk.X)
        
        title_lbl = tk.Label(header_frame, text="🛡️ HỆ THỐNG PHÒNG THỦ MẠNG: NIDS + HIPS (OS FIREWALL)",
                             font=("Segoe UI", 13, "bold"), fg="#38bdf8", bg="#0f172a")
        title_lbl.pack(side=tk.LEFT, padx=15, pady=10)
        
        sub_lbl = tk.Label(header_frame, text="Bảo vệ máy chủ Web :8080 trước DoS & SQLi",
                           font=("Segoe UI", 9, "italic"), fg="#94a3b8", bg="#0f172a")
        sub_lbl.pack(side=tk.RIGHT, padx=15, pady=10)

        main_container = tk.Frame(self.root, padx=15, pady=10)
        main_container.pack(fill=tk.BOTH, expand=True)

        # 2. Cấu hình Card Mạng (Gọn gàng 1 dòng)
        cfg_frame = ttk.LabelFrame(main_container, text=" Card Mạng Giám Sát (Network Interface) ", padding=8)
        cfg_frame.pack(fill=tk.X, pady=5)

        tk.Label(cfg_frame, text="Card Mạng:", font=("Segoe UI", 10, "bold")).pack(side=tk.LEFT, padx=5)
        self.iface_var = tk.StringVar(value=self.default_iface)
        display_values = [item[2] for item in self.ifaces_info]
        self.combo_iface = ttk.Combobox(cfg_frame, textvariable=self.iface_var, values=display_values, width=50, state="readonly")
        self.combo_iface.pack(side=tk.LEFT, padx=5)

        btn_refresh = ttk.Button(cfg_frame, text="🔄 Quét lại", command=self._refresh_interfaces)
        btn_refresh.pack(side=tk.LEFT, padx=5)

        # 3. Khung Nút Bấm Điều Khiển Chính
        ctrl_frame = tk.Frame(main_container, pady=8)
        ctrl_frame.pack(fill=tk.X)

        self.btn_start = tk.Button(ctrl_frame, text="▶ BẬT PHÒNG THỦ TOÀN DIỆN (1 CLICK)", font=("Segoe UI", 11, "bold"),
                                   bg="#0284c7", fg="white", activebackground="#0369a1", activeforeground="white",
                                   padx=16, pady=8, cursor="hand2", relief=tk.RAISED, command=self._start_all_defense)
        self.btn_start.pack(side=tk.LEFT, padx=5)

        self.btn_stop = tk.Button(ctrl_frame, text="⏹ DỪNG PHÒNG THỦ", font=("Segoe UI", 11, "bold"),
                                  bg="#cbd5e1", fg="#64748b", state=tk.DISABLED,
                                  padx=14, pady=8, cursor="hand2", command=self._stop_all_defense)
        self.btn_stop.pack(side=tk.LEFT, padx=5)

        self.btn_reset = tk.Button(ctrl_frame, text="🔄 RESET TRẠNG THÁI SERVER", font=("Segoe UI", 10, "bold"),
                                   bg="#f59e0b", fg="white", activebackground="#d97706", activeforeground="white",
                                   padx=12, pady=8, cursor="hand2", command=self._reset_server_state)
        self.btn_reset.pack(side=tk.LEFT, padx=5)

        self.btn_open_web = tk.Button(ctrl_frame, text="🌐 MỞ WEB MỤC TIÊU (:8080)", font=("Segoe UI", 10, "bold"),
                                      bg="#059669", fg="white", activebackground="#047857", activeforeground="white",
                                      padx=12, pady=8, cursor="hand2", command=self._open_web)
        self.btn_open_web.pack(side=tk.RIGHT, padx=5)

        # 4. Trạng thái hoạt động
        self.lbl_status = tk.Label(main_container, text="Trạng thái: ⭕ Chưa hoạt động (Đang dừng)",
                                   font=("Segoe UI", 10, "bold"), fg="#64748b", anchor=tk.W)
        self.lbl_status.pack(fill=tk.X, pady=4)

        # 5. Khung Nhật Ký Cảnh Báo Trực Tiếp
        log_frame = ttk.LabelFrame(main_container, text=" Nhật Ký Phát Hiện & Tường Lửa Ngăn Chặn (Live Alert Feed) ", padding=5)
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.log_text = scrolledtext.ScrolledText(log_frame, bg="#0b1329", fg="#e2e8f0",
                                                 insertbackground="white", font=("Consolas", 10), wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True)

        self.log_text.tag_config("CRITICAL", foreground="#f87171", font=("Consolas", 10, "bold"))
        self.log_text.tag_config("SUCCESS", foreground="#34d399", font=("Consolas", 10, "bold"))
        self.log_text.tag_config("INFO", foreground="#38bdf8")
        self.log_text.tag_config("STATUS", foreground="#94a3b8")

    def _refresh_interfaces(self):
        self.ifaces_info, default = get_network_interfaces()
        vals = [item[2] for item in self.ifaces_info]
        self.combo_iface["values"] = vals
        if vals:
            self.combo_iface.current(0)
        messagebox.showinfo("Quét card mạng", f"Đã tìm thấy {len(vals)} giao diện mạng!")

    def _start_all_defense(self):
        if self.is_running:
            return

        selected_label = self.iface_var.get()
        iface_name = "Wi-Fi"
        for item in self.ifaces_info:
            if item[2] == selected_label:
                iface_name = item[0]
                break

        self.log_text.insert(tk.END, f"\n" + "=" * 70 + "\n", "INFO")
        self.log_text.insert(tk.END, f"[*] KHỞI ĐỘNG HỆ THỐNG PHÒNG THỦ TOÀN DIỆN (Card: {iface_name})\n", "INFO")
        self.log_text.insert(tk.END, f"=" * 70 + "\n", "INFO")
        self.log_text.see(tk.END)

        try:
            # 1. Khởi động Web Server Nạn nhân (:8080)
            self.server_process = subprocess.Popen(
                [sys.executable, str(BASE_DIR / "part3_webserver" / "server.py")],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace"
            )
            self.log_text.insert(tk.END, "[✓] [1/3] Máy Chủ Web Mục Tiêu (:8080) ĐÃ KHỞI CHẠY!\n", "SUCCESS")

            # 2. Khởi động HIPS Guard (Windows Firewall Controller)
            self.hips_process = subprocess.Popen(
                [sys.executable, str(BASE_DIR / "part2_defense" / "hips_guard.py")],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace"
            )
            self.log_text.insert(tk.END, "[✓] [2/3] Bàn Tay HIPS (Windows Firewall Controller) ĐÃ SẴN SÀNG!\n", "SUCCESS")

            # 3. Khởi động NIDS Engine (Scapy Sniffer)
            self.nids_process = subprocess.Popen(
                [sys.executable, str(BASE_DIR / "part2_defense" / "nids_engine.py"), "--interface", iface_name],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace"
            )
            self.log_text.insert(tk.END, f"[✓] [3/3] Mắt Thần NIDS (Scapy Sniffer) ĐANG GIÁM SÁT TRÊN '{iface_name}'!\n", "SUCCESS")
            self.log_text.insert(tk.END, "\n👉 HỆ THỐNG ĐÃ KÍCH HOẠT ĐẦY ĐỦ. Hãy bảo máy Attacker phát động tấn công!\n\n", "INFO")
            self.log_text.see(tk.END)

            self.is_running = True
            self.btn_start.config(state=tk.DISABLED, bg="#cbd5e1", fg="#64748b")
            self.btn_stop.config(state=tk.NORMAL, bg="#dc2626", fg="white")
            self.lbl_status.config(text=f"Trạng thái: 🟢 ĐANG BẢO VỆ CHỦ ĐỘNG TRÊN '{iface_name}' (Web Server: http://127.0.0.1:8080/)", fg="#16a34a")

            # Đọc log từ NIDS và HIPS
            threading.Thread(target=self._read_process_output, args=(self.nids_process, "NIDS"), daemon=True).start()
            threading.Thread(target=self._read_process_output, args=(self.hips_process, "HIPS"), daemon=True).start()

            # Tự động mở trình duyệt sau 1s
            self.root.after(1000, lambda: webbrowser.open("http://127.0.0.1:8080/"))

        except Exception as e:
            messagebox.showerror("Lỗi khởi động", f"Không thể bật hệ thống: {e}")

    def _read_process_output(self, proc, prefix):
        while self.is_running and proc:
            line = proc.stdout.readline()
            if not line:
                break
            tag = "INFO"
            if "CRITICAL" in line or "PHÁT HIỆN" in line or "ĐÃ PHONG TỎA" in line:
                tag = "CRITICAL"
            elif "THÀNH CÔNG" in line or "[✓]" in line:
                tag = "SUCCESS"
            self.log_text.insert(tk.END, f"[{prefix}] {line}", tag)
            self.log_text.see(tk.END)

    def _stop_all_defense(self):
        if not self.is_running:
            return

        self.log_text.insert(tk.END, "\n[*] Đang dừng toàn bộ các tiến trình phòng thủ và dọn dẹp Tường lửa...\n", "INFO")
        self.is_running = False

        for proc in [self.nids_process, self.hips_process, self.server_process]:
            if proc:
                try:
                    proc.terminate()
                except Exception:
                    pass

        self.btn_start.config(state=tk.NORMAL, bg="#0284c7", fg="white")
        self.btn_stop.config(state=tk.DISABLED, bg="#cbd5e1", fg="#64748b")
        self.lbl_status.config(text="Trạng thái: ⭕ Đã dừng toàn bộ hệ thống", fg="#64748b")
        self.log_text.insert(tk.END, "[✓] Đã dừng toàn bộ tiến trình an toàn.\n\n", "SUCCESS")
        self.log_text.see(tk.END)

    def _reset_server_state(self):
        try:
            req = urllib.request.Request("http://127.0.0.1:8080/api/reset", headers={"User-Agent": "GUIReset/1.0"})
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                self.log_text.insert(tk.END, "[✓] ĐÃ KHÔI PHỤC TRẠNG THÁI MÁY CHỦ WEB (:8080) THÀNH CÔNG!\n", "SUCCESS")
                self.log_text.see(tk.END)
                messagebox.showinfo("Reset Server", "Đã khôi phục trạng thái Web Server thành công!")
        except Exception as e:
            messagebox.showwarning("Reset Server", f"Không thể reset (Máy chủ web có đang chạy không?): {e}")

    def _open_web(self):
        webbrowser.open("http://127.0.0.1:8080/")


def main():
    root = tk.Tk()
    app = NIDSDefenseGUI(root)
    root.protocol("WM_DELETE_WINDOW", lambda: (app._stop_all_defense(), root.destroy()))
    root.mainloop()


if __name__ == "__main__":
    main()
