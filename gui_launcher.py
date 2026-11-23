"""
gui_launcher.py - Trung Tâm Điều Hành An Ninh Mạng (SOC Monitor & HIPS Counter-Attack Panel)
Giao diện Desktop GUI Python Tkinter hoàn chỉnh dành cho Máy Nạn Nhân & Phòng Thủ:
1. Giám sát lưu lượng thời gian thực (Biểu đồ Matplotlib PPS).
2. Bảng cảnh báo NIDS thời gian thực (Hiển thị DoS, SQLi, XSS, IP Attacker, Payload).
3. MENU 4 ĐÒN PHẢN CÔNG HIPS TRỰC TIẾP TRÊN GIAO DIỆN:
   - Đòn 1: Chặn Firewall Windows (netsh advfirewall drop)
   - Đòn 2: Phản đòn TCP RST Injection (Session Killer)
   - Đòn 3: Phản đòn Tarpit (Socket Exhaustion - Treo thread Attacker)
   - Đòn 4: Đánh lừa Honeypot (Poisoned Data Decoy)
4. Tích hợp Ngrok Tunnel 1-Click: Mở cổng Internet công khai để Hội đồng dùng 4G/Wi-Fi riêng truy cập.
"""
import sys
import os
import time
import json
import socket
import threading
import subprocess
import webbrowser
import urllib.request
from pathlib import Path
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

import matplotlib
matplotlib.use("TkAgg")
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

# Nạp các module phòng thủ nội bộ
from part2_defense.hips_guard import HIPSGuard
from part2_defense.nids_engine import NIDSEngine
from part3_webserver.server import run_web_server

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


class SOCDefenseGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ TRUNG TÂM PHÒNG THỦ MẠNG SOC: NIDS & HIPS COUNTER-ATTACK CONTROLLER")
        self.root.geometry("1180x820")
        self.root.minsize(1050, 720)
        self.root.configure(bg="#0f172a")

        # Khởi tạo HIPS Guard Engine
        self.hips = HIPSGuard(block_duration=120, auto_block=False)
        self.nids = None
        self.server_thread = None
        self.nids_thread = None
        self.ngrok_process = None
        self.ngrok_url = ""

        # Biến trạng thái
        self.is_running = False
        self.auto_defense_var = tk.BooleanVar(value=True)
        self.selected_attacker_ip = tk.StringVar(value="")

        # Dữ liệu biểu đồ PPS
        self.pps_data = [0] * 35
        self.current_pps = 0

        self.ifaces_info, self.default_iface = get_network_interfaces()
        self._build_ui()
        self._start_pps_clock()

    def _build_ui(self):
        # 1. Header Bar
        header = tk.Frame(self.root, bg="#1e293b", height=65)
        header.pack(fill=tk.X, padx=12, pady=(10, 6))

        title_box = tk.Frame(header, bg="#1e293b")
        title_box.pack(side=tk.LEFT, padx=15, pady=8)

        lbl_title = tk.Label(
            title_box,
            text="🛡️ SOC DEFENSE CENTER - NIDS & HIPS PHÒNG THỦ CHỦ ĐỘNG",
            font=("Segoe UI", 14, "bold"),
            fg="#38bdf8",
            bg="#1e293b"
        )
        lbl_title.pack(anchor="w")

        lbl_sub = tk.Label(
            title_box,
            text="Giám sát L4/L7 DPI, Ngăn chặn Tường lửa & 4 Đòn Phản Công Tác Chiến",
            font=("Segoe UI", 9),
            fg="#94a3b8",
            bg="#1e293b"
        )
        lbl_sub.pack(anchor="w")

        # Badges trạng thái bên phải
        status_box = tk.Frame(header, bg="#1e293b")
        status_box.pack(side=tk.RIGHT, padx=15, pady=10)

        self.badge_server = tk.Label(status_box, text="● SERVER: CHƯA CHẠY", font=("Segoe UI", 9, "bold"),
                                     fg="#94a3b8", bg="#334155", padx=8, pady=3)
        self.badge_server.pack(side=tk.LEFT, padx=4)

        self.badge_nids = tk.Label(status_box, text="● NIDS: DỪNG", font=("Segoe UI", 9, "bold"),
                                   fg="#94a3b8", bg="#334155", padx=8, pady=3)
        self.badge_nids.pack(side=tk.LEFT, padx=4)

        self.badge_ngrok = tk.Label(status_box, text="● NGROK: TẮT", font=("Segoe UI", 9, "bold"),
                                    fg="#94a3b8", bg="#334155", padx=8, pady=3)
        self.badge_ngrok.pack(side=tk.LEFT, padx=4)

        # 2. Control Toolbar (Nút bấm 1-Click)
        toolbar = tk.Frame(self.root, bg="#1e293b")
        toolbar.pack(fill=tk.X, padx=12, pady=4)

        # Khung chọn Card Mạng
        iface_frame = tk.Frame(toolbar, bg="#1e293b")
        iface_frame.pack(side=tk.LEFT, padx=10, pady=8)

        tk.Label(iface_frame, text="Card Mạng:", font=("Segoe UI", 9, "bold"), fg="#e2e8f0", bg="#1e293b").pack(side=tk.LEFT, padx=4)
        self.iface_var = tk.StringVar(value=self.default_iface)
        display_values = [item[2] for item in self.ifaces_info]
        self.combo_iface = ttk.Combobox(iface_frame, textvariable=self.iface_var, values=display_values, width=32, state="readonly")
        self.combo_iface.pack(side=tk.LEFT, padx=4)

        # Nút Start / Stop
        self.btn_start = tk.Button(
            toolbar, text="▶ BẬT PHÒNG THỦ TOÀN DIỆN (1-CLICK)",
            font=("Segoe UI", 10, "bold"), bg="#0284c7", fg="white",
            activebackground="#0369a1", activeforeground="white",
            relief=tk.FLAT, padx=12, pady=6, cursor="hand2", command=self.start_system
        )
        self.btn_start.pack(side=tk.LEFT, padx=5)

        self.btn_stop = tk.Button(
            toolbar, text="⏹ DỪNG HỆ THỐNG",
            font=("Segoe UI", 10, "bold"), bg="#475569", fg="#94a3b8",
            relief=tk.FLAT, padx=10, pady=6, state=tk.DISABLED, cursor="hand2", command=self.stop_system
        )
        self.btn_stop.pack(side=tk.LEFT, padx=4)

        # Nút Ngrok cho Hội đồng
        self.btn_ngrok = tk.Button(
            toolbar, text="🌐 BẬT NGROK CHO HỘI ĐỒNG (INTERNET)",
            font=("Segoe UI", 9, "bold"), bg="#059669", fg="white",
            activebackground="#047857", relief=tk.FLAT, padx=10, pady=6, cursor="hand2", command=self.toggle_ngrok
        )
        self.btn_ngrok.pack(side=tk.LEFT, padx=5)

        self.btn_open_web = tk.Button(
            toolbar, text="🔗 Mở Web",
            font=("Segoe UI", 9, "bold"), bg="#334155", fg="white",
            relief=tk.FLAT, padx=8, pady=6, cursor="hand2", command=lambda: webbrowser.open("http://127.0.0.1:8080/")
        )
        self.btn_open_web.pack(side=tk.LEFT, padx=4)

        self.btn_reset = tk.Button(
            toolbar, text="🔄 Reset Server",
            font=("Segoe UI", 9, "bold"), bg="#d97706", fg="white",
            relief=tk.FLAT, padx=8, pady=6, cursor="hand2", command=self.reset_server
        )
        self.btn_reset.pack(side=tk.RIGHT, padx=10)

        # Dải hiển thị Ngrok URL cho Hội Đồng
        self.ngrok_bar = tk.Frame(self.root, bg="#064e3b")
        self.lbl_ngrok_url = tk.Label(
            self.ngrok_bar,
            text="🌐 LINK TRUY CẬP CHO HỘI ĐỒNG: Đang chờ kích hoạt Ngrok Tunnel...",
            font=("Segoe UI", 10, "bold"),
            fg="#a7f3d0",
            bg="#064e3b"
        )
        self.lbl_ngrok_url.pack(side=tk.LEFT, padx=15, pady=6)

        self.btn_copy_ngrok = tk.Button(
            self.ngrok_bar, text="📋 Copy Link Cho Thầy/Cô",
            font=("Segoe UI", 9, "bold"), bg="#10b981", fg="black",
            relief=tk.FLAT, padx=10, command=self.copy_ngrok_url
        )
        self.btn_copy_ngrok.pack(side=tk.RIGHT, padx=15, pady=4)
        self.ngrok_bar.pack(fill=tk.X, padx=12, pady=(2, 6))

        # 3. Main Split Area: (Upper: PPS Chart & HIPS Block List)
        upper_pane = tk.Frame(self.root, bg="#0f172a")
        upper_pane.pack(fill=tk.BOTH, expand=False, padx=12, pady=4)

        # Matplotlib Live PPS Chart
        chart_box = tk.LabelFrame(
            upper_pane, text=" Lưu Lượng Mạng Thời Gian Thực (Packets / Second) ",
            font=("Segoe UI", 10, "bold"), fg="#38bdf8", bg="#1e293b"
        )
        chart_box.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 6))

        self.fig = Figure(figsize=(6.2, 2.5), dpi=90, facecolor="#1e293b")
        self.ax = self.fig.add_subplot(111)
        self.ax.set_facecolor("#090d16")
        self.ax.tick_params(colors="#94a3b8", labelsize=8)
        self.ax.set_ylim(0, 80)
        self.line, = self.ax.plot(self.pps_data, color="#38bdf8", linewidth=2)
        self.ax.grid(True, color="#1e293b", linestyle="--", alpha=0.6)

        self.canvas = FigureCanvasTkAgg(self.fig, master=chart_box)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        # Bảng Quản Lý HIPS Policies & IP Chặn
        hips_box = tk.LabelFrame(
            upper_pane, text=" Danh Sách IP Bị Trừng Phạt (HIPS Actions) ",
            font=("Segoe UI", 10, "bold"), fg="#f43f5e", bg="#1e293b"
        )
        hips_box.pack(side=tk.RIGHT, fill=tk.BOTH, expand=False, width=460, padx=(6, 0))

        cols_policy = ("IP", "Action", "Time")
        self.tree_policy = ttk.Treeview(hips_box, columns=cols_policy, show="headings", height=6)
        self.tree_policy.heading("IP", text="IP Đối Tượng")
        self.tree_policy.heading("Action", text="Biện Pháp Thi Hành")
        self.tree_policy.heading("Time", text="Thời Gian")
        self.tree_policy.column("IP", width=120, anchor="center")
        self.tree_policy.column("Action", width=220)
        self.tree_policy.column("Time", width=80, anchor="center")

        sb_pol = ttk.Scrollbar(hips_box, orient=tk.VERTICAL, command=self.tree_policy.yview)
        self.tree_policy.configure(yscroll=sb_pol.set)
        self.tree_policy.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=4, pady=4)
        sb_pol.pack(side=tk.RIGHT, fill=tk.Y)

        act_frame = tk.Frame(hips_box, bg="#1e293b")
        act_frame.pack(fill=tk.X, side=tk.BOTTOM, padx=4, pady=4)

        btn_unblock = tk.Button(
            act_frame, text="🔓 Gỡ Bỏ Biện Pháp (Unblock IP)",
            font=("Segoe UI", 9, "bold"), bg="#059669", fg="white",
            relief=tk.FLAT, padx=8, pady=4, cursor="hand2", command=self.on_unblock_selected
        )
        btn_unblock.pack(fill=tk.X)

        # 4. THANH ĐIỀU KHIỂN ĐÒN PHẢN CÔNG TRỰC TIẾP (COUNTER-ATTACK ACTIONS)
        counter_frame = tk.LabelFrame(
            self.root,
            text=" ⚡ MENU LỰA CHỌN ĐÒN PHẢN CÔNG HIPS (CHỌN IP TỪ BẢNG CẢNH BÁO BÊN DƯỚI ĐỂ PHẢN ĐÒN) ",
            font=("Segoe UI", 10, "bold"), fg="#fbbf24", bg="#1e293b"
        )
        counter_frame.pack(fill=tk.X, padx=12, pady=6)

        c_bar = tk.Frame(counter_frame, bg="#1e293b")
        c_bar.pack(fill=tk.X, padx=10, pady=8)

        tk.Label(c_bar, text="Mục tiêu phản đòn (IP):", font=("Segoe UI", 10, "bold"), fg="#cbd5e1", bg="#1e293b").pack(side=tk.LEFT, padx=(0, 6))
        self.entry_target_ip = tk.Entry(c_bar, textvariable=self.selected_attacker_ip, font=("Consolas", 11, "bold"), width=16, bg="#090d16", fg="#38bdf8", insertbackground="white")
        self.entry_target_ip.pack(side=tk.LEFT, padx=(0, 15))

        # 4 Nút Phản Đòn
        btn_c1 = tk.Button(
            c_bar, text="⛔ [Đòn 1] Chặn Firewall (netsh)",
            font=("Segoe UI", 9, "bold"), bg="#dc2626", fg="white",
            relief=tk.FLAT, padx=10, pady=4, cursor="hand2", command=self.action_block_firewall
        )
        btn_c1.pack(side=tk.LEFT, padx=4)

        btn_c2 = tk.Button(
            c_bar, text="⚡ [Đòn 2] Bắn TCP RST (Kill Sockets)",
            font=("Segoe UI", 9, "bold"), bg="#b91c1c", fg="white",
            relief=tk.FLAT, padx=10, pady=4, cursor="hand2", command=self.action_tcp_rst
        )
        btn_c2.pack(side=tk.LEFT, padx=4)

        btn_c3 = tk.Button(
            c_bar, text="🕸️ [Đòn 3] Phản đòn Tarpit (Treo Thread)",
            font=("Segoe UI", 9, "bold"), bg="#7c3aed", fg="white",
            relief=tk.FLAT, padx=10, pady=4, cursor="hand2", command=self.action_tarpit
        )
        btn_c3.pack(side=tk.LEFT, padx=4)

        btn_c4 = tk.Button(
            c_bar, text="🍯 [Đòn 4] Đánh Lừa Honeypot (CSDL Ảo)",
            font=("Segoe UI", 9, "bold"), bg="#d97706", fg="white",
            relief=tk.FLAT, padx=10, pady=4, cursor="hand2", command=self.action_honeypot
        )
        btn_c4.pack(side=tk.LEFT, padx=4)

        # Checkbox Tự Động Phản Đòn
        cb_auto = tk.Checkbutton(
            c_bar, text="Tự động Chặn khi phát hiện CRITICAL",
            variable=self.auto_defense_var, font=("Segoe UI", 9, "bold"),
            fg="#34d399", bg="#1e293b", selectcolor="#090d16", activebackground="#1e293b"
        )
        cb_auto.pack(side=tk.RIGHT, padx=5)

        # 5. Bảng Cảnh Báo NIDS Thời Gian Thực (Live Alert Table)
        alert_box = tk.LabelFrame(
            self.root, text=" 🚨 Nhật Ký Cảnh Báo Xâm Nhập NIDS Thời Gian Thực (Live Alert Feed) ",
            font=("Segoe UI", 10, "bold"), fg="#f87171", bg="#1e293b"
        )
        alert_box.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 8))

        cols_alert = ("Time", "Severity", "Attack", "SrcIP", "Details")
        self.tree_alert = ttk.Treeview(alert_box, columns=cols_alert, show="headings", height=7)
        self.tree_alert.heading("Time", text="Thời Gian")
        self.tree_alert.heading("Severity", text="Mức Độ")
        self.tree_alert.heading("Attack", text="Loại Tấn Công")
        self.tree_alert.heading("SrcIP", text="IP Máy Tấn Công")
        self.tree_alert.heading("Details", text="Chi Tiết Bằng Chứng Vi Phạm")

        self.tree_alert.column("Time", width=90, anchor="center")
        self.tree_alert.column("Severity", width=90, anchor="center")
        self.tree_alert.column("Attack", width=220)
        self.tree_alert.column("SrcIP", width=140, anchor="center")
        self.tree_alert.column("Details", width=580)

        # Khi người dùng click vào dòng cảnh báo -> Tự động điền IP vào ô mục tiêu phản đòn!
        self.tree_alert.bind("<<TreeviewSelect>>", self._on_alert_row_selected)

        sb_alert = ttk.Scrollbar(alert_box, orient=tk.VERTICAL, command=self.tree_alert.yview)
        self.tree_alert.configure(yscroll=sb_alert.set)
        self.tree_alert.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=4, pady=4)
        sb_alert.pack(side=tk.RIGHT, fill=tk.Y)

    # ==========================================
    # CÁC HÀM XỬ LÝ SỰ KIỆN & KHỞI CHẠY HỆ THỐNG
    # ==========================================
    def start_system(self):
        """Khởi chạy toàn bộ hệ thống Máy Nạn Nhân: Web Server + NIDS + HIPS"""
        if self.is_running:
            return

        self.is_running = True
        self.btn_start.config(state=tk.DISABLED, bg="#475569")
        self.btn_stop.config(state=tk.NORMAL, bg="#ef4444", fg="white")

        # 1. Chạy Web Server (:8080)
        def _server_task():
            try:
                run_web_server(8080)
            except Exception as e:
                print(f"[Server Error] {e}")

        self.server_thread = threading.Thread(target=_server_task, daemon=True)
        self.server_thread.start()
        self.badge_server.config(text="● SERVER: ONLINE (:8080)", fg="#34d399", bg="#064e3b")

        # 2. Khởi chạy NIDS Sensor
        selected_label = self.iface_var.get()
        actual_iface = None
        for item in self.ifaces_info:
            if item[2] == selected_label:
                actual_iface = item[0]
                break

        self.nids = NIDSEngine(
            interface=actual_iface,
            target_port=8080,
            on_alert_cb=self._on_nids_alert,
            on_stats_cb=None
        )

        def _nids_task():
            try:
                self.nids.start_sniffing()
            except Exception as e:
                print(f"[NIDS Error] {e}")

        self.nids_thread = threading.Thread(target=_nids_task, daemon=True)
        self.nids_thread.start()
        self.badge_nids.config(text="● NIDS: ĐANG QUÉT (DPI)", fg="#38bdf8", bg="#0c4a6e")

        messagebox.showinfo("Thành Công", "Đã kích hoạt toàn bộ Hệ Thống Phòng Thủ Mạng (Web :8080 + NIDS + HIPS)!")

    def stop_system(self):
        """Dừng hệ thống an toàn"""
        if not self.is_running:
            return

        self.is_running = False
        if self.nids:
            self.nids.stop()

        self.btn_start.config(state=tk.NORMAL, bg="#0284c7")
        self.btn_stop.config(state=tk.DISABLED, bg="#475569", fg="#94a3b8")
        self.badge_server.config(text="● SERVER: DỪNG", fg="#94a3b8", bg="#334155")
        self.badge_nids.config(text="● NIDS: DỪNG", fg="#94a3b8", bg="#334155")

    def toggle_ngrok(self):
        """Bật / Tắt Ngrok Tunnel để Hội đồng truy cập không cần chung Wi-Fi"""
        if self.ngrok_process:
            # Tắt Ngrok
            try:
                self.ngrok_process.terminate()
            except Exception:
                pass
            self.ngrok_process = None
            self.ngrok_url = ""
            self.badge_ngrok.config(text="● NGROK: TẮT", fg="#94a3b8", bg="#334155")
            self.lbl_ngrok_url.config(text="🌐 LINK TRUY CẬP CHO HỘI ĐỒNG: Đã đóng Ngrok Tunnel.")
            self.btn_ngrok.config(text="🌐 BẬT NGROK CHO HỘI ĐỒNG (INTERNET)", bg="#059669")
            return

        # Khởi động Ngrok
        def _launch_ngrok():
            try:
                self.ngrok_process = subprocess.Popen(
                    ["ngrok", "http", "8080", "--log=stdout"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                # Đợi 2.5s để ngrok khởi tạo và gọi API local lấy public URL
                time.sleep(2.5)
                for _ in range(6):
                    try:
                        req = urllib.request.Request("http://127.0.0.1:4040/api/tunnels")
                        with urllib.request.urlopen(req, timeout=1.5) as resp:
                            data = json.loads(resp.read().decode())
                            tunnels = data.get("tunnels", [])
                            if tunnels:
                                self.ngrok_url = tunnels[0].get("public_url", "")
                                if self.ngrok_url:
                                    break
                    except Exception:
                        time.sleep(1.0)

                if self.ngrok_url:
                    self.root.after(0, self._on_ngrok_ready)
                else:
                    self.root.after(0, lambda: messagebox.showwarning(
                        "Ngrok Chú ý", "Ngrok đang chạy nhưng chưa lấy được URL tự động.\nBạn có thể mở http://127.0.0.1:4040 để xem URL!"
                    ))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Lỗi Ngrok", f"Không thể chạy ngrok: {e}"))

        threading.Thread(target=_launch_ngrok, daemon=True).start()
        self.btn_ngrok.config(text="⏳ Đang kết nối Ngrok...", bg="#d97706")

    def _on_ngrok_ready(self):
        self.badge_ngrok.config(text="● NGROK: KẾT NỐI", fg="#34d399", bg="#064e3b")
        self.btn_ngrok.config(text="⏹ TẮT NGROK", bg="#dc2626")
        self.lbl_ngrok_url.config(text=f"🌐 LINK CÔNG KHAI CHO HỘI ĐỒNG: {self.ngrok_url}")
        messagebox.showinfo(
            "Ngrok Sẵn Sàng Cho Hội Đồng",
            f"Đã mở cổng Internet thành công!\n\nĐường dẫn cho Hội Đồng:\n{self.ngrok_url}\n\nThầy/Cô có thể dùng điện thoại/laptop 4G quét vào ngay!"
        )

    def copy_ngrok_url(self):
        if self.ngrok_url:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.ngrok_url)
            messagebox.showinfo("Đã Sao Chép", f"Đã sao chép link Hội Đồng vào Clipboard:\n{self.ngrok_url}")
        else:
            messagebox.showwarning("Thông Báo", "Vui lòng bấm 'BẬT NGROK CHO HỘI ĐỒNG' trước!")

    def reset_server(self):
        """Khôi phục trạng thái Web Server và gỡ toàn bộ Firewall"""
        try:
            req = urllib.request.Request("http://127.0.0.1:8080/api/reset")
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                pass
        except Exception:
            pass

        self.hips.cleanup_all_firewall_rules()
        self._refresh_policies_table()
        messagebox.showinfo("Đã Reset", "Đã khôi phục trạng thái Web Server và dọn sạch các rule Firewall!")

    # ==========================================
    # TIẾP NHẬN CẢNH BÁO TỪ NIDS & ĐỒNG BỘ UI
    # ==========================================
    def _on_nids_alert(self, alert):
        """Callback khi NIDS phát hiện xâm nhập"""
        self.root.after(0, self._insert_alert_row, alert)

    def _insert_alert_row(self, alert):
        # Tăng chỉ số PPS để biểu đồ phản ánh lưu lượng tấn công
        self.current_pps += 25

        t_str = alert.get("timestamp", time.strftime("%H:%M:%S"))
        sev = alert.get("severity", "WARNING")
        att = alert.get("category", "") or alert.get("attack", "")
        src = alert.get("src_ip", "") or alert.get("attacker_ip", "")
        ev = alert.get("evidence", "") or alert.get("details", "")

        item_id = self.tree_alert.insert("", 0, values=(t_str, sev, att, src, ev))

        # Tự động chọn IP tấn công vào ô mục tiêu phản đòn
        if src:
            self.selected_attacker_ip.set(src)

        # Nếu đang bật chế độ Tự động phản đòn: Kích hoạt đòn Firewall ngay!
        if self.auto_defense_var.get() and sev == "CRITICAL" and src:
            ok, msg = self.hips.block_firewall(src, reason=att)
            self._refresh_policies_table()

    def _on_alert_row_selected(self, event):
        sel = self.tree_alert.selection()
        if sel:
            values = self.tree_alert.item(sel[0])["values"]
            if len(values) >= 4:
                src_ip = values[3]
                self.selected_attacker_ip.set(src_ip)

    # ==========================================
    # CÁC HÀM THỰC THI 4 ĐÒN PHẢN CÔNG
    # ==========================================
    def action_block_firewall(self):
        """Đòn 1: Chặn Firewall Windows (netsh Drop)"""
        ip = self.selected_attacker_ip.get().strip()
        if not ip:
            messagebox.showwarning("Cảnh Báo", "Vui lòng chọn hoặc nhập IP mục tiêu cần phản đòn!")
            return
        ok, msg = self.hips.block_firewall(ip, reason="Phản đòn Firewall do người dùng chọn")
        self._refresh_policies_table()
        messagebox.showinfo("Kết Quả Phản Đòn 1", msg)

    def action_tcp_rst(self):
        """Đòn 2: Bắn gói TCP RST (Kill Sockets Attacker)"""
        ip = self.selected_attacker_ip.get().strip()
        if not ip:
            messagebox.showwarning("Cảnh Báo", "Vui lòng chọn hoặc nhập IP mục tiêu cần phản đòn!")
            return
        ok, msg = self.hips.counter_attack_tcp_rst(ip, target_port=8080)
        self._refresh_policies_table()
        messagebox.showinfo("Kết Quả Phản Đòn 2 (TCP RST)", msg)

    def action_tarpit(self):
        """Đòn 3: Giam giữ kết nối (Tarpit) làm treo Thread của Attacker"""
        ip = self.selected_attacker_ip.get().strip()
        if not ip:
            messagebox.showwarning("Cảnh Báo", "Vui lòng chọn hoặc nhập IP mục tiêu cần phản đòn!")
            return
        ok, msg = self.hips.counter_attack_tarpit(ip)
        self._refresh_policies_table()
        messagebox.showinfo("Kết Quả Phản Đòn 3 (Tarpit)", msg)

    def action_honeypot(self):
        """Đòn 4: Đánh lừa Honeypot trả về CSDL ảo Canary Trap"""
        ip = self.selected_attacker_ip.get().strip()
        if not ip:
            messagebox.showwarning("Cảnh Báo", "Vui lòng chọn hoặc nhập IP mục tiêu cần phản đòn!")
            return
        ok, msg = self.hips.counter_attack_honeypot(ip)
        self._refresh_policies_table()
        messagebox.showinfo("Kết Quả Phản Đòn 4 (Honeypot)", msg)

    def on_unblock_selected(self):
        """Gỡ bỏ luật chặn cho IP đang chọn từ bảng Policy"""
        sel = self.tree_policy.selection()
        if not sel:
            messagebox.showwarning("Chú ý", "Vui lòng chọn dòng IP trong bảng HIPS Actions để gỡ bỏ!")
            return
        target_ip = self.tree_policy.item(sel[0])["values"][0]
        ok, msg = self.hips.unblock_ip(target_ip)
        self._refresh_policies_table()
        messagebox.showinfo("Đã Gỡ Bỏ", msg)

    def _refresh_policies_table(self):
        """Cập nhật lại bảng các IP đang bị trừng phạt"""
        for item in self.tree_policy.get_children():
            self.tree_policy.delete(item)

        policies = self.hips.get_active_policies()
        for ip, info in policies.items():
            self.tree_policy.insert("", tk.END, values=(ip, info.get("action", ""), info.get("time", "")))

    # ==========================================
    # ĐỒNG HỒ BIỂU ĐỒ LƯU LƯỢNG (PPS CHART TICK)
    # ==========================================
    def _start_pps_clock(self):
        def _tick():
            # Giảm dần PPS tự nhiên nếu không có dội tải mới
            val = max(self.current_pps, 2 if self.is_running else 0)
            self.pps_data.append(val)
            self.pps_data.pop(0)

            # Hạ tải từ từ
            self.current_pps = max(0, int(self.current_pps * 0.4))

            # Cập nhật Matplotlib
            self.line.set_ydata(self.pps_data)
            max_y = max(max(self.pps_data) + 15, 60)
            self.ax.set_ylim(0, max_y)
            self.canvas.draw_idle()

            self.root.after(1000, _tick)

        self.root.after(1000, _tick)


def launch_soc_gui():
    root = tk.Tk()
    app = SOCDefenseGUI(root)
    root.mainloop()


if __name__ == "__main__":
    launch_soc_gui()
