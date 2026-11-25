"""
server.py - Máy Chủ Web Mục Tiêu Dịch Vụ Tài Chính (Target Victim Web Server)
Kiến trúc phục vụ trình diễn và bảo vệ đồ án trước Hội đồng:
1. Dịch vụ Web hoàn chỉnh: Đăng ký tài khoản Hội đồng (/register), Đăng nhập (/login),
   Tra cứu số dư, Sao kê, Chuyển tiền, Khoản vay, và Bảng tin phản hồi (/api/comment).
2. Lỗ hổng DoS: Bị khống chế bởi Worker Semaphore (MAX_WORKER_SLOTS = 6).
   Khi bị dội tải DoS, hàng đợi bị nghẽn làm web SẬP hoàn toàn và trả về lỗi 503 Service Unavailable.
   Tự động phục hồi ngay khi HIPS chặn đứng IP tấn công hoặc ngừng dội tải.
3. Lỗ hổng SQL Injection: Khai thác /api/login hoặc /api/data để trích xuất CSDL khách hàng,
   đặc biệt lấy được ngay tài khoản Hội đồng vừa mới đăng ký trên điện thoại/laptop.
4. Lỗ hổng Stored XSS: Cho phép tiêm mã độc JavaScript vào Bảng tin phản hồi.
   Khi Hội đồng xem bảng tin, script tự động chạy trên trình duyệt của Hội đồng,
   ngầm gửi Cookie phiên làm việc về máy Attacker và bật popup cảnh báo an ninh.
5. Hỗ trợ 4 Đòn Phản Công từ HIPS:
   - Firewall / Socket Block: Cắt đứt hoàn toàn kết nối của IP tấn công.
   - TCP RST Mode: Gửi cờ SO_LINGER RST ép sập tức thì mọi socket của Attacker.
   - Tarpit Mode: Giam cầm kết nối 10s ngoài hàng đợi làm treo toàn bộ thread của Attacker.
   - Honeypot Mode: Trả về CSDL giả mạo Canary Trap để đánh lừa Attacker.
"""
import sys
import time
import random
import socket
import struct
import threading
from flask import Flask, request, jsonify, render_template, make_response, redirect, url_for

# Thiết lập encoding UTF-8
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

app = Flask(__name__, template_folder="templates")
app.secret_key = "VKU_NIDS_HIPS_VICTIM_SESSION_SECRET_2026"

# ==========================================
# CẤU HÌNH TÀI NGUYÊN & MÔ PHỎNG SẬP DoS
# ==========================================
MAX_WORKER_SLOTS = 6
worker_semaphore = threading.Semaphore(MAX_WORKER_SLOTS)
active_workers = 0
overload_until = 0.0
active_workers_lock = threading.Lock()

# Trạng thái giám sát của Máy Chủ
server_metrics = {
    "is_crashed": False,
    "crashed_reason": "",
    "crashed_time": "",
    "total_requests": 0,
    "last_latency_ms": 5.0,
    "db_breached": False,
    "breach_time": "",
    "xss_injected": False,
    "xss_time": "",
    "ngrok_url": "",
    "stolen_cookies": []
}

# Danh sách IP bị áp dụng đòn phản công từ HIPS
BLOCKED_IPS = set()
TCP_RST_IPS = set()
TARPITTED_IPS = set()
HONEYPOT_TRAPPED_IPS = set()
counter_lock = threading.Lock()

# ==========================================
# CƠ SỞ DỮ LIỆU TÀI KHOẢN KHÁCH HÀNG (LIVE DB)
# ==========================================
USERS_DATABASE = [
    {
        "id": 1,
        "username": "admin",
        "password": "Admin@2026Password!",
        "full_name": "Quản Trị Viên Hệ Thống",
        "role": "SuperAdmin",
        "balance": "$2,500,000",
        "created_at": "10:00:00",
        "is_new": False
    },
    {
        "id": 2,
        "username": "cfo_finance",
        "password": "CfoSecureKey#99",
        "full_name": "Trần Giám Đốc Tài Chính",
        "role": "CFO",
        "balance": "$1,450,000",
        "created_at": "10:01:00",
        "is_new": False
    },
    {
        "id": 3,
        "username": "vip_client",
        "password": "VipEnterprise2026",
        "full_name": "Nguyễn Doanh Nghiệp VIP",
        "role": "Doanh Nghiệp VIP",
        "balance": "$890,000",
        "created_at": "10:02:00",
        "is_new": False
    },
    {
        "id": 4,
        "username": "customer_le",
        "password": "Password123@",
        "full_name": "Lê Khách Hàng Thường",
        "role": "Khách Hàng Cá Nhân",
        "balance": "$25,000",
        "created_at": "10:03:00",
        "is_new": False
    }
]
db_lock = threading.Lock()

# Dữ liệu Honeypot (Dùng khi kích hoạt Đòn Phản Công 4)
HONEYPOT_FAKE_DATABASE = [
    {
        "id": 901,
        "username": "honey_trap_root",
        "password": "CANARY_TOKEN_CAUGHT_YOU_RED_HANDED",
        "full_name": "Honeypot Trap Account (HIPS Active Countermeasure)",
        "role": "TrappedAttacker",
        "balance": "$0 (Canary Trap)",
        "created_at": "CANARY",
        "is_new": False
    },
    {
        "id": 902,
        "username": "fake_treasury",
        "password": "FAKE_TOKEN_EXPLOIT_ISOLATED_2026",
        "full_name": "Kho Bạc Giả Lập Mê Cung Dữ Liệu",
        "role": "Decoy",
        "balance": "$999,999,999 (Decoy)",
        "created_at": "CANARY",
        "is_new": False
    }
]

INITIAL_WELCOME_COMMENT = {
    "id": 1,
    "author": "Ban Quản Trị DIGIBANK",
    "content": "Chào mừng quý khách và Hội đồng chấm thi đến với Cổng Dịch Vụ Ngân Hàng Trực Tuyến.",
    "is_malicious": False,
    "time": "10:00:00"
}

# Danh sách bình luận / phản hồi (Mục tiêu của Stored XSS)
stored_comments = [dict(INITIAL_WELCOME_COMMENT)]
comments_lock = threading.Lock()

# ==========================================
# TRANG BÁO LỖI 503 CHUẨN NGUYÊN BẢN (DoS PROOF)
# ==========================================
HTML_503_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>503 Service Unavailable</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            background-color: #ffffff;
            color: #333333;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            text-align: center;
            padding: 20px;
        }
        h1 {
            font-size: 110px;
            font-weight: 800;
            color: #1e293b;
            line-height: 1;
            margin-bottom: 16px;
            letter-spacing: -2px;
        }
        h2 {
            font-size: 28px;
            font-weight: 700;
            color: #475569;
            margin-bottom: 14px;
        }
        p {
            font-size: 16px;
            color: #64748b;
            font-weight: 400;
            max-width: 500px;
            line-height: 1.6;
        }
        .badge {
            margin-top: 24px;
            display: inline-block;
            background-color: #fee2e2;
            color: #991b1b;
            padding: 8px 16px;
            border-radius: 9999px;
            font-size: 13px;
            font-weight: 600;
        }
    </style>
</head>
<body>
    <div>
        <h1>503</h1>
        <h2>Service Unavailable</h2>
        <p>The server is temporarily busy, try again later!</p>
        <div class="badge">🔥 Worker pool exhausted due to high traffic volume</div>
    </div>
</body>
</html>"""


def get_client_ip() -> str:
    """Lấy địa chỉ IP thật của Client (hỗ trợ cả mạng LAN trực tiếp và qua Ngrok Tunnel)"""
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"


def get_logged_in_user():
    """Giải mã cookie phiên để lấy thông tin tài khoản đang đăng nhập (hỗ trợ username có dấu _)"""
    user_cookie = request.cookies.get("session_id", "")
    if user_cookie.startswith("SEC_TOKEN_"):
        raw_tail = user_cookie[len("SEC_TOKEN_"):]
        if "_" in raw_tail:
            uname = raw_tail.rsplit("_", 1)[0]
            with db_lock:
                for u in USERS_DATABASE:
                    if u["username"] == uname:
                        return u
    return None


def mark_server_overloaded():
    """Đánh dấu máy chủ đang bị quá tải DoS trong cửa sổ xung kích 3.0s"""
    global overload_until
    overload_until = time.time() + 3.0
    server_metrics["is_crashed"] = True
    server_metrics["crashed_reason"] = "Hàng đợi bị tràn: Toàn bộ 6 Worker Slots bị tê liệt do DoS!"
    server_metrics["crashed_time"] = time.strftime("%H:%M:%S")
    server_metrics["last_latency_ms"] = 3500.0


def is_server_overloaded() -> bool:
    """Kiểm tra động xem Worker Pool có đang bị ngập tải hay đã hồi phục sau khi HIPS chặn"""
    if active_workers >= MAX_WORKER_SLOTS or time.time() < overload_until:
        server_metrics["is_crashed"] = True
        return True
    server_metrics["is_crashed"] = False
    return False


def _force_tcp_rst_current_socket():
    """Ép nhân Hệ điều hành bắn gói TCP RST (SO_LINGER=0) đóng sập kết nối của Attacker tức thì"""
    sock = request.environ.get("werkzeug.socket")
    if isinstance(sock, socket.socket):
        try:
            linger_fmt = "hh" if sys.platform == "win32" else "ii"
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack(linger_fmt, 1, 0))
            sock.shutdown(socket.SHUT_RDWR)
            sock.close()
        except Exception:
            try:
                sock.close()
            except Exception:
                pass


@app.before_request
def enforce_hips_active_countermeasures():
    """Tầng kiểm soát kết nối chủ động phối hợp với HIPS Guard"""
    is_local_ipc = (
        request.remote_addr in ("127.0.0.1", "::1")
        and not request.headers.get("X-Forwarded-For")
    )

    # Bảo vệ các API quản trị nội bộ chỉ cho phép HIPS / SOC GUI trên máy chủ gọi
    if request.path in ("/api/hips/counter_action", "/api/reset"):
        if not is_local_ipc:
            return jsonify({"status": "error", "message": "Forbidden: Local HIPS only"}), 403
        return None

    if request.path == "/api/metrics" and is_local_ipc:
        return None

    client_ip = get_client_ip()
    with counter_lock:
        is_blocked = client_ip in BLOCKED_IPS
        is_rst = client_ip in TCP_RST_IPS
        is_tarpit = client_ip in TARPITTED_IPS

    # Đòn 1 & Đòn 2: Cắt đứt tức thì Socket bằng TCP RST (bổ trợ thêm cho netsh Firewall)
    if is_blocked or is_rst:
        _force_tcp_rst_current_socket()
        return make_response("", 403)

    # Đòn 3: Tarpit giam giữ kết nối ngoài hàng đợi Worker Semaphore (không tốn slot của Hội đồng!)
    if is_tarpit:
        time.sleep(10.0)
        return jsonify({
            "status": "tarpitted",
            "message": "Connection throttled by HIPS Tarpit Countermeasure"
        }), 200

    return None


@app.errorhandler(503)
def handle_503_error(e):
    return HTML_503_PAGE, 503


# ==========================================
# CÁC ROUTE GIAO DIỆN CHÍNH
# ==========================================
@app.route("/")
def home():
    """Trang chủ cổng dịch vụ ngân hàng trực tuyến của khách hàng"""
    server_metrics["total_requests"] += 1

    if is_server_overloaded():
        return HTML_503_PAGE, 503

    acquired = worker_semaphore.acquire(timeout=0.25)
    if not acquired:
        mark_server_overloaded()
        return HTML_503_PAGE, 503

    try:
        logged_user = get_logged_in_user()
        with db_lock:
            current_users = list(USERS_DATABASE)
        with comments_lock:
            current_comments = list(stored_comments)

        resp = make_response(render_template(
            "index.html",
            customers=current_users,
            comments=current_comments,
            logged_user=logged_user,
            metrics=server_metrics
        ))

        # Cấp cookie phiên khách nếu người dùng chưa đăng nhập (phục vụ kiểm thử XSS Session)
        if not request.cookies.get("session_id") and not request.cookies.get("visitor_token"):
            guest_hex = "%06x" % random.randint(0, 0xFFFFFF)
            resp.set_cookie("visitor_token", f"DIGIBANK_GUEST_{guest_hex}", max_age=86400)

        return resp
    finally:
        worker_semaphore.release()


@app.route("/register", methods=["GET", "POST"])
def register_page():
    """Trang Đăng ký Tài khoản Mới dành cho Hội Đồng Chấm Thi"""
    server_metrics["total_requests"] += 1

    if is_server_overloaded():
        return HTML_503_PAGE, 503

    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip() or "Thành Viên Hội Đồng"
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        role = request.form.get("role", "").strip() or "Hội Đồng Chấm Thi"

        if not username or not password:
            with db_lock:
                users_copy = list(USERS_DATABASE)
            with comments_lock:
                cmts_copy = list(stored_comments)
            return render_template(
                "index.html",
                customers=users_copy,
                comments=cmts_copy,
                reg_error="Vui lòng nhập đầy đủ Tên đăng nhập và Mật khẩu!"
            )

        with db_lock:
            for u in USERS_DATABASE:
                if u["username"].lower() == username.lower():
                    users_copy = list(USERS_DATABASE)
                    with comments_lock:
                        cmts_copy = list(stored_comments)
                    return render_template(
                        "index.html",
                        customers=users_copy,
                        comments=cmts_copy,
                        reg_error=f"Tài khoản '{username}' đã tồn tại! Vui lòng chọn tên khác."
                    )

            new_id = len(USERS_DATABASE) + 1
            now_time = time.strftime("%H:%M:%S")
            new_user = {
                "id": new_id,
                "username": username,
                "password": password,
                "full_name": full_name,
                "role": role,
                "balance": "$500,000",
                "created_at": now_time,
                "is_new": True  # Đánh dấu vừa đăng ký để Attacker GUI highlight
            }
            USERS_DATABASE.append(new_user)

        # Tự động set Cookie đăng nhập cho người dùng
        resp = make_response(redirect(url_for("home")))
        rand_token = "%06x" % random.randint(0, 0xFFFFFF)
        session_id = f"SEC_TOKEN_{username}_{rand_token}"
        resp.set_cookie("session_id", session_id, max_age=86400)
        return resp

    return redirect(url_for("home"))


@app.route("/api/register", methods=["POST"])
def api_register():
    """API Đăng ký tài khoản (hỗ trợ JSON)"""
    server_metrics["total_requests"] += 1
    data = request.get_json(silent=True) or request.form

    full_name = data.get("full_name", "").strip() or "Thành Viên Hội Đồng"
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    role = data.get("role", "").strip() or "Hội Đồng Chấm Thi"

    if not username or not password:
        return jsonify({"status": "error", "message": "Thiếu username hoặc password"}), 400

    with db_lock:
        for u in USERS_DATABASE:
            if u["username"].lower() == username.lower():
                return jsonify({"status": "error", "message": "Tài khoản đã tồn tại"}), 409

        new_user = {
            "id": len(USERS_DATABASE) + 1,
            "username": username,
            "password": password,
            "full_name": full_name,
            "role": role,
            "balance": "$500,000",
            "created_at": time.strftime("%H:%M:%S"),
            "is_new": True
        }
        USERS_DATABASE.append(new_user)

    return jsonify({
        "status": "success",
        "message": f"Tạo tài khoản '{username}' thành công!",
        "user": new_user
    }), 201


@app.route("/login", methods=["GET", "POST"])
def login_page():
    """Đăng nhập giao diện khách hàng"""
    server_metrics["total_requests"] += 1

    if is_server_overloaded():
        return HTML_503_PAGE, 503

    if request.method == "POST":
        u = request.form.get("user", "")
        p = request.form.get("pass", "")

        # Kiểm tra đăng nhập hợp lệ
        with db_lock:
            for acc in USERS_DATABASE:
                if acc["username"] == u and acc["password"] == p:
                    resp = make_response(redirect(url_for("home")))
                    rand_token = "%06x" % random.randint(0, 0xFFFFFF)
                    resp.set_cookie("session_id", f"SEC_TOKEN_{u}_{rand_token}", max_age=86400)
                    return resp

        # Nếu có dấu hiệu SQLi trong form login
        if ("' OR '1'='1" in u) or ("UNION" in u.upper()) or ("'--" in u):
            server_metrics["db_breached"] = True
            server_metrics["breach_time"] = time.strftime("%H:%M:%S")
            resp = make_response(redirect(url_for("home")))
            resp.set_cookie("session_id", "SEC_TOKEN_admin_bypass9921", max_age=86400)
            return resp

        with db_lock:
            users_copy = list(USERS_DATABASE)
        with comments_lock:
            cmts_copy = list(stored_comments)
        return render_template(
            "index.html",
            customers=users_copy,
            comments=cmts_copy,
            login_error="Sai tài khoản hoặc mật khẩu!"
        )

    return redirect(url_for("home"))


@app.route("/logout")
def logout():
    resp = make_response(redirect(url_for("home")))
    resp.delete_cookie("session_id")
    return resp


# ==========================================
# CÁC DỊCH VỤ NGÂN HÀNG (STATEMENT, TRANSFER, LOAN)
# ==========================================
@app.route("/service/statement")
def service_statement():
    """Tra cứu số dư & Sao kê điện tử"""
    server_metrics["total_requests"] += 1

    if is_server_overloaded():
        return HTML_503_PAGE, 503

    acquired = worker_semaphore.acquire(timeout=0.25)
    if not acquired:
        mark_server_overloaded()
        return HTML_503_PAGE, 503

    try:
        time.sleep(0.08)
        cust = get_logged_in_user()
        if not cust:
            with db_lock:
                cust = USERS_DATABASE[0]
        return render_template(
            "service_result.html",
            title="TRA CỨU SỐ DƯ & SAO KÊ TÀI KHOẢN",
            service_name="Truy Vấn Biến Động Số Dư Trực Tuyến",
            customer=cust,
            trans_id="STMT-2026-9921",
            status_code=200
        )
    finally:
        worker_semaphore.release()


@app.route("/service/transfer", methods=["GET", "POST"])
def service_transfer_ui():
    """Chuyển tiền nhanh 24/7"""
    server_metrics["total_requests"] += 1

    if is_server_overloaded():
        return HTML_503_PAGE, 503

    acquired = worker_semaphore.acquire(timeout=0.25)
    if not acquired:
        mark_server_overloaded()
        return HTML_503_PAGE, 503

    try:
        time.sleep(0.08)
        cust = get_logged_in_user()
        if not cust:
            with db_lock:
                cust = USERS_DATABASE[0]
        return render_template(
            "service_result.html",
            title="GIAO DỊCH CHUYỂN TIỀN NHANH 24/7",
            service_name="Chuyển Tiền Liên Ngân Hàng Tức Thời",
            customer=cust,
            trans_id="TRF-2026-8812",
            status_code=200
        )
    finally:
        worker_semaphore.release()


@app.route("/service/loan", methods=["GET", "POST"])
def service_loan_ui():
    """Đăng ký khoản vay online"""
    server_metrics["total_requests"] += 1

    if is_server_overloaded():
        return HTML_503_PAGE, 503

    acquired = worker_semaphore.acquire(timeout=0.25)
    if not acquired:
        mark_server_overloaded()
        return HTML_503_PAGE, 503

    try:
        time.sleep(0.08)
        cust = get_logged_in_user()
        if not cust:
            with db_lock:
                cust = USERS_DATABASE[0]
        return render_template(
            "service_result.html",
            title="HỒ SƠ KHOẢN VAY TRỰC TUYẾN",
            service_name="Đăng Ký Vay Tiêu Dùng Tín Chấp",
            customer=cust,
            trans_id="LOAN-2026-5544",
            status_code=200
        )
    finally:
        worker_semaphore.release()


# ==========================================
# CÁC ENDPOINT LỖ HỔNG (VULNERABILITY APIs)
# ==========================================

# 1. DoS Mục Tiêu (/api/search)
@app.route("/api/search", methods=["GET", "POST"])
def search_service():
    """
    Endpoint xử lý nặng - Mục tiêu tấn công DoS.
    Mỗi request chiếm giữ 1 worker slot trong 2.0s.
    Khi bị dội dập hàng chục request, 6 slots bị chiếm cạn kiệt,
    máy chủ trả về lỗi 503 Service Unavailable làm sập toàn bộ web!
    """
    global active_workers
    server_metrics["total_requests"] += 1
    client_ip = get_client_ip()

    def _is_ip_punished():
        with counter_lock:
            return client_ip in BLOCKED_IPS or client_ip in TCP_RST_IPS or client_ip in TARPITTED_IPS

    start_time = time.time()
    acquired = worker_semaphore.acquire(timeout=0.25)
    if not acquired:
        if _is_ip_punished():
            _force_tcp_rst_current_socket()
            return make_response("", 403)
        mark_server_overloaded()
        return jsonify({"status": "CRASHED", "error": "503 SERVICE UNAVAILABLE! Server pool exhausted!"}), 503

    with active_workers_lock:
        active_workers += 1
        if active_workers >= MAX_WORKER_SLOTS and not _is_ip_punished():
            mark_server_overloaded()

    try:
        # Giả lập truy vấn dữ liệu nặng 2.0s; giải phóng slot ngay sau 0.1s nếu HIPS vừa khóa IP Attacker!
        for _ in range(20):
            if _is_ip_punished():
                _force_tcp_rst_current_socket()
                return make_response("", 403)
            time.sleep(0.1)
        elapsed_ms = round((time.time() - start_time) * 1000, 1)
        server_metrics["last_latency_ms"] = elapsed_ms
        return jsonify({"status": "success", "latency_ms": elapsed_ms}), 200
    finally:
        with active_workers_lock:
            active_workers -= 1
        worker_semaphore.release()


# 2. SQL Injection Khai thác CSDL (/api/login và /api/data)
@app.route("/api/login", methods=["GET", "POST"])
@app.route("/api/data", methods=["GET", "POST"])
def vulnerable_login_and_data():
    """
    Lỗ hổng SQL Injection:
    Khi nhận payload ' OR '1'='1 hoặc UNION SELECT:
    - Nếu IP đang bị HIPS phản đòn Honeypot: Trả về CSDL giả mạo canary.
    - Bình thường: Trích xuất TOÀN BỘ CSDL người dùng, bao gồm tài khoản mới nhất
      mà Hội đồng vừa tạo trên web!
    """
    server_metrics["total_requests"] += 1
    client_ip = get_client_ip()

    user = request.args.get("user") or request.form.get("user") or request.args.get("query") or ""
    user_str = str(user).replace("%20", " ").replace("+", " ")

    is_sqli = (
        ("' OR " in user_str.upper())
        or ("UNION" in user_str.upper() and "SELECT" in user_str.upper())
        or ("OR 1=1" in user_str.upper())
        or ("ADMIN' --" in user_str.upper())
        or ("'" in user_str and "--" in user_str)
    )

    if is_sqli:
        server_metrics["db_breached"] = True
        server_metrics["breach_time"] = time.strftime("%H:%M:%S")

        with counter_lock:
            in_honeypot = client_ip in HONEYPOT_TRAPPED_IPS

        # Kiểm tra phản đòn Honeypot từ HIPS
        if in_honeypot:
            return jsonify({
                "status": "PWNED_HONEYPOT",
                "message": "🍯 [HONEYPOT TRAPPED] Trích xuất thành công dữ liệu CSDL!",
                "leaked_database": HONEYPOT_FAKE_DATABASE,
                "total_records": len(HONEYPOT_FAKE_DATABASE),
                "is_honeypot": True
            }), 200

        # Bình thường: Trả về CSDL thật gồm cả tài khoản Hội đồng vừa đăng ký!
        with db_lock:
            data_to_leak = list(USERS_DATABASE)

        return jsonify({
            "status": "PWNED",
            "message": "🔥 TẤN CÔNG SQLi THÀNH CÔNG! Đã bypass xác thực và trích xuất toàn bộ CSDL khách hàng!",
            "leaked_database": data_to_leak,
            "total_records": len(data_to_leak),
            "is_honeypot": False
        }), 200

    # Đăng nhập bình thường
    pwd = request.args.get("pass") or request.form.get("pass") or ""
    with db_lock:
        for acc in USERS_DATABASE:
            if acc["username"] == user and acc["password"] == pwd:
                return jsonify({"status": "success", "user": acc["username"], "role": acc["role"]}), 200

    return jsonify({"status": "failed", "message": "Sai tài khoản hoặc mật khẩu"}), 401


# 3. Stored XSS & Cướp Cookie (/api/comment, /api/xss/exfiltrate, /api/xss/stolen_cookies)
@app.route("/api/comment", methods=["GET", "POST"])
def vulnerable_comment():
    """
    Lỗ hổng Stored XSS:
    Lưu trực tiếp mã HTML/JavaScript của kẻ tấn công vào danh sách phản hồi.
    Khi người dùng (Hội đồng) vào xem trang web, script tự thực thi:
    1. Ngầm gửi Cookie phiên về /api/xss/exfiltrate.
    2. Bật popup cảnh báo trên trình duyệt Hội đồng.
    """
    server_metrics["total_requests"] += 1
    content = request.args.get("content") or request.form.get("content") or ""
    author = request.args.get("author") or request.form.get("author") or "Ẩn Danh"

    if content:
        lower_c = content.lower()
        is_mal = ("<script" in lower_c) or ("onerror=" in lower_c) or ("onload=" in lower_c) or ("javascript:" in lower_c)
        if is_mal:
            server_metrics["xss_injected"] = True
            server_metrics["xss_time"] = time.strftime("%H:%M:%S")

        with comments_lock:
            new_cmt = {
                "id": len(stored_comments) + 1,
                "author": author,
                "content": content,
                "is_malicious": is_mal,
                "time": time.strftime("%H:%M:%S")
            }
            stored_comments.append(new_cmt)

        # Nếu là người dùng thật gửi form HTML từ trình duyệt -> Chuyển hướng mượt mà về trang chủ
        accept_hdr = request.headers.get("Accept", "")
        if request.method == "POST" and "text/html" in accept_hdr and not is_mal:
            return redirect(url_for("home"))

        return jsonify({
            "status": "PWNED" if is_mal else "success",
            "message": "🔥 ĐÃ LƯU MÃ ĐỘC XSS VÀO BẢNG TIN PHẢN HỒI!" if is_mal else "Đã đăng ý kiến đóng góp",
            "saved_content": content,
            "is_malicious": is_mal
        }), 200

    return jsonify({"status": "error", "message": "Nội dung phản hồi không được để trống"}), 400


@app.route("/api/xss/exfiltrate", methods=["GET", "POST"])
def xss_exfiltrate():
    """
    Điểm tiếp nhận Cookie bị đánh cắp từ trình duyệt nạn nhân (Hội đồng).
    Kịch bản Stored XSS Session Hijacking.
    """
    cookie_stolen = (request.args.get("cookie") or request.form.get("cookie") or "").strip()
    ua = request.args.get("ua") or request.headers.get("User-Agent", "Unknown Browser")
    client_ip = get_client_ip()

    if not cookie_stolen:
        # Fallback đọc trực tiếp từ Cookie Header của request nếu document.cookie rỗng
        raw_hdr_cookie = request.headers.get("Cookie", "").strip()
        cookie_stolen = raw_hdr_cookie or "GUEST_BROWSER_SESSION (Chưa tạo tài khoản)"

    now_str = time.strftime("%H:%M:%S")
    record = {
        "timestamp": now_str,
        "victim_ip": client_ip,
        "user_agent": ua,
        "cookie": cookie_stolen
    }

    # Tránh trùng lặp liên tục cùng 1 phiên khi người dùng F5 nhiều lần
    existing = next(
        (item for item in server_metrics["stolen_cookies"]
         if item["victim_ip"] == client_ip and item["cookie"] == cookie_stolen),
        None
    )
    if existing:
        existing["timestamp"] = now_str
        existing["user_agent"] = ua
    else:
        server_metrics["stolen_cookies"].append(record)

    print(f"[🔥 XSS ALERT] ĐÃ CƯỚP ĐƯỢC COOKIE TỪ IP {client_ip}: {cookie_stolen}")
    return jsonify({"status": "intercepted", "message": "Cookie captured"}), 200


@app.route("/api/xss/stolen_cookies", methods=["GET"])
def get_stolen_cookies():
    """API để máy Attacker kéo danh sách Cookie đã cướp được từ Hội đồng"""
    return jsonify({
        "status": "success",
        "stolen_cookies": server_metrics["stolen_cookies"],
        "total": len(server_metrics["stolen_cookies"])
    })


# ==========================================
# CÁC API ĐIỀU KHIỂN & PHẢN ĐÒN TỪ HIPS
# ==========================================
@app.route("/api/health", methods=["GET"])
def health_check():
    """Kiểm tra độ trễ và tình trạng sẵn sàng của máy chủ"""
    server_metrics["total_requests"] += 1
    if is_server_overloaded():
        return jsonify({
            "status": "SERVER_CRASHED",
            "error": "🔥 503 SERVICE UNAVAILABLE! Toàn bộ Worker Slots đã bị DoS chiếm cạn kiệt!",
            "latency_ms": 3000
        }), 503

    acquired = worker_semaphore.acquire(timeout=0.5)
    if not acquired:
        mark_server_overloaded()
        return jsonify({
            "status": "SERVER_CRASHED",
            "error": "🔥 503 SERVICE UNAVAILABLE! Toàn bộ Worker Slots đã bị DoS chiếm cạn kiệt!",
            "latency_ms": 3000
        }), 503

    try:
        return jsonify({
            "status": "HEALTHY",
            "message": "🟢 Máy chủ phản hồi tức thì!",
            "latency_ms": 5.0,
            "available_slots": max(0, MAX_WORKER_SLOTS - active_workers)
        }), 200
    finally:
        worker_semaphore.release()


@app.route("/api/metrics", methods=["GET"])
def get_metrics():
    """API cung cấp chỉ số thời gian thực cho Dashboard"""
    with db_lock:
        users_copy = list(USERS_DATABASE)
    with comments_lock:
        cmts_copy = list(stored_comments)
    return jsonify({
        "metrics": server_metrics,
        "active_workers": active_workers,
        "max_workers": MAX_WORKER_SLOTS,
        "load_pct": int((active_workers / MAX_WORKER_SLOTS) * 100),
        "customers": users_copy,
        "comments": cmts_copy,
        "blocked_ips": list(BLOCKED_IPS),
        "tcp_rst_ips": list(TCP_RST_IPS),
        "tarpitted_ips": list(TARPITTED_IPS),
        "honeypot_ips": list(HONEYPOT_TRAPPED_IPS)
    })


@app.route("/api/hips/counter_action", methods=["POST"])
def hips_counter_action():
    """Tiếp nhận lệnh phản đòn từ HIPS (Block / TCP RST / Tarpit / Honeypot)"""
    global overload_until
    data = request.get_json(silent=True) or request.form
    action = data.get("action", "")
    ip = data.get("ip", "").strip()

    with counter_lock:
        if action == "BLOCK":
            BLOCKED_IPS.add(ip)
            overload_until = 0.0
            server_metrics["is_crashed"] = False
            return jsonify({"status": "success", "message": f"Đã khóa kết nối IP {ip}"})
        elif action == "TCP_RST":
            TCP_RST_IPS.add(ip)
            overload_until = 0.0
            server_metrics["is_crashed"] = False
            return jsonify({"status": "success", "message": f"Đã kích hoạt TCP RST liên tục lên IP {ip}"})
        elif action == "TARPIT":
            TARPITTED_IPS.add(ip)
            overload_until = 0.0
            server_metrics["is_crashed"] = False
            return jsonify({"status": "success", "message": f"Đã kích hoạt Phản đòn Tarpit lên IP {ip}"})
        elif action == "HONEYPOT":
            HONEYPOT_TRAPPED_IPS.add(ip)
            return jsonify({"status": "success", "message": f"Đã kích hoạt Phản đòn Honeypot bẫy CSDL ảo lên IP {ip}"})
        elif action == "CLEAR_COUNTER":
            BLOCKED_IPS.discard(ip)
            TCP_RST_IPS.discard(ip)
            TARPITTED_IPS.discard(ip)
            HONEYPOT_TRAPPED_IPS.discard(ip)
            return jsonify({"status": "success", "message": f"Đã giải tỏa phản đòn cho IP {ip}"})

    return jsonify({"status": "error", "message": "Hành động không hợp lệ"}), 400


@app.route("/api/reset", methods=["GET", "POST"])
def reset_server():
    """Khôi phục trạng thái an toàn ban đầu (xóa mã độc XSS, gỡ quá tải, xóa bẫy)"""
    global overload_until
    overload_until = 0.0
    server_metrics["is_crashed"] = False
    server_metrics["crashed_reason"] = ""
    server_metrics["crashed_time"] = ""
    server_metrics["last_latency_ms"] = 5.0
    server_metrics["db_breached"] = False
    server_metrics["breach_time"] = ""
    server_metrics["xss_injected"] = False
    server_metrics["xss_time"] = ""
    server_metrics["stolen_cookies"].clear()

    with comments_lock:
        # Loại bỏ các bình luận chứa mã độc XSS đã bị tiêm trước đó
        clean_cmts = [c for c in stored_comments if not c.get("is_malicious")]
        stored_comments.clear()
        stored_comments.extend(clean_cmts if clean_cmts else [dict(INITIAL_WELCOME_COMMENT)])

    with counter_lock:
        BLOCKED_IPS.clear()
        TCP_RST_IPS.clear()
        TARPITTED_IPS.clear()
        HONEYPOT_TRAPPED_IPS.clear()

    return jsonify({"status": "success", "message": "Máy chủ đã được khôi phục an toàn!"})


# ==========================================
# KHỞI CHẠY MÁY CHỦ
# ==========================================
def run_web_server(port=8080):
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True, use_reloader=False)


if __name__ == "__main__":
    print("=" * 70)
    print("   🌐 WEB SERVER NẠN NHÂN (PORT 8080) ĐANG KHỞI CHẠY   ")
    print("   👉 Truy cập trang web nội bộ: http://127.0.0.1:8080/                  ")
    print("=" * 70)
    run_web_server(8080)
