"""
server.py - Máy Chủ Web Mục Tiêu "Nạn Nhân Thuần Túy" (Pure Victim Web Server)
KIẾN TRÚC ĐỘC LẬP:
- HOÀN TOÀN KHÔNG CHỨA LOGIC BẢO MẬT (Không có NIDS, không có HIPS, không có middleware lọc payload).
- Có tài nguyên giới hạn (Worker Slots = 6). Khi bị DoS dội vào, các luồng bị kẹt cứng làm máy chủ SẬP (503 Service Unavailable / Timed Out).
- Chứa lỗ hổng SQLi (trích xuất CSDL khách hàng) và XSS (lưu mã độc vào diễn đàn).
"""
import time
import threading
from pathlib import Path
from flask import Flask, request, jsonify, render_template

app = Flask(__name__, template_folder="templates")

# Giới hạn số luồng xử lý đồng thời để mô phỏng sập máy chủ do DoS
MAX_WORKER_SLOTS = 6
worker_semaphore = threading.Semaphore(MAX_WORKER_SLOTS)
active_workers = 0
active_workers_lock = threading.Lock()

# Trạng thái máy chủ
server_metrics = {
    "is_crashed": False,
    "crashed_reason": "",
    "crashed_time": "",
    "total_requests": 0,
    "last_latency_ms": 5.0,
    "db_breached": False,
    "breach_time": "",
    "xss_injected": False,
    "xss_time": ""
}

# CSDL khách hàng nhạy cảm (Mục tiêu của SQL Injection)
MOCK_CUSTOMERS = [
    {"id": 1, "username": "admin", "full_name": "Quản Trị Viên Hệ Thống", "role": "SuperAdmin", "balance": "$2,500,000", "secret_hash": "$2b$12$e8xAdminPass2026"},
    {"id": 2, "username": "cfo_finance", "full_name": "Trần Giám Đốc Tài Chính", "role": "CFO", "balance": "$1,450,000", "secret_hash": "$2b$12$f9yCfoKey99"},
    {"id": 3, "username": "vip_client", "full_name": "Nguyễn Doanh Nghiệp VIP", "role": "VIP", "balance": "$890,000", "secret_hash": "$2b$12$a1bClientPass"},
    {"id": 4, "username": "customer_02", "full_name": "Lê Khách Hàng Thường", "role": "User", "balance": "$25,000", "secret_hash": "$2b$12$p0qNormal123"}
]

# Danh sách bình luận diễn đàn (Mục tiêu của XSS)
stored_comments = [
    {"author": "Hệ Thống", "content": "Cổng thông tin ngân hàng số chào đón quý khách.", "is_malicious": False, "time": "10:00:00"}
]


# Trang báo lỗi 503 chuẩn nguyên bản theo hình mẫu thực tế
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
        }
        h1 {
            font-size: 105px;
            font-weight: 800;
            color: #333333;
            line-height: 1;
            margin-bottom: 16px;
            letter-spacing: -2px;
        }
        h2 {
            font-size: 28px;
            font-weight: 700;
            color: #444444;
            margin-bottom: 14px;
        }
        p {
            font-size: 15px;
            color: #777777;
            font-weight: 400;
        }
    </style>
</head>
<body>
    <div>
        <h1>503</h1>
        <h2>Service Unavailable</h2>
        <p>The server is temporarily busy, try again later!</p>
    </div>
</body>
</html>"""


@app.errorhandler(503)
def handle_503_error(e):
    """Bắt mọi mã lỗi 503 để hiển thị màn hình trắng chuẩn nguyên bản"""
    return HTML_503_PAGE, 503


@app.route("/")
def home():
    """Trang chủ cổng dịch vụ ngân hàng trực tuyến của khách hàng"""
    server_metrics["total_requests"] += 1

    # Nếu máy chủ đang bị sập do DoS -> Trả về lỗi 503 ngay lập tức
    if server_metrics["is_crashed"]:
        return HTML_503_PAGE, 503

    # Thử lấy worker slot để phục vụ yêu cầu truy cập trang chủ
    acquired = worker_semaphore.acquire(timeout=0.3)
    if not acquired:
        server_metrics["is_crashed"] = True
        return HTML_503_PAGE, 503

    try:
        return render_template(
            "index.html",
            customers=MOCK_CUSTOMERS,
            comments=stored_comments
        )
    finally:
        worker_semaphore.release()


@app.route("/service/statement")
def service_statement():
    """Khách hàng nhấn chọn dịch vụ: Tra cứu số dư & Sao kê điện tử"""
    server_metrics["total_requests"] += 1

    if server_metrics["is_crashed"]:
        return HTML_503_PAGE, 503

    acquired = worker_semaphore.acquire(timeout=0.3)
    if not acquired:
        server_metrics["is_crashed"] = True
        return HTML_503_PAGE, 503

    try:
        time.sleep(0.1)
        return render_template(
            "service_result.html",
            title="TRA CỨU SỐ DƯ & SAO KÊ TÀI KHOẢN",
            service_name="Truy Vấn Biến Động Số Dư Trực Tuyến",
            customer=MOCK_CUSTOMERS[0],
            trans_id="STMT-2026-9921",
            status_code=200
        )
    finally:
        worker_semaphore.release()


@app.route("/service/transfer", methods=["GET", "POST"])
def service_transfer_ui():
    """Khách hàng nhấn chọn dịch vụ: Chuyển tiền nhanh 24/7"""
    server_metrics["total_requests"] += 1

    if server_metrics["is_crashed"]:
        return HTML_503_PAGE, 503

    acquired = worker_semaphore.acquire(timeout=0.3)
    if not acquired:
        server_metrics["is_crashed"] = True
        return HTML_503_PAGE, 503

    try:
        time.sleep(0.1)
        return render_template(
            "service_result.html",
            title="GIAO DỊCH CHUYỂN TIỀN NHANH 24/7",
            service_name="Chuyển Tiền Liên Ngân Hàng Tức Thời",
            customer=MOCK_CUSTOMERS[0],
            trans_id="TRF-2026-8812",
            status_code=200
        )
    finally:
        worker_semaphore.release()


@app.route("/service/loan", methods=["GET", "POST"])
def service_loan_ui():
    """Khách hàng nhấn chọn dịch vụ: Đăng ký khoản vay online"""
    server_metrics["total_requests"] += 1

    if server_metrics["is_crashed"]:
        return HTML_503_PAGE, 503

    acquired = worker_semaphore.acquire(timeout=0.3)
    if not acquired:
        server_metrics["is_crashed"] = True
        return HTML_503_PAGE, 503

    try:
        time.sleep(0.1)
        return render_template(
            "service_result.html",
            title="HỒ SƠ KHOẢN VAY TRỰC TUYẾN",
            service_name="Đăng Ký Vay Tiêu Dùng Tín Chấp",
            customer=MOCK_CUSTOMERS[0],
            trans_id="LOAN-2026-5544",
            status_code=200
        )
    finally:
        worker_semaphore.release()


@app.route("/dashboard")
def dashboard_view():
    """Bảng điều khiển kỹ thuật dành riêng cho việc đo đạc và kiểm thử"""
    return render_template(
        "dashboard.html",
        metrics=server_metrics,
        active_workers=active_workers,
        max_workers=MAX_WORKER_SLOTS,
        customers=MOCK_CUSTOMERS,
        comments=stored_comments
    )


@app.route("/api/health", methods=["GET"])
def health_check():
    """Kiểm tra độ trễ và khả năng phản hồi của máy chủ"""
    server_metrics["total_requests"] += 1
    # Nếu không còn worker slot nào trong vòng 2.0s -> Bị DoS đánh sập!
    acquired = worker_semaphore.acquire(timeout=2.0)
    if not acquired:
        server_metrics["is_crashed"] = True
        return jsonify({
            "status": "SERVER_CRASHED",
            "error": "🔥 503 SERVICE UNAVAILABLE! Toàn bộ Worker Slots đã bị DoS chiếm cạn kiệt!",
            "latency_ms": 3000
        }), 503

    try:
        server_metrics["is_crashed"] = False
        return jsonify({
            "status": "HEALTHY",
            "message": "🟢 Máy chủ phản hồi tức thì!",
            "latency_ms": 5.0,
            "available_slots": MAX_WORKER_SLOTS - active_workers
        }), 200
    finally:
        worker_semaphore.release()


@app.route("/api/search", methods=["GET", "POST"])
def search_service():
    """
    Endpoint xử lý nặng - Mục tiêu tấn công DoS.
    Không có HIPS bảo vệ: Mỗi request chiếm giữ 1 worker slot trong 2.0s.
    Khi bị dội dập hàng chục request, máy chủ lập tức nghẽn cứng và sập!
    """
    global active_workers
    server_metrics["total_requests"] += 1
    start_time = time.time()

    acquired = worker_semaphore.acquire(timeout=0.3)
    if not acquired:
        server_metrics["is_crashed"] = True
        server_metrics["crashed_reason"] = "Hàng đợi bị tràn: Toàn bộ 6 Worker Slots bị tê liệt do DoS!"
        server_metrics["crashed_time"] = time.strftime("%H:%M:%S")
        server_metrics["last_latency_ms"] = 3500.0
        return jsonify({"status": "CRASHED", "error": "503 SERVICE UNAVAILABLE! Server pool exhausted!"}), 503

    with active_workers_lock:
        active_workers += 1

    try:
        # Giả lập truy vấn dữ liệu nặng, giữ slot trong 2.0s để quan sát rõ rệt
        time.sleep(2.0)
        elapsed_ms = round((time.time() - start_time) * 1000, 1)
        server_metrics["last_latency_ms"] = elapsed_ms
        return jsonify({"status": "success", "latency_ms": elapsed_ms}), 200
    finally:
        with active_workers_lock:
            active_workers -= 1
        worker_semaphore.release()


@app.route("/api/login", methods=["GET", "POST"])
def vulnerable_login():
    """
    Lỗ hổng SQL Injection thuần túy:
    Không có bất kỳ kiểm tra hay lọc chuỗi nào.
    Kẻ tấn công truyền ' OR '1'='1 -> Xuất trọn toàn bộ cơ sở dữ liệu khách hàng!
    """
    server_metrics["total_requests"] += 1
    user = request.args.get("user") or request.form.get("user") or ""

    if ("' OR '1'='1" in user) or ("UNION" in user.upper()) or ("' OR '1'='1" in user.replace("%20", " ")):
        server_metrics["db_breached"] = True
        server_metrics["breach_time"] = time.strftime("%H:%M:%S")
        try:
            total_bal = sum(int(c["balance"].replace("$", "").replace(",", "")) for c in MOCK_CUSTOMERS)
            total_bal_str = f"${total_bal:,}"
        except Exception:
            total_bal_str = "$4,865,000"
        return jsonify({
            "status": "PWNED",
            "message": "🔥 TẤN CÔNG SQLi THÀNH CÔNG! Đã bypass xác thực và trích xuất dữ liệu CSDL!",
            "leaked_database": MOCK_CUSTOMERS,
            "total_records": len(MOCK_CUSTOMERS),
            "total_balance_leaked": total_bal_str
        }), 200

    if user == "admin" and request.args.get("pass") == "password123":
        return jsonify({"status": "success", "user": "admin"}), 200

    return jsonify({"status": "failed", "message": "Sai tài khoản hoặc mật khẩu"}), 401


@app.route("/api/reset", methods=["GET", "POST"])
def reset_server():
    """Khôi phục trạng thái máy chủ sau khi bị tấn công"""
    server_metrics["is_crashed"] = False
    server_metrics["crashed_reason"] = ""
    server_metrics["crashed_time"] = ""
    server_metrics["last_latency_ms"] = 5.0
    server_metrics["db_breached"] = False
    server_metrics["breach_time"] = ""
    server_metrics["xss_injected"] = False
    server_metrics["xss_time"] = ""
    return jsonify({"status": "success", "message": "Máy chủ đã được khôi phục trạng thái an toàn!"})


@app.route("/api/transfer", methods=["POST"])
def transfer_money():
    """Chức năng thay đổi dữ liệu số dư ngân hàng trên web"""
    if server_metrics["is_crashed"]:
        return jsonify({"error": "503 SERVICE UNAVAILABLE: Máy chủ đang bị sập do DoS!"}), 503

    amount = 500000
    try:
        if request.is_json and request.json:
            amount = int(request.json.get("amount", 500000))
    except Exception:
        amount = 500000

    curr_balance = int(MOCK_CUSTOMERS[0]["balance"].replace("$", "").replace(",", ""))
    new_balance = curr_balance + amount
    MOCK_CUSTOMERS[0]["balance"] = f"${new_balance:,}"
    return jsonify({
        "status": "success",
        "message": f"Chuyển tiền thành công! Số dư mới của Admin là: {MOCK_CUSTOMERS[0]['balance']}",
        "new_balance": MOCK_CUSTOMERS[0]["balance"]
    }), 200


@app.route("/api/comment", methods=["GET", "POST"])
def vulnerable_comment():
    """
    Lỗ hổng XSS thuần túy:
    Lưu trực tiếp mã HTML/JavaScript của người dùng vào bộ nhớ máy chủ.
    """
    server_metrics["total_requests"] += 1
    content = request.args.get("content") or request.form.get("content") or ""
    author = request.args.get("author") or "Khách"

    if content:
        is_mal = ("<script" in content.lower()) or ("onerror=" in content.lower())
        if is_mal:
            server_metrics["xss_injected"] = True

        stored_comments.append({
            "author": author,
            "content": content,
            "is_malicious": is_mal,
            "time": time.strftime("%H:%M:%S")
        })
        return jsonify({
            "status": "PWNED" if is_mal else "success",
            "message": "🔥 ĐÃ LƯU MÃ ĐỘC VÀO TRANG CHỦ!" if is_mal else "Đã đăng bình luận",
            "saved_content": content
        }), 200

    return jsonify({"status": "error", "message": "Nội dung trống"}), 400


@app.route("/api/metrics", methods=["GET"])
def get_metrics():
    """API cung cấp chỉ số cho UI tự động cập nhật"""
    return jsonify({
        "metrics": server_metrics,
        "active_workers": active_workers,
        "max_workers": MAX_WORKER_SLOTS,
        "load_pct": int((active_workers / MAX_WORKER_SLOTS) * 100),
        "customers": MOCK_CUSTOMERS,
        "comments": stored_comments
    })


if __name__ == "__main__":
    print("=" * 70)
    print("   🌐 WEB SERVER NẠN NHÂN THUẦN TÚY (PORT 8080) ĐANG KHỞI CHẠY   ")
    print("   ⚠️  MÁY CHỦ NÀY HOÀN TOÀN KHÔNG CÓ LOGIC BẢO MẬT NỘI TẠI!     ")
    print("   👉 Truy cập trang web: http://127.0.0.1:8080/                  ")
    print("=" * 70)
    app.run(host="0.0.0.0", port=8080, debug=False, threaded=True)
