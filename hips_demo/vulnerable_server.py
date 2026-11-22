"""
vulnerable_server.py - Máy Chủ Web Mục Tiêu Tích Hợp HIPS Middleware In-Line
Hỗ trợ chuyển đổi trạng thái HIPS (Bật / Tắt) để thấy rõ sự khác biệt:
- KHI HIPS TẮT: Các cuộc tấn công (SQLi, CmdI, Path Traversal) thực thi THẬT trên máy chủ.
- KHI HIPS BẬT: HIPS Middleware chặn đứng ngay tại cửa ngõ (@app.before_request), trả về HTTP 403 Forbidden.
"""
import os
import sys
import time
import subprocess
from pathlib import Path
from flask import Flask, request, jsonify, render_template_string, redirect, url_for

# Nạp HIPS Engine
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))
from hips_engine import HIPSEngine

app = Flask(__name__)
hips = HIPSEngine()

# Mock Database người dùng nhạy cảm
MOCK_USERS_DB = [
    {"id": 1, "username": "admin", "password_hash": "$2b$12$e8x...SuperSecretAdminPass2026", "role": "Administrator", "balance": "$1,500,000"},
    {"id": 2, "username": "finance_manager", "password_hash": "$2b$12$f9y...FinanceChiefPass99", "role": "Finance", "balance": "$850,000"},
    {"id": 3, "username": "customer_01", "password_hash": "$2b$12$a1b...UserPlainPass123", "role": "Customer", "balance": "$12,400"}
]


# =============================================================================
# HIPS IN-LINE INTERCEPTOR (TRÁI TIM CỦA CƠ CHẾ NGĂN CHẶN)
# =============================================================================
@app.before_request
def hips_middleware():
    """
    Hook chạy TRƯỚC TẤT CẢ các route.
    Nếu HIPS bật và phát hiện nguy hại -> CHẶN ĐỨNG NGAY LẬP TỨC (Trả về HTTP 403).
    Không cho phép gói tin chạm vào Controller hay Database!
    """
    # Bỏ qua các route quản trị giao diện HIPS
    if request.path in ["/", "/hips/toggle", "/hips/status", "/static"]:
        return None

    client_ip = request.remote_addr or "127.0.0.1"
    method = request.method
    path = request.path
    query = request.query_string.decode("utf-8", errors="replace")
    body = request.get_data(as_text=True)

    # Đưa vào HIPS Engine thẩm định in-line
    allowed, block_info = hips.inspect_and_filter(client_ip, method, path, query, body)

    if not allowed:
        # HÀNH ĐỘNG NGĂN CHẶN: ÉP ĐÓNG VÀ TRẢ VỀ 403 FORBIDDEN
        response = jsonify({
            "status": "BLOCKED_BY_HIPS",
            "hips_action": block_info.get("action", "DROP_AND_BLOCK"),
            "threat_category": block_info.get("category"),
            "severity": block_info.get("severity"),
            "rule_id": block_info.get("rule_id"),
            "reason": block_info.get("reason"),
            "evidence": block_info.get("matched_text"),
            "client_ip": client_ip,
            "timestamp": block_info.get("timestamp"),
            "message": "⚠️ KẾT NỐI BỊ CHẶN BỞI HIPS: Hành vi xâm nhập máy chủ đã bị vô hiệu hóa an toàn!"
        })
        response.status_code = 403
        return response

    return None  # Cho phép đi tiếp vào controller


# =============================================================================
# CÁC ROUTE NGHIỆP VỤ (VULNERABLE ENDPOINTS)
# =============================================================================

@app.route("/api/login", methods=["GET", "POST"])
def vulnerable_login():
    """Lỗ hổng 1: SQL Injection (Trích xuất toàn bộ Database)"""
    user_input = request.args.get("user") or request.form.get("user") or ""
    pass_input = request.args.get("pass") or request.form.get("pass") or ""

    # Mô phỏng câu truy vấn SQL lỏng lẻo: SELECT * FROM users WHERE username = '{user_input}'
    # Nếu không có HIPS: Kẻ tấn công truyền ' OR '1'='1 hoặc UNION SELECT -> Bị cướp sạch dữ liệu
    if ("' OR '1'='1" in user_input) or ("' OR '1'='1" in user_input.replace("%20", " ")) or ("UNION" in user_input.upper()):
        return jsonify({
            "status": "PWNED_WITHOUT_HIPS",
            "message": "🔥 TẤN CÔNG THÀNH CÔNG (DO KHÔNG CÓ HIPS): Đã bypass xác thực và trích xuất toàn bộ CSDL nhạy cảm!",
            "leaked_database": MOCK_USERS_DB
        }), 200

    if user_input == "admin" and pass_input == "password123":
        return jsonify({"status": "success", "message": "Đăng nhập hợp lệ", "user": "admin"}), 200

    return jsonify({"status": "failed", "message": "Sai tài khoản hoặc mật khẩu"}), 401


@app.route("/api/exec", methods=["GET", "POST"])
def vulnerable_exec():
    """Lỗ hổng 2: OS Command Injection (Thực thi lệnh hệ điều hành)"""
    cmd_param = request.args.get("ip") or request.form.get("ip") or request.args.get("cmd") or ""

    if not cmd_param:
        return jsonify({"status": "error", "message": "Thiếu tham số 'ip' hoặc 'cmd'"}), 400

    # Lỗ hổng: Nối chuỗi trực tiếp vào lệnh shell máy chủ (ping <cmd_param>)
    # Nếu không có HIPS: Lệnh sau dấu ';' (như whoami, dir, cat) sẽ THỰC THI THẬT trên máy chủ!
    try:
        # Tách lệnh độc hại nếu có ghép chuỗi
        actual_cmd = cmd_param
        if ";" in cmd_param:
            actual_cmd = cmd_param.split(";", 1)[1].strip()
        elif "|" in cmd_param:
            actual_cmd = cmd_param.split("|", 1)[1].strip()

        # Thực thi lệnh hệ thống thật
        res = subprocess.check_output(actual_cmd, shell=True, stderr=subprocess.STDOUT, timeout=3.0)
        output_str = res.decode("utf-8", errors="replace")

        return jsonify({
            "status": "COMPROMISED_WITHOUT_HIPS",
            "message": "🔥 MÁY CHỦ BỊ THỰC THI MÃ TỪ XA (DO KHÔNG CÓ HIPS)! Lệnh shell đã chạy trực tiếp trên OS!",
            "executed_command": actual_cmd,
            "host_os_output": output_str
        }), 200
    except Exception as e:
        return jsonify({"status": "exec_error", "error": str(e)}), 500


@app.route("/api/read_file", methods=["GET"])
def vulnerable_read_file():
    """Lỗ hổng 3: Path Traversal (Đọc trộm file cấu hình bí mật)"""
    file_path = request.args.get("file", "")

    if not file_path:
        return jsonify({"status": "error", "message": "Thiếu tham số ?file="}), 400

    # Nếu không có HIPS: Kẻ tấn công truyền ../secret_config.json -> Đọc lén chìa khóa bảo mật
    try:
        # Đường dẫn tương đối
        target = BASE_DIR / file_path
        if not target.exists():
            target = Path(file_path)

        if target.exists() and target.is_file():
            content = target.read_text(encoding="utf-8", errors="replace")
            return jsonify({
                "status": "DATA_LEAKED_WITHOUT_HIPS",
                "message": "🔥 RÒ RỈ TÀI LIỆU TUYỆT MẬT (DO KHÔNG CÓ HIPS): Kẻ tấn công đã đọc trộm file hệ thống!",
                "file_path": str(target),
                "stolen_content": content
            }), 200
        else:
            return jsonify({"status": "not_found", "message": f"Không tìm thấy file: {file_path}"}), 404
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


# =============================================================================
# GIAO DIỆN QUẢN TRỊ TRỰC QUAN & CÔNG TẮC BẬT/TẮT HIPS
# =============================================================================

@app.route("/hips/toggle", methods=["GET", "POST"])
def toggle_hips():
    """Bật / Tắt HIPS bằng 1 click"""
    new_state = not hips.enabled
    hips.set_enabled(new_state)
    return redirect(url_for("home_dashboard"))


@app.route("/hips/status", methods=["GET"])
def hips_status_api():
    """API trả về thông số thống kê HIPS cho UI"""
    return jsonify({
        "enabled": hips.enabled,
        "stats": hips.stats,
        "recent_blocks": hips.event_history[:15]
    })


@app.route("/")
def home_dashboard():
    """Giao diện Web trực quan thể hiện rõ nét sự khác biệt giữa Có HIPS và Không có HIPS"""
    html_template = """
    <!DOCTYPE html>
    <html lang="vi">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>HIPS vs Không HIPS - Đối Chứng An Toàn Máy Chủ</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
            body { background-color: #0f172a; color: #e2e8f0; font-family: 'Segoe UI', Tahoma, sans-serif; }
            .card { background-color: #1e293b; border: 1px solid #334155; border-radius: 12px; }
            .badge-pwned { background-color: #ef4444; color: white; padding: 6px 12px; border-radius: 6px; font-weight: bold; }
            .badge-safe { background-color: #10b981; color: white; padding: 6px 12px; border-radius: 6px; font-weight: bold; }
            .status-banner-off { background: linear-gradient(135deg, #7f1d1d, #991b1b); border-left: 6px solid #ef4444; }
            .status-banner-on { background: linear-gradient(135deg, #064e3b, #065f46); border-left: 6px solid #10b981; }
            .btn-toggle-on { background-color: #10b981; border: none; font-weight: bold; padding: 12px 24px; font-size: 1.1rem; }
            .btn-toggle-off { background-color: #ef4444; border: none; font-weight: bold; padding: 12px 24px; font-size: 1.1rem; }
            pre { background-color: #090d16; color: #38bdf8; padding: 12px; border-radius: 8px; font-size: 0.85rem; }
            .table-dark { background-color: #1e293b; }
        </style>
    </head>
    <body class="p-4">
        <div class="container-fluid max-w-7xl">
            <!-- Header -->
            <div class="d-flex justify-content-between align-items-center mb-4 pb-3 border-bottom border-secondary">
                <div>
                    <h2 class="fw-bold text-white mb-1">🛡️ HỆ THỐNG PHÒNG THỦ MÁY CHỦ NỘI TẠI (HIPS DEMO)</h2>
                    <p class="text-secondary mb-0">Host-based Intrusion Prevention System | So sánh Đối chứng Trực tiếp: <strong>HIPS ON vs HIPS OFF</strong></p>
                </div>
                <div>
                    <a href="/hips/toggle" class="btn text-white shadow-lg {% if hips_enabled %}btn-toggle-off{% else %}btn-toggle-on{% endif %}">
                        {% if hips_enabled %}
                            🛑 BẤM ĐỂ TẮT HIPS (Hạ Phòng Thủ)
                        {% else %}
                            🛡️ BẤM ĐỂ BẬT HIPS (Bảo Vệ Ngay)
                        {% endif %}
                    </a>
                </div>
            </div>

            <!-- Banner Trạng thái -->
            <div class="p-4 rounded-3 mb-4 shadow {% if hips_enabled %}status-banner-on{% else %}status-banner-off{% endif %}">
                <div class="d-flex align-items-center justify-content-between">
                    <div>
                        <h4 class="fw-bold mb-1">
                            {% if hips_enabled %}
                                🟢 TRẠNG THÁI: HIPS ĐANG BẬT (CHỦ ĐỘNG BẢO VỆ MÁY CHỦ)
                            {% else %}
                                🔴 TRẠNG THÁI: HIPS ĐANG TẮT (MÁY CHỦ ĐANG TRẦN TRỤI KHÔNG BẢO VỆ!)
                            {% endif %}
                        </h4>
                        <p class="mb-0 opacity-75">
                            {% if hips_enabled %}
                                Mọi Request độc hại (SQLi, CmdI, LFI) đều bị <strong>chặn đứng tại In-line Middleware (HTTP 403 Forbidden)</strong> trước khi chạm tới Controller. Kẻ tấn công bị cách ly IP!
                            {% else %}
                                Cảnh báo: Các lỗ hổng bảo mật sẽ <strong>THỰC THI THẬT</strong> trên máy chủ. Kẻ tấn công có thể cướp dữ liệu người dùng và chạy lệnh shell chiếm quyền!
                            {% endif %}
                        </p>
                    </div>
                    <div class="text-end">
                        <span class="fs-1">{% if hips_enabled %}🔒{% else %}🔓{% endif %}</span>
                    </div>
                </div>
            </div>

            <!-- Thống kê Card -->
            <div class="row g-3 mb-4">
                <div class="col-md-3">
                    <div class="card p-3 text-center">
                        <h6 class="text-secondary">Tổng Request Kiểm tra</h6>
                        <h2 class="fw-bold text-info mb-0">{{ stats.total_inspected }}</h2>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card p-3 text-center">
                        <h6 class="text-secondary">Đã Chặn Đứng (Blocked)</h6>
                        <h2 class="fw-bold text-danger mb-0">{{ stats.total_blocked }}</h2>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card p-3 text-center">
                        <h6 class="text-secondary">SQL Injection Bị Diệt</h6>
                        <h2 class="fw-bold text-warning mb-0">{{ stats.sqli_blocked }}</h2>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card p-3 text-center">
                        <h6 class="text-secondary">Lệnh Shell OS Bị Khóa</h6>
                        <h2 class="fw-bold text-danger mb-0">{{ stats.cmdi_blocked }}</h2>
                    </div>
                </div>
            </div>

            <!-- Bảng So sánh Trực quan -->
            <div class="card p-4 mb-4">
                <h5 class="fw-bold text-white mb-3">📊 BẢNG ĐỐI CHỨNG HÀNH VI: KHI KHÔNG CÓ HIPS VS KHI CÓ HIPS</h5>
                <div class="table-responsive">
                    <table class="table table-dark table-hover table-bordered mb-0 align-middle">
                        <thead>
                            <tr class="table-secondary text-dark">
                                <th style="width: 20%;">Kịch bản Tấn công</th>
                                <th style="width: 40%;" class="text-danger">❌ KHI KHÔNG CÓ HIPS (HIPS OFF)</th>
                                <th style="width: 40%;" class="text-success">✅ KHI CÓ HIPS BẢO VỆ (HIPS ON)</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td>
                                    <strong>1. SQL Injection</strong><br>
                                    <small class="text-secondary">URL: /api/login?user=admin' OR '1'='1</small>
                                </td>
                                <td>
                                    <span class="badge-pwned mb-2 d-inline-block">PWNED - THÀNH CÔNG (200 OK)</span><br>
                                    Bypass xác thực thành công! Server xuất toàn bộ mật khẩu băm và số dư ngân hàng ra ngoài.
                                </td>
                                <td>
                                    <span class="badge-safe mb-2 d-inline-block">BLOCKED (403 FORBIDDEN)</span><br>
                                    HIPS bắt mẫu <code>' OR '1'='1</code> ngay lập tức. Ngắt kết nối, không cho phép truy vấn Database.
                                </td>
                            </tr>
                            <tr>
                                <td>
                                    <strong>2. OS Command Injection</strong><br>
                                    <small class="text-secondary">POST /api/exec | ip=127.0.0.1; whoami</small>
                                </td>
                                <td>
                                    <span class="badge-pwned mb-2 d-inline-block">COMPROMISED (200 OK)</span><br>
                                    Lệnh <code>whoami</code> hoặc lệnh shell thực thi THẬT trên hệ điều hành máy chủ, trả về thông tin hệ thống!
                                </td>
                                <td>
                                    <span class="badge-safe mb-2 d-inline-block">BLOCKED (403 FORBIDDEN)</span><br>
                                    HIPS Command Guard chặn đứng ký tự ghép lệnh <code>; whoami</code>. Không cho subprocess chạy!
                                </td>
                            </tr>
                            <tr>
                                <td>
                                    <strong>3. Path Traversal (LFI)</strong><br>
                                    <small class="text-secondary">GET /api/read_file?file=secret_config.json</small>
                                </td>
                                <td>
                                    <span class="badge-pwned mb-2 d-inline-block">LEAKED (200 OK)</span><br>
                                    Đọc trộm thành công file <code>secret_config.json</code> chứa Database Password & Admin API Token.
                                </td>
                                <td>
                                    <span class="badge-safe mb-2 d-inline-block">BLOCKED (403 FORBIDDEN)</span><br>
                                    HIPS File Guard phát hiện mẫu <code>secret_config.json</code> và <code>../</code>. Chặn truy cập file nhạy cảm.
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Danh sách Cảnh báo Ngăn chặn Gần nhất -->
            <div class="card p-4">
                <h5 class="fw-bold text-white mb-3">🚨 NHẬT KÝ NGĂN CHẶN CỦA HIPS THEO THỜI GIAN THỰC (PREVENTION FEED)</h5>
                {% if recent_events %}
                <div class="table-responsive">
                    <table class="table table-dark table-striped align-middle">
                        <thead>
                            <tr>
                                <th>Thời gian</th>
                                <th>IP Kẻ Tấn Công</th>
                                <th>Loại Tấn Công</th>
                                <th>Mức Độ</th>
                                <th>Hành Động HIPS</th>
                                <th>Đoạn Mã Độc Bị Bắt</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for ev in recent_events %}
                            <tr>
                                <td><small class="text-secondary">{{ ev.timestamp }}</small></td>
                                <td><code>{{ ev.client_ip }}</code></td>
                                <td><span class="badge bg-warning text-dark">{{ ev.category }}</span></td>
                                <td><span class="badge bg-danger">{{ ev.severity }}</span></td>
                                <td><span class="badge bg-success">{{ ev.action }}</span></td>
                                <td><code class="text-danger">{{ ev.matched_text }}</code></td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
                {% else %}
                <div class="text-center py-4 text-secondary">
                    Chưa ghi nhận sự kiện ngăn chặn nào. Hãy bật HIPS và dùng công cụ Attacker bắn thử để xem kết quả!
                </div>
                {% endif %}
            </div>
        </div>
    </body>
    </html>
    """
    return render_template_string(
        html_template,
        hips_enabled=hips.enabled,
        stats=hips.stats,
        recent_events=hips.event_history[:10]
    )


if __name__ == "__main__":
    port = 8088
    print("=" * 70)
    print(f"   🛡️ MÁY CHỦ WEB TÍCH HỢP HIPS (PORT {port}) ĐANG KHỞI CHẠY   ")
    print(f"   👉 Truy cập Dashboard Quản trị HIPS: http://127.0.0.1:{port}/")
    print("=" * 70)
    app.run(host="0.0.0.0", port=port, debug=False)
