"""
victim_web_server.py - Máy chủ Web mục tiêu giả lập (Dummy Target Web Application)
Chạy trên Máy 2 (Victim: 0.0.0.0:8080) để tiếp nhận các kết nối TCP và HTTP từ Máy 1.
Giúp hoàn tất bắt tay TCP 3 bước (3-way Handshake) để truyền tải toàn vẹn payload L7 vào NIDS Sniffer.
"""
import sys
import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


class TargetAppHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Trả về HTTP 200 cho mọi yêu cầu GET (SQLi, XSS, Path Traversal, Recon)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Server", "Vulnerable-Web-App/1.0 (Lab Target)")
        self.end_headers()
        response_body = f"""
        <html>
            <head><title>Victim Web Server</title></head>
            <body>
                <h2>Victim Web Server - Target Application Port {self.server.server_port}</h2>
                <p>Status: Active & Listening</p>
                <p>Received Request: <code>{self.path}</code></p>
            </body>
        </html>
        """
        self.wfile.write(response_body.encode("utf-8"))

    def do_POST(self):
        # Đọc body của POST request (để bẫy Command Injection, SQLi Login)
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Server", "Vulnerable-Web-App/1.0 (Lab Target)")
        self.end_headers()
        self.wfile.write(b'{"status": "success", "message": "Payload received and processed"}')

    def log_message(self, format, *args):
        # In log vắn tắt trên terminal của máy chủ mục tiêu
        print(f"[VictimApp] {self.client_address[0]}:{self.client_address[1]} - {args[0]}")


def run_target_server(port: int = 8080):
    server_address = ("0.0.0.0", port)
    httpd = HTTPServer(server_address, TargetAppHandler)
    print("=" * 65)
    print(f"   MÁY CHỦ MỤC TIÊU GIẢ LẬP ĐANG HOẠT ĐỘNG TẠI: http://0.0.0.0:{port}   ")
    print(f"   (Sẵn sàng nhận traffic tấn công từ Máy 1 để NIDS bắt gói)   ")
    print("=" * 65)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[VictimApp] Dừng máy chủ mục tiêu.")
        httpd.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Victim Target Web Server")
    parser.add_argument("--port", type=int, default=8080, help="Port lắng nghe (mặc định: 8080)")
    args = parser.parse_args()
    run_target_server(args.port)
