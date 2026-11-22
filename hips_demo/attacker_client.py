"""
attacker_client.py - Công Cụ Phát Động Tấn Công Đối Chứng (HIPS Verification Client)
Chức năng:
1. Phát động 3 đòn tấn công thực tế: SQLi, OS Command Injection, Path Traversal.
2. In kết quả trực quan ra màn hình Console để thấy rõ:
   - Khi KHÔNG CÓ HIPS: Nhận HTTP 200 OK + Dữ liệu mật bị cướp / Lệnh shell thực thi thật!
   - Khi CÓ HIPS BẢO VỆ: Nhận HTTP 403 Forbidden + Thông báo ngăn chặn và cách ly IP từ HIPS!
"""
import sys
import time
import argparse
import urllib.request
import urllib.parse
import urllib.error
import json

# Màu sắc ANSI
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def test_sqli(target_ip: str, target_port: int):
    print(f"\n{BOLD}{CYAN}--- [TEST 1: TẤN CÔNG SQL INJECTION] ---{RESET}")
    payload = "admin' OR '1'='1"
    url = f"http://{target_ip}:{target_port}/api/login?user={urllib.parse.quote(payload)}&pass=arbitrary"
    print(f"[*] Mục tiêu: {url}")
    print(f"[*] Payload chèn vào URL: {YELLOW}{payload}{RESET}")

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Attacker-SQLi/1.0"})
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            print(f"\n{RED}{BOLD}❌ KẾT QUẢ: TẤN CÔNG THÀNH CÔNG (KHÔNG CÓ HIPS BẢO VỆ)!{RESET}")
            print(f"  ├─ Mã phản hồi HTTP: {resp.status} OK")
            print(f"  ├─ Trạng thái máy chủ: {RED}PWNED / COMPROMISED{RESET}")
            print(f"  └─ Dữ liệu Database bị trích xuất lậu:")
            for u in data.get("leaked_database", []):
                print(f"     • User: {u['username']} | Role: {u['role']} | PassHash: {u['password_hash'][:15]}... | Balance: {u['balance']}")

    except urllib.error.HTTPError as e:
        if e.code == 403:
            block_data = json.loads(e.read().decode("utf-8"))
            print(f"\n{GREEN}{BOLD}✅ KẾT QUẢ: TẤN CÔNG BỊ CHẶN ĐỨNG (HIPS ĐANG BẢO VỆ MÁY CHỦ)!{RESET}")
            print(f"  ├─ Mã phản hồi HTTP: {GREEN}{e.code} FORBIDDEN (Truy cập bị từ chối){RESET}")
            print(f"  ├─ Hành động của HIPS: {GREEN}{block_data.get('hips_action')}{RESET}")
            print(f"  ├─ Lý do chặn: {block_data.get('reason')}")
            print(f"  └─ Bằng chứng phát hiện: {YELLOW}{block_data.get('evidence')}{RESET}")
        else:
            print(f"[-] Lỗi HTTP không mong muốn: {e}")
    except Exception as e:
        print(f"[-] Không thể kết nối tới máy chủ: {e}")


def test_command_injection(target_ip: str, target_port: int):
    print(f"\n{BOLD}{CYAN}--- [TEST 2: TẤN CÔNG OS COMMAND INJECTION] ---{RESET}")
    url = f"http://{target_ip}:{target_port}/api/exec"
    body_data = "ip=127.0.0.1; whoami"
    print(f"[*] Mục tiêu: POST {url}")
    print(f"[*] Payload lệnh chèn vào Body: {YELLOW}{body_data}{RESET}")

    try:
        req = urllib.request.Request(
            url,
            data=body_data.encode("utf-8"),
            headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "Attacker-CmdI/1.0"}
        )
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            print(f"\n{RED}{BOLD}❌ KẾT QUẢ: TẤN CÔNG THÀNH CÔNG (KHÔNG CÓ HIPS BẢO VỆ)!{RESET}")
            print(f"  ├─ Mã phản hồi HTTP: {resp.status} OK")
            print(f"  ├─ Lệnh shell đã thực thi trên OS: {RED}{data.get('executed_command')}{RESET}")
            print(f"  └─ Kết quả trả về trực tiếp từ Hệ điều hành máy chủ:")
            print(f"     {YELLOW}{data.get('host_os_output').strip()}{RESET}")

    except urllib.error.HTTPError as e:
        if e.code == 403:
            block_data = json.loads(e.read().decode("utf-8"))
            print(f"\n{GREEN}{BOLD}✅ KẾT QUẢ: TẤN CÔNG BỊ CHẶN ĐỨNG (HIPS ĐANG BẢO VỆ MÁY CHỦ)!{RESET}")
            print(f"  ├─ Mã phản hồi HTTP: {GREEN}{e.code} FORBIDDEN (Lệnh shell bị phong tỏa){RESET}")
            print(f"  ├─ Hành động của HIPS: {GREEN}{block_data.get('hips_action')}{RESET}")
            print(f"  ├─ Luật kích hoạt: {block_data.get('rule_id')} ({block_data.get('threat_category')})")
            print(f"  └─ Máy chủ: {GREEN}AN TOÀN TUYỆT ĐỐI - Lệnh OS KHÔNG được phép chạy!{RESET}")
        else:
            print(f"[-] Lỗi HTTP: {e}")
    except Exception as e:
        print(f"[-] Không thể kết nối tới máy chủ: {e}")


def test_path_traversal(target_ip: str, target_port: int):
    print(f"\n{BOLD}{CYAN}--- [TEST 3: TẤN CÔNG PATH TRAVERSAL (ĐỌC TRỘM FILE BÍ MẬT)] ---{RESET}")
    filename = "secret_config.json"
    url = f"http://{target_ip}:{target_port}/api/read_file?file={filename}"
    print(f"[*] Mục tiêu: {url}")
    print(f"[*] Tệp tin cố tình đọc lén: {YELLOW}{filename}{RESET}")

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Attacker-LFI/1.0"})
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            print(f"\n{RED}{BOLD}❌ KẾT QUẢ: TẤN CÔNG THÀNH CÔNG (KHÔNG CÓ HIPS BẢO VỆ)!{RESET}")
            print(f"  ├─ Mã phản hồi HTTP: {resp.status} OK")
            print(f"  ├─ Đường dẫn file bị đọc trộm: {data.get('file_path')}")
            print(f"  └─ Nội dung bí mật bị đánh cắp:")
            print(f"     {YELLOW}{data.get('stolen_content')}{RESET}")

    except urllib.error.HTTPError as e:
        if e.code == 403:
            block_data = json.loads(e.read().decode("utf-8"))
            print(f"\n{GREEN}{BOLD}✅ KẾT QUẢ: TẤN CÔNG BỊ CHẶN ĐỨNG (HIPS ĐANG BẢO VỆ MÁY CHỦ)!{RESET}")
            print(f"  ├─ Mã phản hồi HTTP: {GREEN}{e.code} FORBIDDEN (Truy cập file bị cấm){RESET}")
            print(f"  ├─ Hành động của HIPS: {GREEN}{block_data.get('hips_action')}{RESET}")
            print(f"  ├─ Lý do chặn: {block_data.get('reason')}")
            print(f"  └─ Tệp tin mật: {GREEN}ĐƯỢC BẢO VỆ NGUYÊN VẸN!{RESET}")
        else:
            print(f"[-] Lỗi HTTP: {e}")
    except Exception as e:
        print(f"[-] Không thể kết nối tới máy chủ: {e}")


def run_full_suite(target_ip: str, target_port: int):
    print("=" * 70)
    print(f"   ⚔️  BẮT ĐẦU CHẠY BỘ KIỂM THỬ ĐỐI CHỨNG HIPS: ➔ {target_ip}:{target_port}   ")
    print("=" * 70)
    test_sqli(target_ip, target_port)
    time.sleep(1.0)
    test_command_injection(target_ip, target_port)
    time.sleep(1.0)
    test_path_traversal(target_ip, target_port)
    print("\n" + "=" * 70)
    print("   [HOÀN TẤT KIỂM THỬ] Mời quan sát Dashboard: http://" + f"{target_ip}:{target_port}/   ")
    print("=" * 70)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Attacker Client for HIPS Verification Demo")
    parser.add_argument("--ip", type=str, default="127.0.0.1", help="Địa chỉ IP của máy chủ Web HIPS (Mặc định 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8088, help="Cổng Web của máy chủ HIPS (Mặc định 8088)")
    parser.add_argument("--action", choices=["all", "sqli", "cmdi", "lfi"], default="all", help="Kịch bản cần bắn")

    args = parser.parse_args()

    if args.action == "sqli":
        test_sqli(args.ip, args.port)
    elif args.action == "cmdi":
        test_command_injection(args.ip, args.port)
    elif args.action == "lfi":
        test_path_traversal(args.ip, args.port)
    else:
        run_full_suite(args.ip, args.port)
