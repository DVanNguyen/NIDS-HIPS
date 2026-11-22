"""
Traffic Generator & PCAP Synthesizer.
Generates normal traffic and attack scenarios (SQLi, XSS, Path Traversal, Cmd Injection, Port Scan, SYN Flood)
for live injection or saving to PCAP for Suricata benchmarking.
"""
import time
from pathlib import Path
from typing import List
from scapy.all import IP, TCP, Raw, wrpcap


def build_http_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                      method: str, path: str, host: str = "example.com", body: str = "") -> IP:
    """Build a realistic HTTP TCP/IP packet with Scapy."""
    payload = f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n"
    if body:
        payload += f"Content-Length: {len(body)}\r\n\r\n{body}"
    else:
        payload += "\r\n"

    pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="PA", seq=1000, ack=2000) / Raw(load=payload.encode())
    return pkt


def generate_benchmark_attacks(target_ip: str = "192.168.1.50") -> List[IP]:
    """
    Generate a full sequence of benchmark attack packets and normal baseline packets.
    """
    packets: List[IP] = []
    base_time = time.time()

    # 1. Normal Baseline HTTP Traffic (Inbound web visitors)
    for i in range(5):
        pkt = build_http_packet("172.56.21.80", target_ip, 40000 + i, 80, "GET", f"/products?page={i}")
        pkt.time = base_time + (i * 0.1)
        packets.append(pkt)

    # 2. SQL Injection Attack (INBOUND from Public Internet: 45.33.32.156 -> 192.168.1.50)
    pkt_sqli1 = build_http_packet(
        "45.33.32.156", target_ip, 45100, 80,
        "GET", "/search.php?id=1'%20UNION%20SELECT%20id,username,password%20FROM%20users--"
    )
    pkt_sqli1.time = base_time + 0.6
    packets.append(pkt_sqli1)

    # 3. SQL Injection Attack (INTERNAL Lateral Movement: 192.168.1.101 -> 192.168.1.50)
    pkt_sqli2 = build_http_packet(
        "192.168.1.101", target_ip, 45101, 80,
        "POST", "/login", body="username=admin' OR '1'='1&password=xyz"
    )
    pkt_sqli2.time = base_time + 0.8
    packets.append(pkt_sqli2)

    # 4. Cross-Site Scripting (INBOUND: 104.244.42.1 -> 192.168.1.50)
    pkt_xss = build_http_packet(
        "104.244.42.1", target_ip, 45200, 80,
        "GET", "/comment?user=guest&text=%3Cscript%3Ealert(document.cookie)%3C/script%3E"
    )
    pkt_xss.time = base_time + 1.0
    packets.append(pkt_xss)

    # 5. Path Traversal (INBOUND: 185.220.101.5 -> 192.168.1.50)
    pkt_lfi = build_http_packet(
        "185.220.101.5", target_ip, 45300, 80,
        "GET", "/view?file=../../../../etc/passwd"
    )
    pkt_lfi.time = base_time + 1.2
    packets.append(pkt_lfi)

    # 6. OS Command Injection (INTERNAL Compromised Host: 192.168.1.104 -> 192.168.1.50)
    pkt_cmdi = build_http_packet(
        "192.168.1.104", target_ip, 45400, 80,
        "POST", "/api/ping", body="ip=127.0.0.1; cat /etc/passwd; whoami"
    )
    pkt_cmdi.time = base_time + 1.4
    packets.append(pkt_cmdi)

    # 7. TCP Port Scan (INBOUND Reconnaissance from Internet: 103.28.36.22 scanning target)
    scan_ip = "103.28.36.22"
    for idx, port in enumerate(range(20, 45)):
        scan_pkt = IP(src=scan_ip, dst=target_ip) / TCP(sport=55000 + idx, dport=port, flags="S", seq=500 + idx)
        scan_pkt.time = base_time + 1.6 + (idx * 0.01)
        packets.append(scan_pkt)

    # 8. TCP SYN Flood (60 rapid SYN packets to port 80)
    flood_ip = "10.0.0.88"
    for idx in range(60):
        flood_pkt = IP(src=flood_ip, dst=target_ip) / TCP(sport=30000 + idx, dport=80, flags="S", seq=1000 + idx)
        flood_pkt.time = base_time + 2.0 + (idx * 0.005)
        packets.append(flood_pkt)

    return packets


def save_benchmark_pcap(output_path: str = "data/benchmark_attacks.pcap") -> str:
    """Generate attacks and save to a PCAP file ready for replay and Suricata testing."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    pkts = generate_benchmark_attacks()
    wrpcap(str(path), pkts)
    print(f"[TrafficGenerator] Generated {len(pkts)} packets and saved to: {path.resolve()}")
    return str(path.resolve())


if __name__ == "__main__":
    save_benchmark_pcap()
