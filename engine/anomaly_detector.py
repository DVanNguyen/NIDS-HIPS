"""
Sliding-Window Anomaly Detection Engine for Transport Layer Attacks.
Identifies TCP SYN Flood (DoS) and Port Scanning in real-time.
"""
import time
import threading
from typing import Dict, Set, List, Any, Optional
from collections import deque
from config.settings import (
    SYN_FLOOD_THRESHOLD,
    PORT_SCAN_THRESHOLD,
    WINDOW_SIZE_SECONDS
)
from parsers.tcp_ip_parser import ParsedPacket


class AnomalyDetector:
    def __init__(self,
                 syn_threshold: int = SYN_FLOOD_THRESHOLD,
                 scan_threshold: int = PORT_SCAN_THRESHOLD,
                 window_sec: float = WINDOW_SIZE_SECONDS):
        self.syn_threshold = syn_threshold
        self.scan_threshold = scan_threshold
        self.window_sec = window_sec

        self._lock = threading.Lock()
        # Per IP: deque of timestamps of SYN packets: {src_ip: deque([t1, t2, ...])}
        self._syn_history: Dict[str, deque] = {}
        # Per IP: deque of tuples (timestamp, dst_port): {src_ip: deque([(t1, p1), ...])}
        self._port_history: Dict[str, deque] = {}
        # Per IP: frequency map of ports in window for strict O(1) distinct counting
        self._port_counts: Dict[str, Dict[int, int]] = {}

        # Alert cooldown tracker: {(src_ip, alert_type): last_alert_time}
        self._cooldowns: Dict[tuple, float] = {}
        self._cooldown_period = 2.0  # seconds between repeated alerts for same IP

    def inspect_packet(self, pkt: ParsedPacket) -> List[Dict[str, Any]]:
        """
        Evaluate parsed packet against anomaly windows.
        Returns list of anomaly alerts.
        """
        if pkt.protocol != "TCP":
            return []

        now = time.time()
        alerts = []
        src_ip = pkt.src_ip
        dst_ip = pkt.dst_ip
        dst_port = pkt.dst_port

        direction = pkt.direction

        with self._lock:
            # 0. Định kỳ dọn dẹp các IP không còn hoạt động để chống rò rỉ RAM
            if now - getattr(self, "_last_gc", 0.0) > 5.0:
                self._last_gc = now
                stale_syn = [ip for ip, q in self._syn_history.items() if not q or (now - q[-1] > 10.0)]
                for ip in stale_syn:
                    del self._syn_history[ip]
                stale_port = [ip for ip, q in self._port_history.items() if not q or (now - q[-1][0] > 10.0)]
                for ip in stale_port:
                    del self._port_history[ip]
                    if ip in self._port_counts:
                        del self._port_counts[ip]
                stale_cd = [k for k, t in self._cooldowns.items() if now - t > 30.0]
                for k in stale_cd:
                    del self._cooldowns[k]

            # 1. SYN Flood Inspection
            if pkt.is_syn and not pkt.is_ack:
                if src_ip not in self._syn_history:
                    self._syn_history[src_ip] = deque()
                
                syn_q = self._syn_history[src_ip]
                syn_q.append(now)

                # Amortized O(1) purge older than window
                while syn_q and (now - syn_q[0]) > self.window_sec:
                    syn_q.popleft()

                syn_count = len(syn_q)
                if syn_count >= self.syn_threshold:
                    if self._can_alert(src_ip, "DOS_SYN_FLOOD", now):
                        evid = f"SYN Rate: {syn_count} pkts/sec (Threshold: {self.syn_threshold})"
                        evid_slice = f"DOS SYN FLOOD: >>> {syn_count} pkts/sec <<< vượt ngưỡng {self.syn_threshold} pkts/sec"
                        alerts.append({
                            "category": "DOS_SYN_FLOOD",
                            "severity": "CRITICAL",
                            "rule_id": "TCP_DOS_001",
                            "rule_name": "TCP SYN Flood DoS Attack",
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "direction": direction,
                            "src_port": pkt.src_port,
                            "dst_port": dst_port,
                            "protocol": "TCP",
                            "evidence": evid,
                            "evidence_slice": evid_slice,
                            "details": f"High volume of unacknowledged SYN packets ({syn_count}/sec) from {src_ip}",
                            "payload_sample": f"Flags={pkt.tcp_flags}, Seq={pkt.seq}, Len={pkt.raw_len}"
                        })

            # 2. Port Scan Inspection (Strict O(1) Amortized via Frequency Map)
            if dst_port is not None:
                if src_ip not in self._port_history:
                    self._port_history[src_ip] = deque()
                    self._port_counts[src_ip] = {}

                port_q = self._port_history[src_ip]
                port_counts = self._port_counts[src_ip]

                port_q.append((now, dst_port))
                port_counts[dst_port] = port_counts.get(dst_port, 0) + 1

                # Amortized O(1) purge older than window
                while port_q and (now - port_q[0][0]) > self.window_sec:
                    _, old_p = port_q.popleft()
                    port_counts[old_p] -= 1
                    if port_counts[old_p] <= 0:
                        del port_counts[old_p]

                distinct_count = len(port_counts)
                if distinct_count >= self.scan_threshold:
                    if self._can_alert(src_ip, "PORT_SCAN", now):
                        sample_ports = sorted(list(port_counts.keys()))[:8]
                        evid = f"Distinct Ports: {distinct_count} ports/sec (Sample: {sample_ports}...)"
                        evid_slice = f"PORT SCAN: >>> {distinct_count} ports/sec <<< mẫu cổng: {sample_ports}..."
                        alerts.append({
                            "category": "PORT_SCAN",
                            "severity": "HIGH",
                            "rule_id": "TCP_SCAN_001",
                            "rule_name": "TCP Port Scan (Reconnaissance)",
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "direction": direction,
                            "src_port": pkt.src_port,
                            "dst_port": dst_port,
                            "protocol": "TCP",
                            "evidence": evid,
                            "evidence_slice": evid_slice,
                            "details": f"Rapid scanning of {distinct_count} distinct ports within {self.window_sec}s window",
                            "payload_sample": f"Flags={pkt.tcp_flags}, Target={dst_ip}:{dst_port}"
                        })

        return alerts

    def _can_alert(self, src_ip: str, alert_type: str, now: float) -> bool:
        key = (src_ip, alert_type)
        last_time = self._cooldowns.get(key, 0.0)
        if now - last_time >= self._cooldown_period:
            self._cooldowns[key] = now
            return True
        return False
