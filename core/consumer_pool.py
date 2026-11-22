"""
Consumer Worker Pool for Multi-threaded NIDS.
Manages concurrent worker threads that dissect packets, match rules, and detect anomalies.
"""
import threading
from typing import List
from config.settings import NUM_CONSUMER_WORKERS
from core.queue_manager import PacketQueue
from core.alert_manager import AlertManager
from parsers.tcp_ip_parser import TCPIPParser
from parsers.http_parser import HTTPParser
from engine.rule_matcher import RuleMatcher
from engine.anomaly_detector import AnomalyDetector


class ConsumerWorkerPool:
    def __init__(self,
                 queue: PacketQueue,
                 alert_manager: AlertManager,
                 num_workers: int = NUM_CONSUMER_WORKERS):
        self.queue = queue
        self.alert_manager = alert_manager
        self.num_workers = num_workers
        self.workers: List[threading.Thread] = []
        self._running = False

        # Shared parsers and engines
        self.tcp_parser = TCPIPParser()
        self.http_parser = HTTPParser()
        self.rule_matcher = RuleMatcher()
        self.anomaly_detector = AnomalyDetector()

    def start(self):
        """Start all consumer worker threads."""
        self._running = True
        self.workers = []
        for i in range(self.num_workers):
            t = threading.Thread(target=self._worker_loop, name=f"ConsumerWorker-{i+1}", daemon=True)
            t.start()
            self.workers.append(t)
        print(f"[ConsumerPool] Started {self.num_workers} parallel consumer workers.")

    def stop(self):
        """Signal workers to stop and wait for completion."""
        self._running = False
        for t in self.workers:
            t.join(timeout=1.0)
        print("[ConsumerPool] All consumer workers stopped.")

    def _worker_loop(self):
        while self._running:
            raw_pkt = self.queue.get(block=True, timeout=0.2)
            if raw_pkt is None:
                continue

            try:
                # 1. Parse Layer 3 & Layer 4 (IP/TCP/UDP)
                parsed = self.tcp_parser.parse(raw_pkt)
                if not parsed:
                    continue

                # 2. Check Transport-Layer Anomaly (SYN Flood, Port Scan)
                anomaly_alerts = self.anomaly_detector.inspect_packet(parsed)
                for alert_data in anomaly_alerts:
                    self.alert_manager.trigger_alert(
                        category=alert_data["category"],
                        severity=alert_data["severity"],
                        rule_id=alert_data["rule_id"],
                        rule_name=alert_data["rule_name"],
                        src_ip=alert_data["src_ip"],
                        dst_ip=alert_data["dst_ip"],
                        direction=alert_data.get("direction", parsed.direction),
                        src_port=alert_data["src_port"],
                        dst_port=alert_data["dst_port"],
                        protocol=alert_data["protocol"],
                        evidence=alert_data["evidence"],
                        evidence_slice=alert_data.get("evidence_slice", alert_data["evidence"]),
                        details=alert_data["details"],
                        payload_sample=alert_data["payload_sample"]
                    )

                # 3. Check Application-Layer HTTP (SQLi, XSS, Path Traversal, etc.)
                if parsed.payload and parsed.src_port and parsed.dst_port:
                    http_data = self.http_parser.parse_payload(
                        src_ip=parsed.src_ip,
                        dst_ip=parsed.dst_ip,
                        src_port=parsed.src_port,
                        dst_port=parsed.dst_port,
                        payload=parsed.payload,
                        seq=parsed.seq
                    )

                    if http_data:
                        rule_matches = self.rule_matcher.inspect_http(http_data)
                        for match in rule_matches:
                            self.alert_manager.trigger_alert(
                                category=match["category"],
                                severity=match["severity"],
                                rule_id=match["rule_id"],
                                rule_name=match["rule_name"],
                                src_ip=parsed.src_ip,
                                dst_ip=parsed.dst_ip,
                                direction=parsed.direction,
                                src_port=parsed.src_port,
                                dst_port=parsed.dst_port,
                                protocol="HTTP",
                                evidence=match["evidence"],
                                evidence_slice=match.get("evidence_slice", match["evidence"]),
                                details=f"{match['details']} | URI: {http_data.raw_uri}",
                                payload_sample=http_data.full_text[:400]
                            )

            except Exception as e:
                # Shield worker thread from crashing on corrupted payloads
                pass
            finally:
                self.queue.task_done()
