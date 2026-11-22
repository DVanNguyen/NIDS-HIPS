"""
Producer Thread for Multi-threaded NIDS.
Captures network traffic at high speed from a live network interface or replays PCAP files.
Pushes packets non-blocking into PacketQueue to eliminate packet-drop bottlenecks.
"""
import time
import threading
from typing import Optional
from pathlib import Path
from scapy.all import AsyncSniffer, PcapReader
from core.queue_manager import PacketQueue


class PacketProducer:
    def __init__(self, queue: PacketQueue):
        self.queue = queue
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._sniffer: Optional[AsyncSniffer] = None

    def start_live_capture(self, interface: Optional[str] = None, bpf_filter: str = ""):
        """
        Start live packet capture on network card interface.
        """
        self._running = True
        print(f"[Producer] Starting live capture on interface: {interface or 'Default'} (Filter: '{bpf_filter}')")

        def _packet_callback(pkt):
            if not self._running:
                return
            # Non-blocking put: if queue is full, increment drop count and return instantly
            self.queue.put(pkt, block=False)

        self._sniffer = AsyncSniffer(
            iface=interface,
            filter=bpf_filter if bpf_filter else None,
            prn=_packet_callback,
            store=False
        )
        self._sniffer.start()

    def start_pcap_replay(self, pcap_path: str, speed_multiplier: float = 0.0):
        """
        Replay packets from a PCAP file in a dedicated thread.
        speed_multiplier = 0.0 means replay as fast as possible.
        """
        self._running = True
        self._thread = threading.Thread(
            target=self._pcap_worker,
            args=(pcap_path, speed_multiplier),
            name="PCAP-Producer",
            daemon=True
        )
        self._thread.start()

    def _pcap_worker(self, pcap_path: str, speed_multiplier: float):
        path = Path(pcap_path)
        if not path.exists():
            print(f"[Producer] PCAP file not found: {pcap_path}")
            return

        print(f"[Producer] Replaying PCAP file: {pcap_path} (Speed multiplier: {speed_multiplier})")
        last_pkt_time = None

        try:
            with PcapReader(str(path)) as reader:
                for pkt in reader:
                    if not self._running:
                        break

                    # Optional pacing based on original packet timestamps
                    if speed_multiplier > 0 and hasattr(pkt, "time"):
                        current_pkt_time = float(pkt.time)
                        if last_pkt_time is not None:
                            delay = (current_pkt_time - last_pkt_time) / speed_multiplier
                            if 0 < delay < 2.0:
                                time.sleep(delay)
                        last_pkt_time = current_pkt_time

                    self.queue.put(pkt, block=False)
        except Exception as e:
            print(f"[Producer] Error reading PCAP: {e}")
        finally:
            print("[Producer] PCAP replay finished.")

    def stop(self):
        """Stop packet collection cleanly."""
        self._running = False
        if self._sniffer and self._sniffer.running:
            self._sniffer.stop()
            self._sniffer = None
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)
        print("[Producer] Packet Producer stopped.")
