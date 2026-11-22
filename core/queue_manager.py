"""
Thread-safe Packet Queue with real-time performance telemetry.
Monitors queue occupancy, packet drops, and throughput.
"""
import time
import queue
import threading
from typing import Optional, Dict, Any
from config.settings import QUEUE_MAXSIZE


class PacketQueue:
    def __init__(self, maxsize: int = QUEUE_MAXSIZE):
        self._maxsize = maxsize
        self._queue = queue.Queue(maxsize=maxsize)
        self._lock = threading.Lock()

        # Telemetry metrics
        self.total_received = 0
        self.total_processed = 0
        self.total_dropped = 0
        self._last_calc_time = time.time()
        self._last_processed_count = 0
        self.current_pps = 0.0

    def put(self, packet, block: bool = False, timeout: Optional[float] = None) -> bool:
        """
        Put packet into queue. Drops packet safely if queue is full to prevent memory explosion.
        """
        try:
            self._queue.put(packet, block=block, timeout=timeout)
            with self._lock:
                self.total_received += 1
            return True
        except queue.Full:
            with self._lock:
                self.total_dropped += 1
            return False

    def get(self, block: bool = True, timeout: Optional[float] = 0.5):
        """
        Retrieve packet from queue.
        """
        try:
            packet = self._queue.get(block=block, timeout=timeout)
            with self._lock:
                self.total_processed += 1
            return packet
        except queue.Empty:
            return None

    def task_done(self):
        self._queue.task_done()

    def get_stats(self) -> Dict[str, Any]:
        """
        Return snapshot of queue performance metrics for Web Dashboard.
        """
        now = time.time()
        with self._lock:
            q_size = self._queue.qsize()
            occupancy = round((q_size / self._maxsize) * 100, 2) if self._maxsize > 0 else 0.0

            # Calculate Packets Per Second (PPS)
            dt = now - self._last_calc_time
            if dt >= 0.5:
                processed_diff = self.total_processed - self._last_processed_count
                self.current_pps = round(processed_diff / dt, 1)
                self._last_calc_time = now
                self._last_processed_count = self.total_processed

            return {
                "queue_size": q_size,
                "max_size": self._maxsize,
                "occupancy_percent": occupancy,
                "total_received": self.total_received,
                "total_processed": self.total_processed,
                "total_dropped": self.total_dropped,
                "pps": self.current_pps,
            }
