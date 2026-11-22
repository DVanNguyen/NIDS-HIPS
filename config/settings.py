"""
Configuration settings for the Multi-threaded Network IDS.
"""
from dataclasses import dataclass
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_DIR = BASE_DIR / "config"
LOGS_DIR = BASE_DIR / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)

# Queue & Concurrency Settings
QUEUE_MAXSIZE: int = 10000        # Maximum packets in buffer before dropping
NUM_CONSUMER_WORKERS: int = 4     # Number of parallel consumer worker threads
PRODUCER_POLL_TIMEOUT: float = 0.5  # Seconds to wait during queue operations

# HTTP Session & Assembly Settings
HTTP_SESSION_TTL: float = 10.0    # Seconds before unfinished TCP/HTTP sessions are purged (Anti-Memory Leak)
HTTP_MAX_BUFFER_SIZE: int = 65536 # 64 KB max payload buffer per session
MAX_SESSIONS_TRACKED: int = 5000  # Max active sessions tracked in memory

# Anomaly Detection Thresholds (Sliding Window: 1.0 second)
SYN_FLOOD_THRESHOLD: int = 40     # SYN packets per second from single IP
PORT_SCAN_THRESHOLD: int = 15     # Distinct destination ports scanned per second from single IP
WINDOW_SIZE_SECONDS: float = 1.0  # Sliding window duration

# Dashboard & Logging Settings
DASHBOARD_HOST: str = "127.0.0.1"
DASHBOARD_PORT: int = 5000
ALERT_LOG_FILE: Path = LOGS_DIR / "alerts.json"
SURICATA_EVE_LOG_DEFAULT: Path = LOGS_DIR / "suricata_eve.json"
