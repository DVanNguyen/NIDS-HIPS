"""
run_attacker.py - Khởi Chạy Giao Diện Máy Tấn Công (Red Team Exploit Console)
"""
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from part1_attacker.attacker_gui import main

if __name__ == "__main__":
    main()
