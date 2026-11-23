"""
run_defense.py - Trình Khởi Chạy Giao Diện Phòng Thủ Mạng (Máy Nạn Nhân)
Mở Trung Tâm Điều Hành SOC: NIDS DPI + HIPS Firewall + 4 Đòn Phản Công + Ngrok Internet
"""
import sys
from pathlib import Path
import tkinter as tk

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from gui_launcher import SOCDefenseGUI

if __name__ == "__main__":
    root = tk.Tk()
    app = SOCDefenseGUI(root)
    root.mainloop()
