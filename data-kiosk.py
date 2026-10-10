"""Giữ tương thích tên file cũ: chạy giao diện OTInspect.

    python data-kiosk.py
tương đương
    python -m otinspect gui
"""
import sys

from otinspect.gui.app import main

if __name__ == "__main__":
    sys.exit(main())
