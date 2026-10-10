"""Backward-compatible entry point: launches the OTInspect GUI.

    python data-kiosk.py
is equivalent to
    python -m otinspect gui
"""
import sys

from otinspect.gui.app import main

if __name__ == "__main__":
    sys.exit(main())
