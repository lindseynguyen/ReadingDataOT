# PyInstaller spec: builds two single-file executables.
#   OTInspect      - GUI (no console window on Windows)
#   otinspect-cli  - command line
# Usage:  pyinstaller packaging/otinspect.spec --noconfirm --clean
import os

ROOT = os.path.abspath(os.path.join(SPECPATH, ".."))
datas = [(os.path.join(ROOT, "otinspect", "rules", "builtin.json"), os.path.join("otinspect", "rules")),
         (os.path.join(ROOT, "otinspect", "standards", "mappings.json"), os.path.join("otinspect", "standards"))]
hidden = [
    "otinspect.parsers.scl", "otinspect.parsers.comtrade", "otinspect.parsers.pcap",
    "otinspect.parsers.plc_l5x", "otinspect.parsers.plc_iec", "otinspect.parsers.devicedesc",
    "otinspect.parsers.netconfig", "otinspect.parsers.otcmd",
    "otinspect.parsers.logfile", "otinspect.parsers.archive", "otinspect.parsers.binary",
    "defusedxml.ElementTree", "yaml",
]
excludes = ["tkinter", "unittest", "pydoc", "PyQt5.QtWebEngineWidgets", "PyQt5.QtWebEngineCore",
            "PyQt5.QtQml", "PyQt5.QtQuick", "PyQt5.QtMultimedia", "PyQt5.QtBluetooth", "PyQt5.QtSql",
            "PyQt5.QtNetwork", "PyQt5.QtDesigner", "PyQt5.QtTest", "numpy"]
version_file = os.path.join(SPECPATH, "version_info.txt")
version_file = version_file if os.path.exists(version_file) else None


def build(script, name, console, extra_excludes=()):
    a = Analysis([os.path.join(SPECPATH, script)], pathex=[ROOT], datas=datas, hiddenimports=hidden,
                 excludes=excludes + list(extra_excludes), noarchive=False)
    pyz = PYZ(a.pure)
    return EXE(pyz, a.scripts, a.binaries, a.datas, [], name=name, console=console,
               upx=False, strip=False, debug=False, version=version_file)


gui = build("gui_entry.py", "OTInspect", console=False)
cli = build("cli_entry.py", "otinspect-cli", console=True, extra_excludes=["PyQt5"])
