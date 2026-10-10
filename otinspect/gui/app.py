"""PyQt5 GUI: scans in a QThread (no freezing), File / Asset /
Finding tables with filter and sort, detail panel, HTML/JSON/CSV export."""
from __future__ import annotations

import json
import os
import sys
import webbrowser

from PyQt5 import QtCore, QtGui, QtWidgets

from ..core.model import ScanResult
from ..core.scanner import scan
from ..report.export import SEV_ORDER, to_csv, to_html, to_json

SEV_COLOR = {"high": "#f8d7d3", "medium": "#fbe7c6", "low": "#dde9f7", "info": "#ececea"}


class ScanWorker(QtCore.QThread):
    progress = QtCore.pyqtSignal(int, int, str)
    done = QtCore.pyqtSignal(object)
    failed = QtCore.pyqtSignal(str)

    def __init__(self, path: str, recursive: bool):
        super().__init__()
        self.path, self.recursive = path, recursive

    def run(self):
        try:
            res = scan(self.path, self.recursive, progress=lambda i, n, p: self.progress.emit(i, n, p))
            self.done.emit(res)
        except Exception as e:
            self.failed.emit(f"{type(e).__name__}: {e}")


def _table(headers: list[str]) -> QtWidgets.QTableWidget:
    t = QtWidgets.QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
    t.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
    t.setSortingEnabled(True)
    t.horizontalHeader().setStretchLastSection(True)
    t.verticalHeader().setVisible(False)
    return t


def _fill(t: QtWidgets.QTableWidget, rows: list[list], payload: list | None = None, colors: list | None = None):
    t.setSortingEnabled(False)
    t.setRowCount(len(rows))
    for r, row in enumerate(rows):
        for c, v in enumerate(row):
            it = QtWidgets.QTableWidgetItem()
            if isinstance(v, (int, float)):
                it.setData(QtCore.Qt.DisplayRole, v)
            else:
                it.setText(str(v))
            if payload is not None and c == 0:
                it.setData(QtCore.Qt.UserRole, payload[r])
            if colors and colors[r]:
                it.setBackground(QtGui.QColor(colors[r]))
                it.setForeground(QtGui.QColor("#1d2329"))
            t.setItem(r, c, it)
    t.setSortingEnabled(True)
    t.resizeColumnsToContents()


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("OTInspect – OT/ICS File Inventory")
        self.resize(1300, 820)
        self.result: ScanResult | None = None
        self.worker: ScanWorker | None = None

        # --- path bar
        self.path_edit = QtWidgets.QLineEdit()
        self.path_edit.setPlaceholderText("Select a file or folder to analyze…")
        b_file = QtWidgets.QPushButton("Open file…")
        b_dir = QtWidgets.QPushButton("Open folder…")
        self.recursive = QtWidgets.QCheckBox("Include subfolders")
        self.recursive.setChecked(True)
        self.b_scan = QtWidgets.QPushButton("Analyze")
        self.b_scan.setDefault(True)
        b_file.clicked.connect(self.pick_file)
        b_dir.clicked.connect(self.pick_dir)
        self.b_scan.clicked.connect(self.start_scan)
        top = QtWidgets.QHBoxLayout()
        for w in (QtWidgets.QLabel("Path:"), self.path_edit, b_file, b_dir, self.recursive, self.b_scan):
            top.addWidget(w)

        # --- filter + tabs
        self.filter_edit = QtWidgets.QLineEdit()
        self.filter_edit.setPlaceholderText("Quick filter (name, IP, type, rule…)")
        self.filter_edit.textChanged.connect(self.apply_filter)
        self.summary_lbl = QtWidgets.QLabel("Not scanned yet")

        self.t_files = _table(["Path", "Category", "Description", "Size", "SHA-256", "Error"])
        self.t_assets = _table(["Name", "Kind", "Vendor", "Model", "Version", "IP", "Subnet", "MAC", "Protocols", "Source"])
        self.t_find = _table(["Severity", "Rule", "Message", "Asset", "Source"])
        self.t_files.itemSelectionChanged.connect(self.show_detail)
        self.tabs = QtWidgets.QTabWidget()
        self.tabs.addTab(self.t_files, "File")
        self.tabs.addTab(self.t_assets, "Assets")
        self.tabs.addTab(self.t_find, "Findings")

        self.detail = QtWidgets.QPlainTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setFont(QtGui.QFontDatabase.systemFont(QtGui.QFontDatabase.FixedFont))
        split = QtWidgets.QSplitter(QtCore.Qt.Vertical)
        split.addWidget(self.tabs)
        split.addWidget(self.detail)
        split.setSizes([520, 220])

        # --- bottom bar
        self.progress = QtWidgets.QProgressBar()
        self.progress.setVisible(False)
        bot = QtWidgets.QHBoxLayout()
        for text, fn in (("Export HTML", self.export_html), ("Export JSON", self.export_json),
                         ("Export CSV", self.export_csv), ("IEC 61850 reference",
                                                         lambda: webbrowser.open("https://iec61850.dvl.iec.ch/"))):
            b = QtWidgets.QPushButton(text)
            b.clicked.connect(fn)
            bot.addWidget(b)
        bot.addStretch(1)
        bot.addWidget(self.progress, 2)

        lay = QtWidgets.QVBoxLayout()
        lay.addLayout(top)
        fl = QtWidgets.QHBoxLayout()
        fl.addWidget(self.filter_edit, 1)
        fl.addWidget(self.summary_lbl)
        lay.addLayout(fl)
        lay.addWidget(split, 1)
        lay.addLayout(bot)
        w = QtWidgets.QWidget()
        w.setLayout(lay)
        self.setCentralWidget(w)
        self.setAcceptDrops(True)

    # ---------- path selection / drag and drop
    def pick_file(self):
        p, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Open file")
        if p:
            self.path_edit.setText(p)

    def pick_dir(self):
        p = QtWidgets.QFileDialog.getExistingDirectory(self, "Open folder")
        if p:
            self.path_edit.setText(p)

    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()

    def dropEvent(self, e):
        urls = e.mimeData().urls()
        if urls:
            self.path_edit.setText(urls[0].toLocalFile())
            self.start_scan()

    # ---------- scan
    def start_scan(self):
        path = self.path_edit.text().strip()
        if not os.path.exists(path):
            QtWidgets.QMessageBox.warning(self, "OTInspect", "Path does not exist.")
            return
        self.b_scan.setEnabled(False)
        self.progress.setVisible(True)
        self.progress.setValue(0)
        self.summary_lbl.setText("Scanning…")
        self.worker = ScanWorker(path, self.recursive.isChecked())
        self.worker.progress.connect(self.on_progress)
        self.worker.done.connect(self.on_done)
        self.worker.failed.connect(self.on_failed)
        self.worker.start()

    def on_progress(self, i, n, p):
        self.progress.setMaximum(max(n, 1))
        self.progress.setValue(i)
        self.statusBar().showMessage(p)

    def on_failed(self, msg):
        self.b_scan.setEnabled(True)
        self.progress.setVisible(False)
        QtWidgets.QMessageBox.critical(self, "Error", msg)

    def on_done(self, res: ScanResult):
        self.result = res
        self.b_scan.setEnabled(True)
        self.progress.setVisible(False)
        self.statusBar().clearMessage()
        _fill(self.t_files, [[f.path, f.category, f.file_type, f.size, f.sha256[:16], f.error] for f in res.files],
              payload=list(range(len(res.files))))
        _fill(self.t_assets, [[a.name, a.kind, a.vendor, a.model, a.version, a.ip, a.subnet, a.mac,
                               ", ".join(a.protocols), os.path.basename(a.source)] for a in res.assets])
        fs = sorted(res.findings, key=lambda x: SEV_ORDER.get(x.severity, 9))
        _fill(self.t_find, [[x.severity, x.rule, x.message, x.asset, os.path.basename(x.source)] for x in fs],
              colors=[SEV_COLOR.get(x.severity) for x in fs])
        high = sum(1 for x in fs if x.severity == "high")
        self.summary_lbl.setText(f"{len(res.files)} files · {len(res.assets)} assets · "
                                 f"{len(fs)} findings ({high} high)")
        self.tabs.setTabText(1, f"Assets ({len(res.assets)})")
        self.tabs.setTabText(2, f"Findings ({len(fs)})")
        self.apply_filter(self.filter_edit.text())

    def show_detail(self):
        if not self.result:
            return
        rows = self.t_files.selectionModel().selectedRows()
        if not rows:
            return
        idx = self.t_files.item(rows[0].row(), 0).data(QtCore.Qt.UserRole)
        f = self.result.files[idx]
        self.detail.setPlainText(json.dumps(f.to_dict(), ensure_ascii=False, indent=2))

    def apply_filter(self, text: str):
        text = text.lower().strip()
        for t in (self.t_files, self.t_assets, self.t_find):
            for r in range(t.rowCount()):
                hit = not text or any(text in (t.item(r, c).text().lower() if t.item(r, c) else "")
                                      for c in range(t.columnCount()))
                t.setRowHidden(r, not hit)

    # ---------- export
    def _need(self) -> bool:
        if not self.result:
            QtWidgets.QMessageBox.information(self, "OTInspect", "Nothing to export yet.")
            return False
        return True

    def export_html(self):
        if not self._need():
            return
        p, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save HTML", "ot_report.html", "HTML (*.html)")
        if p:
            to_html(self.result, p)
            webbrowser.open("file://" + os.path.abspath(p))

    def export_json(self):
        if not self._need():
            return
        p, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save JSON", "ot_report.json", "JSON (*.json)")
        if p:
            to_json(self.result, p)

    def export_csv(self):
        if not self._need():
            return
        d = QtWidgets.QFileDialog.getExistingDirectory(self, "Choose folder for CSV files")
        if d:
            to_csv(self.result, d)
            QtWidgets.QMessageBox.information(self, "OTInspect", f"Saved files/assets/findings.csv to {d}")


def main() -> int:
    app = QtWidgets.QApplication(sys.argv)
    w = MainWindow()
    w.show()
    return app.exec_()


if __name__ == "__main__":
    sys.exit(main())
