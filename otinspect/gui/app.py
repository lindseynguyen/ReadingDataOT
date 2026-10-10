"""PyQt5 GUI: scans in a QThread (no freezing), File / Asset /
Finding tables with filter and sort, detail panel, HTML/JSON/CSV export."""
from __future__ import annotations

import json
import os
import pathlib
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

    def __init__(self, path: str, recursive: bool, rules: list[str], advisories: str | None):
        super().__init__()
        self.path, self.recursive = path, recursive
        self.rules, self.advisories = rules, advisories

    def run(self):
        try:
            res = scan(self.path, self.recursive, progress=lambda i, n, p: self.progress.emit(i, n, p),
                       rules=self.rules, advisories=self.advisories)
            self.done.emit(res)
        except Exception as e:
            self.failed.emit(f"{type(e).__name__}: {e}")


class SortItem(QtWidgets.QTableWidgetItem):
    """Item that sorts by an explicit key (severity order, numbers) instead of text."""

    def __init__(self, text: str, key):
        super().__init__(text)
        self.key = key

    def __lt__(self, other):
        if isinstance(other, SortItem):
            try:
                return self.key < other.key
            except TypeError:
                pass
        return super().__lt__(other)


MAX_COL_W = 420


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
            if isinstance(v, (int, float)):
                it = QtWidgets.QTableWidgetItem()
                it.setData(QtCore.Qt.DisplayRole, v)
            elif isinstance(v, str) and v in SEV_ORDER:
                it = SortItem(v, SEV_ORDER[v])
            else:
                it = QtWidgets.QTableWidgetItem(str(v))
                it.setToolTip(str(v) if len(str(v)) > 60 else "")
            if payload is not None and c == 0:
                it.setData(QtCore.Qt.UserRole, payload[r])
            if colors and colors[r]:
                it.setBackground(QtGui.QColor(colors[r]))
                it.setForeground(QtGui.QColor("#1d2329"))
            t.setItem(r, c, it)
    t.setSortingEnabled(True)
    t.resizeColumnsToContents()
    for c in range(t.columnCount() - 1):
        if t.columnWidth(c) > MAX_COL_W:
            t.setColumnWidth(c, MAX_COL_W)


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("OTInspect – OT/ICS File Inventory")
        self.resize(1300, 820)
        self.result: ScanResult | None = None
        self.worker: ScanWorker | None = None
        self.settings = QtCore.QSettings("OTInspect", "OTInspect")

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
        self.t_find = _table(["Severity", "Rule", "Asset", "Source", "Message"])
        self.t_files.itemSelectionChanged.connect(self.show_detail)
        self.t_assets.itemSelectionChanged.connect(self.show_asset)
        self.t_find.itemSelectionChanged.connect(self.show_finding)
        self._findings = []
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
                         ("Export CSV", self.export_csv), ("Compare SCD…", self.compare_scd),
                         ("Advisory DB…", self.pick_advisories), ("Rules folder…", self.pick_rules)):
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
        rules_dir = self.settings.value("rules_dir", "") or ""
        adv = self.settings.value("advisories", "") or None
        self.worker = ScanWorker(path, self.recursive.isChecked(), [rules_dir] if rules_dir else [], adv)
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
        fs = sorted(res.findings, key=lambda x: SEV_ORDER.get(x.severity, 9))
        _fill(self.t_find, [[x.severity, x.rule, x.asset, os.path.basename(x.source), x.message] for x in fs],
              payload=list(range(len(fs))), colors=[SEV_COLOR.get(x.severity) for x in fs])
        self._findings = fs
        _fill(self.t_assets, [[a.name, a.kind, a.vendor, a.model, a.version, a.ip, a.subnet, a.mac,
                               ", ".join(a.protocols), os.path.basename(a.source)] for a in res.assets],
              payload=list(range(len(res.assets))))
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

    def _selected(self, t):
        rows = t.selectionModel().selectedRows()
        if not rows or not self.result:
            return None
        return t.item(rows[0].row(), 0).data(QtCore.Qt.UserRole)

    def show_asset(self):
        i = self._selected(self.t_assets)
        if i is not None:
            from dataclasses import asdict
            self.detail.setPlainText(json.dumps(asdict(self.result.assets[i]), ensure_ascii=False, indent=2))

    def show_finding(self):
        i = self._selected(self.t_find)
        if i is not None:
            f = self._findings[i]
            self.detail.setPlainText(f"[{f.severity.upper()}] {f.rule}\n\n{f.message}\n\nAsset:  {f.asset}\nSource: {f.source}")

    def apply_filter(self, text: str):
        text = text.lower().strip()
        for t in (self.t_files, self.t_assets, self.t_find):
            for r in range(t.rowCount()):
                hit = not text or any(text in (t.item(r, c).text().lower() if t.item(r, c) else "")
                                      for c in range(t.columnCount()))
                t.setRowHidden(r, not hit)

    # ---------- settings / tools
    def pick_advisories(self):
        cur = self.settings.value("advisories", "") or ""
        p, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Advisory DB (built with: otinspect advisories import)", cur, "JSON (*.json)")
        if p:
            self.settings.setValue("advisories", p)
            self.statusBar().showMessage(f"Advisory DB: {p} (used on next scan)", 6000)
        elif cur and QtWidgets.QMessageBox.question(self, "OTInspect", "Stop using the advisory DB?") \
                == QtWidgets.QMessageBox.Yes:
            self.settings.setValue("advisories", "")

    def pick_rules(self):
        d = QtWidgets.QFileDialog.getExistingDirectory(self, "Folder with extra YAML/JSON rules")
        self.settings.setValue("rules_dir", d or "")
        self.statusBar().showMessage(f"Extra rules: {d or 'none'} (used on next scan)", 6000)

    def compare_scd(self):
        flt = "SCL (*.scd *.icd *.cid *.iid *.ssd *.sed *.xml);;All files (*)"
        old, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Old SCL file", "", flt)
        if not old:
            return
        new, _ = QtWidgets.QFileDialog.getOpenFileName(self, "New SCL file", os.path.dirname(old), flt)
        if not new:
            return
        from ..diff import diff_scl, diff_text
        from ..report.export import diff_to_html
        try:
            res = diff_scl(old, new)
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Compare SCD", str(e))
            return
        self.detail.setPlainText(diff_text(res))
        out, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save diff report", "scd_diff.html", "HTML (*.html)")
        if out:
            diff_to_html(res, out)
            webbrowser.open(pathlib.Path(out).resolve().as_uri())

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
            webbrowser.open(pathlib.Path(p).resolve().as_uri())

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
