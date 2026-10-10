"""Giao diện PyQt5: quét trong QThread (không treo), bảng File / Thiết bị /
Phát hiện có lọc và sắp xếp, panel chi tiết, xuất HTML/JSON/CSV."""
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
        self.setWindowTitle("OTInspect – Kiểm kê file OT/ICS")
        self.resize(1300, 820)
        self.result: ScanResult | None = None
        self.worker: ScanWorker | None = None

        # --- thanh chọn đường dẫn
        self.path_edit = QtWidgets.QLineEdit()
        self.path_edit.setPlaceholderText("Chọn file hoặc thư mục cần phân tích…")
        b_file = QtWidgets.QPushButton("Chọn file…")
        b_dir = QtWidgets.QPushButton("Chọn thư mục…")
        self.recursive = QtWidgets.QCheckBox("Quét thư mục con")
        self.recursive.setChecked(True)
        self.b_scan = QtWidgets.QPushButton("Phân tích")
        self.b_scan.setDefault(True)
        b_file.clicked.connect(self.pick_file)
        b_dir.clicked.connect(self.pick_dir)
        self.b_scan.clicked.connect(self.start_scan)
        top = QtWidgets.QHBoxLayout()
        for w in (QtWidgets.QLabel("Đường dẫn:"), self.path_edit, b_file, b_dir, self.recursive, self.b_scan):
            top.addWidget(w)

        # --- bộ lọc + tabs
        self.filter_edit = QtWidgets.QLineEdit()
        self.filter_edit.setPlaceholderText("Lọc nhanh (tên, IP, loại, rule…)")
        self.filter_edit.textChanged.connect(self.apply_filter)
        self.summary_lbl = QtWidgets.QLabel("Chưa quét")

        self.t_files = _table(["Đường dẫn", "Loại", "Mô tả", "Kích thước", "SHA-256", "Lỗi"])
        self.t_assets = _table(["Tên", "Loại", "Hãng", "Model", "Version", "IP", "Subnet", "MAC", "Giao thức", "Nguồn"])
        self.t_find = _table(["Mức", "Rule", "Mô tả", "Thiết bị", "Nguồn"])
        self.t_files.itemSelectionChanged.connect(self.show_detail)
        self.tabs = QtWidgets.QTabWidget()
        self.tabs.addTab(self.t_files, "File")
        self.tabs.addTab(self.t_assets, "Thiết bị")
        self.tabs.addTab(self.t_find, "Phát hiện rủi ro")

        self.detail = QtWidgets.QPlainTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setFont(QtGui.QFontDatabase.systemFont(QtGui.QFontDatabase.FixedFont))
        split = QtWidgets.QSplitter(QtCore.Qt.Vertical)
        split.addWidget(self.tabs)
        split.addWidget(self.detail)
        split.setSizes([520, 220])

        # --- nút dưới
        self.progress = QtWidgets.QProgressBar()
        self.progress.setVisible(False)
        bot = QtWidgets.QHBoxLayout()
        for text, fn in (("Xuất HTML", self.export_html), ("Xuất JSON", self.export_json),
                         ("Xuất CSV", self.export_csv), ("Tham khảo IEC 61850",
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

    # ---------- chọn đường dẫn / kéo thả
    def pick_file(self):
        p, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Chọn file")
        if p:
            self.path_edit.setText(p)

    def pick_dir(self):
        p = QtWidgets.QFileDialog.getExistingDirectory(self, "Chọn thư mục")
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

    # ---------- quét
    def start_scan(self):
        path = self.path_edit.text().strip()
        if not os.path.exists(path):
            QtWidgets.QMessageBox.warning(self, "OTInspect", "Đường dẫn không tồn tại.")
            return
        self.b_scan.setEnabled(False)
        self.progress.setVisible(True)
        self.progress.setValue(0)
        self.summary_lbl.setText("Đang quét…")
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
        QtWidgets.QMessageBox.critical(self, "Lỗi", msg)

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
        self.summary_lbl.setText(f"{len(res.files)} file · {len(res.assets)} thiết bị · "
                                 f"{len(fs)} phát hiện ({high} cao)")
        self.tabs.setTabText(1, f"Thiết bị ({len(res.assets)})")
        self.tabs.setTabText(2, f"Phát hiện rủi ro ({len(fs)})")
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

    # ---------- xuất
    def _need(self) -> bool:
        if not self.result:
            QtWidgets.QMessageBox.information(self, "OTInspect", "Chưa có kết quả để xuất.")
            return False
        return True

    def export_html(self):
        if not self._need():
            return
        p, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Lưu HTML", "ot_report.html", "HTML (*.html)")
        if p:
            to_html(self.result, p)
            webbrowser.open("file://" + os.path.abspath(p))

    def export_json(self):
        if not self._need():
            return
        p, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Lưu JSON", "ot_report.json", "JSON (*.json)")
        if p:
            to_json(self.result, p)

    def export_csv(self):
        if not self._need():
            return
        d = QtWidgets.QFileDialog.getExistingDirectory(self, "Chọn thư mục lưu CSV")
        if d:
            to_csv(self.result, d)
            QtWidgets.QMessageBox.information(self, "OTInspect", f"Đã lưu files/assets/findings.csv vào {d}")


def main() -> int:
    app = QtWidgets.QApplication(sys.argv)
    w = MainWindow()
    w.show()
    return app.exec_()


if __name__ == "__main__":
    sys.exit(main())
