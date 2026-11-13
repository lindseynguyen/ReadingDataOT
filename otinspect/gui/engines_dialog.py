"""GUI settings for the optional YARA and capa engines (stored in QSettings)."""
from __future__ import annotations

from PyQt5 import QtCore, QtWidgets

from ..engines import EngineConfig, status
from ..engines.yara_engine import compile_rules


def config_from_settings(s: QtCore.QSettings, workers: int = 4) -> EngineConfig:
    def b(key, d=False):
        v = s.value(key, d)
        return v if isinstance(v, bool) else str(v).lower() == "true"
    yr = [p for p in str(s.value("engines/yara_rules", "") or "").split("|") if p]
    return EngineConfig(
        yara=b("engines/yara"), yara_rules=yr, yara_builtin=b("engines/yara_builtin", True),
        yara_timeout=int(s.value("engines/yara_timeout", 60)),
        capa=b("engines/capa"), capa_cmd=str(s.value("engines/capa_path", "") or "") or None,
        capa_rules=str(s.value("engines/capa_rules", "") or ""), capa_sigs=str(s.value("engines/capa_sigs", "") or ""),
        capa_timeout=float(s.value("engines/capa_timeout", 180)), capa_workers=int(s.value("engines/capa_workers", 2)),
        capa_max_mb=float(s.value("engines/capa_max_mb", 32)), max_file_mb=float(s.value("engines/max_mb", 128)),
        workers=workers)


class _Status(QtCore.QThread):
    done = QtCore.pyqtSignal(object)

    def __init__(self, cfg):
        super().__init__()
        self.cfg = cfg

    def run(self):
        try:
            st = status(self.cfg)
            rs = compile_rules(self.cfg.yara_rules, self.cfg.yara_builtin) if st["yara"]["available"] else None
            st["yara"]["compiled"] = len(rs.files) if rs else 0
            st["yara"]["errors"] = rs.errors if rs else []
        except Exception as e:
            st = {"error": f"{type(e).__name__}: {e}"}
        self.done.emit(st)


def _browse(edit: QtWidgets.QLineEdit, folder: bool, title: str):
    b = QtWidgets.QPushButton("…")
    b.setFixedWidth(32)

    def pick():
        p = (QtWidgets.QFileDialog.getExistingDirectory(None, title, edit.text()) if folder
             else QtWidgets.QFileDialog.getOpenFileName(None, title, edit.text())[0])
        if p:
            edit.setText(p)
    b.clicked.connect(pick)
    w = QtWidgets.QWidget()
    h = QtWidgets.QHBoxLayout(w)
    h.setContentsMargins(0, 0, 0, 0)
    h.addWidget(edit, 1)
    h.addWidget(b)
    return w


class EnginesDialog(QtWidgets.QDialog):
    def __init__(self, settings: QtCore.QSettings, parent=None):
        super().__init__(parent)
        self.s = settings
        self.setWindowTitle("Detection engines – YARA and capa")
        self.resize(680, 520)
        cfg = config_from_settings(settings)

        self.ck_yara = QtWidgets.QCheckBox("Scan files with YARA")
        self.ck_yara.setChecked(cfg.yara)
        self.ck_builtin = QtWidgets.QCheckBox("Include the built-in OT/ICS rules")
        self.ck_builtin.setChecked(cfg.yara_builtin)
        self.lst_rules = QtWidgets.QListWidget()
        self.lst_rules.addItems(cfg.yara_rules)
        self.lst_rules.setMaximumHeight(90)
        b_add_dir, b_add_file, b_del = (QtWidgets.QPushButton(t) for t in ("Add folder…", "Add file…", "Remove"))
        b_add_dir.clicked.connect(lambda: self._add(True))
        b_add_file.clicked.connect(lambda: self._add(False))
        b_del.clicked.connect(lambda: [self.lst_rules.takeItem(self.lst_rules.row(i))
                                       for i in self.lst_rules.selectedItems()])
        rb = QtWidgets.QHBoxLayout()
        for w in (b_add_dir, b_add_file, b_del):
            rb.addWidget(w)
        rb.addStretch(1)
        self.sp_ytime = QtWidgets.QSpinBox()
        self.sp_ytime.setRange(1, 3600)
        self.sp_ytime.setValue(cfg.yara_timeout)
        self.sp_max = QtWidgets.QDoubleSpinBox()
        self.sp_max.setRange(0, 100000)
        self.sp_max.setValue(cfg.max_file_mb)
        y = QtWidgets.QFormLayout()
        y.addRow(self.ck_yara)
        y.addRow(self.ck_builtin)
        y.addRow("Extra rule files / folders", self.lst_rules)
        y.addRow("", rb)
        y.addRow("Timeout per file (s)", self.sp_ytime)
        y.addRow("Skip files larger than (MB, 0 = no limit)", self.sp_max)
        gy = QtWidgets.QGroupBox("YARA")
        gy.setLayout(y)

        self.ck_capa = QtWidgets.QCheckBox("Identify capabilities of executables (PE / ELF / .NET) with capa")
        self.ck_capa.setChecked(cfg.capa)
        self.e_capa = QtWidgets.QLineEdit(cfg.capa_cmd or "")
        self.e_capa.setPlaceholderText("capa.exe from github.com/mandiant/capa/releases (empty = auto-detect)")
        self.e_crules = QtWidgets.QLineEdit(cfg.capa_rules)
        self.e_crules.setPlaceholderText("only for pip-installed capa (standalone capa has rules embedded)")
        self.e_csigs = QtWidgets.QLineEdit(cfg.capa_sigs)
        self.sp_ctime = QtWidgets.QSpinBox()
        self.sp_ctime.setRange(10, 7200)
        self.sp_ctime.setValue(int(cfg.capa_timeout))
        self.sp_cwork = QtWidgets.QSpinBox()
        self.sp_cwork.setRange(1, 16)
        self.sp_cwork.setValue(cfg.capa_workers)
        self.sp_cmax = QtWidgets.QDoubleSpinBox()
        self.sp_cmax.setRange(0, 100000)
        self.sp_cmax.setValue(cfg.capa_max_mb)
        c = QtWidgets.QFormLayout()
        c.addRow(self.ck_capa)
        c.addRow("capa executable", _browse(self.e_capa, False, "capa executable"))
        c.addRow("Rules folder", _browse(self.e_crules, True, "capa rules"))
        c.addRow("Signatures folder", _browse(self.e_csigs, True, "capa signatures"))
        c.addRow("Timeout per executable (s)", self.sp_ctime)
        c.addRow("Parallel capa processes", self.sp_cwork)
        c.addRow("Skip executables larger than (MB)", self.sp_cmax)
        gc = QtWidgets.QGroupBox("capa")
        gc.setLayout(c)

        self.lbl = QtWidgets.QLabel("Click 'Check engines' to see what is installed.")
        self.lbl.setWordWrap(True)
        self.lbl.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
        self.b_check = QtWidgets.QPushButton("Check engines")
        self.b_check.clicked.connect(self.check)
        note = QtWidgets.QLabel("Nothing is executed: YARA matches bytes, capa analyses statically in a separate "
                                "process with a time limit. Results are cached by file hash.")
        note.setWordWrap(True)
        note.setStyleSheet("color:#66707a")
        bb = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Save | QtWidgets.QDialogButtonBox.Cancel)
        bb.accepted.connect(self.save)
        bb.rejected.connect(self.reject)
        bot = QtWidgets.QHBoxLayout()
        bot.addWidget(self.b_check)
        bot.addStretch(1)
        bot.addWidget(bb)
        lay = QtWidgets.QVBoxLayout(self)
        for w in (gy, gc, note, self.lbl):
            lay.addWidget(w)
        lay.addLayout(bot)
        self._t = None

    def _add(self, folder: bool):
        if folder:
            p = QtWidgets.QFileDialog.getExistingDirectory(self, "Folder with YARA rules")
        else:
            p = QtWidgets.QFileDialog.getOpenFileName(self, "YARA rule file", "", "YARA (*.yar *.yara *.rule *.rules);;All files (*)")[0]
        if p:
            self.lst_rules.addItem(p)

    def _cfg(self) -> EngineConfig:
        return EngineConfig(yara=self.ck_yara.isChecked(), yara_builtin=self.ck_builtin.isChecked(),
                            yara_rules=[self.lst_rules.item(i).text() for i in range(self.lst_rules.count())],
                            yara_timeout=self.sp_ytime.value(), capa=self.ck_capa.isChecked(),
                            capa_cmd=self.e_capa.text().strip() or None, capa_rules=self.e_crules.text().strip(),
                            capa_sigs=self.e_csigs.text().strip(), capa_timeout=self.sp_ctime.value(),
                            capa_workers=self.sp_cwork.value(), capa_max_mb=self.sp_cmax.value(),
                            max_file_mb=self.sp_max.value())

    def check(self):
        self.b_check.setEnabled(False)
        self.lbl.setText("Checking…")
        self._t = _Status(self._cfg())
        self._t.done.connect(self._show)
        self._t.start()

    def _show(self, st):
        self.b_check.setEnabled(True)
        if "error" in st:
            self.lbl.setText("✘ " + st["error"])
            return
        y, c = st["yara"], st["capa"]
        lines = [(f"✔ YARA: {y['backend']} {y['version']}, {y['compiled']} rule file(s) compiled"
                  if y["available"] else "✘ YARA: not installed (pip install yara-python)")]
        lines += [f"   ! {e}" for e in y.get("errors", [])[:5]]
        lines.append(f"✔ capa {c['version']} ({c['command']})" if c["available"]
                     else f"✘ capa: {c.get('error') or 'not found'}")
        self.lbl.setText("\n".join(lines))

    def save(self):
        c = self._cfg()
        s = self.s
        s.setValue("engines/yara", c.yara)
        s.setValue("engines/yara_builtin", c.yara_builtin)
        s.setValue("engines/yara_rules", "|".join(c.yara_rules))
        s.setValue("engines/yara_timeout", c.yara_timeout)
        s.setValue("engines/max_mb", c.max_file_mb)
        s.setValue("engines/capa", c.capa)
        s.setValue("engines/capa_path", c.capa_cmd or "")
        s.setValue("engines/capa_rules", c.capa_rules)
        s.setValue("engines/capa_sigs", c.capa_sigs)
        s.setValue("engines/capa_timeout", c.capa_timeout)
        s.setValue("engines/capa_workers", c.capa_workers)
        s.setValue("engines/capa_max_mb", c.capa_max_mb)
        self.accept()
