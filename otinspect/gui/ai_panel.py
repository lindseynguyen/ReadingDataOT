"""GUI for the optional internal-AI assistant: profile settings dialog and analysis tab."""
from __future__ import annotations

from PyQt5 import QtCore, QtGui, QtWidgets

from ..ai import (LANGUAGES, PROVIDERS, TASKS, AIConfigError, AIProfile, AIRequestError, ChatClient,
                  check_endpoint, get_api_key, keyring_available, load_profiles, prepare, save_profiles,
                  send, set_api_key)
from ..ai.config import config_path, default_profile_name

PRESETS = {
    "litellm": ("https://llm-gateway.internal.example/v1", "ot-analyst"),
    "openai_compatible": ("http://localhost:11434/v1", "llama3.1:8b"),
    "azure_openai": ("https://my-resource.openai.azure.com", "deployment-name"),
}
STORE_LABELS = {"keyring": "OS keyring (recommended)", "env": "Environment variable", "session": "This session only"}


class _Worker(QtCore.QThread):
    ok = QtCore.pyqtSignal(object)
    err = QtCore.pyqtSignal(str)

    def __init__(self, fn):
        super().__init__()
        self.fn = fn

    def run(self):
        try:
            self.ok.emit(self.fn())
        except (AIConfigError, AIRequestError, ValueError, OSError) as e:
            self.err.emit(str(e))
        except Exception as e:                        # never crash the GUI
            self.err.emit(f"{type(e).__name__}: {e}")


def _file_row(edit: QtWidgets.QLineEdit, title: str, flt: str = "PEM (*.pem *.crt *.cer *.key);;All files (*)"):
    b = QtWidgets.QPushButton("…")
    b.setFixedWidth(32)

    def pick():
        p, _ = QtWidgets.QFileDialog.getOpenFileName(None, title, edit.text(), flt)
        if p:
            edit.setText(p)
    b.clicked.connect(pick)
    h = QtWidgets.QHBoxLayout()
    h.setContentsMargins(0, 0, 0, 0)
    h.addWidget(edit, 1)
    h.addWidget(b)
    w = QtWidgets.QWidget()
    w.setLayout(h)
    return w


class AISettingsDialog(QtWidgets.QDialog):
    """Create / edit AI profiles. API keys go to the keyring, the environment or memory, never to disk."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("AI settings – internal model")
        self.resize(720, 640)
        try:
            self.profiles = load_profiles()
        except (AIConfigError, ValueError, OSError) as e:
            QtWidgets.QMessageBox.warning(self, "AI settings", f"Could not read {config_path()}:\n{e}")
            self.profiles = {}
        self.default = default_profile_name() or next(iter(self.profiles), "")
        self.current: str | None = None
        self._worker = None

        # ---- profile selector
        self.cb_profile = QtWidgets.QComboBox()
        b_new, b_del = QtWidgets.QPushButton("New"), QtWidgets.QPushButton("Delete")
        b_new.clicked.connect(self.new_profile)
        b_del.clicked.connect(self.delete_profile)
        self.ck_default = QtWidgets.QCheckBox("Default profile")
        top = QtWidgets.QHBoxLayout()
        for w in (QtWidgets.QLabel("Profile:"), self.cb_profile, b_new, b_del, self.ck_default):
            top.addWidget(w)
        top.addStretch(1)

        # ---- connection
        self.e_name = QtWidgets.QLineEdit()
        self.cb_provider = QtWidgets.QComboBox()
        for k, v in PROVIDERS.items():
            self.cb_provider.addItem(v, k)
        self.cb_provider.currentIndexChanged.connect(self._provider_changed)
        self.e_url = QtWidgets.QLineEdit()
        self.e_model = QtWidgets.QLineEdit()
        self.e_azver = QtWidgets.QLineEdit()
        self.e_user = QtWidgets.QLineEdit()
        self.e_user.setPlaceholderText("optional, e.g. otinspect-<team> (LiteLLM spend / audit tracking)")
        self.e_headers = QtWidgets.QLineEdit()
        self.e_headers.setPlaceholderText("x-litellm-tags=otinspect; x-team=ot-sec   (no secrets here)")
        conn = QtWidgets.QFormLayout()
        conn.addRow("Name", self.e_name)
        conn.addRow("Provider", self.cb_provider)
        conn.addRow("Base URL", self.e_url)
        conn.addRow("Model / deployment", self.e_model)
        conn.addRow("Azure API version", self.e_azver)
        conn.addRow("User tag", self.e_user)
        conn.addRow("Extra headers", self.e_headers)

        # ---- credentials
        self.cb_store = QtWidgets.QComboBox()
        for k, v in STORE_LABELS.items():
            self.cb_store.addItem(v, k)
        if not keyring_available():
            self.cb_store.model().item(0).setEnabled(False)
            self.cb_store.setItemText(0, "OS keyring (pip install keyring)")
        self.cb_store.currentIndexChanged.connect(self._store_changed)
        self.e_env = QtWidgets.QLineEdit()
        self.e_key = QtWidgets.QLineEdit()
        self.e_key.setEchoMode(QtWidgets.QLineEdit.Password)
        self.e_key.setPlaceholderText("leave empty to keep the stored key")
        self.lbl_key = QtWidgets.QLabel()
        cred = QtWidgets.QFormLayout()
        cred.addRow("Store API key in", self.cb_store)
        cred.addRow("Variable name", self.e_env)
        cred.addRow("API key", self.e_key)
        cred.addRow("", self.lbl_key)

        # ---- security
        self.ck_tls = QtWidgets.QCheckBox("Verify TLS certificate")
        self.e_ca = QtWidgets.QLineEdit()
        self.e_cert, self.e_ckey = QtWidgets.QLineEdit(), QtWidgets.QLineEdit()
        self.e_proxy = QtWidgets.QLineEdit()
        self.e_proxy.setPlaceholderText("empty = direct connection (system proxy is ignored)")
        self.ck_internal = QtWidgets.QCheckBox("Internal endpoints only (refuse public IP addresses)")
        self.e_allowed = QtWidgets.QLineEdit()
        self.e_allowed.setPlaceholderText("hosts allowed even if public, e.g. *.openai.azure.com")
        self.ck_http = QtWidgets.QCheckBox("Allow plain HTTP (lab only: prompts and key travel unencrypted)")
        self.sp_timeout = QtWidgets.QDoubleSpinBox()
        self.sp_timeout.setRange(1, 600)
        self.sp_tokens = QtWidgets.QSpinBox()
        self.sp_tokens.setRange(16, 32000)
        self.sp_temp = QtWidgets.QDoubleSpinBox()
        self.sp_temp.setRange(0, 2)
        self.sp_temp.setSingleStep(0.1)
        sec = QtWidgets.QFormLayout()
        sec.addRow(self.ck_tls)
        sec.addRow("Internal CA bundle", _file_row(self.e_ca, "CA bundle"))
        sec.addRow("Client certificate (mTLS)", _file_row(self.e_cert, "Client certificate"))
        sec.addRow("Client key (mTLS)", _file_row(self.e_ckey, "Client key"))
        sec.addRow("Proxy", self.e_proxy)
        sec.addRow(self.ck_internal)
        sec.addRow("Allowed hosts", self.e_allowed)
        sec.addRow(self.ck_http)
        sec.addRow("Timeout (s)", self.sp_timeout)
        sec.addRow("Max answer tokens", self.sp_tokens)
        sec.addRow("Temperature", self.sp_temp)

        # ---- privacy
        self.ck_ips = QtWidgets.QCheckBox("Mask IP addresses")
        self.ck_macs = QtWidgets.QCheckBox("Mask MAC addresses")
        self.ck_names = QtWidgets.QCheckBox("Mask asset / host names")
        self.ck_paths = QtWidgets.QCheckBox("Mask file paths and names")
        self.ck_secrets = QtWidgets.QCheckBox("Remove passwords, communities, keys and tokens")
        self.sp_find, self.sp_assets = QtWidgets.QSpinBox(), QtWidgets.QSpinBox()
        self.sp_find.setRange(0, 5000)
        self.sp_assets.setRange(0, 5000)
        self.sp_chars = QtWidgets.QSpinBox()
        self.sp_chars.setRange(2000, 2_000_000)
        self.sp_chars.setSingleStep(10000)
        self.ck_confirm = QtWidgets.QCheckBox("Show exactly what will be sent and ask before each request")
        self.ck_audit = QtWidgets.QCheckBox("Audit log (time, user, endpoint, model, hash and size; no content)")
        priv = QtWidgets.QFormLayout()
        for w in (self.ck_ips, self.ck_macs, self.ck_names, self.ck_paths, self.ck_secrets):
            priv.addRow(w)
        priv.addRow("Max findings sent", self.sp_find)
        priv.addRow("Max assets sent", self.sp_assets)
        priv.addRow("Max prompt size (chars)", self.sp_chars)
        priv.addRow(self.ck_confirm)
        priv.addRow(self.ck_audit)
        note = QtWidgets.QLabel("Masked values are replaced by tokens such as IP-3 or ASSET-7. The mapping stays on "
                                "this computer and the real values are put back into the answer locally. "
                                "The scanned folder path, file hashes and file contents are never sent.")
        note.setWordWrap(True)
        note.setStyleSheet("color:#66707a")
        priv.addRow(note)

        tabs = QtWidgets.QTabWidget()
        for lay, title in ((conn, "Connection"), (cred, "API key"), (sec, "Security"), (priv, "Privacy")):
            w = QtWidgets.QWidget()
            w.setLayout(lay)
            tabs.addTab(w, title)

        # ---- buttons
        self.b_test = QtWidgets.QPushButton("Test connection")
        self.b_test.clicked.connect(self.test)
        self.lbl_test = QtWidgets.QLabel()
        self.lbl_test.setWordWrap(True)
        self.lbl_test.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
        bb = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Save | QtWidgets.QDialogButtonBox.Close)
        bb.accepted.connect(self.save)
        bb.rejected.connect(self.reject)
        bot = QtWidgets.QHBoxLayout()
        bot.addWidget(self.b_test)
        bot.addWidget(self.lbl_test, 1)
        bot.addWidget(bb)

        lay = QtWidgets.QVBoxLayout(self)
        lay.addLayout(top)
        lay.addWidget(tabs, 1)
        lay.addWidget(QtWidgets.QLabel(f"Profiles file: {config_path()} (no API keys inside)"))
        lay.addLayout(bot)

        if not self.profiles:
            p = AIProfile(name="internal-gateway", base_url=PRESETS["litellm"][0], model=PRESETS["litellm"][1],
                          secret_store="keyring" if keyring_available() else "env")
            self.profiles[p.name] = p
            self.default = p.name
        self.cb_profile.addItems(list(self.profiles))
        self.cb_profile.currentTextChanged.connect(self._switch)
        self.cb_profile.setCurrentText(self.default)
        self._switch(self.cb_profile.currentText())

    # ---------------------------------------------------------------- form <-> profile
    def _load(self, p: AIProfile):
        self.e_name.setText(p.name)
        self.cb_provider.setCurrentIndex(max(0, self.cb_provider.findData(p.provider)))
        self.e_url.setText(p.base_url)
        self.e_model.setText(p.model)
        self.e_azver.setText(p.azure_api_version)
        self.e_user.setText(p.user_tag)
        self.e_headers.setText("; ".join(f"{k}={v}" for k, v in p.extra_headers.items()))
        self.cb_store.setCurrentIndex(max(0, self.cb_store.findData(p.secret_store)))
        self.e_env.setText(p.api_key_env)
        self.e_key.clear()
        self.ck_tls.setChecked(p.verify_tls)
        self.e_ca.setText(p.ca_bundle)
        self.e_cert.setText(p.client_cert)
        self.e_ckey.setText(p.client_key)
        self.e_proxy.setText(p.proxy)
        self.ck_internal.setChecked(p.internal_only)
        self.e_allowed.setText(", ".join(p.allowed_hosts))
        self.ck_http.setChecked(p.allow_http)
        self.sp_timeout.setValue(p.timeout_s)
        self.sp_tokens.setValue(p.max_tokens)
        self.sp_temp.setValue(p.temperature)
        for ck, v in ((self.ck_ips, p.mask_ips), (self.ck_macs, p.mask_macs), (self.ck_names, p.mask_names),
                      (self.ck_paths, p.mask_paths), (self.ck_secrets, p.mask_secrets),
                      (self.ck_confirm, p.confirm_before_send), (self.ck_audit, p.audit_log)):
            ck.setChecked(v)
        self.sp_find.setValue(p.max_findings)
        self.sp_assets.setValue(p.max_assets)
        self.sp_chars.setValue(p.max_prompt_chars)
        self.ck_default.setChecked(p.name == self.default)
        self._provider_changed()
        self._store_changed()

    def _form(self) -> AIProfile:
        headers = {}
        for part in self.e_headers.text().split(";"):
            if part.strip():
                k, _, v = part.partition("=")
                headers[k.strip()] = v.strip()
        base = self.profiles.get(self.current) or AIProfile()
        p = AIProfile(**{**base.to_dict(),
            "name": self.e_name.text().strip(), "provider": self.cb_provider.currentData(),
            "base_url": self.e_url.text().strip(), "model": self.e_model.text().strip(),
            "azure_api_version": self.e_azver.text().strip() or base.azure_api_version,
            "user_tag": self.e_user.text().strip(), "extra_headers": headers,
            "secret_store": self.cb_store.currentData(), "api_key_env": self.e_env.text().strip(),
            "verify_tls": self.ck_tls.isChecked(), "ca_bundle": self.e_ca.text().strip(),
            "client_cert": self.e_cert.text().strip(), "client_key": self.e_ckey.text().strip(),
            "proxy": self.e_proxy.text().strip(), "internal_only": self.ck_internal.isChecked(),
            "allowed_hosts": [h.strip() for h in self.e_allowed.text().split(",") if h.strip()],
            "allow_http": self.ck_http.isChecked(), "timeout_s": self.sp_timeout.value(),
            "max_tokens": self.sp_tokens.value(), "temperature": round(self.sp_temp.value(), 2),
            "mask_ips": self.ck_ips.isChecked(), "mask_macs": self.ck_macs.isChecked(),
            "mask_names": self.ck_names.isChecked(), "mask_paths": self.ck_paths.isChecked(),
            "mask_secrets": self.ck_secrets.isChecked(), "max_findings": self.sp_find.value(),
            "max_assets": self.sp_assets.value(), "max_prompt_chars": self.sp_chars.value(),
            "confirm_before_send": self.ck_confirm.isChecked(), "audit_log": self.ck_audit.isChecked()})
        p.validate(resolve=False)
        return p

    def _provider_changed(self):
        az = self.cb_provider.currentData() == "azure_openai"
        self.e_azver.setEnabled(az)
        url, model = PRESETS.get(self.cb_provider.currentData(), ("", ""))
        self.e_url.setPlaceholderText(url)
        self.e_model.setPlaceholderText(model)

    def _store_changed(self):
        store = self.cb_store.currentData()
        self.e_env.setEnabled(store == "env")
        self.e_key.setEnabled(store != "env")
        try:
            p = self.profiles.get(self.current) or AIProfile()
            p = AIProfile(**{**p.to_dict(), "secret_store": store, "api_key_env": self.e_env.text() or p.api_key_env})
            has = bool(get_api_key(p))
        except Exception:
            has = False
        where = {"env": f"read from %{self.e_env.text() or 'VAR'}% / ${self.e_env.text() or 'VAR'} at run time",
                 "keyring": "stored in the OS keyring", "session": "kept in memory until OTInspect closes"}[store]
        self.lbl_key.setText(f"Key {where}: {'present' if has else 'not set'}")

    def _switch(self, name: str):
        if name and name in self.profiles:
            self.current = name
            self._load(self.profiles[name])

    # ---------------------------------------------------------------- actions
    def new_profile(self):
        name, ok = QtWidgets.QInputDialog.getText(self, "New AI profile", "Profile name:")
        name = (name or "").strip()
        if not ok or not name:
            return
        if name in self.profiles:
            QtWidgets.QMessageBox.warning(self, "AI settings", "A profile with this name exists.")
            return
        self.profiles[name] = AIProfile(name=name, secret_store="keyring" if keyring_available() else "env")
        self.cb_profile.addItem(name)
        self.cb_profile.setCurrentText(name)

    def delete_profile(self):
        if not self.current or QtWidgets.QMessageBox.question(
                self, "AI settings", f"Delete profile '{self.current}' and its stored key?") != QtWidgets.QMessageBox.Yes:
            return
        p = self.profiles.pop(self.current)
        try:
            set_api_key(p, "")
        except AIConfigError:
            pass
        self.cb_profile.removeItem(self.cb_profile.currentIndex())
        save_profiles(self.profiles, self.default)

    def _apply(self) -> AIProfile | None:
        try:
            p = self._form()
        except (AIConfigError, ValueError) as e:
            QtWidgets.QMessageBox.warning(self, "AI settings", str(e))
            return None
        if p.name != self.current:
            if p.name in self.profiles:
                QtWidgets.QMessageBox.warning(self, "AI settings", "A profile with this name exists.")
                return None
            self.profiles.pop(self.current, None)
            idx = self.cb_profile.currentIndex()
            self.cb_profile.blockSignals(True)
            self.cb_profile.setItemText(idx, p.name)
            self.cb_profile.blockSignals(False)
            self.current = p.name
        self.profiles[p.name] = p
        if self.e_key.text():
            try:
                set_api_key(p, self.e_key.text())
            except Exception as e:
                QtWidgets.QMessageBox.warning(self, "AI settings", f"Could not store the key: {e}")
                return None
            self.e_key.clear()
        if self.ck_default.isChecked() or not self.default:
            self.default = p.name
        self._store_changed()
        return p

    def save(self):
        if self._apply() is None:
            return
        try:
            path = save_profiles(self.profiles, self.default)
        except (AIConfigError, OSError) as e:
            QtWidgets.QMessageBox.warning(self, "AI settings", str(e))
            return
        self.lbl_test.setText(f"Saved to {path}")
        self.accept()

    def test(self):
        p = self._apply()
        if p is None:
            return

        def run():
            p.validate(resolve=False)
            ips = check_endpoint(p)
            c = ChatClient(p)
            lines = [f"Policy OK: {p.host} → {', '.join(ips)}",
                     f"API key: {'present' if c.key else 'not set'}"]
            try:
                models = c.list_models()
                lines.append(f"Model '{p.model}' {'listed' if p.model in models else 'not in /models list'}")
            except AIRequestError as e:
                lines.append(f"/models: {e}")
            r = c.chat([{"role": "user", "content": "Reply with the single word OK."}])
            lines.append(f"Chat OK ({r.model}): {r.text.strip()[:30]}")
            return "\n".join(lines)

        self.b_test.setEnabled(False)
        self.lbl_test.setText("Testing…")
        self._worker = _Worker(run)
        self._worker.ok.connect(lambda s: (self.lbl_test.setText("✔ " + s), self.b_test.setEnabled(True)))
        self._worker.err.connect(lambda s: (self.lbl_test.setText("✘ " + s), self.b_test.setEnabled(True)))
        self._worker.start()


class PreviewDialog(QtWidgets.QDialog):
    def __init__(self, text: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Data that will be sent to the AI endpoint")
        self.resize(900, 640)
        t = QtWidgets.QPlainTextEdit(text)
        t.setReadOnly(True)
        t.setFont(QtGui.QFontDatabase.systemFont(QtGui.QFontDatabase.FixedFont))
        bb = QtWidgets.QDialogButtonBox()
        bb.addButton("Send", QtWidgets.QDialogButtonBox.AcceptRole)
        bb.addButton(QtWidgets.QDialogButtonBox.Cancel)
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        lay = QtWidgets.QVBoxLayout(self)
        lay.addWidget(t, 1)
        lay.addWidget(bb)


class AIPanel(QtWidgets.QWidget):
    """'AI Assistant' tab. get_result / get_finding are callables provided by the main window."""

    def __init__(self, get_result, get_finding, parent=None):
        super().__init__(parent)
        self.get_result, self.get_finding = get_result, get_finding
        self._worker = None
        self.cb_profile = QtWidgets.QComboBox()
        self.cb_task = QtWidgets.QComboBox()
        for k, (label, _) in TASKS.items():
            self.cb_task.addItem(label, k)
        self.cb_task.currentIndexChanged.connect(self._task_changed)
        self.cb_lang = QtWidgets.QComboBox()
        for k, v in LANGUAGES.items():
            self.cb_lang.addItem(v, k)
        self.e_q = QtWidgets.QLineEdit()
        self.e_q.setPlaceholderText("Question about this scan, e.g. Which hosts can stop the PLCs?")
        self.b_settings = QtWidgets.QPushButton("AI settings…")
        self.b_preview = QtWidgets.QPushButton("Preview data")
        self.b_run = QtWidgets.QPushButton("Run analysis")
        self.b_save = QtWidgets.QPushButton("Save answer…")
        self.b_settings.clicked.connect(self.open_settings)
        self.b_preview.clicked.connect(lambda: self.run(preview_only=True))
        self.b_run.clicked.connect(self.run)
        self.b_save.clicked.connect(self.save_answer)
        self.out = QtWidgets.QPlainTextEdit()           # plain text only: model output is never rendered as HTML
        self.out.setReadOnly(True)
        self.out.setPlaceholderText(
            "Optional AI assistance through your organisation's internal model (LiteLLM gateway, vLLM, Ollama, "
            "Azure OpenAI private endpoint).\n\nConfigure a profile in 'AI settings…', scan a folder, then run an "
            "analysis. Identifiers are masked before sending and restored locally. Answers are decision support: "
            "verify them against the findings.")
        self.lbl = QtWidgets.QLabel()
        r1 = QtWidgets.QHBoxLayout()
        for w in (QtWidgets.QLabel("Profile:"), self.cb_profile, QtWidgets.QLabel("Task:"), self.cb_task,
                  QtWidgets.QLabel("Language:"), self.cb_lang):
            r1.addWidget(w)
        r1.addStretch(1)
        r1.addWidget(self.b_settings)
        r2 = QtWidgets.QHBoxLayout()
        r2.addWidget(self.e_q, 1)
        for w in (self.b_preview, self.b_run, self.b_save):
            r2.addWidget(w)
        lay = QtWidgets.QVBoxLayout(self)
        lay.addLayout(r1)
        lay.addLayout(r2)
        lay.addWidget(self.out, 1)
        lay.addWidget(self.lbl)
        self.reload_profiles()
        self._task_changed()

    def reload_profiles(self):
        cur = self.cb_profile.currentText()
        self.cb_profile.clear()
        try:
            names = list(load_profiles())
            dflt = default_profile_name()
        except (AIConfigError, ValueError, OSError) as e:
            names, dflt = [], ""
            self.lbl.setText(f"AI profiles: {e}")
        self.cb_profile.addItems(names)
        self.cb_profile.setCurrentText(cur if cur in names else dflt)
        self.b_run.setEnabled(bool(names))
        self.b_preview.setEnabled(bool(names))
        if not names:
            self.lbl.setText("No AI profile yet: open 'AI settings…'. Nothing is sent anywhere until you run an analysis.")

    def _task_changed(self):
        self.e_q.setVisible(self.cb_task.currentData() == "question")

    def open_settings(self):
        AISettingsDialog(self).exec_()
        self.reload_profiles()

    def explain(self, finding):
        self.cb_task.setCurrentIndex(self.cb_task.findData("explain"))
        self.run(focus=finding)

    def run(self, preview_only: bool = False, focus=None):
        res = self.get_result()
        if res is None:
            QtWidgets.QMessageBox.information(self, "AI Assistant", "Scan a file or folder first.")
            return
        try:
            p = load_profiles()[self.cb_profile.currentText()]
            task = self.cb_task.currentData()
            if task == "explain" and focus is None:
                focus = self.get_finding()
            req = prepare(res, p, task, question=self.e_q.text(), focus=focus,
                          language=self.cb_lang.currentData())
        except (KeyError, AIConfigError, ValueError, OSError) as e:
            QtWidgets.QMessageBox.warning(self, "AI Assistant", str(e) or "Select a profile")
            return
        if preview_only:
            PreviewDialog(req.preview(), self).exec_()
            return
        if p.confirm_before_send and PreviewDialog(req.preview(), self).exec_() != QtWidgets.QDialog.Accepted:
            return
        self.b_run.setEnabled(False)
        self.lbl.setText(f"Sending {req.stats['chars']:,} characters to {p.host} ({req.stats['masked']})…")
        self._worker = _Worker(lambda: send(req))
        self._worker.ok.connect(self._done)
        self._worker.err.connect(self._failed)
        self._worker.start()

    def _done(self, ans):
        self.b_run.setEnabled(True)
        self.out.setPlainText(ans.text)
        u = ans.usage or {}
        tok = f", {u.get('prompt_tokens', '?')}+{u.get('completion_tokens', '?')} tokens" if u else ""
        cut = " – answer was cut off (raise Max answer tokens)" if ans.finish_reason == "length" else ""
        self.lbl.setText(f"{TASKS[ans.task][0]} · model {ans.model}{tok}{cut} · decision support, verify before acting")

    def _failed(self, msg):
        self.b_run.setEnabled(True)
        self.lbl.setText("")
        QtWidgets.QMessageBox.warning(self, "AI Assistant", msg)

    def save_answer(self):
        if not self.out.toPlainText():
            return
        p, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save answer", "otinspect_ai.md", "Markdown (*.md);;Text (*.txt)")
        if p:
            with open(p, "w", encoding="utf-8") as fh:
                fh.write("<!-- OTInspect AI answer. Contains real identifiers: handle as confidential. -->\n\n")
                fh.write(self.out.toPlainText() + "\n")
