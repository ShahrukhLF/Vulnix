#!/usr/bin/env python3
"""
Vulnix GUI — Final FYP-I Edition (Modern Dark Theme)
Author: Shahrukh Karim | Supervisor: Dr. Husnain Mansoor
"""

import sys, os, json, subprocess, getpass, glob
from datetime import datetime
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QTextEdit, QProgressBar, QTableWidget,
    QTableWidgetItem, QMessageBox, QDialog, QFormLayout, QFileDialog, QFrame
)
from PyQt5.QtGui import QFont

# ---------- Authentication Helpers ----------
try:
    import pam
    PAM_AVAILABLE = True
except Exception:
    PAM_AVAILABLE = False

CONFIG_PATH = os.path.expanduser("~/.vulnix_config.json")
DEFAULT_CONFIG = {
    "auth_user": getpass.getuser(),
    "scan_paths": {
        "network": "./scripts/scan_network.sh",
        "web": "./scripts/scan_web.sh",
        "full": "./scripts/run_full_assessment.sh"
    },
    "last_report": ""
}


def load_config():
    if os.path.exists(CONFIG_PATH):
        try:
            return json.load(open(CONFIG_PATH))
        except Exception:
            pass
    json.dump(DEFAULT_CONFIG, open(CONFIG_PATH, "w"), indent=2)
    return DEFAULT_CONFIG.copy()


def save_config(cfg):
    json.dump(cfg, open(CONFIG_PATH, "w"), indent=2)


def pam_authenticate(u, p):
    if not PAM_AVAILABLE:
        return False
    try:
        return pam.pam().authenticate(u, p)
    except Exception:
        return False


def sudo_validate_current_user(p):
    try:
        proc = subprocess.Popen(["/bin/bash", "-lc", "sudo -S -k -v"],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, universal_newlines=True)
        proc.communicate(p + "\n", timeout=6)
        return proc.returncode == 0
    except Exception:
        return False


def authenticate_system_user(u, p):
    if u == "root" and os.geteuid() == 0:
        return True, "Running as root"
    if PAM_AVAILABLE:
        ok = pam_authenticate(u, p)
        return ok, ("OK" if ok else "Failed")
    if u == getpass.getuser():
        ok = sudo_validate_current_user(p)
        return ok, ("OK" if ok else "Failed")
    return False, "Cannot verify user"


# ---------- Worker ----------
class ScanWorker(QThread):
    output_line = pyqtSignal(str)
    finished_signal = pyqtSignal(int)
    progress = pyqtSignal(int)

    def __init__(self, cmd, out_dir):
        super().__init__()
        self.cmd = cmd
        self._p = None
        self.out_dir = out_dir

    def run(self):
        self.output_line.emit(f"Running: {self.cmd}")
        try:
            self._p = subprocess.Popen(
                ["/bin/bash", "-lc", self.cmd],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                bufsize=1, universal_newlines=True
            )
            count = 0
            for line in self._p.stdout:
                txt = line.rstrip("\n")
                self.output_line.emit(txt)
                count += 1
                if count % 10 == 0:
                    self.progress.emit(min(95, count // 3))
            self._p.wait()
            self.progress.emit(100)
            self.finished_signal.emit(self._p.returncode or 0)
        except Exception as e:
            self.output_line.emit(str(e))
            self.finished_signal.emit(-1)

    def stop(self):
        if self._p and self._p.poll() is None:
            self._p.terminate()


# ---------- Login ----------
class LoginDialog(QDialog):
    def __init__(self, parent=None, cfg=None):
        super().__init__(parent)
        self.cfg = cfg or load_config()
        self.setModal(True)
        self.setWindowTitle("Vulnix — Privileged Login")
        self.setFixedSize(440, 240)
        self.build_ui()

    def build_ui(self):
        v = QVBoxLayout(self)
        title = QLabel("Sign in to Vulnix")
        title.setFont(QFont("Segoe UI", 14, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        v.addWidget(title)

        form = QFormLayout()
        self.user = QLineEdit(self.cfg.get("auth_user", getpass.getuser()))
        self.pwd = QLineEdit()
        self.pwd.setEchoMode(QLineEdit.Password)
        form.addRow("Username:", self.user)
        form.addRow("Password:", self.pwd)
        v.addLayout(form)

        self.msg = QLabel("")
        v.addWidget(self.msg)

        btn = QPushButton("Sign In")
        btn.clicked.connect(self.try_login)
        v.addWidget(btn, alignment=Qt.AlignRight)

    def try_login(self):
        u, p = self.user.text().strip(), self.pwd.text()
        if not u or not p:
            self.msg.setText("Enter username and password")
            self.msg.setStyleSheet("color:#EF5350;")
            return
        ok, msg = authenticate_system_user(u, p)
        if ok:
            c = load_config()
            c["auth_user"] = u
            save_config(c)
            self.accept()
        else:
            self.msg.setText("Invalid credentials — " + msg)
            self.msg.setStyleSheet("color:#EF5350;")


# ---------- Main Window ----------
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.cfg = load_config()
        self.worker = None
        self.setWindowTitle("Vulnix — Automated Vulnerability Toolkit")
        self.setMinimumSize(1100, 720)
        self.build_ui()

    def build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)

        # Sidebar
        side = QFrame()
        side.setFixedWidth(260)
        side.setObjectName("sidebar")
        s = QVBoxLayout(side)
        s.setContentsMargins(20, 20, 20, 20)
        s.setSpacing(14)

        logo = QLabel("VULNIX")
        logo.setFont(QFont("Segoe UI", 20, QFont.Bold))
        logo.setAlignment(Qt.AlignCenter)
        logo.setObjectName("logo")
        s.addWidget(logo)

        # Buttons
        self.b_net = QPushButton("Network Scan")
        self.b_web = QPushButton("Web Scan")
        self.b_full = QPushButton("Full Assessment")
        self.b_reports = QPushButton("Reports")
        self.b_last = QPushButton("Last Report")
        self.b_settings = QPushButton("Settings")
        self.b_logs = QPushButton("Logs")
        self.b_about = QPushButton("About")

        for b in [self.b_net, self.b_web, self.b_full, self.b_reports,
                  self.b_last, self.b_settings, self.b_logs, self.b_about]:
            b.setMinimumHeight(44)
            s.addWidget(b)

        s.addStretch()
        s.addWidget(QLabel(f"User: {self.cfg.get('auth_user', getpass.getuser())}"))

        # Main content
        content = QWidget()
        v = QVBoxLayout(content)
        v.setContentsMargins(20, 20, 20, 20)
        v.setSpacing(12)

        ctrl = QHBoxLayout()
        self.target = QLineEdit()
        self.target.setPlaceholderText("Target (IP / Host)")
        self.start = QPushButton("Start")
        self.start.setFixedWidth(140)
        ctrl.addWidget(self.target)
        ctrl.addWidget(self.start)
        v.addLayout(ctrl)

        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.console.setMinimumHeight(260)
        v.addWidget(self.console)

        self.progress = QProgressBar()
        self.progress.setFixedHeight(18)
        v.addWidget(self.progress)

        self.cancel = QPushButton("Cancel")
        self.cancel.setDisabled(True)
        v.addWidget(self.cancel, alignment=Qt.AlignLeft)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(
            ["Severity", "Finding", "Evidence", "Remediation"])
        self.table.setMinimumHeight(180)
        v.addWidget(self.table)

        root.addWidget(side)
        root.addWidget(content, 1)

        # Connections
        self.start.clicked.connect(lambda: self.start_scan("network"))
        self.b_net.clicked.connect(lambda: self.start_scan("network"))
        self.b_web.clicked.connect(lambda: self.start_scan("web"))
        self.b_full.clicked.connect(lambda: self.start_scan("full"))
        self.cancel.clicked.connect(self.cancel_scan)
        self.b_reports.clicked.connect(self.show_reports)
        self.b_last.clicked.connect(self.show_last_report)
        self.b_settings.clicked.connect(self.open_settings)
        self.b_logs.clicked.connect(self.open_logs)
        self.b_about.clicked.connect(self.show_about)

        self.setStyleSheet(self.qss())

    # ---------- Scan Handling ----------
    def start_scan(self, kind):
        t = self.target.text().strip()
        if not t:
            QMessageBox.warning(self, "Missing Target", "Enter a target IP/hostname.")
            return
        path = self.cfg["scan_paths"].get(kind)
        if not os.path.exists(path):
            self.console.append(f"Script not found: {path}")
            return

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = f"results/{t}_{ts}"
        os.makedirs(out, exist_ok=True)
        cmd = f"{path} '{t}' '{out}'"

        self.console.append(f"Starting {kind} scan on {t} ...")
        self.start.setDisabled(True)
        self.cancel.setDisabled(False)

        self.worker = ScanWorker(cmd, out)
        self.worker.output_line.connect(self.console.append)
        self.worker.progress.connect(self.progress.setValue)
        self.worker.finished_signal.connect(lambda c: self.scan_done(c, out))
        self.worker.start()

    def cancel_scan(self):
        if self.worker:
            self.worker.stop()
            self.console.append("Scan cancelled.")
            self.cancel.setDisabled(True)
            self.start.setDisabled(False)

    def scan_done(self, code, out):
        cfg = load_config()
        cfg["last_report"] = out
        save_config(cfg)
        txt = self.console.toPlainText().upper()
        crit = sum(1 for l in txt.splitlines() if "CRITICAL" in l)
        high = sum(1 for l in txt.splitlines() if "HIGH" in l)
        med = sum(1 for l in txt.splitlines() if "MEDIUM" in l)
        low = sum(1 for l in txt.splitlines() if "LOW" in l)
        total = crit + high + med + low
        msg = (f"Scan finished (exit {code}).\n"
               f"Total Findings: {total}\nCritical: {crit}, High: {high}, Medium: {med}, Low: {low}")
        self.console.append(msg)
        QMessageBox.information(self, "Scan Summary", msg)
        self.progress.setValue(0)
        self.start.setDisabled(False)
        self.cancel.setDisabled(True)

    # ---------- Other Actions ----------
    def show_reports(self):
        d = os.path.abspath("./results")
        os.makedirs(d, exist_ok=True)
        QMessageBox.information(self, "Reports", f"Reports stored at:\n{d}")

    def show_last_report(self):
        cfg = load_config()
        last = cfg.get("last_report", "")
        if not last or not os.path.exists(last):
            QMessageBox.warning(self, "Last Report", "No previous report found.")
            return
        files = sorted(glob.glob(os.path.join(last, "*.txt")))
        if not files:
            QMessageBox.warning(self, "Last Report", "No .txt report found in last scan folder.")
            return
        fpath = files[-1]
        with open(fpath, "r", errors="ignore") as f:
            text = f.read()
        self.console.setText(text)
        QMessageBox.information(self, "Last Report", f"Showing report from:\n{fpath}")

    def open_settings(self):
        QMessageBox.information(self, "Settings", "Settings feature available in FYP-II.")

    def open_logs(self):
        p, _ = QFileDialog.getOpenFileName(self, "Open Log", "./results")
        if p:
            self.console.setText(open(p, "r", errors="ignore").read())

    def show_about(self):
        QMessageBox.information(self, "About Vulnix",
            "Vulnix — Automated Offensive Security Toolkit\n"
            "Final Year Project (FYP-I)\n\n"
            "Developed by: Shahrukh Karim\n"
            "Supervised by: Dr. Husnain Mansoor\n"
            "Department of Computer Science, 2025\n\n"
            "Kali Linux | PyQt5 | Nmap | Nikto\n"
            "© 2025 Vulnix Project")

    # ---------- Modern Theme ----------
    def qss(self):
        return """
        QMainWindow { background-color: #131E2B; font-family: 'Segoe UI'; color: #E0E7FF; }
        #sidebar { background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #0B1A2A, stop:1 #122B48); }
        #logo { color: #E0E7FF; }
        QPushButton {
            background-color: #1E88E5; color: #E0E7FF;
            border-radius: 8px; padding: 10px; font-weight: 600;
        }
        QPushButton:hover { background-color: #42A5F5; }
        QPushButton:disabled { background-color: #4A5568; color: #94A3B8; }
        QTextEdit, QLineEdit, QTableWidget {
            background-color: #1E293B; border: 1px solid #2E3A50;
            border-radius: 6px; color: #E0E7FF; padding: 6px;
        }
        QHeaderView::section {
            background-color: #243447; color: #E0E7FF;
            padding: 4px; border: none;
        }
        QProgressBar {
            background-color: #1E293B; border: 1px solid #2E3A50;
            border-radius: 8px; text-align: center; color: #E0E7FF;
        }
        QProgressBar::chunk { background-color: #1E88E5; border-radius: 8px; }
        QLabel { color: #E0E7FF; }
        """

# ---------- Run ----------
def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    cfg = load_config()
    login = LoginDialog(None, cfg)
    if login.exec_() != QDialog.Accepted:
        sys.exit(0)
    w = MainWindow()
    w.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
