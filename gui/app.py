#!/usr/bin/env python3
"""
Vulnix GUI — Automated Vulnerability Toolkit
Author: Shahrukh Karim | Supervisor: Dr. Husnain Mansoor

UPDATES:
- Moved Scan Controls to the top right (Advisor Requirement).
- Implemented Dropdown for Scan Mode selection.
- Cleaned up Sidebar.
"""

import sys, os, json, subprocess, glob
from datetime import datetime
import database  # Manages the SQLite database

from PyQt5.QtCore import Qt, QThread, pyqtSignal, QUrl
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QTextEdit, QProgressBar, QTableWidget,
    QTableWidgetItem, QMessageBox, QDialog, QFormLayout, QFileDialog, QFrame,
    QHeaderView, QDialogButtonBox, QStackedWidget, QComboBox
)
from PyQt5.QtGui import QFont, QColor, QBrush, QDesktopServices

# ---------- Config Functions ----------

CONFIG_PATH = os.path.expanduser("~/.vulnix_config.json")

DEFAULT_CONFIG = {
    "scan_paths": {
        "quick": "./scripts/scan_quick.sh",
        "deep": "./scripts/scan_deep.sh",
        "web_quick": "./scripts/scan_web_quick.sh",
        "web_deep": "./scripts/scan_web_deep.sh",
        "full": "./scripts/run_full_assessment.sh"
    },
    "last_report": ""
}

def load_config():
    cfg = DEFAULT_CONFIG.copy()
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, 'r') as f:
                saved_cfg = json.load(f)
            for key, value in saved_cfg.items():
                if key != "scan_paths":
                    cfg[key] = value
            if "scan_paths" in saved_cfg:
                cfg["scan_paths"].update(saved_cfg["scan_paths"])
        except Exception:
            pass 
    else:
        save_config(cfg)
    return cfg

def save_config(cfg):
    try:
        with open(CONFIG_PATH, 'w') as f:
            json.dump(cfg, f, indent=2)
    except Exception as e:
        print(f"Error saving config: {e}")


# ---------- Scan Worker ----------

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
        # NOTE: Sudo is called here. Ensure scripts are executable.
        full_cmd = f"sudo {self.cmd}"
        self.output_line.emit(f"Running: {full_cmd}")
        try:
            self._p = subprocess.Popen(
                ["/bin/bash", "-lc", full_cmd],
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
            self.output_line.emit(f"CRITICAL SCRIPT ERROR: {e}")
            self.finished_signal.emit(-1)

    def stop(self):
        if self._p and self._p.poll() is None:
            self._p.terminate()


# ---------- Helper: Styled Message Box ----------

class StyledMessageBox:
    @staticmethod
    def _create_msg_box(icon, title, text):
        msg = QMessageBox()
        msg.setIcon(icon)
        msg.setWindowTitle(title)
        msg.setText(text)
        msg.setStyleSheet(VulnixApp.qss()) 
        return msg

    @staticmethod
    def info(parent, title, text):
        msg = StyledMessageBox._create_msg_box(QMessageBox.Information, title, text)
        msg.exec_()

    @staticmethod
    def warning(parent, title, text):
        msg = StyledMessageBox._create_msg_box(QMessageBox.Warning, title, text)
        msg.exec_()


# ---------- VIEW 1: Login Screen ----------

class LoginView(QWidget):
    loginSuccess = pyqtSignal(int, str)
    goToSignUp = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.build_ui()

    def build_ui(self):
        outer_layout = QVBoxLayout(self)
        outer_layout.setAlignment(Qt.AlignCenter)

        container = QFrame()
        container.setFixedWidth(400)
        
        v = QVBoxLayout(container)
        v.setSpacing(20)
        v.setContentsMargins(30, 30, 30, 30)

        title = QLabel("Sign in to Vulnix")
        title.setFont(QFont("Segoe UI", 18, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        v.addWidget(title)

        form = QFormLayout()
        self.user = QLineEdit()
        self.user.setPlaceholderText("Username")
        self.user.setMinimumHeight(35)
        
        self.pwd = QLineEdit()
        self.pwd.setEchoMode(QLineEdit.Password)
        self.pwd.setPlaceholderText("Password")
        self.pwd.setMinimumHeight(35)
        
        self.user.returnPressed.connect(self.try_login)
        self.pwd.returnPressed.connect(self.try_login)
        
        form.addRow(self.user)
        form.addRow(self.pwd)
        v.addLayout(form)

        self.msg = QLabel("")
        self.msg.setAlignment(Qt.AlignCenter)
        v.addWidget(self.msg)

        self.login_btn = QPushButton("Sign In")
        self.login_btn.setMinimumHeight(40)
        self.login_btn.clicked.connect(self.try_login)
        v.addWidget(self.login_btn)

        self.signup_btn = QPushButton("Create New Account")
        self.signup_btn.setMinimumHeight(40)
        self.signup_btn.setCursor(Qt.PointingHandCursor)
        self.signup_btn.clicked.connect(self.goToSignUp.emit)
        v.addWidget(self.signup_btn)

        outer_layout.addWidget(container)

    def try_login(self):
        u_text = self.user.text().strip()
        p_text = self.pwd.text()
        
        if not u_text or not p_text:
            self.msg.setText("Enter username and password")
            self.msg.setStyleSheet("color:#EF5350;")
            return
        
        ok, user_id = database.check_user(u_text, p_text)
        if ok:
            self.msg.setText("")
            self.user.clear()
            self.pwd.clear()
            self.loginSuccess.emit(user_id, u_text)
        else:
            self.msg.setText("Invalid username or password.")
            self.msg.setStyleSheet("color:#EF5350;")


# ---------- VIEW 2: Sign Up Screen ----------

class SignUpView(QWidget):
    signUpSuccess = pyqtSignal()
    goBack = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.build_ui()

    def build_ui(self):
        outer_layout = QVBoxLayout(self)
        outer_layout.setAlignment(Qt.AlignCenter)

        container = QFrame()
        container.setFixedWidth(400)
        
        v = QVBoxLayout(container)
        v.setSpacing(20)
        v.setContentsMargins(30, 30, 30, 30)

        title = QLabel("Create Account")
        title.setFont(QFont("Segoe UI", 18, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        v.addWidget(title)

        form = QFormLayout()
        self.user = QLineEdit()
        self.user.setPlaceholderText("Choose Username")
        self.user.setMinimumHeight(35)

        self.pwd1 = QLineEdit()
        self.pwd1.setEchoMode(QLineEdit.Password)
        self.pwd1.setPlaceholderText("Password")
        self.pwd1.setMinimumHeight(35)

        self.pwd2 = QLineEdit()
        self.pwd2.setEchoMode(QLineEdit.Password)
        self.pwd2.setPlaceholderText("Confirm Password")
        self.pwd2.setMinimumHeight(35)
        
        self.user.returnPressed.connect(self.try_signup)
        self.pwd1.returnPressed.connect(self.try_signup)
        self.pwd2.returnPressed.connect(self.try_signup)
        
        form.addRow(self.user)
        form.addRow(self.pwd1)
        form.addRow(self.pwd2)
        v.addLayout(form)

        self.msg = QLabel("")
        self.msg.setAlignment(Qt.AlignCenter)
        v.addWidget(self.msg)

        self.create_btn = QPushButton("Create Account")
        self.create_btn.setMinimumHeight(40)
        self.create_btn.clicked.connect(self.try_signup)
        v.addWidget(self.create_btn)

        self.back_btn = QPushButton("Back to Login")
        self.back_btn.setMinimumHeight(40)
        self.back_btn.setCursor(Qt.PointingHandCursor)
        self.back_btn.clicked.connect(self.go_back_safe)
        v.addWidget(self.back_btn)

        outer_layout.addWidget(container)

    def go_back_safe(self):
        self.msg.setText("")
        self.user.clear()
        self.pwd1.clear()
        self.pwd2.clear()
        self.goBack.emit()

    def try_signup(self):
        u = self.user.text().strip()
        p1 = self.pwd1.text()
        p2 = self.pwd2.text()

        if not u or not p1 or not p2:
            self.msg.setText("All fields are required.")
            self.msg.setStyleSheet("color:#EF5350;")
            return
        
        if p1 != p2:
            self.msg.setText("Passwords do not match.")
            self.msg.setStyleSheet("color:#EF5350;")
            return

        success, message = database.add_user(u, p1)
        
        if success:
            StyledMessageBox.info(self, "Success", "Account created! You can now log in.")
            self.go_back_safe()
        else:
            self.msg.setText(message)
            self.msg.setStyleSheet("color:#EF5350;")


# ---------- VIEW 3: Dashboard ----------

class DashboardView(QWidget):
    logoutSignal = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.user_id = None
        self.username = "Unknown"
        self.cfg = load_config()
        self.worker = None
        self.build_ui()

    def set_user(self, user_id, username):
        self.user_id = user_id
        self.username = username
        self.user_label.setText(f"User: {self.username}")

    def build_ui(self):
        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)

        # --- LEFT SIDEBAR (Cleaned Up) ---
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
        
        # Navigation Buttons Only
        self.b_open_reports = QPushButton("Open Reports Folder")
        self.b_last = QPushButton("Last Report")
        self.b_logs = QPushButton("Logs")
        self.b_settings = QPushButton("Settings")
        self.b_about = QPushButton("About")
        self.b_logout = QPushButton("Logout")
        
        buttons = [
            self.b_open_reports, self.b_last, 
            self.b_logs, self.b_settings, self.b_about
        ]

        for b in buttons:
            b.setMinimumHeight(44)
            s.addWidget(b)
        
        s.addStretch()
        self.user_label = QLabel("User: ...")
        s.addWidget(self.user_label)
        s.addWidget(self.b_logout)
        
        root.addWidget(side)

        # --- MAIN CONTENT AREA ---
        content = QWidget()
        v = QVBoxLayout(content)
        v.setContentsMargins(20, 20, 20, 20)
        v.setSpacing(12)
        
        # --- NEW CONTROL BAR (Target | Mode | Start) ---
        ctrl_bar = QHBoxLayout()
        ctrl_bar.setSpacing(10)

        # 1. Input Field
        self.target = QLineEdit()
        self.target.setPlaceholderText("Enter Target IP or Hostname...")
        self.target.setMinimumHeight(45)
        ctrl_bar.addWidget(self.target, 3) # Stretch factor 3 (takes up most space)

        # 2. Mode Selector Dropdown
        self.scan_mode = QComboBox()
        self.scan_mode.addItems([
            "Quick Network Scan",
            "Deep Network Scan",
            "Quick Web Scan",
            "Deep Web Scan",
            "Full Assessment"
        ])
        self.scan_mode.setMinimumHeight(45)
        self.scan_mode.setFixedWidth(200)
        self.scan_mode.setCursor(Qt.PointingHandCursor)
        ctrl_bar.addWidget(self.scan_mode, 1) # Stretch factor 1

        # 3. Start Button
        self.start_btn = QPushButton("Start Scan")
        self.start_btn.setMinimumHeight(45)
        self.start_btn.setFixedWidth(120)
        self.start_btn.setCursor(Qt.PointingHandCursor)
        self.start_btn.setStyleSheet("background-color: #4CAF50; font-weight: bold;")
        self.start_btn.clicked.connect(self.initiate_selected_scan)
        ctrl_bar.addWidget(self.start_btn, 0)

        # 4. Cancel Button (Hidden by default or placed next to start)
        self.cancel = QPushButton("Stop")
        self.cancel.setMinimumHeight(45)
        self.cancel.setFixedWidth(80)
        self.cancel.setDisabled(True)
        self.cancel.setStyleSheet("background-color: #EF5350; font-weight: bold;") 
        self.cancel.clicked.connect(self.cancel_scan)
        ctrl_bar.addWidget(self.cancel, 0)

        v.addLayout(ctrl_bar)
        
        # Console Log
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.console.setMinimumHeight(260)
        v.addWidget(self.console)
        
        # Progress Bar
        self.progress = QProgressBar()
        self.progress.setFixedHeight(18)
        v.addWidget(self.progress)
        
        # Results Table
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(
            ["Severity", "Finding", "Evidence", "Remediation"])
        self.table.setMinimumHeight(180)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.Stretch)
        
        v.addWidget(self.table)
        root.addWidget(content, 1)

        # --- Connections for Sidebar ---
        self.b_open_reports.clicked.connect(self.open_reports_folder)
        self.b_last.clicked.connect(self.show_last_report_window)
        self.b_settings.clicked.connect(self.open_settings)
        self.b_logs.clicked.connect(self.open_logs)
        self.b_about.clicked.connect(self.show_about)
        self.b_logout.clicked.connect(self.logoutSignal.emit)

    # ---------- Logic Functions ----------

    def initiate_selected_scan(self):
        """ Reads dropdown and calls start_scan with correct key """
        mode_text = self.scan_mode.currentText()
        
        # Map User-Friendly Text to Config Keys
        mapping = {
            "Quick Network Scan": "quick",
            "Deep Network Scan": "deep",
            "Quick Web Scan": "web_quick",
            "Deep Web Scan": "web_deep",
            "Full Assessment": "full"
        }
        
        key = mapping.get(mode_text)
        if key:
            self.start_scan(key)

    def start_scan(self, kind):
        t = self.target.text().strip()
        if not t:
            StyledMessageBox.warning(self, "Missing Target", "Please enter a target IP or URL.")
            return
        
        path = self.cfg["scan_paths"].get(kind)
        if not path or not os.path.exists(path):
            self.console.append(f"Script not found: {path}")
            return

        self.console.clear()
        self.table.setRowCount(0)

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_t = t.replace(".", "-").replace("/", "_")
        out_folder = os.path.abspath(f"results/{safe_t}_{ts}")
        os.makedirs(out_folder, exist_ok=True)
        
        cmd = f"{path} '{t}' '{out_folder}'"
        self.console.append(f"Starting {kind.upper()} scan on {t} ...")
        
        # UI State Update
        self.start_btn.setDisabled(True)
        self.cancel.setDisabled(False)
        self.scan_mode.setDisabled(True)
        self.target.setDisabled(True)
        
        self.current_scan_kind = kind
        self.current_scan_target = t

        self.worker = ScanWorker(cmd, out_folder)
        self.worker.output_line.connect(self.console.append)
        self.worker.progress.connect(self.progress.setValue)
        self.worker.finished_signal.connect(lambda code: self.scan_done(code, out_folder))
        self.worker.start()

    def cancel_scan(self):
        if self.worker:
            self.worker.stop()
            self.console.append("Scan cancelled by user.")
            self.cancel.setDisabled(True)

    def scan_done(self, code, out_folder):
        # Reset UI State
        self.start_btn.setDisabled(False)
        self.scan_mode.setDisabled(False)
        self.target.setDisabled(False)
        self.cancel.setDisabled(True)
        self.progress.setValue(0)

        if code == 0:
            database.log_scan(
                self.user_id,
                self.current_scan_target,
                self.current_scan_kind,
                out_folder
            )
            self.console.append(f"Scan logged to database.")
    
        self.cfg["last_report"] = out_folder
        save_config(self.cfg)
        
        summary_file = os.path.join(out_folder, "summary.json")
        findings_count = 0
        if code == 0 and os.path.exists(summary_file):
            self.console.append(f"Parsing summary file: {summary_file}")
            findings_count = self.load_results_to_table(summary_file)
        elif code == 0:
            self.console.append("Scan finished, but no 'summary.json' was found.")

        if code != -15: # -15 is SIGTERM (Cancel)
            msg = (f"Scan finished (exit code {code}).\n"
                   f"Total Findings: {findings_count}")
            self.console.append(msg)
            StyledMessageBox.info(self, "Scan Summary", msg)
        
    def load_results_to_table(self, file_path):
        try:
            with open(file_path, 'r') as f:
                findings = json.load(f)
            if not isinstance(findings, list): return 0

            self.table.setRowCount(len(findings))
            for row_idx, finding in enumerate(findings):
                sev = finding.get("severity", "N/A")
                fin = finding.get("finding", "No details")
                evi = finding.get("evidence", "")
                rem = finding.get("remediation", "N/A")
                
                sev_item = QTableWidgetItem(sev)
                fin_item = QTableWidgetItem(fin)
                evi_item = QTableWidgetItem(evi)
                rem_item = QTableWidgetItem(rem)
                
                color = QColor("#E0E7FF")
                s_up = sev.upper()
                if "CRITICAL" in s_up: color = QColor("#F44336")
                elif "HIGH" in s_up:   color = QColor("#FF9800")
                elif "MEDIUM" in s_up: color = QColor("#FFC107")
                elif "LOW" in s_up:    color = QColor("#4CAF50")
                
                sev_item.setForeground(QBrush(color))
                self.table.setItem(row_idx, 0, sev_item)
                self.table.setItem(row_idx, 1, fin_item)
                self.table.setItem(row_idx, 2, evi_item)
                self.table.setItem(row_idx, 3, rem_item)
            return len(findings)
        except Exception as e:
            self.console.append(f"Error parsing results: {e}")
            return 0

    def open_reports_folder(self):
        d = os.path.abspath("./results")
        os.makedirs(d, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(d))

    def show_last_report_window(self):
        self.cfg = load_config()
        last_folder = self.cfg.get("last_report", "")
        
        if not last_folder or not os.path.exists(last_folder):
            StyledMessageBox.warning(self, "Last Report", "No previous report found.")
            return

        report_file = os.path.join(last_folder, "report.txt")
        if not os.path.exists(report_file):
            StyledMessageBox.warning(self, "Last Report", "No 'report.txt' found in folder.")
            return

        try:
            with open(report_file, "r", errors="ignore") as f:
                content = f.read()
            dialog = ReportViewerDialog(f"Report: {os.path.basename(last_folder)}", content, self)
            dialog.exec_()
        except Exception as e:
            StyledMessageBox.warning(self, "Error", f"Could not read report: {e}")

    def open_settings(self):
        StyledMessageBox.info(self, "Settings", "Settings feature available in FYP-II.")

    def open_logs(self):
        p, _ = QFileDialog.getOpenFileName(self, "Open Log", "./results")
        if p:
            try:
                self.console.setText(open(p, "r", errors="ignore").read())
            except Exception:
                pass

    def show_about(self):
        StyledMessageBox.info(self, "About Vulnix", 
            "Vulnix — Automated Offensive Security Toolkit\n"
            "Final Year Project (FYP-I) 2025\n"
            "Developed by: Shahrukh Karim")


# ---------- Report Viewer (Independent Window) ----------
class ReportViewerDialog(QDialog):
    def __init__(self, title, content, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumSize(700, 500)
        layout = QVBoxLayout(self)
        self.txt = QTextEdit()
        self.txt.setReadOnly(True)
        self.txt.setText(content)
        self.txt.setFont(QFont("Monospace", 10))
        layout.addWidget(self.txt)
        btn = QDialogButtonBox(QDialogButtonBox.Close)
        btn.rejected.connect(self.reject)
        layout.addWidget(btn)


# ---------- Main Application Controller ----------
class VulnixApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Vulnix — Automated Vulnerability Toolkit")
        self.setMinimumSize(1100, 720)
        
        try:
            database.create_tables()
        except Exception as e:
            print(f"DB Init Error: {e}")

        self.stack = QStackedWidget()
        self.setCentralWidget(self.stack)

        self.login_view = LoginView()
        self.signup_view = SignUpView()
        self.dashboard_view = DashboardView()

        self.stack.addWidget(self.login_view)
        self.stack.addWidget(self.signup_view)
        self.stack.addWidget(self.dashboard_view)

        self.login_view.loginSuccess.connect(self.handle_login_success)
        self.login_view.goToSignUp.connect(lambda: self.stack.setCurrentIndex(1))
        self.signup_view.goBack.connect(lambda: self.stack.setCurrentIndex(0))
        self.dashboard_view.logoutSignal.connect(self.handle_logout)

        self.setStyleSheet(VulnixApp.qss())
        self.stack.setCurrentIndex(0)

    def handle_login_success(self, user_id, username):
        self.dashboard_view.set_user(user_id, username)
        self.stack.setCurrentIndex(2)

    def handle_logout(self):
        self.stack.setCurrentIndex(0)

    @staticmethod
    def qss():
        return """
        QMainWindow, QWidget, QDialog, QMessageBox, QFileDialog { 
            background-color: #131E2B; font-family: 'Segoe UI'; color: #E0E7FF;
        }
        #sidebar { 
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0B1A2A, stop:1 #122B48);
        }
        #logo { color: #E0E7FF; }
        QLabel { color: #E0E7FF; background: transparent; }
        QTextEdit, QLineEdit, QTableWidget {
            background-color: #1E293B; border: 1px solid #2E3A50; border-radius: 6px; color: #E0E7FF; padding: 6px;
        }
        QPushButton {
            background-color: #1E88E5; color: #E0E7FF; border-radius: 8px; padding: 10px; font-weight: 600; min-width: 80px;
        }
        QPushButton:hover { background-color: #42A5F5; }
        QPushButton:disabled { background-color: #4A5568; color: #94A3B8; }
        QComboBox {
            background-color: #1E293B; border: 1px solid #2E3A50; border-radius: 6px; color: #E0E7FF; padding: 6px;
        }
        QComboBox::drop-down { border: none; }
        QComboBox::down-arrow { image: none; border-left: 5px solid transparent; border-right: 5px solid transparent; border-top: 5px solid #E0E7FF; margin-right: 10px; }
        QTableWidget { gridline-color: #2E3A50; }
        QTableWidget::item:selected { background-color: #1E88E5; color: #E0E7FF; }
        QHeaderView::section { background-color: #243447; color: #E0E7FF; padding: 4px; border: none; }
        QProgressBar { background-color: #1E293B; border: 1px solid #2E3A50; border-radius: 8px; text-align: center; color: #E0E7FF; }
        QProgressBar::chunk { background-color: #1E88E5; border-radius: 8px; }
        QDialogButtonBox QPushButton { /* Inherit standard button */ }
        """

def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setQuitOnLastWindowClosed(False)
    w = VulnixApp()
    w.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
