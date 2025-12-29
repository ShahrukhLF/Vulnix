#!/usr/bin/env python3
"""
Vulnix GUI — Automated Vulnerability Toolkit
Author: Shahrukh Karim | Supervisor: Dr. Husnain Mansoor

UPDATES:
- CSS FIX: Reordered ':focus' and ':hover' rules. 
  Now 'Network Scan' button correctly turns blue on hover even when focused.
"""

import sys, os, json, subprocess, sqlite3, glob, stat, hashlib
from datetime import datetime
import database  # Manages the SQLite database (for login/signup)

from PyQt5.QtCore import Qt, QThread, pyqtSignal, QUrl, QSize
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QTextEdit, QProgressBar, QTableWidget,
    QTableWidgetItem, QMessageBox, QDialog, QFormLayout, QFileDialog, QFrame,
    QHeaderView, QDialogButtonBox, QStackedWidget, QComboBox, QTabWidget,
    QInputDialog, QSizePolicy
)
from PyQt5.QtGui import QFont, QColor, QBrush, QDesktopServices, QIcon

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
}

def load_config():
    """Loads configuration with fallback to defaults."""
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

# ---------- Validation Helper ----------

def is_target_reachable(target):
    """
    Checks reachability. 
    UPDATED: If Ping fails, we still allow the scan to proceed 
    because modern targets (like Stapler) often block Ping.
    """
    clean_target = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
    
    if not clean_target:
        return False, "Target is empty."

    # OPTIONAL: You can keep the ping just for logging, but don't block on it.
    try:
        ret_code = subprocess.call(
            ['ping', '-c', '1', '-W', '1', clean_target],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        if ret_code == 0:
            return True, "Target is reachable."
        else:
            # THIS IS THE FIX: Return True even if ping fails.
            # We let the Nmap script (with -Pn) handle the actual connection.
            return True, f"Ping failed, but forcing scan (assuming firewall blocks Ping)."
            
    except Exception as e:
        # Even if the ping command crashes, let's try to run the scan anyway.
        return True, f"Validation skipped: {str(e)}"

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
        u = self.user.text().strip()
        p = self.pwd.text()
        if not u or not p:
            self.msg.setText("Enter username and password")
            self.msg.setStyleSheet("color:#EF5350;")
            return
        ok, user_id = database.check_user(u, p)
        if ok:
            self.msg.setText("")
            self.user.clear()
            self.pwd.clear()
            self.loginSuccess.emit(user_id, u)
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
            return
        if p1 != p2:
            self.msg.setText("Passwords do not match.")
            return
        success, message = database.add_user(u, p1)
        if success:
            StyledMessageBox.info(self, "Success", "Account created!")
            self.go_back_safe()
        else:
            self.msg.setText(message)

# ---------- VIEW 3: Mode Selection (Corrected) ----------

class ModeSelectionView(QWidget):
    """
    Screen 2: Allows user to choose between Network Scan and Web Scan.
    UPDATED: CSS Fixed so Hover works even when button is focused.
    """
    modeSelected = pyqtSignal(str) # Emits "network" or "web"
    logoutSignal = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.build_ui()

    def build_ui(self):
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)
        layout.setSpacing(50)

        # Header
        title = QLabel("Select Vulnerability Assessment Mode")
        title.setFont(QFont("Segoe UI", 24, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        # Buttons Container
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(60) 
        btn_layout.setAlignment(Qt.AlignCenter)

        # CSS Styling (FIXED):
        # We define :focus BEFORE :hover. This way, if both are true (user hovers a focused button),
        # the :hover rule wins because it comes later in the cascade.
        btn_style = """
            QPushButton {
                background-color: #1E293B; 
                border: 3px solid #1E88E5; 
                border-radius: 15px;
                color: #E0E7FF;
                padding: 10px;
                text-align: center;
                outline: none; 
            }
            /* Focus rule comes FIRST */
            QPushButton:focus {
                border: 3px solid #1E88E5; 
                background-color: #1E293B;
            }
            /* Hover rule comes AFTER to override focus color */
            QPushButton:hover {
                background-color: #1E88E5;
                color: white;
                border: 3px solid #42A5F5;
            }
            QPushButton:pressed {
                background-color: #1565C0;
            }
        """

        # Network Scan Button
        self.btn_net = QPushButton("Network Scan")
        self.btn_net.setFixedSize(280, 160) 
        self.btn_net.setFont(QFont("Segoe UI", 18, QFont.Bold))
        self.btn_net.setStyleSheet(btn_style)
        self.btn_net.setCursor(Qt.PointingHandCursor)
        self.btn_net.clicked.connect(lambda: self.modeSelected.emit("network"))
        btn_layout.addWidget(self.btn_net)

        # Web Scan Button
        self.btn_web = QPushButton("Web Scan")
        self.btn_web.setFixedSize(280, 160) 
        self.btn_web.setFont(QFont("Segoe UI", 18, QFont.Bold))
        self.btn_web.setStyleSheet(btn_style)
        self.btn_web.setCursor(Qt.PointingHandCursor)
        self.btn_web.clicked.connect(lambda: self.modeSelected.emit("web"))
        btn_layout.addWidget(self.btn_web)

        layout.addLayout(btn_layout)

        # Logout option at bottom
        self.btn_logout = QPushButton("Logout")
        self.btn_logout.setFixedSize(120, 40)
        self.btn_logout.setStyleSheet("background-color: #546E7A; border-radius: 6px; border: none; outline: none;")
        self.btn_logout.clicked.connect(self.logoutSignal.emit)
        layout.addWidget(self.btn_logout, alignment=Qt.AlignCenter)

# ---------- VIEW 4: Dashboard (Dynamic & Isolated) ----------

class DashboardView(QWidget):
    logoutSignal = pyqtSignal()
    changeModeSignal = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.user_id = None
        self.username = "Unknown"
        self.cfg = load_config()
        self.worker = None
        self.current_mode = "network" 
        self.build_ui()

    def set_user(self, user_id, username):
        self.user_id = user_id
        self.username = username
        self.user_label.setText(f"User: {self.username}")

    def set_mode(self, mode):
        self.current_mode = mode
        self.refresh_dropdown()
        if mode == "network":
            self.mode_label.setText("MODE: NETWORK SCAN")
            self.mode_label.setStyleSheet("color: #2196F3; font-weight: bold; font-size: 14px;")
        else:
            self.mode_label.setText("MODE: WEB SCAN")
            self.mode_label.setStyleSheet("color: #9C27B0; font-weight: bold; font-size: 14px;")

    def build_ui(self):
        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)

        # --- SIDEBAR ---
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
        
        self.b_open_reports = QPushButton("Open Reports")
        self.b_last = QPushButton("Last Report")
        self.b_logs = QPushButton("Logs")
        self.b_settings = QPushButton("Settings (Advanced)")
        self.b_about = QPushButton("About")
        self.b_change_mode = QPushButton("Change Mode") 
        self.b_logout = QPushButton("Logout")
        
        buttons = [self.b_open_reports, self.b_last, self.b_logs, self.b_settings, self.b_about, self.b_change_mode]
        for b in buttons:
            b.setMinimumHeight(44)
            s.addWidget(b)
        
        s.addStretch()
        self.user_label = QLabel("User: ...")
        s.addWidget(self.user_label)
        s.addWidget(self.b_logout)
        root.addWidget(side)

        # --- CONTENT ---
        content = QWidget()
        v = QVBoxLayout(content)
        v.setContentsMargins(20, 20, 20, 20)
        v.setSpacing(12)
        
        self.mode_label = QLabel("MODE: ...")
        v.addWidget(self.mode_label, alignment=Qt.AlignRight)

        # Control Bar
        ctrl_bar = QHBoxLayout()
        ctrl_bar.setSpacing(10)

        self.target = QLineEdit()
        self.target.setPlaceholderText("Enter Target IP (Network) or URL (Web)...")
        self.target.setMinimumHeight(45)
        ctrl_bar.addWidget(self.target, 3) 

        self.scan_mode = QComboBox()
        self.scan_mode.setMinimumHeight(45)
        self.scan_mode.setFixedWidth(240)
        self.scan_mode.setCursor(Qt.PointingHandCursor)
        ctrl_bar.addWidget(self.scan_mode, 1)

        self.start_btn = QPushButton("Start Scan")
        self.start_btn.setMinimumHeight(45)
        self.start_btn.setFixedWidth(120)
        self.start_btn.setCursor(Qt.PointingHandCursor)
        self.start_btn.setStyleSheet("background-color: #4CAF50; font-weight: bold;")
        self.start_btn.clicked.connect(self.initiate_selected_scan)
        ctrl_bar.addWidget(self.start_btn, 0)

        self.cancel = QPushButton("Stop")
        self.cancel.setMinimumHeight(45)
        self.cancel.setFixedWidth(80)
        self.cancel.setDisabled(True)
        self.cancel.setStyleSheet("background-color: #EF5350; font-weight: bold;") 
        self.cancel.clicked.connect(self.cancel_scan)
        ctrl_bar.addWidget(self.cancel, 0)

        v.addLayout(ctrl_bar)
        
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.console.setMinimumHeight(260)
        v.addWidget(self.console)
        
        self.progress = QProgressBar()
        self.progress.setFixedHeight(18)
        v.addWidget(self.progress)
        
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Severity", "Finding", "Evidence", "Remediation"])
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(3, QHeaderView.Stretch)
        v.addWidget(self.table)
        root.addWidget(content, 1)

        self.b_open_reports.clicked.connect(self.open_reports_folder)
        self.b_last.clicked.connect(self.show_last_report_window)
        self.b_settings.clicked.connect(self.open_settings)
        self.b_logs.clicked.connect(self.open_logs)
        self.b_about.clicked.connect(self.show_about)
        self.b_change_mode.clicked.connect(self.changeModeSignal.emit)
        self.b_logout.clicked.connect(self.logoutSignal.emit)

    def refresh_dropdown(self):
        self.scan_mode.clear()
        if self.current_mode == "network":
            self.scan_mode.addItem("Quick Network Scan", "quick")
            self.scan_mode.addItem("Deep Network Scan", "deep")
        else:
            self.scan_mode.addItem("Quick Web Scan", "web_quick")
            self.scan_mode.addItem("Deep Web Scan", "web_deep")
        
        self.scan_mode.addItem("Full Assessment", "full")

        core_scripts = ["scan_quick.sh", "scan_deep.sh", "scan_web_quick.sh", "scan_web_deep.sh", "run_full_assessment.sh"]
        custom_files = glob.glob("./scripts/*.sh")
        for f in custom_files:
            fname = os.path.basename(f)
            if fname not in core_scripts:
                display_name = f"Custom: {fname.replace('.sh', '')}"
                self.scan_mode.addItem(display_name, f) 

    def initiate_selected_scan(self):
        t = self.target.text().strip()
        is_ok, msg = is_target_reachable(t)
        if not is_ok:
            StyledMessageBox.warning(self, "Validation Failed", msg)
            self.console.append(f"Validation Failed: {msg}")
            return

        selected_data = self.scan_mode.currentData()
        script_path = ""
        if selected_data in self.cfg["scan_paths"]:
            script_path = self.cfg["scan_paths"][selected_data]
        elif os.path.exists(selected_data):
            script_path = selected_data
        else:
             self.console.append(f"Error: Script path not found for {selected_data}")
             return

        self.start_scan_process(t, script_path)

    def start_scan_process(self, target, path):
        self.console.clear()
        self.table.setRowCount(0)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_t = target.replace(".", "-").replace("/", "_")
        
        # USER ISOLATION: Create subdirectory for username
        user_folder = self.username if self.username else "default_user"
        out_folder = os.path.abspath(f"results/{user_folder}/{safe_t}_{ts}")
        os.makedirs(out_folder, exist_ok=True)
        
        cmd = f"{path} '{target}' '{out_folder}'"
        self.console.append(f"Starting scan on {target} ...")
        
        self.start_btn.setDisabled(True)
        self.cancel.setDisabled(False)
        self.target.setDisabled(True)
        self.scan_mode.setDisabled(True)
        
        self.current_scan_target = target
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
        self.start_btn.setDisabled(False)
        self.target.setDisabled(False)
        self.scan_mode.setDisabled(False)
        self.cancel.setDisabled(True)
        self.progress.setValue(0)

        if code == 0:
            database.log_scan(self.user_id, self.current_scan_target, self.scan_mode.currentText(), out_folder)
            self.console.append(f"Scan logged to database.")
    
        # Save last report globally for fallback, but main retrieval is via DB
        self.cfg["last_report"] = out_folder
        save_config(self.cfg)
        
        summary_file = os.path.join(out_folder, "summary.json")
        findings = 0
        if code == 0 and os.path.exists(summary_file):
            findings = self.load_results_to_table(summary_file)
        
        if code != -15:
            msg = f"Scan finished (exit code {code}).\nTotal Findings: {findings}"
            self.console.append(msg)
            StyledMessageBox.info(self, "Scan Summary", msg)
        
    def load_results_to_table(self, file_path):
        try:
            with open(file_path, 'r') as f: findings = json.load(f)
            if not isinstance(findings, list): return 0
            self.table.setRowCount(len(findings))
            for row_idx, f in enumerate(findings):
                self.table.setItem(row_idx, 0, QTableWidgetItem(f.get("severity", "")))
                self.table.setItem(row_idx, 1, QTableWidgetItem(f.get("finding", "")))
                self.table.setItem(row_idx, 2, QTableWidgetItem(f.get("evidence", "")))
                self.table.setItem(row_idx, 3, QTableWidgetItem(f.get("remediation", "")))
            return len(findings)
        except: return 0

    def open_reports_folder(self):
        # USER ISOLATION: Open specific user folder if possible
        user_folder = self.username if self.username else "default_user"
        path = os.path.abspath(f"./results/{user_folder}")
        if not os.path.exists(path):
            path = os.path.abspath("./results")
        QDesktopServices.openUrl(QUrl.fromLocalFile(path))

    def show_last_report_window(self):
        # Retrieve LAST report for THIS user from Database (USER ISOLATION)
        try:
            conn = sqlite3.connect("vulnix.db")
            c = conn.cursor()
            # Assuming table scans has: id, user_id, target, scan_type, scan_path, timestamp
            c.execute("SELECT scan_path FROM scans WHERE user_id=? ORDER BY id DESC LIMIT 1", (self.user_id,))
            res = c.fetchone()
            conn.close()
            
            if res and res[0] and os.path.exists(res[0]):
                report_file = os.path.join(res[0], "report.txt")
                if os.path.exists(report_file):
                    with open(report_file, "r") as f:
                        ReportViewerDialog(f"Report: {os.path.basename(res[0])}", f.read(), self).exec_()
                    return
        except Exception:
            pass

        StyledMessageBox.warning(self, "Info", "No scan history found for this user.")

    def open_logs(self):
        user_folder = self.username if self.username else "default_user"
        path = os.path.abspath(f"./results/{user_folder}")
        p, _ = QFileDialog.getOpenFileName(self, "Open Log", path)
        if p: self.console.setText(open(p, "r", errors="ignore").read())

    def show_about(self):
        StyledMessageBox.info(self, "About", "Vulnix v1.0\nFYP-I Project")

    def open_settings(self):
        dlg = SettingsDialog(self.user_id, self.username, self) # Pass username/ID
        dlg.accountDeleted.connect(lambda: self.logoutSignal.emit())
        dlg.scriptSaved.connect(self.refresh_dropdown) 
        dlg.exec_()

# ---------- NEW: Advanced Settings Dialog (Fixed) ----------

class SettingsDialog(QDialog):
    accountDeleted = pyqtSignal()
    scriptSaved = pyqtSignal()

    def __init__(self, user_id, username, parent=None):
        super().__init__(parent)
        self.user_id = user_id
        self.username = username
        self.setWindowTitle("Advanced Settings")
        self.setMinimumSize(700, 500)
        self.setWindowFlags(self.windowFlags() | Qt.WindowMinMaxButtonsHint)
        self.build_ui()

    def build_ui(self):
        layout = QVBoxLayout(self)
        self.tabs = QTabWidget()
        
        # Tab 1: Account Management (Improved UI)
        self.tab_account = QWidget()
        acc_layout = QVBoxLayout(self.tab_account)
        acc_layout.setAlignment(Qt.AlignTop)
        
        acc_lbl = QLabel(f"Manage Account: {self.username}")
        acc_lbl.setFont(QFont("Segoe UI", 14, QFont.Bold))
        
        warn_box = QFrame()
        warn_box.setStyleSheet("background-color: #2E1A1A; border: 1px solid #D32F2F; border-radius: 6px; padding: 10px;")
        wb_layout = QVBoxLayout(warn_box)
        w_lbl = QLabel("⚠️ DANGER ZONE")
        w_lbl.setStyleSheet("color: #FF5252; font-weight: bold;")
        desc = QLabel("Deleting your account is permanent. All scan history will be lost.")
        desc.setWordWrap(True)
        wb_layout.addWidget(w_lbl)
        wb_layout.addWidget(desc)
        
        self.btn_delete = QPushButton("Delete My Account")
        self.btn_delete.setFixedSize(180, 40)
        self.btn_delete.setStyleSheet("background-color: #D32F2F; color: white; border-radius: 6px; font-weight: bold;")
        self.btn_delete.setCursor(Qt.PointingHandCursor)
        self.btn_delete.clicked.connect(self.delete_account)
        
        acc_layout.addWidget(acc_lbl)
        acc_layout.addWidget(warn_box)
        acc_layout.addSpacing(20)
        acc_layout.addWidget(self.btn_delete)
        acc_layout.addStretch()
        
        # Tab 2: Custom Script Editor
        self.tab_script = QWidget()
        scr_layout = QVBoxLayout(self.tab_script)
        
        lbl = QLabel("Create Custom Scan Script")
        lbl.setFont(QFont("Segoe UI", 11, QFont.Bold))
        
        self.script_name = QLineEdit()
        self.script_name.setPlaceholderText("Script Name (e.g. custom_nmap_scan)")
        
        self.script_content = QTextEdit()
        self.script_content.setPlaceholderText("#!/bin/bash\n# Write your shell script here...\n\necho 'Starting Custom Scan...'\n# Use $1 for target IP and $2 for output folder")
        self.script_content.setFont(QFont("Monospace", 10))
        self.script_content.setStyleSheet("background-color: #0F1724; color: #00FF00;")
        
        self.btn_save_script = QPushButton("Save and Add to Dropdown")
        self.btn_save_script.setMinimumHeight(40)
        self.btn_save_script.setStyleSheet("background-color: #4CAF50; font-weight: bold;")
        self.btn_save_script.clicked.connect(self.save_custom_script)
        
        scr_layout.addWidget(lbl)
        scr_layout.addWidget(self.script_name)
        scr_layout.addWidget(self.script_content)
        scr_layout.addWidget(self.btn_save_script)
        
        self.tabs.addTab(self.tab_account, "Account")
        self.tabs.addTab(self.tab_script, "Custom Scripts")
        layout.addWidget(self.tabs)

    def delete_account(self):
        pwd, ok = QInputDialog.getText(self, "Confirm Deletion", "Enter your password to confirm:", QLineEdit.Password)
        if not ok or not pwd: return

        # FIX: Check password using database logic directly
        # This fixes the issue where local hashing didn't match DB hashing
        is_valid, _ = database.check_user(self.username, pwd)

        if is_valid:
            confirm = QMessageBox.question(self, "Final Warning", "Are you absolutely sure?", QMessageBox.Yes | QMessageBox.No)
            if confirm == QMessageBox.Yes:
                try:
                    conn = sqlite3.connect("vulnix.db")
                    c = conn.cursor()
                    c.execute("DELETE FROM users WHERE id=?", (self.user_id,))
                    c.execute("DELETE FROM scans WHERE user_id=?", (self.user_id,))
                    conn.commit()
                    conn.close()
                    StyledMessageBox.info(self, "Goodbye", "Account deleted.")
                    self.accountDeleted.emit()
                    self.close()
                except Exception as e:
                    StyledMessageBox.warning(self, "Error", str(e))
        else:
            StyledMessageBox.warning(self, "Error", "Incorrect password.")

    def save_custom_script(self):
        name = self.script_name.text().strip().replace(" ", "_")
        if not name:
            StyledMessageBox.warning(self, "Error", "Please enter a script name.")
            return
        
        content = self.script_content.toPlainText()
        if not content:
            StyledMessageBox.warning(self, "Error", "Script content cannot be empty.")
            return

        filename = f"{name}.sh"
        path = os.path.join("scripts", filename)
        
        try:
            os.makedirs("scripts", exist_ok=True)
            with open(path, "w") as f:
                f.write(content)
            st = os.stat(path)
            os.chmod(path, st.st_mode | stat.S_IEXEC)
            
            StyledMessageBox.info(self, "Success", f"Script saved to {path}!\nIt is now available in the dropdown.")
            self.scriptSaved.emit()
        except Exception as e:
            StyledMessageBox.warning(self, "Error", f"Could not save script: {e}")

# ---------- Report Viewer (Unchanged) ----------

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

# ---------- Main Controller (Unchanged) ----------

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
        self.mode_view = ModeSelectionView() 
        self.dashboard_view = DashboardView() 

        self.stack.addWidget(self.login_view)      
        self.stack.addWidget(self.signup_view)     
        self.stack.addWidget(self.mode_view)       
        self.stack.addWidget(self.dashboard_view)  

        self.login_view.loginSuccess.connect(self.handle_login_success)
        self.login_view.goToSignUp.connect(lambda: self.stack.setCurrentIndex(1))
        self.signup_view.goBack.connect(lambda: self.stack.setCurrentIndex(0))
        
        self.mode_view.modeSelected.connect(self.handle_mode_selection)
        self.mode_view.logoutSignal.connect(self.handle_logout)

        self.dashboard_view.logoutSignal.connect(self.handle_logout)
        self.dashboard_view.changeModeSignal.connect(lambda: self.stack.setCurrentIndex(2))

        self.setStyleSheet(VulnixApp.qss())
        self.stack.setCurrentIndex(0)

    def handle_login_success(self, user_id, username):
        self.dashboard_view.set_user(user_id, username)
        self.stack.setCurrentIndex(2) 

    def handle_mode_selection(self, mode):
        self.dashboard_view.set_mode(mode)
        self.stack.setCurrentIndex(3) 

    def handle_logout(self):
        self.stack.setCurrentIndex(0)

    @staticmethod
    def qss():
        return """
        QMainWindow, QWidget, QDialog, QMessageBox, QFileDialog, QTabWidget::pane { 
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
        QTabBar::tab { background: #2E3A50; color: #E0E7FF; padding: 10px; margin-right: 2px; border-top-left-radius: 6px; border-top-right-radius: 6px;}
        QTabBar::tab:selected { background: #1E88E5; font-weight: bold; }
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
