#!/usr/bin/env python3
"""
Vulnix GUI — Automated Vulnerability Toolkit
Author: Shahrukh Karim | Supervisor: Dr. Husnain Mansoor

This file contains the main PyQt5 application window, login logic,
and scan orchestration for the Vulnix project.
"""

import sys, os, json, subprocess, getpass, glob
from datetime import datetime
import database # Manages the SQLite database for users and scans
import hashlib

# Import all necessary PyQt5 components
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QUrl
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QTextEdit, QProgressBar, QTableWidget,
    QTableWidgetItem, QMessageBox, QDialog, QFormLayout, QFileDialog, QFrame,
    QHeaderView, QDialogButtonBox
)
from PyQt5.QtGui import QFont, QColor, QBrush, QDesktopServices


# ---------- Config Functions ----------
# These functions manage a simple JSON config file for storing
# script paths and the location of the last report.

CONFIG_PATH = os.path.expanduser("~/.vulnix_config.json")
DEFAULT_CONFIG = {
    "scan_paths": {
        "network": "./scripts/scan_network.sh",
        "web": "./scripts/scan_web.sh",
        "full": "./scripts/run_full_assessment.sh"
    },
    "last_report": ""
}

def load_config():
    """
    Loads the config file from disk.
    It loads defaults first, then overwrites them with any saved values.
    This fixes the bug where 'last_report' was being overwritten.
    """
    # Start with the default configuration
    cfg = DEFAULT_CONFIG.copy()
    
    if os.path.exists(CONFIG_PATH):
        try:
            # Load the saved file
            with open(CONFIG_PATH, 'r') as f:
                saved_cfg = json.load(f)
            
            # Update the defaults with the saved values
            cfg.update(saved_cfg)
            
        except Exception:
            # On error, just return the defaults (which we already loaded)
            pass
    else:
        # If the file doesn't exist, create it with the defaults
        save_config(cfg)
        
    return cfg

def save_config(cfg):
    """Saves the config dictionary back to the JSON file."""
    try:
        with open(CONFIG_PATH, 'w') as f:
            json.dump(cfg, f, indent=2)
    except Exception as e:
        print(f"Error saving config: {e}")


# ---------- Scan Worker Thread ----------
class ScanWorker(QThread):
    """
    This QThread runs the backend Bash script in a separate process.
    This is critical for preventing the GUI from freezing during a scan.
    """
    # Signals to communicate back to the main GUI thread
    output_line = pyqtSignal(str)     # Sends one line of console output
    finished_signal = pyqtSignal(int) # Sends the script's exit code
    progress = pyqtSignal(int)        # Sends a simple progress update

    def __init__(self, cmd, out_dir):
        super().__init__()
        self.cmd = cmd
        self._p = None # This will hold the subprocess object
        self.out_dir = out_dir

    def run(self):
        """The main logic for the worker thread."""
        # The script must be run with sudo, as configured in /etc/sudoers.d/vulnix
        full_cmd = f"sudo {self.cmd}"
        self.output_line.emit(f"Running: {full_cmd}")
        
        try:
            # Start the backend script
            self._p = subprocess.Popen(
                ["/bin/bash", "-lc", full_cmd],
                stdout=subprocess.PIPE, 
                stderr=subprocess.STDOUT, # Combine stdout and stderr
                bufsize=1, 
                universal_newlines=True
            )
            
            # Read the script's output line by line, in real-time
            count = 0
            for line in self._p.stdout:
                txt = line.rstrip("\n")
                self.output_line.emit(txt) # Send the line to the GUI console
                
                # Simple progress simulation
                count += 1
                if count % 10 == 0:
                    self.progress.emit(min(95, count // 3)) # Don't go to 100
            
            self._p.wait() # Wait for the process to terminate
            self.progress.emit(100)
            self.finished_signal.emit(self._p.returncode or 0)
            
        except Exception as e:
            self.output_line.emit(f"CRITICAL SCRIPT ERROR: {e}")
            self.finished_signal.emit(-1) # Signal failure

    def stop(self):
        """Public method to allow the GUI to cancel the scan."""
        if self._p and self._p.poll() is None:
            # 'poll()' is None if the process is still running
            self._p.terminate()


# ---------- Sign Up Dialog ----------
class SignUpDialog(QDialog):
    """A popup dialog window for creating a new user account."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setModal(True)
        self.setWindowTitle("Vulnix — Create Account")
        self.setFixedSize(440, 280)
        self.build_ui()

    def build_ui(self):
        """Lays out the widgets for the sign-up form."""
        v = QVBoxLayout(self)
        title = QLabel("Create a New Account")
        title.setFont(QFont("Segoe UI", 14, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        v.addWidget(title)

        form = QFormLayout()
        self.user = QLineEdit()
        self.pwd1 = QLineEdit()
        self.pwd1.setEchoMode(QLineEdit.Password)
        self.pwd2 = QLineEdit()
        self.pwd2.setEchoMode(QLineEdit.Password)
        
        form.addRow("Username:", self.user)
        form.addRow("Password:", self.pwd1)
        form.addRow("Confirm Password:", self.pwd2)
        v.addLayout(form)

        self.msg = QLabel("") # For status messages (e.g., "Passwords mismatch")
        v.addWidget(self.msg)
        v.addStretch()

        btn = QPushButton("Create Account")
        btn.clicked.connect(self.try_signup)
        v.addWidget(btn, alignment=Qt.AlignRight)

    def try_signup(self):
        """Validates input and attempts to create a user in the database."""
        u = self.user.text().strip()
        p1 = self.pwd1.text()
        p2 = self.pwd2.text()

        # Simple validation
        if not u or not p1 or not p2:
            self.msg.setText("All fields are required.")
            self.msg.setStyleSheet("color:#EF5350;") # Red
            return
        
        if p1 != p2:
            self.msg.setText("Passwords do not match.")
            self.msg.setStyleSheet("color:#EF5350;") # Red
            return

        # Call the database function to add the user
        success, message = database.add_user(u, p1)
        
        if success:
            # Show a success popup
            StyledMessageBox.info(self, "Success", "Account created successfully! You can now log in.")
            self.accept() # Close the signup window
        else:
            # Show the error (e.g., "Username already exists")
            self.msg.setText(message)
            self.msg.setStyleSheet("color:#EF5350;") # Red


# ---------- Login Dialog ----------
class LoginDialog(QDialog):
    """A popup dialog window for user authentication."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setModal(True) # This blocks the main window until login is done
        self.setWindowTitle("Vulnix — Privileged Login")
        self.setFixedSize(440, 280)
        self.build_ui()
        
        # We will store the user's ID and name here after a successful login
        self.user_id = None
        self.username = None

    def build_ui(self):
        """Lays out the widgets for the login form."""
        v = QVBoxLayout(self)
        title = QLabel("Sign in to Vulnix")
        title.setFont(QFont("Segoe UI", 14, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        v.addWidget(title)

        form = QFormLayout()
        self.user = QLineEdit()
        self.user.setPlaceholderText("Enter your app username")
        self.pwd = QLineEdit()
        self.pwd.setEchoMode(QLineEdit.Password)
        form.addRow("Username:", self.user)
        form.addRow("Password:", self.pwd)
        v.addLayout(form)

        self.msg = QLabel("") # For status messages (e.g., "Invalid password")
        v.addWidget(self.msg)
        v.addStretch()

        # Button layout (Login + Sign Up)
        h = QHBoxLayout()
        self.signup_btn = QPushButton("Create Account")
        self.signup_btn.clicked.connect(self.open_signup)
        
        self.login_btn = QPushButton("Sign In")
        self.login_btn.clicked.connect(self.try_login)
        self.login_btn.setDefault(True) # Pressing Enter clicks this button

        h.addWidget(self.signup_btn)
        h.addStretch()
        h.addWidget(self.login_btn)
        v.addLayout(h)

    def open_signup(self):
        """Hides the login window and shows the sign-up dialog."""
        self.hide()
        dialog = SignUpDialog(self)
        dialog.exec_() # This blocks until the signup dialog is closed
        self.show() # Show the login window again

    def try_login(self):
        """Validates credentials against the database."""
        u, p = self.user.text().strip(), self.pwd.text()
        if not u or not p:
            self.msg.setText("Enter username and password")
            self.msg.setStyleSheet("color:#EF5350;")
            return
        
        # Ask the database if this user/password is valid
        ok, user_id = database.check_user(u, p)
        
        if ok:
            # Store the user's info and close the dialog
            self.user_id = user_id
            self.username = u
            self.accept() # This signals to the main app that login was successful
        else:
            self.msg.setText("Invalid username or password.")
            self.msg.setStyleSheet("color:#EF5350;")


# ---------- Report Viewer Dialog ----------
class ReportViewerDialog(QDialog):
    """
    This is a new custom dialog window. Its only job is to
    display the text from the .txt report file in a simple popup.
    """
    def __init__(self, title, content, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumSize(700, 500)
        
        layout = QVBoxLayout(self)
        
        # This text area will hold the report content
        self.report_text = QTextEdit()
        self.report_text.setReadOnly(True)
        self.report_text.setText(content)
        # Use a monospace font for reports, it looks more professional
        self.report_text.setFont(QFont("Monospace", 10))
        
        layout.addWidget(self.report_text)
        
        # Add a standard "Close" button
        button_box = QDialogButtonBox(QDialogButtonBox.Close)
        button_box.rejected.connect(self.reject) # 'Close' button triggers reject()
        layout.addWidget(button_box)


# ---------- Styled Message Box Wrapper ----------
class StyledMessageBox:
    """
    This is a helper class to create QMessageBoxes that
    use our dark stylesheet, fixing the "white popup" bug.
    """
    @staticmethod
    def _create_msg_box(icon, title, text):
        msg = QMessageBox()
        msg.setIcon(icon)
        msg.setWindowTitle(title)
        msg.setText(text)
        # Apply the main window's stylesheet to the popup
        msg.setStyleSheet(MainWindow.qss()) 
        return msg

    @staticmethod
    def info(parent, title, text):
        """Shows a styled Information popup."""
        msg = StyledMessageBox._create_msg_box(QMessageBox.Information, title, text)
        msg.exec_()

    @staticmethod
    def warning(parent, title, text):
        """Shows a styled Warning popup."""
        msg = StyledMessageBox._create_msg_box(QMessageBox.Warning, title, text)
        msg.exec_()


# ---------- Main Window ----------
class MainWindow(QMainWindow):
    """
    The main application window, which contains the sidebar,
    console, and results table.
    """
    # We store the stylesheet as a class variable so the
    # StyledMessageBox helper can access it.
    _qss = ""

    def __init__(self, user_id, username):
        super().__init__()
        self.user_id = user_id
        self.username = username
        self.cfg = load_config() # Load the config *once* at the start
        self.worker = None # This will hold the active ScanWorker thread
        self.setWindowTitle("Vulnix — Automated Vulnerability Toolkit")
        self.setMinimumSize(1100, 720)
        
        # Load the stylesheet into the class variable
        MainWindow._qss = self.qss()
        
        self.build_ui()
        self.setStyleSheet(MainWindow._qss) # Apply style to this main window

    def build_ui(self):
        """Lays out all the main widgets in the window."""
        central = QWidget()
        self.setCentralWidget(central)
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)

        # --- Sidebar ---
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
        
        # Create all the buttons for the sidebar
        self.b_net = QPushButton("Network Scan")
        self.b_web = QPushButton("Web Scan")
        self.b_full = QPushButton("Full Assessment")
        self.b_open_reports = QPushButton("Open Reports Folder")
        self.b_last = QPushButton("Last Report")
        self.b_settings = QPushButton("Settings")
        self.b_logs = QPushButton("Logs")
        self.b_about = QPushButton("About")
        
        # Add all buttons to the sidebar layout
        for b in [self.b_net, self.b_web, self.b_full, self.b_open_reports,
                  self.b_last, self.b_settings, self.b_logs, self.b_about]:
            b.setMinimumHeight(44)
            s.addWidget(b)
        
        s.addStretch() # Pushes the user label to the bottom
        s.addWidget(QLabel(f"User: {self.username}"))
        
        root.addWidget(side)

        # --- Main Content Area ---
        content = QWidget()
        v = QVBoxLayout(content)
        v.setContentsMargins(20, 20, 20, 20)
        v.setSpacing(12)
        
        # The top bar, which now only contains the target input
        ctrl = QHBoxLayout()
        self.target = QLineEdit()
        self.target.setPlaceholderText("Enter Target IP or Hostname...")
        ctrl.addWidget(self.target) # The QLineEdit now takes 100% of the space
        v.addLayout(ctrl)
        
        # The console for raw script output
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.console.setMinimumHeight(260)
        v.addWidget(self.console)
        
        # The progress bar
        self.progress = QProgressBar()
        self.progress.setFixedHeight(18)
        v.addWidget(self.progress)
        
        # The cancel button (only enabled during a scan)
        self.cancel = QPushButton("Cancel")
        self.cancel.setDisabled(True)
        v.addWidget(self.cancel, alignment=Qt.AlignLeft)

        # The main results table
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(
            ["Severity", "Finding", "Evidence", "Remediation"])
        self.table.setMinimumHeight(180)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        
        # This fixes the "squished column" bug
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents) # Severity
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)           # Finding
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents) # Evidence
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)           # Remediation
        
        v.addWidget(self.table)
        
        root.addWidget(content, 1) # Add the main content area

        # --- Connect Signals to Slots ---
        # Connect all the buttons to their functions
        self.b_net.clicked.connect(lambda: self.start_scan("network"))
        self.b_web.clicked.connect(lambda: self.start_scan("web"))
        self.b_full.clicked.connect(lambda: self.start_scan("full"))
        self.cancel.clicked.connect(self.cancel_scan)
        
        self.b_open_reports.clicked.connect(self.open_reports_folder)
        self.b_last.clicked.connect(self.show_last_report_window)
        
        self.b_settings.clicked.connect(self.open_settings)
        self.b_logs.clicked.connect(self.open_logs)
        self.b_about.clicked.connect(self.show_about)
        

    # ---------- Scan Handling ----------
    
    def start_scan(self, kind):
        """
        This function is called when any of the scan buttons are pressed.
        It prepares and launches the ScanWorker thread.
        """
        t = self.target.text().strip()
        if not t:
            # Use our styled popup for the warning
            StyledMessageBox.warning(self, "Missing Target", "Please enter a target IP/hostname in the top bar.")
            return
        
        path = self.cfg["scan_paths"].get(kind)
        if not os.path.exists(path):
            self.console.append(f"Script not found: {path}")
            return

        # Clear the results from the *previous* scan
        self.console.clear()
        self.table.setRowCount(0)

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        # Sanitize target IP for the directory name (e.g., 192.168.1.10 -> 192-168-1-10)
        safe_t = t.replace(".", "-").replace("/", "_") # Also protect against /
        
        # This is the fix for the "Last Report" bug.
        # We create an *absolute path* for the output directory.
        out_folder = os.path.abspath(f"results/{safe_t}_{ts}")
        
        os.makedirs(out_folder, exist_ok=True)
        # We pass the *real* IP to the script, and the *absolute* path
        cmd = f"{path} '{t}' '{out_folder}'"

        self.console.append(f"Starting {kind} scan on {t} ...")
        
        self.cancel.setDisabled(False) # Enable the 'Cancel' button
        
        # Store these for logging when the scan finishes
        self.current_scan_kind = kind
        self.current_scan_target = t

        # Create and start the worker thread
        self.worker = ScanWorker(cmd, out_folder)
        self.worker.output_line.connect(self.console.append)
        self.worker.progress.connect(self.progress.setValue)
        
        # This lambda function captures the 'out_folder' variable (now absolute)
        # and passes it to scan_done along with the 'code' from the signal.
        self.worker.finished_signal.connect(lambda code: self.scan_done(code, out_folder))
        
        self.worker.start()

    def cancel_scan(self):
        """Called when the 'Cancel' button is pressed."""
        if self.worker:
            self.worker.stop()
            self.console.append("Scan cancelled by user.")
            self.cancel.setDisabled(True)

    def scan_done(self, code, out_folder):
        """
        This function is the "slot" that the worker's 'finished_signal'
        connects to. It runs when the scan is complete.
        """
        # Log the scan to our SQLite database
        if code == 0: # 0 means the script exited successfully
            database.log_scan(
                self.user_id,
                self.current_scan_target,
                self.current_scan_kind,
                out_folder # This is the absolute report_path
            )
            self.console.append(f"Scan logged to database.")
    
        # Save the *absolute path* to this scan's folder as the "last report"
        self.cfg["last_report"] = out_folder
        save_config(self.cfg)
        
        # After the scan, we try to parse the 'summary.json'
        # that the script *should* have created.
        summary_file = os.path.join(out_folder, "summary.json")
        findings_count = 0
        if code == 0 and os.path.exists(summary_file):
            self.console.append(f"Parsing summary file: {summary_file}")
            findings_count = self.load_results_to_table(summary_file)
        elif code == 0:
            self.console.append("Scan finished, but no 'summary.json' was found.")

        # Show a final popup summary
        msg = (f"Scan finished (exit code {code}).\n"
               f"Total Findings: {findings_count}")
        self.console.append(msg)
        StyledMessageBox.info(self, "Scan Summary", msg)
        
        self.progress.setValue(0)
        self.cancel.setDisabled(True) # Re-disable the 'Cancel' button

    def load_results_to_table(self, file_path):
        """
        Parses the 'summary.json' file and populates the GUI table.
        Returns the number of findings loaded.
        """
        try:
            with open(file_path, 'r') as f:
                findings = json.load(f)
            
            if not isinstance(findings, list):
                self.console.append("Error: summary.json is not a valid list.")
                return 0

            self.table.setRowCount(len(findings))
            
            for row_idx, finding in enumerate(findings):
                # Get data, with defaults if keys are missing
                sev = finding.get("severity", "N/A")
                fin = finding.get("finding", "No details")
                evi = finding.get("evidence", "")
                rem = finding.get("remediation", "N/A")
                
                # Create table items
                sev_item = QTableWidgetItem(sev)
                fin_item = QTableWidgetItem(fin)
                evi_item = QTableWidgetItem(evi)
                rem_item = QTableWidgetItem(rem)
                
                # Color-code the 'Severity' cell
                color = QColor("#E0E7FF") # Default (white-ish)
                if sev.upper() == "CRITICAL":
                    color = QColor("#F44336") # Red
                elif sev.upper() == "HIGH":
                    color = QColor("#FF9800") # Orange
                elif sev.upper() == "MEDIUM":
                    color = QColor("#FFC107") # Amber
                elif sev.upper() == "LOW":
                    color = QColor("#4CAF50") # Green
                
                sev_item.setForeground(QBrush(color))

                # Add all items to the table row
                self.table.setItem(row_idx, 0, sev_item)
                self.table.setItem(row_idx, 1, fin_item)
                self.table.setItem(row_idx, 2, evi_item)
                self.table.setItem(row_idx, 3, rem_item)
            
            self.console.append(f"Successfully loaded {len(findings)} findings into the table.")
            return len(findings)

        except Exception as e:
            self.console.append(f"Error parsing summary file '{file_path}': {e}")
            return 0

    # ---------- Other Button Functions ----------
    
    def open_reports_folder(self):
        """Opens the '/results' folder in the system's file manager."""
        d = os.path.abspath("./results")
        os.makedirs(d, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(d))

    def show_last_report_window(self):
        """
        Finds the last scan's .txt report and opens it in our
        new ReportViewerDialog popup.
        """
        # We re-load the config from the file *every time*
        # to get the most up-to-date value.
        cfg = load_config()
        last_folder = cfg.get("last_report", "")
        
        # This check will now work because last_folder is an absolute path
        if not last_folder or not os.path.exists(last_folder):
            StyledMessageBox.warning(self, "Last Report", "No previous report found. Please run a scan first.")
            return

        # Find the main .txt report file in that scan's folder
        report_file = os.path.join(last_folder, "report.txt")

        if not os.path.exists(report_file):
            StyledMessageBox.warning(self, "Last Report", "No 'report.txt' file found in the last scan folder.")
            return

        # Try to read the report file
        try:
            with open(report_file, "r", errors="ignore") as f:
                content = f.read()
            
            # Create and show our new report viewer dialog
            title = f"Report: {os.path.basename(last_folder)}"
            dialog = ReportViewerDialog(title, content, self)
            dialog.exec_() # This shows the dialog

        except Exception as e:
            StyledMessageBox.warning(self, "Error Reading Report", f"Could not read report file: {e}")

    def open_settings(self):
        """Placeholder for FYP-II."""
        StyledMessageBox.info(self, "Settings", "Settings feature available in FYP-II.")

    def open_logs(self):
        """Lets the user open any file and view it in the console."""
        # QFileDialog will be styled by our new QSS
        p, _ = QFileDialog.getOpenFileName(self, "Open Log", "./results")
        if p:
            try:
                self.console.setText(open(p, "r", errors="ignore").read())
            except Exception as e:
                StyledMessageBox.warning(self, "Error", f"Could not open file: {e}")

    def show_about(self):
        """Shows the 'About' popup."""
        StyledMessageBox.info(self, "About Vulnix",
            "Vulnix — Automated Offensive Security Toolkit\n"
            "Final Year Project (FYP-I)\n\n"
            "Developed by: Shahrukh Karim\n"
            "Supervised by: Dr. Husnain Mansoor\n"
            "Department of Computer Science, 2025\n\n"
            "Kali Linux | PyQt5 | Nmap | Nikto\n"
            "© 2025 Vulnix Project")

    # ---------- Stylesheet (QSS) ----------
    @staticmethod
    def qss():
        """
        This function returns the global stylesheet (QSS) for the application.
        It's written to style all windows, including popups.
        """
        return """
        /* --- Base Window Styles --- */
        QMainWindow, QDialog, QMessageBox, QFileDialog { 
            background-color: #131E2B; 
            font-family: 'Segoe UI'; 
            color: #E0E7FF;
            border: 1px solid #2E3A50;
        }

        /* --- Sidebar --- */
        #sidebar { 
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                        stop:0 #0B1A2A, stop:1 #122B48);
            border: none;
        }
        #logo { color: #E0E7FF; border: none; }

        /* --- General Widgets (in all windows) --- */
        QLabel {
            color: #E0E7FF;
            background-color: transparent;
            border: none;
        }
        
        QTextEdit, QLineEdit, QTableWidget {
            background-color: #1E293B; 
            border: 1px solid #2E3A50;
            border-radius: 6px; 
            color: #E0E7FF; 
            padding: 6px;
        }
        
        /* --- Buttons (in all windows) --- */
        QPushButton {
            background-color: #1E88E5; 
            color: #E0E7FF;
            border-radius: 8px; 
            padding: 10px; 
            font-weight: 600;
            min-width: 80px;
        }
        QPushButton:hover { background-color: #42A5F5; }
        QPushButton:disabled { background-color: #4A5568; color: #94A3B8; }

        /* --- Table Specifics --- */
        QTableWidget { gridline-color: #2E3A50; }
        QTableWidget::item:selected {
            background-color: #1E88E5;
            color: #E0E7FF;
        }
        QHeaderView::section {
            background-color: #243447; 
            color: #E0E7FF;
            padding: 4px; 
            border: none;
        }

        /* --- Progress Bar --- */
        QProgressBar {
            background-color: #1E293B; 
            border: 1px solid #2E3A50;
            border-radius: 8px; 
            text-align: center; 
            color: #E0E7FF;
        }
        QProgressBar::chunk { 
            background-color: #1E88E5; 
            border-radius: 8px; 
        }
        
        /* --- Form Layout (for Login/Signup) --- */
        QFormLayout QLabel {
            font-weight: 600;
        }
        
        /* --- Style the Dialog Button Box (e.g., in ReportViewer) --- */
        QDialogButtonBox QPushButton {
            /* Use the default button style */
        }
        """

# ---------- Run Application ----------
def main():
    """The main entry point for the application."""
    app = QApplication(sys.argv)
    app.setStyle("Fusion") # 'Fusion' style is a good base
    
    # Initialize database tables on startup
    try:
        database.create_tables()
    except Exception as e:
        QMessageBox.critical(None, "Database Error", f"Could not initialize database:\n{e}")
        sys.exit(1)

    # We must set the global style *before* creating the dialog
    # to ensure it's styled correctly.
    app.setStyleSheet(MainWindow.qss())
    
    # Show the login dialog first
    login = LoginDialog(None)
    if login.exec_() != QDialog.Accepted:
        sys.exit(0) # Exit if login is cancelled
    
    # If login is successful, pass the user_id and username to the MainWindow
    w = MainWindow(user_id=login.user_id, username=login.username)
    w.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
