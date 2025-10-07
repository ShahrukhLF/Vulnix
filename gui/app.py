#!/usr/bin/env python3
"""
gui/app.py
Simple PyQt5 GUI for Vulnix (FYP Toolkit). Features:

* Input for target (network or web)
* Buttons: Run Network Scan, Run Web Scan
* Checkbox to enable intrusive tests (sqlmap)
* Live log area that streams subprocess output
* Button to open the latest summary file or generated PDF

Usage:
python3 gui/app.py
Dependencies:
pip3 install pyqt5
Run from project root so relative paths to scripts/ and results/ work.
"""
import sys
import os
import glob
import shlex
import subprocess
from PyQt5.QtWidgets import (
QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
QTextEdit, QLabel, QLineEdit, QCheckBox, QFileDialog, QMessageBox
)
from PyQt5.QtCore import QThread, pyqtSignal

# Helper worker to run a subprocess and stream stdout/stderr back to the UI

class RunnerThread(QThread):
output = pyqtSignal(str)
finished = pyqtSignal(int)  # exit code

```
def __init__(self, cmd, cwd=None):
    super().__init__()
    self.cmd = cmd
    self.cwd = cwd

def run(self):
    # Start subprocess and stream output line by line
    self.output.emit(f"[+] Running: {self.cmd}\n")
    # Use shell=False for safety — split the command
    proc = subprocess.Popen(shlex.split(self.cmd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=self.cwd, text=True)
    for line in proc.stdout:
        self.output.emit(line.rstrip() + "\n")
    proc.wait()
    self.finished.emit(proc.returncode)
```

class VulnixGUI(QWidget):
def **init**(self):
super().**init**()
self.setWindowTitle("Vulnix Toolkit - FYP")
self.setGeometry(200, 200, 900, 600)
self.setup_ui()

```
def setup_ui(self):
    layout = QVBoxLayout()

    # Target input
    tlayout = QHBoxLayout()
    tlayout.addWidget(QLabel("Target (IP or URL):"))
    self.target_input = QLineEdit()
    self.target_input.setPlaceholderText("e.g. 192.168.78.102  or  http://192.168.78.101:3000")
    tlayout.addWidget(self.target_input)
    layout.addLayout(tlayout)

    # Buttons
    btn_layout = QHBoxLayout()
    self.net_btn = QPushButton("Run Network Scan")
    self.net_btn.clicked.connect(self.run_network_scan)
    btn_layout.addWidget(self.net_btn)

    self.web_btn = QPushButton("Run Web Scan")
    self.web_btn.clicked.connect(self.run_web_scan)
    btn_layout.addWidget(self.web_btn)

    self.intrusive_chk = QCheckBox("Enable intrusive tests (sqlmap)")
    btn_layout.addWidget(self.intrusive_chk)

    self.open_report_btn = QPushButton("Open Latest Report Folder")
    self.open_report_btn.clicked.connect(self.open_latest_report)
    btn_layout.addWidget(self.open_report_btn)

    layout.addLayout(btn_layout)

    # Live log area
    self.log = QTextEdit()
    self.log.setReadOnly(True)
    layout.addWidget(self.log)

    self.setLayout(layout)

def append_log(self, text):
    self.log.moveCursor(self.log.textCursor().End)
    self.log.insertPlainText(text)
    self.log.ensureCursorVisible()

def run_network_scan(self):
    target = self.target_input.text().strip()
    if not target:
        QMessageBox.warning(self, "Input required", "Please enter a target IP for network scan.")
        return
    # Command points to scripts/scan_network.sh
    cmd = f"sudo ./scripts/scan_network.sh {shlex.quote(target)}"
    self.run_cmd(cmd)

def run_web_scan(self):
    target = self.target_input.text().strip()
    if not target:
        QMessageBox.warning(self, "Input required", "Please enter a target URL for web scan.")
        return
    intrusive = self.intrusive_chk.isChecked()
    cmd = f"sudo ./scripts/scan_web.sh {shlex.quote(target)}"
    if intrusive:
        cmd += " --enable-intrusive"
    self.run_cmd(cmd)

def run_cmd(self, cmd):
    # Disable buttons while running
    self.net_btn.setEnabled(False)
    self.web_btn.setEnabled(False)
    self.open_report_btn.setEnabled(False)
    self.append_log(f"\n[COMMAND] {cmd}\n")
    self.thread = RunnerThread(cmd, cwd=os.getcwd())
    self.thread.output.connect(self.append_log)
    self.thread.finished.connect(self.on_finished)
    self.thread.start()

def on_finished(self, exit_code):
    self.append_log(f"\n[PROCESS EXITED] code={exit_code}\n")
    self.net_btn.setEnabled(True)
    self.web_btn.setEnabled(True)
    self.open_report_btn.setEnabled(True)

def open_latest_report(self):
    # Find the most recent summary PDF or summary text in results/
    results_dir = os.path.join(os.getcwd(), "results")
    if not os.path.isdir(results_dir):
        QMessageBox.information(self, "No results", "No results/ directory found yet. Run a scan first.")
        return
    # Look for PDFs first, then summary_*.txt
    pdfs = glob.glob(os.path.join(results_dir, "**", "report_*.pdf"), recursive=True)
    if pdfs:
        latest = max(pdfs, key=os.path.getmtime)
        self.open_file(latest)
        return
    summaries = glob.glob(os.path.join(results_dir, "**", "summary_*.txt"), recursive=True)
    if summaries:
        latest = max(summaries, key=os.path.getmtime)
        self.open_file(latest)
        return
    QMessageBox.information(self, "No reports", "No PDF or summary files found in results/.")

def open_file(self, path):
    self.append_log(f"[OPEN] {path}\n")
    try:
        if sys.platform.startswith("linux"):
            subprocess.Popen(["xdg-open", path])
        elif sys.platform.startswith("win"):
            os.startfile(path)
        elif sys.platform.startswith("darwin"):
            subprocess.Popen(["open", path])
        else:
            QMessageBox.information(self, "Open file", f"Please open the file manually: {path}")
    except Exception as e:
        QMessageBox.warning(self, "Open failed", str(e))
```

def main():
app = QApplication(sys.argv)
gui = VulnixGUI()
gui.show()
sys.exit(app.exec_())

if **name** == "**main**":
main()
