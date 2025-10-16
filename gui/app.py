#!/usr/bin/env python3
"""
Vulnix GUI / CLI launcher

This file provides two modes:
1) If PyQt5 is installed, runs the original PyQt5 GUI (same feature set).
2) If PyQt5 is NOT installed, falls back to a simple command-line interactive
   launcher which allows non-technical users to run the same scan scripts and
   open the latest generated report. This prevents ModuleNotFoundError in
   environments where PyQt5 is not available.

Usage:
  - GUI (preferred, if PyQt5 installed):
      python3 gui/app.py
  - CLI fallback (automatically used if PyQt5 missing):
      python3 gui/app.py

Notes:
  - This script assumes the scan scripts exist at scripts/scan_network.sh and
    scripts/scan_web.sh and are executable. Reports are expected under results/.
  - The CLI fallback streams subprocess output live so users can see progress.

Author: ChatGPT (modified to include CLI fallback for environments missing PyQt5)
"""

from __future__ import annotations

import os
import shlex
import subprocess
import sys
from pathlib import Path
from datetime import datetime
import glob
import time

# Configuration
NETWORK_SCRIPT = os.path.join("scripts", "scan_network.sh")
WEB_SCRIPT = os.path.join("scripts", "scan_web.sh")
RESULTS_DIR = "results"

# Helper utilities shared by GUI and CLI

def find_latest_report(safe_target_fragment: str | None = None) -> str | None:
    base = Path(RESULTS_DIR)
    if not base.exists():
        return None
    try:
        if safe_target_fragment:
            candidate = base / safe_target_fragment
            if candidate.exists() and candidate.is_dir():
                reports = sorted(candidate.glob('report_*.txt'), key=lambda p: p.stat().st_mtime, reverse=True)
                if reports:
                    return str(reports[0])
        # fallback search across all
        reports = sorted(base.glob('**/report_*.txt'), key=lambda p: p.stat().st_mtime, reverse=True)
        if reports:
            return str(reports[0])
    except Exception as e:
        print(f"[ERROR] finding report: {e}")
    return None


def open_file_with_default_app(path: str) -> None:
    """Open path with the platform default application (Linux: xdg-open)."""
    if not path or not os.path.exists(path):
        print(f"Report not found: {path}")
        return
    try:
        if sys.platform.startswith("linux"):
            subprocess.Popen(["xdg-open", path])
        elif sys.platform == "darwin":
            subprocess.Popen(["open", path])
        elif sys.platform.startswith("win"):
            os.startfile(path)
        else:
            print(f"Cannot open files automatically on this OS: {sys.platform}")
    except Exception as e:
        print(f"Failed to open file: {e}")


def run_command_stream(cmd: str) -> int:
    """Run a shell command and stream stdout/stderr to the console. Returns exit code."""
    print(f"[CMD] {cmd}")
    args = shlex.split(cmd)
    try:
        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
    except FileNotFoundError as e:
        print(f"Command not found: {e}")
        return 127
    except Exception as e:
        print(f"Failed to start process: {e}")
        return 1

    # stream lines
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            print(line.rstrip())
    except KeyboardInterrupt:
        print('\n[INFO] Keyboard interrupt received, terminating process...')
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            pass
        return -1
    rc = proc.wait()
    print(f"[INFO] Process finished with exit code {rc}")
    return rc


# CLI fallback implementation
def cli_menu():
    """Simple CLI menu for environments without PyQt5."""
    print("Vulnix - CLI Launcher (PyQt5 not available)")
    print("This fallback lets you run the same scans and open reports.")

    while True:
        print("\nSelect an option:")
        print("  1) Run Network Scan (fast)")
        print("  2) Run Network Scan (full, slow)")
        print("  3) Run Web Scan (provide full URL, e.g. http://192.168.78.101:3000)")
        print("  4) Open Latest Report (optionally for a target)")
        print("  5) List results/ directories")
        print("  6) Exit")
        choice = input("Choice: ").strip()

        if choice == "1":
            target = input("Enter target IP or hostname (e.g. 192.168.78.102): ").strip()
            if not target:
                print("Invalid target")
                continue
            cmd = f"sudo {NETWORK_SCRIPT} {shlex.quote(target)}"
            run_command_stream(cmd)
        elif choice == "2":
            target = input("Enter target IP or hostname (e.g. 192.168.78.102): ").strip()
            if not target:
                print("Invalid target")
                continue
            cmd = f"sudo {NETWORK_SCRIPT} {shlex.quote(target)} --full-scan"
            run_command_stream(cmd)
        elif choice == "3":
            url = input("Enter full URL (e.g. http://192.168.78.101:3000): ").strip()
            if not (url.startswith("http://") or url.startswith("https://")):
                print("Invalid URL — must start with http:// or https://")
                continue
            cmd = f"sudo {WEB_SCRIPT} {shlex.quote(url)}"
            run_command_stream(cmd)
        elif choice == "4":
            t = input("Optional: Enter target IP or URL to prefer its latest report (press Enter to search all): ").strip()
            safe_fragment = None
            if t:
                if t.startswith('http://') or t.startswith('https://'):
                    safe_fragment = t.replace('http://', '').replace('https://', '').replace('/', '_').replace(':', '_')
                else:
                    safe_fragment = t.replace('/', '_').replace(':', '_')
            rpt = find_latest_report(safe_fragment)
            if rpt:
                print(f"Opening report: {rpt}")
                open_file_with_default_app(rpt)
            else:
                print("No report found. Run a scan first.")
        elif choice == "5":
            base = Path(RESULTS_DIR)
            if not base.exists():
                print("No results directory found yet.")
                continue
            for p in sorted(base.iterdir()):
                if p.is_dir():
                    try:
                        m = max([f.stat().st_mtime for f in p.glob('report_*.txt')], default=0)
                        print(f"{p.name} (latest report mtime: {datetime.fromtimestamp(m) if m else 'N/A'})")
                    except Exception:
                        print(p.name)
        elif choice == "6":
            print("Exiting.")
            break
        else:
            print("Invalid option — choose 1-6.")


# GUI Implementation (only loaded if PyQt5 available)
try:
    from PyQt5.QtCore import Qt, QThread, pyqtSignal
    from PyQt5.QtWidgets import (
        QApplication,
        QMainWindow,
        QWidget,
        QVBoxLayout,
        QHBoxLayout,
        QLabel,
        QLineEdit,
        QPushButton,
        QTextEdit,
        QCheckBox,
        QFileDialog,
        QMessageBox,
    )

    class ProcessThreadGUI(QThread):
        output_line = pyqtSignal(str)
        finished_signal = pyqtSignal(int)

        def __init__(self, cmd, cwd=None):
            super().__init__()
            self.cmd = cmd
            self.cwd = cwd
            self._proc = None

        def run(self):
            try:
                args = shlex.split(self.cmd)
                self._proc = subprocess.Popen(
                    args,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    cwd=self.cwd,
                    bufsize=1,
                    universal_newlines=True,
                )
            except Exception as e:
                self.output_line.emit(f"[ERROR] Failed to start process: {e}\n")
                self.finished_signal.emit(-1)
                return

            try:
                for line in self._proc.stdout:
                    self.output_line.emit(line.rstrip())
            except Exception as e:
                self.output_line.emit(f"[ERROR] Reading process output failed: {e}\n")

            rc = self._proc.wait()
            self.finished_signal.emit(rc)

        def terminate(self):
            if self._proc and self._proc.poll() is None:
                try:
                    self._proc.terminate()
                except Exception:
                    pass
            super().terminate()


    class MainWindowGUI(QMainWindow):
        def __init__(self):
            super().__init__()
            self.setWindowTitle("Vulnix - FYP Toolkit (GUI)")
            self.setMinimumSize(900, 600)

            central = QWidget()
            self.setCentralWidget(central)
            layout = QVBoxLayout(central)

            # Row: target input
            row = QHBoxLayout()
            row.addWidget(QLabel("Target (IP or URL):"))
            self.target_input = QLineEdit()
            self.target_input.setPlaceholderText("e.g. 192.168.78.102  or  http://192.168.78.101:3000")
            row.addWidget(self.target_input)

            # Checkbox for network full scan
            self.full_scan_cb = QCheckBox("Network: run full scan (-p-) (slow)")
            row.addWidget(self.full_scan_cb)

            layout.addLayout(row)

            # Row: buttons
            btn_row = QHBoxLayout()
            self.net_btn = QPushButton("Run Network Scan")
            self.net_btn.clicked.connect(self.on_run_network)
            btn_row.addWidget(self.net_btn)

            self.web_btn = QPushButton("Run Web Scan")
            self.web_btn.clicked.connect(self.on_run_web)
            btn_row.addWidget(self.web_btn)

            self.open_report_btn = QPushButton("Open Latest Report")
            self.open_report_btn.clicked.connect(self.on_open_latest_report)
            btn_row.addWidget(self.open_report_btn)

            self.choose_btn = QPushButton("Browse Target...")
            self.choose_btn.clicked.connect(self.on_browse_target)
            btn_row.addWidget(self.choose_btn)

            layout.addLayout(btn_row)

            # Output log area
            self.log = QTextEdit()
            self.log.setReadOnly(True)
            layout.addWidget(self.log)

            # Footer status
            status_row = QHBoxLayout()
            self.status_label = QLabel("Ready")
            status_row.addWidget(self.status_label)
            status_row.addStretch()
            layout.addLayout(status_row)

            # Variables
            self.proc_thread = None

        def append(self, text):
            self.log.append(text)
            self.log.moveCursor(self.log.textCursor().End)

        def _validate_target_for_network(self, target):
            if target.startswith("http://") or target.startswith("https://"):
                QMessageBox.warning(self, "Invalid target", "Network scan expects an IP or hostname (no http://).")
                return False
            if not target.strip():
                QMessageBox.warning(self, "Invalid target", "Please enter a target IP or hostname.")
                return False
            return True

        def _validate_target_for_web(self, target):
            if not (target.startswith("http://") or target.startswith("https://")):
                QMessageBox.warning(self, "Invalid target", "Web scan expects a URL like http://<ip>:3000")
                return False
            return True

        def _find_latest_report(self, safe_target_fragment=None):
            try:
                base = Path(RESULTS_DIR)
                if not base.exists():
                    return None

                if safe_target_fragment:
                    candidate_dir = base / safe_target_fragment
                    if candidate_dir.exists() and candidate_dir.is_dir():
                        reports = sorted(candidate_dir.glob('report_*.txt'), key=os.path.getmtime, reverse=True)
                        if reports:
                            return str(reports[0])
                reports = sorted(base.glob('**/report_*.txt'), key=os.path.getmtime, reverse=True)
                if reports:
                    return str(reports[0])
            except Exception as e:
                self.append(f"[ERROR] finding report: {e}")
            return None

        def _open_file(self, path):
            if not path:
                QMessageBox.information(self, "Open Report", "No report found.")
                return
            if not os.path.exists(path):
                QMessageBox.information(self, "Open Report", f"Report not found: {path}")
                return
            try:
                subprocess.Popen(["xdg-open", path])
            except Exception:
                QMessageBox.information(self, "Open Report", f"Could not open report: {path}")

        def on_browse_target(self):
            path = QFileDialog.getExistingDirectory(self, "Select results folder (optional)")
            if path:
                self.target_input.setText(path)

        def on_open_latest_report(self):
            t = self.target_input.text().strip()
            safe_fragment = None
            if t:
                if t.startswith('http://') or t.startswith('https://'):
                    safe_fragment = t.replace('http://', '').replace('https://', '').replace('/', '_').replace(':', '_')
                else:
                    safe_fragment = t.replace('/', '_').replace(':', '_')
            report = self._find_latest_report(safe_fragment)
            if report:
                self.append(f"[INFO] Opening report: {report}")
                self._open_file(report)
            else:
                QMessageBox.information(self, "Open Report", "No report found. Run a scan first.")

        def _run_command(self, cmd):
            self.net_btn.setEnabled(False)
            self.web_btn.setEnabled(False)
            self.open_report_btn.setEnabled(False)
            self.status_label.setText("Scanning...")
            self.append(f"[CMD] {cmd}")

            self.proc_thread = ProcessThreadGUI(cmd)
            self.proc_thread.output_line.connect(lambda ln: self.append(ln))
            self.proc_thread.finished_signal.connect(self._on_proc_finished)
            self.proc_thread.start()

        def _on_proc_finished(self, rc):
            self.append(f"[INFO] Process finished with exit code {rc}")
            self.net_btn.setEnabled(True)
            self.web_btn.setEnabled(True)
            self.open_report_btn.setEnabled(True)
            self.status_label.setText("Ready")
            t = self.target_input.text().strip()
            safe_fragment = None
            if t:
                if t.startswith('http://') or t.startswith('https://'):
                    safe_fragment = t.replace('http://', '').replace('https://', '').replace('/', '_').replace(':', '_')
                else:
                    safe_fragment = t.replace('/', '_').replace(':', '_')
            report = self._find_latest_report(safe_fragment)
            if report:
                self.append(f"[INFO] Latest report: {report}")

        def on_run_network(self):
            target = self.target_input.text().strip()
            if not self._validate_target_for_network(target):
                return
            full = self.full_scan_cb.isChecked()
            if full:
                cmd = f"sudo {NETWORK_SCRIPT} {shlex.quote(target)} --full-scan"
            else:
                cmd = f"sudo {NETWORK_SCRIPT} {shlex.quote(target)}"
            self._run_command(cmd)

        def on_run_web(self):
            target = self.target_input.text().strip()
            if not self._validate_target_for_web(target):
                return
            cmd = f"sudo {WEB_SCRIPT} {shlex.quote(target)}"
            self._run_command(cmd)

    def ensure_scripts_exist_gui():
        missing = []
        if not os.path.exists(NETWORK_SCRIPT):
            missing.append(NETWORK_SCRIPT)
        if not os.path.exists(WEB_SCRIPT):
            missing.append(WEB_SCRIPT)
        if missing:
            QMessageBox.critical(None, "Missing scripts", "The following required scripts are missing:\n" + "\n".join(missing))
            return False
        return True

except ModuleNotFoundError:
    # PyQt5 not available; GUI won't be loaded. We'll use CLI fallback instead.
    QApplication = None
    MainWindowGUI = None


def main():
    # If PyQt5 is available, launch GUI; otherwise launch CLI fallback.
    if QApplication is not None:
        app = QApplication(sys.argv)
        win = MainWindowGUI()
        if not ensure_scripts_exist_gui():
            win.append("[ERROR] Required scripts are missing. Place them in scripts/ and restart.")
        win.show()
        sys.exit(app.exec_())
    else:
        print("PyQt5 is not installed in this environment. Launching CLI fallback.")
        # Ensure scripts exist before showing the CLI
        missing = []
        if not os.path.exists(NETWORK_SCRIPT):
            missing.append(NETWORK_SCRIPT)
        if not os.path.exists(WEB_SCRIPT):
            missing.append(WEB_SCRIPT)
        if missing:
            print("The following required scripts are missing:")
            for m in missing:
                print("  -", m)
            print("Please add them to the scripts/ folder and re-run this program.")
            sys.exit(1)
        cli_menu()


if __name__ == '__main__':
    main()
