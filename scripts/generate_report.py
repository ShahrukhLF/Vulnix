#!/usr/bin/env python3
"""
generate_report.py
Simple report generator for Vulnix: turns a summary text (summary_*.txt) into a readable PDF.

Usage:
python3 scripts/generate_report.py --summary results/<target>/summary_<ts>.txt --outpdf results/<target>/report_<ts>.pdf

Dependencies:
pip3 install fpdf2
"""
import argparse
from fpdf import FPDF
from pathlib import Path
import textwrap

def parse_summary_text(text):
"""
Split the summary into simple sections using '=== SECTION ===' markers.
Returns list of (heading, body).
"""
lines = text.splitlines()
sections = []
cur_heading = "Overview"
cur_body = []
for line in lines:
if line.strip().startswith("===") and line.strip().endswith("==="):
# save previous section
if cur_body:
sections.append((cur_heading.strip(), "\n".join(cur_body).strip()))
cur_heading = line.strip("= ").strip()
cur_body = []
else:
cur_body.append(line)
if cur_body:
sections.append((cur_heading.strip(), "\n".join(cur_body).strip()))
return sections

class PDFReport:
def **init**(self, outpath):
self.pdf = FPDF()
self.pdf.set_auto_page_break(auto=True, margin=12)
self.outpath = Path(outpath)

```
def add_title(self, title):
    self.pdf.add_page()
    self.pdf.set_font("Arial", "B", 16)
    self.pdf.cell(0, 10, title, ln=True, align="C")
    self.pdf.ln(4)

def add_section(self, heading, body):
    self.pdf.set_font("Arial", "B", 12)
    self.pdf.cell(0, 8, heading, ln=True)
    self.pdf.ln(2)
    # set monospace-like font for technical excerpts
    self.pdf.set_font("Courier", size=9)
    wrapped = textwrap.fill(body, width=100)
    self.pdf.multi_cell(0, 5, wrapped)
    self.pdf.ln(4)

def save(self):
    self.outpath.parent.mkdir(parents=True, exist_ok=True)
    self.pdf.output(str(self.outpath))
```

def main():
parser = argparse.ArgumentParser()
parser.add_argument("--summary", required=True, help="Path to summary text file")
parser.add_argument("--outpdf", required=True, help="Path to output PDF")
args = parser.parse_args()

```
sfile = Path(args.summary)
if not sfile.exists():
    print(f"[ERROR] Summary file not found: {sfile}")
    return

text = sfile.read_text(encoding="utf-8", errors="ignore")
sections = parse_summary_text(text)
rpt = PDFReport(args.outpdf)
rpt.add_title(f"Vulnix Scan Report - {sfile.parent.name}")
for heading, body in sections:
    rpt.add_section(heading, body)
rpt.save()
print(f"[+] PDF generated: {args.outpdf}")
```

if **name** == "**main**":
main()
