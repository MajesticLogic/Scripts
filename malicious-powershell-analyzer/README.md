# Malicious PowerShell Analyzer

A Python toolkit for scanning PowerShell scripts to detect obfuscation, suspicious APIs, and persistence mechanisms.

## Features
- AST Parsing: Leverages PowerShell AST to identify command invocations and script blocks
- Deobfuscation: Auto-unescape encoded PowerShell commands and strings
- Heuristics & Signatures: Built-in indicators for Invoke-Obfuscation patterns, Wscript use, reflection loading
- Persistence Detection: Flags registry, scheduled task, and WMI event subscriptions
- Reporting: JSON and HTML reports with severity scores and IOCs

## Installation
```bash
pip install -r requirements.txt
```

## Usage
```bash
python analyzer/cli.py --input scripts/malicious.ps1 --output report.html
```
