import pytest
from analyzer.cli import main as run_cli

def test_benign(tmp_path, capsys):
    benign = tmp_path / "benign.ps1"
    benign.write_text("Write-Host 'Hello World'")
    out = tmp_path / "report.json"
    run_cli(['--input', str(benign), '--output', str(out)])
    data = out.read_text()
    assert 'findings' in data
