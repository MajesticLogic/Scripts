from analyzer.deobfuscator import unescape_command

SIGNATURES = [
    'Invoke-Obfuscation',
    'DownloadFile',
    'Invoke-Expression',
    'Register-ScheduledTask',
]

HEURISTICS = {
    'high': ['Base64', 'Reflection', 'Assembly.Load'],
    'medium': ['Wscript.Shell', 'net.WebClient'],
    'low': ['Write-Host', 'Get-Process'],
}

def analyze_commands(cmds):
    findings = []
    for cmd in cmds:
        text = unescape_command(cmd['raw']) if 'raw' in cmd else cmd['name']
        for sig in SIGNATURES:
            if sig.lower() in text.lower():
                findings.append({'type': 'signature', 'match': sig, 'context': text})
        for level, patterns in HEURISTICS.items():
            for pat in patterns:
                if pat.lower() in text.lower():
                    findings.append({'type': 'heuristic', 'level': level, 'match': pat, 'context': text})
    return findings
