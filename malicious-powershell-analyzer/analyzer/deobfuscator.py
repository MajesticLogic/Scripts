import re, codecs

def unescape_command(cmd):
    # Handle %u encoding, base64, and reversible obfuscation
    # Base64 pattern
    b64 = re.search(r"(?<=-EncodedCommand\s+)([A-Za-z0-9+/=]+)", cmd)
    if b64:
        raw = codecs.decode(b64.group(1), 'base64')
        return raw.decode('utf-16le', errors='ignore')
    return cmd
