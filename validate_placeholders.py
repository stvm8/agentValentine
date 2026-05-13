#!/usr/bin/env python3
"""
PostToolUse hook — validates that Playbook/CHAIN files contain no hardcoded
lab-specific values. Reads Claude Code hook JSON from stdin, exits 0 (clean)
or emits a reason message (violations found).
"""

import json
import re
import sys

WATCHED_PATHS = ("Playbooks/", "CHAINS/")

# Each tuple: (label, pattern)
# Patterns intentionally avoid matching <placeholder> syntax.
PATTERNS = [
    (
        "email address",
        re.compile(
            r"(?<![<\w])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![>\w])"
        ),
    ),
    (
        "UUID/GUID",
        re.compile(
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
        ),
    ),
    (
        "NTLM hash",
        re.compile(r"\b[0-9a-fA-F]{32}\b"),
    ),
    (
        "DOMAIN\\user",
        # Require 2+ chars for the user portion to avoid false positives like GET\n
        re.compile(r"\b([A-Z][A-Z0-9]{1,14})\\([A-Za-z0-9._-]{2,})\b"),
    ),
    (
        "hardcoded IP (non-example)",
        # True 4-octet match for all RFC1918 ranges
        re.compile(
            r"(?<![<.])\b((?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3})\b(?![>/])"
        ),
    ),
    (
        "bare FQDN",
        # hostname.domain.tld — catches lab-specific FQDNs like dc01.corp.local
        # Negative lookbehind includes / to avoid matching inside URLs (after //)
        re.compile(
            r"(?<![<.\w/])([A-Za-z0-9][A-Za-z0-9-]{1,})\.([A-Za-z0-9][A-Za-z0-9-]{1,})\.([A-Za-z]{2,})\b"
        ),
    ),
    (
        "machine account (HOSTNAME$)",
        # Catches AD machine account notation: DC01$, MCORP-DC$, etc.
        re.compile(r"(?<!\w)([A-Za-z0-9][A-Za-z0-9-]{2,})\$(?!\w)"),
    ),
]

# Exact values that are universal constants, not lab-specific
ALLOWED_EXACT = {
    "aad3b435b51404eeaad3b435b51404ee",  # empty LM hash constant
    "git@github.com",                     # GitHub SSH remote URL
    "00000000-0000-0000-0000-000000000000",  # null UUID
}

# Well-known CLSIDs, AD schema GUIDs, and Azure/Microsoft app IDs
ALLOWED_UUIDS = {
    # AD schema rights GUIDs
    "00299570-246d-11d0-a768-00aa006e0529",
    "7ca9c789-14ce-46e3-a722-83f4097af532",
    # Potato/COM CLSIDs
    "e60687f7-01a1-40aa-86ac-db1cbf673334",
    "c08afd90-f2a1-11d1-8455-00a0c91f3880",
    "c8c47398-2682-2867-f35d-41516ed952e5",
    "8d52f9da-361b-4dc3-8fa7-af5f282fa741",
    # Microsoft/Azure well-known app IDs
    "d3590ed6-52b3-4102-aeff-aad2292ab01c",  # Microsoft Office
    "d3590ed6-52b3-4102-aedd-a47eb6b5b65d",  # Microsoft Office (variant)
    "d3590ed6-52b3-4102-aedd-a47eb6b5b5cb",  # Microsoft Graph PowerShell
    "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator role
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",  # Azure app ID
}

# DOMAIN\user pattern: Windows built-ins and generic placeholder prefixes
ALLOWED_DOMAIN_PREFIXES = {
    "AUTHORITY",   # NT AUTHORITY\SYSTEM
    "BUILTIN",     # BUILTIN\Users, BUILTIN\Administrators
    "HKLM",        # Registry hive
    "HKCU",        # Registry hive
    "HKEY",        # Registry hive (HKEY_LOCAL_MACHINE etc.)
    "GLOBALROOT",  # \\.\GLOBALROOT\Device\*
    "LOGONSERVER", # \\LOGONSERVER\NETLOGON
    "NT",          # NT\CurrentVersion
    "NDP",         # NDP\v4 (.NET path)
    "NET",         # NET\Framework64
    "SOFTWARE",    # SOFTWARE\Classes, SOFTWARE\Microsoft
    "SYSTEM",      # SYSTEM\CurrentControlSet (registry)
    "DOMAIN",      # Generic placeholder (DOMAIN\user is already placeholder form)
    "LOCAL",       # LOCAL\scripts style paths
    "SYSVOL",      # SYSVOL\domain.local share path component
    "AD",          # C:\AD\Tools style Windows tool paths
    "SERVER",      # SERVER\ShareName generic example
    "PARENT",      # PARENT\Administrator generic domain placeholder
    "DC01",        # DC01\SYSVOL — very common generic DC hostname in examples
}

# Common RFC1918 network base addresses used as generic range examples
ALLOWED_IP_BASES = {
    "10.0.0.0", "10.0.0.1",
    "172.16.0.0", "172.16.0.1",
    "192.168.0.0", "192.168.0.1",
    "192.168.1.0", "192.168.1.1",
}

# Public documentation/tooling domains commonly referenced in payloads or links
ALLOWED_FQDN_SUFFIXES = {
    "microsoft.com", "azure.com", "microsoftonline.com", "azurewebsites.net",
    "github.com", "github.io",
    "google.com", "googleapis.com",
    "amazonaws.com", "awsstatic.com",
    "cloudflare.com",
    "mitre.org",
    "gitbook.io", "gitbook.com",
    "pypi.org",
    "kali.org",
}

# Generic machine-account-like tokens that are not lab-specific hostnames
ALLOWED_MACHINE_ACCOUNTS = {
    "MACHINE",                          # impacket generic placeholder
    "ADMIN", "IPC", "PRINT",           # Windows hidden share names (ADMIN$, IPC$, PRINT$)
    "SYSVOL", "NETLOGON",              # Windows default share names
    "newmachine", "images", "share", "plaintext",  # generic example variable names
    "InconspicuousMachineAccount",     # CRTP training lab generic name
}


def _inside_angle_brackets(line: str, match) -> bool:
    """Return True if the match is enclosed in <...> on the same line."""
    before = line[: match.start()]
    after = line[match.end():]
    last_open = before.rfind("<")
    last_close = before.rfind(">")
    # An unclosed < precedes the match AND a > follows it → inside <...>
    return last_open > last_close and ">" in after


def check_file(path: str) -> list[str]:
    try:
        text = open(path).read()
    except OSError:
        return []

    violations = []
    for lineno, line in enumerate(text.splitlines(), 1):
        # Skip comment lines and blockquote lines
        if re.match(r"^\s*[#>]", line):
            continue
        for label, pattern in PATTERNS:
            for match in pattern.finditer(line):
                val = match.group()
                val_lower = val.lower()

                # Skip if enclosed in angle brackets (explicit placeholder)
                if _inside_angle_brackets(line, match):
                    continue

                # Universal constant allowlist
                if val_lower in ALLOWED_EXACT or val in ALLOWED_EXACT:
                    continue

                # UUID-specific allowlist
                if label == "UUID/GUID" and val_lower in ALLOWED_UUIDS:
                    continue

                # DOMAIN\user — skip Windows built-ins and generic prefixes
                if label == "DOMAIN\\user":
                    prefix = match.group(1)
                    if prefix in ALLOWED_DOMAIN_PREFIXES:
                        continue

                # IP — skip common network base addresses and CIDR ranges
                if label == "hardcoded IP (non-example)":
                    ip = match.group(1)
                    if ip in ALLOWED_IP_BASES:
                        continue
                    # Skip if immediately followed by / (CIDR notation)
                    after = line[match.end():]
                    if after.startswith("/"):
                        continue

                # FQDN — skip well-known public documentation/tooling domains
                if label == "bare FQDN":
                    fqdn_lower = val.lower()
                    if any(fqdn_lower.endswith("." + suf) for suf in ALLOWED_FQDN_SUFFIXES):
                        continue

                # Machine account — skip generic share names and placeholder names
                if label == "machine account (HOSTNAME$)":
                    if match.group(1).upper() in {a.upper() for a in ALLOWED_MACHINE_ACCOUNTS}:
                        continue

                violations.append(f"  line {lineno}: [{label}] {val!r}")

    return violations


def main():
    raw = sys.stdin.read()
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        print("{}")
        return

    tool_name = payload.get("tool_name", "")
    if tool_name not in ("Write", "Edit"):
        print("{}")
        return

    file_path = payload.get("tool_input", {}).get("file_path", "")
    if not any(p in file_path for p in WATCHED_PATHS):
        print("{}")
        return

    violations = check_file(file_path)
    if not violations:
        print("{}")
        return

    lines = "\n".join(violations)
    reason = (
        f"[PLACEHOLDER VIOLATION] Hardcoded lab-specific values detected in {file_path}:\n"
        f"{lines}\n"
        "Replace with <placeholder> syntax before continuing."
    )
    print(json.dumps({"reason": reason}))


if __name__ == "__main__":
    main()
