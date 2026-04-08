#!/usr/bin/env python3
"""
scopeExtract.py — Multi-platform bug bounty scope extractor.

Parses raw ROE text from Bugcrowd, HackerOne, Intigriti, or YesWeHack
into Obsidian-compatible markdown + machine-readable target lists for recon tools.

Usage:
    python scopeExtract.py -f raw_scope.txt -o scope.md
    python scopeExtract.py -f raw_scope.txt -o scope.md -d ./recon_lists/
"""

import argparse
import os
import re
import sys
from datetime import datetime

# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------

PLATFORM_HINTS = {
    "bugcrowd":   ["bugcrowd", "bugcrowdninja", "crowdcontrol"],
    "hackerone":   ["hackerone", "h1", "hacker one"],
    "intigriti":   ["intigriti"],
    "yeswehack":   ["yeswehack", "yes we hack"],
}

def detect_platform(text):
    lower = text.lower()
    for platform, hints in PLATFORM_HINTS.items():
        if any(h in lower for h in hints):
            return platform
    return "unknown"

# ---------------------------------------------------------------------------
# Scope splitting
# ---------------------------------------------------------------------------

OUT_OF_SCOPE_PATTERNS = [
    r"out[\s-]*of[\s-]*scope",
    r"ouf[\s-]*of[\s-]*scope",       # common typo on Bugcrowd
    r"exclusions",
    r"not\s+eligible",
    r"assets?\s+out\s+of\s+scope",
    r"out[\s-]*of[\s-]*scope\s+assets?",
]

def split_scope(text):
    pattern = "|".join(OUT_OF_SCOPE_PATTERNS)
    parts = re.split(pattern, text, maxsplit=1, flags=re.IGNORECASE)
    in_scope = parts[0]
    out_scope = parts[1] if len(parts) > 1 else ""
    return in_scope, out_scope

# ---------------------------------------------------------------------------
# Target extraction
# ---------------------------------------------------------------------------

NOISE_DOMAINS = {
    "bugcrowd.com", "hackerone.com", "intigriti.com", "yeswehack.com",
    "play.google.com", "apps.apple.com", "itunes.apple.com",
    "support.google.com", "support.apple.com",
    "docs.google.com", "drive.google.com",
    "cdn.jsdelivr.net", "cdnjs.cloudflare.com",
    "fonts.googleapis.com", "ajax.googleapis.com",
    "www.w3.org", "schema.org",
}

NOISE_SUBSTRINGS = [
    "bugcrowd.com", "hackerone.com", "intigriti.com", "yeswehack.com",
]

def _is_noise(value):
    v = value.lower().strip(".")
    if v in NOISE_DOMAINS:
        return True
    return any(n in v for n in NOISE_SUBSTRINGS)

def extract_targets(text):
    """Return a dict of categorised targets found in text."""

    targets = {
        "wildcards": set(),
        "domains":   set(),
        "urls":      set(),
        "ips":       set(),
        "cidrs":     set(),
        "ports":     set(),      # host:port
        "mobile":    set(),      # reverse-domain app IDs
        "github":    set(),
        "api":       set(),      # explicit /api/... paths
    }

    # --- Wildcards: *.example.com ---
    for m in re.finditer(r'\*\.([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}', text):
        val = m.group(0)
        if not _is_noise(val):
            targets["wildcards"].add(val)

    # --- CIDRs: 10.0.0.0/8 ---
    for m in re.finditer(r'\b(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\b', text):
        targets["cidrs"].add(m.group(1))

    # --- IPs (after CIDRs so we can exclude them) ---
    for m in re.finditer(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', text):
        ip = m.group(1)
        # skip if it's part of a CIDR already captured
        if any(ip in c for c in targets["cidrs"]):
            continue
        octets = ip.split(".")
        if all(0 <= int(o) <= 255 for o in octets):
            targets["ips"].add(ip)

    # --- URLs with protocol ---
    for m in re.finditer(r'https?://([a-zA-Z0-9.-]+(?::\d+)?(?:/[^\s)\]<>,\"\']*)?)', text):
        full = m.group(0)
        host = m.group(1).split("/")[0].split(":")[0]
        if _is_noise(host):
            # check if it's a mobile store link
            if "play.google.com" in host or "apps.apple.com" in host or "itunes.apple.com" in host:
                # extract app ID from Play Store URL
                pkg = re.search(r'id=([a-zA-Z0-9_.]+)', full)
                if pkg:
                    targets["mobile"].add(pkg.group(1))
                # extract from Apple URL path (e.g. /app/appname/id12345)
                apple_id = re.search(r'/id(\d+)', full)
                if apple_id:
                    targets["mobile"].add(f"apple:id{apple_id.group(1)}")
            continue
        targets["urls"].add(full.rstrip(".,;:)]}"))
        targets["domains"].add(host)

    # --- Port-specific targets: host:8443 (not part of a URL) ---
    for m in re.finditer(r'(?<!/)(?<!//)([a-zA-Z0-9.-]+):(\d{2,5})\b', text):
        host = m.group(1)
        port = m.group(2)
        if not _is_noise(host) and host not in ("http", "https"):
            targets["ports"].add(f"{host}:{port}")
            targets["domains"].add(host)

    # --- Standalone domains (not already captured via URLs) ---
    for m in re.finditer(r'\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63})\b', text):
        domain = m.group(1).rstrip(".")
        if _is_noise(domain):
            continue
        # skip things that look like file extensions, versions, etc.
        tld = domain.rsplit(".", 1)[-1].lower()
        if tld in ("js", "css", "html", "json", "xml", "txt", "md", "py", "sh", "yml", "yaml", "png", "jpg", "gif", "pdf"):
            continue
        # skip if it's an IP (already handled)
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
            continue
        targets["domains"].add(domain)

    # --- Mobile app identifiers: com.company.app / org.project.app ---
    for m in re.finditer(r'\b((?:com|org|net|io)\.[a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)+)\b', text):
        candidate = m.group(1)
        # must have at least 3 segments and not look like a domain we already have
        parts = candidate.split(".")
        if len(parts) >= 3 and parts[-1].lower() not in ("com", "org", "net", "io"):
            targets["mobile"].add(candidate)

    # --- GitHub repos ---
    for m in re.finditer(r'github\.com/([a-zA-Z0-9._-]+(?:/[a-zA-Z0-9._-]+)?)', text):
        targets["github"].add(f"github.com/{m.group(1)}")

    # --- API paths: /api/v1/... ---
    for m in re.finditer(r'(/api/[a-zA-Z0-9/._-]+)', text):
        targets["api"].add(m.group(1).rstrip("/"))

    # Clean: remove domains that are just wildcard bases
    wildcard_bases = {w.lstrip("*.") for w in targets["wildcards"]}
    targets["domains"] -= wildcard_bases

    # Sort everything for deterministic output
    return {k: sorted(v) for k, v in targets.items()}

# ---------------------------------------------------------------------------
# Rule extraction
# ---------------------------------------------------------------------------

def extract_rules(text):
    """Extract engagement rules from raw text. Only include rules actually present."""
    can_do = []
    cannot_do = []
    lower = text.lower()

    # --- CAN DO ---
    if "bugcrowdninja" in lower:
        can_do.append("Register accounts using your `@bugcrowdninja.com` email address.")

    header_match = re.search(r'(X-[a-zA-Z0-9-]+:<[a-zA-Z0-9]+>)', text)
    if header_match:
        can_do.append(f"Add the `{header_match.group(1)}` header to all HTTP traffic.")
    elif "x-bug-bounty" in lower:
        can_do.append("Add the `X-Bug-Bounty:<username>` header to all HTTP traffic.")

    if "single report" in lower or "single ticket" in lower or "single submission" in lower:
        can_do.append("Combine identical vulns across domains/environments into a single report.")

    if re.search(r'\b30\s*days?\b', lower) and ("n-day" in lower or "0-day" in lower or "third.party" in lower or "3rd.party" in lower):
        can_do.append("Report N-day / 3rd-party 0-day bugs only after 30 days from public release.")

    if "stolen" in lower or "dark web" in lower or "breached" in lower:
        can_do.append("Report stolen/breached credentials (points only, no bounty).")

    if "safe harbor" in lower or "safe harbour" in lower:
        can_do.append("Safe harbor policy applies — authorized testing is protected.")

    # --- CANNOT DO ---
    if "other users" in lower or "other user" in lower or "other accounts" in lower:
        cannot_do.append("Do not target, manipulate, or access other users' data.")

    if "dos" in lower or "ddos" in lower or "denial of service" in lower or "volumetric" in lower:
        cannot_do.append("No DoS, DDoS, or volumetric testing.")

    if "social engineering" in lower or "phishing" in lower:
        cannot_do.append("No social engineering, phishing, or physical attacks.")

    if "proof of concept" in lower or "poc" in lower:
        cannot_do.append("All submissions must include a working PoC.")

    if "post-exploitation" in lower or "post exploitation" in lower:
        cannot_do.append("Stop and submit immediately upon post-exploitation or data destruction risk.")

    if "automated scanning" in lower or "automated scan" in lower or "mass scan" in lower:
        cannot_do.append("No automated mass scanning — targeted testing only.")

    if "production" in lower and ("stability" in lower or "integrity" in lower or "disrupt" in lower):
        cannot_do.append("Do not compromise production stability or integrity.")

    if "public disclosure" in lower or "publicly disclos" in lower:
        cannot_do.append("No public disclosure before authorization from the program.")

    return can_do, cannot_do

# ---------------------------------------------------------------------------
# Reward tier extraction
# ---------------------------------------------------------------------------

def extract_reward_tiers(text):
    """Try to pull bounty/reward tables from raw text."""
    tiers = []
    # Match patterns like: Critical ... $5,000 - $10,000  or  P1 ... $10000
    for m in re.finditer(
        r'((?:P[1-5]|Critical|High|Medium|Low|Informational|None))\s*[:\-|]*\s*'
        r'(\$[\d,]+(?:\s*[-–]\s*\$[\d,]+)?)',
        text, re.IGNORECASE
    ):
        tiers.append((m.group(1).strip(), m.group(2).strip()))
    return tiers

# ---------------------------------------------------------------------------
# Excluded vuln types
# ---------------------------------------------------------------------------

def extract_excluded_vulns(out_of_scope_text):
    """Extract vulnerability types mentioned as excluded."""
    excluded = []
    lower = out_of_scope_text.lower()

    vuln_patterns = [
        (r"self[- ]?xss", "Self-XSS"),
        (r"missing.*security.*header", "Missing security headers"),
        (r"ssl[/ ]tls", "SSL/TLS configuration issues"),
        (r"spf[/ ]dkim[/ ]dmarc|email.*spoof", "SPF/DKIM/DMARC / email spoofing"),
        (r"open redirect", "Open redirects (unless chainable)"),
        (r"rate limit", "Rate limiting issues"),
        (r"clickjack", "Clickjacking"),
        (r"csv injection|formula injection", "CSV/formula injection"),
        (r"best.?practice", "Best-practice / informational findings"),
        (r"logout.*csrf|csrf.*logout", "CSRF on logout"),
        (r"content.?spoof", "Content spoofing"),
        (r"tabnab", "Tabnabbing"),
        (r"host.?header", "Host header injection"),
        (r"stack.?trace|verbose.?error", "Stack traces / verbose errors"),
        (r"autocomplete", "Autocomplete on forms"),
    ]

    for pattern, label in vuln_patterns:
        if re.search(pattern, lower):
            excluded.append(label)

    return excluded

# ---------------------------------------------------------------------------
# Obsidian markdown generation
# ---------------------------------------------------------------------------

def generate_markdown(raw_text, platform):
    in_scope_raw, out_scope_raw = split_scope(raw_text)

    in_targets  = extract_targets(in_scope_raw)
    out_targets = extract_targets(out_scope_raw)
    can_do, cannot_do = extract_rules(raw_text)
    reward_tiers = extract_reward_tiers(raw_text)
    excluded_vulns = extract_excluded_vulns(out_scope_raw)

    date_str = datetime.now().strftime("%Y-%m-%d")

    # --- YAML frontmatter ---
    md = f"---\ntags:\n  - bugbounty\n  - {platform}\n  - target-scope\ndate: {date_str}\n---\n\n"

    # --- In Scope ---
    md += "> [!success] In Scope\n"
    if in_targets["urls"]:
        md += f"> - **URLs:** `{'`, `'.join(in_targets['urls'])}`\n"
    if in_targets["wildcards"]:
        md += f"> - **Wildcards:** `{'`, `'.join(in_targets['wildcards'])}`\n"
    if in_targets["domains"]:
        md += f"> - **Domains:** `{'`, `'.join(in_targets['domains'])}`\n"
    if in_targets["ips"]:
        md += f"> - **IPs:** `{'`, `'.join(in_targets['ips'])}`\n"
    if in_targets["cidrs"]:
        md += f"> - **CIDRs:** `{'`, `'.join(in_targets['cidrs'])}`\n"
    if in_targets["ports"]:
        md += f"> - **Port Targets:** `{'`, `'.join(in_targets['ports'])}`\n"
    if in_targets["mobile"]:
        md += f"> - **Mobile Apps:** `{'`, `'.join(in_targets['mobile'])}`\n"
    if in_targets["github"]:
        md += f"> - **Source Code:** `{'`, `'.join(in_targets['github'])}`\n"
    if in_targets["api"]:
        md += f"> - **API Endpoints:** `{'`, `'.join(in_targets['api'])}`\n"

    # --- Out of Scope ---
    md += "\n> [!danger] Out of Scope\n"
    all_out = (out_targets["wildcards"] + out_targets["domains"] +
               out_targets["urls"] + out_targets["ips"] + out_targets["cidrs"])
    if all_out:
        md += f"> - `{'`, `'.join(all_out)}`\n"
    md += "> - Third-party providers and services not explicitly listed above.\n"

    # --- Excluded vulnerability types ---
    if excluded_vulns:
        md += "\n> [!caution] Excluded Vulnerability Types\n"
        for v in excluded_vulns:
            md += f"> - {v}\n"

    # --- Reward tiers ---
    if reward_tiers:
        md += "\n> [!tip] Reward Tiers\n"
        for severity, bounty in reward_tiers:
            md += f"> - **{severity}:** {bounty}\n"

    # --- What you can do ---
    if can_do:
        md += "\n> [!info] What You Can Do\n"
        for item in can_do:
            md += f"> - {item}\n"

    # --- What you cannot do ---
    if cannot_do:
        md += "\n> [!warning] What You Cannot Do\n"
        for item in cannot_do:
            md += f"> - {item}\n"

    return md, in_targets

# ---------------------------------------------------------------------------
# Machine-readable target list output
# ---------------------------------------------------------------------------

def write_target_lists(targets, output_dir):
    os.makedirs(output_dir, exist_ok=True)

    file_map = {
        "domains.txt":   targets["domains"],
        "wildcards.txt": targets["wildcards"],
        "urls.txt":      targets["urls"],
        "ips.txt":       targets["ips"] + targets["cidrs"],
        "mobile.txt":    targets["mobile"],
        "ports.txt":     targets["ports"],
        "github.txt":    targets["github"],
    }

    written = []
    for fname, items in file_map.items():
        if not items:
            continue
        path = os.path.join(output_dir, fname)
        with open(path, "w") as f:
            f.write("\n".join(items) + "\n")
        written.append(f"{fname} ({len(items)})")

    return written

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Extract bug bounty scope into Obsidian markdown + recon target lists."
    )
    parser.add_argument("-f", "--file", required=True,
                        help="Input file containing raw program scope/ROE.")
    parser.add_argument("-o", "--output", required=True,
                        help="Output Obsidian markdown file.")
    parser.add_argument("-d", "--output-dir", default=None,
                        help="Directory for machine-readable target lists (default: same dir as -o).")
    return parser.parse_args()

def main():
    args = parse_arguments()

    try:
        with open(args.file, "r", encoding="utf-8") as f:
            raw_text = f.read()
    except FileNotFoundError:
        print(f"[-] Error: {args.file} not found.")
        sys.exit(1)

    platform = detect_platform(raw_text)
    markdown, in_targets = generate_markdown(raw_text, platform)

    # Write Obsidian markdown
    try:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(markdown)
        print(f"[+] Obsidian scope file: {args.output} (platform: {platform})")
    except IOError:
        print(f"[-] Error: Could not write {args.output}")
        sys.exit(1)

    # Write recon target lists
    output_dir = args.output_dir or os.path.dirname(args.output) or "."
    written = write_target_lists(in_targets, output_dir)
    if written:
        print(f"[+] Target lists in {output_dir}/: {', '.join(written)}")
    else:
        print("[!] No machine-readable targets extracted.")

if __name__ == "__main__":
    main()
