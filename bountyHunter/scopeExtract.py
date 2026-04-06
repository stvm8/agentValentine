import argparse
import re
import sys
from datetime import datetime

def parse_arguments():
    parser = argparse.ArgumentParser(description="Extract Bugcrowd scope into an Obsidian-compatible Markdown summary.")
    parser.add_argument("-f", "--file", required=True, help="Input file containing the raw Bugcrowd program details.")
    parser.add_argument("-o", "--output", required=True, help="Output Markdown file name.")
    return parser.parse_args()

def extract_targets(text):
    # Regex to find wildcard domains (*.example.com)
    wildcards = set(re.findall(r'\*\.[a-zA-Z0-9.-]+', text))
    
    # Regex to find URLs and extract the domain/path
    urls = set(re.findall(r'https?://([a-zA-Z0-9.-]+(?:/[a-zA-Z0-9./_-]*)?)', text))
    
    # Filter out common noise
    noise = ['play.google.com', 'apps.apple.com', 'bugcrowd.com', 'docs']
    clean_urls = {url for url in urls if not any(n in url for n in noise)}
    
    # Specific GitHub repos
    github = set(re.findall(r'github\.com/[a-zA-Z0-9.-]+', text))
    
    return sorted(list(wildcards)), sorted(list(clean_urls)), sorted(list(github))

def generate_obsidian_markdown(raw_text):
    # Split text to separate In-Scope from Out-of-Scope
    split_keywords = re.split(r'Ouf of scope|Out of scope', raw_text, maxsplit=1, flags=re.IGNORECASE)
    in_scope_raw = split_keywords[0]
    out_of_scope_raw = split_keywords[1] if len(split_keywords) > 1 else ""

    # Extract targets
    in_wild, in_urls, in_git = extract_targets(in_scope_raw)
    out_wild, out_urls, out_git = extract_targets(out_of_scope_raw)

    # Dynamic Rule Extraction
    can_do = []
    cannot_do = []

    if "bugcrowdninja" in raw_text.lower():
        can_do.append("Register accounts using your `@bugcrowdninja.com` email address.")
    
    header_match = re.search(r'(X-[a-zA-Z0-9-]+:<[a-zA-Z0-9]+>)', raw_text)
    if header_match:
        can_do.append(f"Add the `{header_match.group(1)}` header to all your HTTP traffic.")
    elif "X-Bug-Bounty" in raw_text:
        can_do.append("Add the `X-Bug-Bounty:<bugcrowdusername>` header to all your HTTP traffic.")

    if "single report" in raw_text.lower() or "single ticket" in raw_text.lower():
        can_do.append("Combine identical vulnerabilities found across multiple domains/environments into a single report.")
    
    if "30 days" in raw_text.lower():
        can_do.append("Report N-day/3rd party 0-day bugs only after 30 days from their public release.")
    
    if "stolen" in raw_text.lower() or "dark web" in raw_text.lower():
        can_do.append("Report stolen/breached credentials (eligible for points only, no bounty).")

    if "post-exploitation" in raw_text.lower():
        can_do.append("Stop testing and submit immediately if you identify a vulnerability leading to post-exploitation or data destruction.")

    # Cannot Do
    cannot_do.append("Do not target, manipulate, or access other users' data (only use your own credentials).")
    
    if "dos" in raw_text.lower() or "ddos" in raw_text.lower():
        cannot_do.append("Do not perform DoS, DDoS, network DoS, or volumetric testing.")
        
    cannot_do.append("Do not compromise the stability and integrity of the site (especially production).")
    
    if "social engineering" in raw_text.lower():
        cannot_do.append("Do not engage in social engineering, phishing, or physical attacks.")
        
    if "proof of concept" in raw_text.lower() or "poc" in raw_text.lower():
        cannot_do.append("Do not submit reports without a working Proof of Concept (PoC).")
        
    cannot_do.append("Do not submit P5s, open redirects, or best-practice issues (SSL/TLS, DNS, missing security headers).")

    # Build Obsidian Markdown
    date_str = datetime.now().strftime("%Y-%m-%d")
    
    # Obsidian YAML Frontmatter (Properties)
    md_content = f"---\ntags:\n  - bugbounty\n  - bugcrowd\n  - target-scope\ndate: {date_str}\n---\n\n"

    # In Scope - Obsidian Callout
    md_content += "> [!success] In Scope\n"
    if in_urls:
        md_content += f"> - **Specific Assets:** `{'`, `'.join(in_urls)}`\n"
    if in_wild:
        md_content += f"> - **Wildcards:** `{'`, `'.join(in_wild)}`\n"
    if in_git:
        md_content += f"> - **Source Code:** `{'`, `'.join(in_git)}`\n"

    # Out of Scope - Obsidian Callout
    md_content += "\n> [!danger] Out of Scope\n"
    if out_wild or out_urls:
        all_out = out_wild + out_urls
        md_content += f"> - `{'`, `'.join(all_out)}`\n"
    md_content += "> - Third-party providers and services.\n"
    md_content += "> - Any domains, subdomains, or properties not explicitly listed as in scope.\n"

    # What you can do - Obsidian Callout
    md_content += "\n> [!info] What You Can Do\n"
    for item in can_do:
        md_content += f"> - {item}\n"

    # What you cannot do - Obsidian Callout
    md_content += "\n> [!warning] What You Cannot Do\n"
    for item in cannot_do:
        md_content += f"> - {item}\n"

    return md_content

def main():
    args = parse_arguments()

    try:
        with open(args.file, 'r', encoding='utf-8') as f:
            raw_text = f.read()
    except FileNotFoundError:
        print(f"Error: The file {args.file} was not found.")
        sys.exit(1)

    markdown_output = generate_obsidian_markdown(raw_text)

    try:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(markdown_output)
        print(f"[+] Successfully generated Obsidian compatible file: {args.output}")
    except IOError:
        print(f"Error: Could not write to file {args.output}")
        sys.exit(1)

if __name__ == "__main__":
    main()
