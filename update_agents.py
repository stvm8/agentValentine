import os
import re
import sys

# Define base paths
HOME = os.path.expanduser("~")
BASE_DIR = os.path.join(HOME, "Pentester", "AI_Teams")

AGENTS = [
    "bountyHunter",
    "ctfPlayer",
    "netPen",
    "cloudPen",
    "webApiPen",
	"bakAgent"
]

def get_pasted_content():
    print("\n[+] Paste the Markdown section you want to update (e.g. ## Command Parser).")
    print("[+] When finished pasting, type 'EOF' on a new line and press Enter:")
    print("-" * 60)

    lines = []
    while True:
        try:
            line = input()
            if line.strip() == 'EOF':
                break
            lines.append(line)
        except KeyboardInterrupt:
            print("\n[!] Update cancelled by user.")
            sys.exit(0)
        except EOFError:
            break

    return '\n'.join(lines)

def identify_section(content):
    # Search for the first ## header in the pasted content
    match = re.search(r'^##\s+(.+)', content, re.MULTILINE)
    if match:
        return match.group(1).strip()
    return None

def select_agents():
    print("\n" + "="*40)
    print(" WHICH AGENT DO YOU WANT TO UPDATE?")
    print("="*40)
    for i, agent in enumerate(AGENTS, 1):
        print(f" {i}. {agent}")
    print(f" {len(AGENTS) + 1}. ALL AGENTS")
    print("="*40)

    while True:
        try:
            choice = input("\nEnter number (or Ctrl+C to cancel): ").strip()

            if not choice.isdigit():
                print("[-] Invalid input. Please enter a number.")
                continue

            choice = int(choice)
            if 1 <= choice <= len(AGENTS):
                return [AGENTS[choice - 1]]
            elif choice == len(AGENTS) + 1:
                return AGENTS
            else:
                print("[-] Choice out of range.")
        except KeyboardInterrupt:
            print("\n[!] Update cancelled gracefully.")
            sys.exit(0)

def update_agent_file(agent_name, section_name, new_content):
    file_path = os.path.join(BASE_DIR, agent_name, "CLAUDE.md")

    if not os.path.exists(file_path):
        print(f"[-] Skipped {agent_name}: CLAUDE.md not found.")
        return

    with open(file_path, 'r', encoding='utf-8') as f:
        file_content = f.read()

    # Match from the ## header line until the next ## header (or end of file)
    # re.escape handles section names with special characters
    pattern = re.compile(
        rf'^(##\s+{re.escape(section_name)}\s*\n).*?(?=^##\s|\Z)',
        re.DOTALL | re.MULTILINE
    )
    match = pattern.search(file_content)

    if match:
        # Ensure new_content ends with a newline before the next section
        replacement = new_content.rstrip('\n') + '\n\n'
        updated_content = file_content[:match.start()] + replacement + file_content[match.end():]

        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(updated_content)
        print(f"[✔] Successfully updated '## {section_name}' in {agent_name}/CLAUDE.md")
    else:
        # Section not found — append at end of file
        print(f"[~] Section '## {section_name}' not found in {agent_name}. Appending to end of file...")
        updated_content = file_content.rstrip('\n') + '\n\n' + new_content.rstrip('\n') + '\n'
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(updated_content)
        print(f"[✔] Successfully appended '## {section_name}' to {agent_name}/CLAUDE.md")

def main():
    try:
        pasted_content = get_pasted_content()

        if not pasted_content.strip():
            print("\n[-] No content provided. Exiting.")
            sys.exit(0)

        section_name = identify_section(pasted_content)

        if not section_name:
            print("\n[✖] Error: Could not identify a valid Markdown section header in your pasted content.")
            print("Ensure your pasted block starts with something like '## Command Parser'")
            sys.exit(1)

        print(f"\n[+] Detected Target Section: ## {section_name}")

        selected_agents = select_agents()

        print("\n[+] Applying updates...")
        for agent in selected_agents:
            update_agent_file(agent, section_name, pasted_content)

        print("\n[🚀] Update Complete!")

    except KeyboardInterrupt:
        print("\n[!] Update cancelled gracefully.")
        sys.exit(0)

if __name__ == "__main__":
    main()
