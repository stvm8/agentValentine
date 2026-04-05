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
	"bakAgent"
]

def get_pasted_content():
    print("\n[+] Paste the XML block you want to update (e.g. <command_parser> ... </command_parser>).")
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

def identify_tag(content):
    # Search for the first valid XML tag in the pasted content
    match = re.search(r'<([a-zA-Z0-9_]+)>', content)
    if match:
        return match.group(1)
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

def update_agent_file(agent_name, tag_name, new_content):
    file_path = os.path.join(BASE_DIR, agent_name, "CLAUDE.md")
    
    if not os.path.exists(file_path):
        print(f"[-] Skipped {agent_name}: CLAUDE.md not found.")
        return

    with open(file_path, 'r', encoding='utf-8') as f:
        file_content = f.read()

    # Regex to find the exact tag block (handles multiline with re.DOTALL)
    pattern = re.compile(rf'<{tag_name}>.*?</{tag_name}>', re.DOTALL)
    match = pattern.search(file_content)

    if match:
        # Safe string splicing (avoids regex backreference issues if pasted content has special chars)
        updated_content = file_content[:match.start()] + new_content + file_content[match.end():]
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(updated_content)
        print(f"[✔] Successfully updated <{tag_name}> in {agent_name}/CLAUDE.md")
    else:
        # If the tag doesn't exist, inject it right before </system_instructions>
        print(f"[~] Tag <{tag_name}> not found in {agent_name}. Injecting it into system_instructions...")
        end_tag = "</system_instructions>"
        if end_tag in file_content:
            updated_content = file_content.replace(end_tag, f"\n  {new_content}\n{end_tag}")
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(updated_content)
            print(f"[✔] Successfully injected <{tag_name}> into {agent_name}/CLAUDE.md")
        else:
            print(f"[✖] Failed to update {agent_name}: Could not find </system_instructions> boundary.")

def main():
    try:
        pasted_content = get_pasted_content()
        
        if not pasted_content.strip():
            print("\n[-] No content provided. Exiting.")
            sys.exit(0)
            
        tag_name = identify_tag(pasted_content)
        
        if not tag_name:
            print("\n[✖] Error: Could not identify a valid XML root tag in your pasted content.")
            print("Ensure your pasted block starts with something like <command_parser>")
            sys.exit(1)
            
        print(f"\n[+] Detected Target Block: <{tag_name}>")
        
        selected_agents = select_agents()
        
        print("\n[+] Applying updates...")
        for agent in selected_agents:
            update_agent_file(agent, tag_name, pasted_content)
            
        print("\n[🚀] Update Complete!")
        
    except KeyboardInterrupt:
        print("\n[!] Update cancelled gracefully.")
        sys.exit(0)

if __name__ == "__main__":
    main()
