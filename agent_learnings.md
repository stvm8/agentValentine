# Global Brain — Index
# This file has been split into domain-specific files for scalability.
# Each agent reads/writes to its domain file(s) instead of this monolith.

# Domain Files:
##   learnings/web.md       — Web & API Security (bountyHunter, webApiPen)
##   learnings/cloud.md     — Cloud Security (cloudPen)
##   learnings/network.md   — Network & AD Security (netPen)
##   learnings/ctf.md       — CTF & Pro Labs (ctfPlayer)
##   learnings/general.md   — Cross-domain techniques (ALL agents)

# Format per entry: #Tag1 #Tag2 [YYYY-MM-DD] Issue: X -> Solution: Y

# To search all domains: grep -ri "<keyword>" learnings/
- To search one domain:  grep -i "<keyword>" learnings/web.md