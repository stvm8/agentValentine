# General Learnings
# Domain: Cross-domain techniques, tool usage, environment issues
# Format: #Tag1 #Tag2 [YYYY-MM-DD] Issue: X -> Solution: Y
# Agents: ALL

#Nmap #Recon [2026-04-05] Issue: Used sudo for nmap unnecessarily. Solution: nmap -sV -sC scans do not require sudo; only raw SYN scans (-sS) need root privileges.
#Windows #CSharp #Compilation [2026-04-05] Issue: Exploits requiring Visual Studio or complex .NET framework references (like SharpWSUS) cannot be reliably compiled via Linux 'mcs' or 'dotnet'. Solution: Immediately halt and ask the user to compile it on a Windows VM and transfer the .exe to the workspace.
#TunnelVision #AgentBehavior #StuckLoop #ProposalLoop #general [2026-04-20] Issue: Repeated same failed vector (getTGT.py / SSH GSSAPI) across multiple turns after user explicit dismissal — ctf_state was incomplete but agent did not ask, instead kept proposing variations -> Solution: When user dismisses a vector or says state is missing, explicitly ask "what has been tried?" before forming next proposal. Do not assume ctf_state.md is complete. Track user dismissals as implicit strikes.
#TechRecon #SourceCode #CMS #Framework #RouteEnum #KnownVersion #rabbit-hole #technique [2026-04-26] Issue: Known CMS (CamaleonCMS 2.9.0) was identified but enumeration relied on generic wordlists instead of reading app-specific routes — missed /admin/media/download_private_file?file= (path traversal vector) entirely -> Solution: When a specific technology/version is fingerprinted, read its source code or technical docs (GitHub, gem source, official docs) to enumerate routes, controllers, and known sensitive endpoints BEFORE running generic wordlist fuzzing. App-specific routes will never appear in raft-medium.
