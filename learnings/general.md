# General Learnings
# Domain: Cross-domain techniques, tool usage, environment issues
# Format: #Tag1 #Tag2 [YYYY-MM-DD] Issue: X -> Solution: Y
# Agents: ALL

#Nmap #Recon [2026-04-05] Issue: Used sudo for nmap unnecessarily. Solution: nmap -sV -sC scans do not require sudo; only raw SYN scans (-sS) need root privileges.
#Windows #CSharp #Compilation [2026-04-05] Issue: Exploits requiring Visual Studio or complex .NET framework references (like SharpWSUS) cannot be reliably compiled via Linux 'mcs' or 'dotnet'. Solution: Immediately halt and ask the user to compile it on a Windows VM and transfer the .exe to the workspace.
