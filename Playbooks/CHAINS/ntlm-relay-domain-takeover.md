# Chain: NTLM Relay → Credential Dump → DCSync → Domain Takeover
Tags: ntlm, relay, smb, credential, dump, dcsync, domain, ad, kerberos, lsass
Chain Severity: Critical
Entry Condition: Network position allowing NTLM relay (SMB signing disabled on target, or coerce available)

## Node 1 — NTLM Relay Position Confirmed
Technique: [[AD/NTLM_Relay]]
Strike Vector: "NTLM relay position"
Condition: SMB signing disabled on target host OR coercion primitive available (PetitPotam, PrintSpooler, DFSCoerce)
Standalone Severity: High
Branches:
  - Relay to LDAP/S → Node 2A (ACL abuse / shadow credentials)
  - Relay to SMB (signing disabled) → Node 2B (command execution)
  - Relay to HTTP (ADCS ESC8) → [[Chain: adcs-domain-takeover]] Node 1

## Node 2A — ACL Abuse via LDAP Relay
Technique: [[AD/ACL_Abuse_Exploit]]
Strike Vector: "LDAP relay ACL write"
Condition: Relay to LDAP succeeds; relayed account has write privilege on a high-value object
Standalone Severity: High
Branches:
  - WriteDACL / GenericAll on Domain object → Node 3
  - Shadow credentials written on target account → Node 3 (via obtained TGT)
  - No writable ACL on useful object → [TERMINAL] LDAP Relay Limited ACL (Medium)

## Node 2B — SMB Relay Code Execution
Technique: [[AD/Net_Exec_Exec]]
Strike Vector: "SMB relay exec"
Condition: Relay to SMB succeeds; local admin on target host
Standalone Severity: High
Branches:
  - Local admin on non-DC host → Node 3 alt (credential dump via lsass)
  - Local admin on DC → Node 4 directly

## Node 3 — Credential Dump
Technique: [[AD/Credential_Dumping_Remote]]
Strike Vector: "credential dump post-relay"
Condition: Code execution or ACL write on host with cached domain creds or NTDS access
Standalone Severity: Critical
Branches:
  - DA / DA-equivalent hash or plaintext obtained → Node 4
  - Service account or standard user hash → [TERMINAL] Credential Theft — non-privileged (High); attempt Kerberoast or pass-the-hash laterally
  - LSASS protected (PPL/Credential Guard) → strike; try [[AD/Credential_Dumping_Local]] VSS path

## Node 4 — DCSync / Domain Takeover
Technique: [[AD/DCSync_DomainTakeover]]
Strike Vector: "DCSync domain takeover"
Condition: DA or replication rights (DS-Replication-Get-Changes-All) on domain
Standalone Severity: Critical
Branches:
  - All domain hashes dumped (krbtgt obtained) → [TERMINAL] Chain Complete — Domain Takeover (Critical)
  - krbtgt rotated / protected → [TERMINAL] Partial — DA access confirmed, persistence via [[AD/Domain_Persistence]] (Critical)
