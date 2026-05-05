# Pivot Protocol

A pivot is a mid-engagement domain crossing between any two specialist domains (webapp, network, cloud). This protocol defines when to pivot, how to hand off, and how the receiving specialist resumes.

## Pivot Triggers

### webapp → network
Propose a pivot when ANY of the following is confirmed:
- RCE or interactive shell obtained on the server
- SSRF confirmed with access to internal RFC1918 addresses (10.x, 172.16-31.x, 192.168.x)
- Domain or network credentials discovered (domain\user format, LDAP bind creds, SMB hashes, Kerberos tickets)
- Internal subnets or hostnames identified and reachable through the app
- VPN credentials or config files recovered
- SMB, LDAP, WinRM, Kerberos ports reachable via SSRF or webshell

### network → webapp
Propose a pivot when ANY of the following is confirmed:
- Internal web application or admin panel discovered on a newly-pivoted subnet
- Web credentials found during network enumeration (config files, registry, AD attributes, secrets in shares)
- HTTP/HTTPS service on an internal host reachable via the current tunnel
- Web application credentials found in credential harvesting (LSASS, SAM, DPAPI)

### webapp → cloud
Propose a pivot when ANY of the following is confirmed:
- SSRF confirmed reaching instance metadata service (169.254.169.254 or fd00:ec2::254)
- AWS/Azure/GCP credentials found in JS bundles, .env files, error messages, or config endpoints
- Cloud storage bucket/blob URL discovered with write or list access
- Cloud provider API key recovered from app source, headers, or response bodies

### cloud → webapp
Propose a pivot when ANY of the following is confirmed:
- Lambda HTTP endpoint or API Gateway URL discovered during cloud enumeration
- S3 static site or CloudFront distribution hosting an admin panel or webapp
- Web application credentials found in Parameter Store, Secrets Manager, Key Vault, or GCP Secret Manager
- Cloud function source code reveals internal webapp endpoints or hardcoded credentials

### network → cloud
Propose a pivot when ANY of the following is confirmed:
- IAM access keys or service principal credentials found in registry, files, or memory dump
- Instance metadata service reachable from a compromised host (169.254.169.254)
- Managed identity or workload identity token obtained from a cloud-joined machine
- Cloud provider CLI config files discovered (aws/credentials, .azure/, gcloud/config)

### cloud → network
Propose a pivot when ANY of the following is confirmed:
- VPN Gateway, ExpressRoute, or Direct Connect connection found in cloud network topology
- Azure AD Connect or hybrid identity configuration discovered (on-prem AD bridged to cloud)
- On-premises IP ranges or internal hostnames referenced in VPC/VNET peering or route tables
- Domain credentials or NTLM hashes recovered from cloud secrets (Secrets Manager, Key Vault, SSM Parameter Store)

## Pivot Proposal Format

```
[PIVOT DETECTED] From: <webapp|network|cloud> → To: <webapp|network|cloud>
Trigger: <specific finding — e.g., "SSRF confirmed reaching 10.0.0.0/8 via /api/fetch">
Evidence: <file and line where finding is documented>
[PROPOSAL] Task: Write pivot_handoff.md, run /save, clear session, resume with /<specialist> continue: <client>
Expected Outcome: Seamless handoff preserving current state; next specialist seeded with crossing finding.
[HALTING. AWAITING USER APPROVAL.]
```

## pivot_handoff.md Format

Write to `<platform>/<client>/pivot_handoff.md`:

```markdown
# Pivot Handoff
**Date:** <date>
**From:** <webapp|network|cloud>
**To:** <webapp|network|cloud>
**Client:** <client>
**Platform:** <platform>

## Pivot Finding
**Type:** <RCE|SSRF|Creds|InternalHost|...>
**Detail:** <exact finding — endpoint, command, credential, host>
**Documented In:** <vulnerabilities.md|creds.md|loot.md — file and entry>

## Engagement State at Pivot
**WSTG Phases Completed:** <list completed [x] phases from progress.md, or N/A>
**Network Phases Completed:** <list completed phases, or N/A>
**Confirmed Vulns:** <count and one-line summary from vulnerabilities.md>
**Creds Available:** <from creds.md — usernames, hashes, tokens>
**Remaining Webapp Vectors:** <untested [ ] WSTG items worth revisiting post-pivot, or None>

## Seeding for Next Specialist
**Entry Point:** <IP/URL/host that is the crossing point>
**Immediate Priority:** <what to do first — e.g., "enumerate internal subnet 10.0.1.0/24 reachable via SSRF">
**Known Constraints:** <firewall rules, AV, network filtering observed so far>
**Suggested First Proposal:** <brief description of the first attack the next specialist should propose>
```

## Receiving Specialist Behavior

When a specialist is invoked with `continue:` and `pivot_handoff.md` exists in the engagement directory:
1. Read `pivot_handoff.md` FIRST, before reading progress.md.
2. Treat the pivot finding as the highest-priority seed — it is the confirmed entry point.
3. Update the appropriate state file with the crossing finding immediately: `network_topology.md` (→ network), `endpoints.md` (→ webapp), `assets.md` + `iam_enum.md` (→ cloud).
4. The first proposal must target the entry point named in pivot_handoff.md, not a generic "next untested item."
5. After the pivot entry point is exhausted, resume from the normal checklist (WSTG or network methodology).
