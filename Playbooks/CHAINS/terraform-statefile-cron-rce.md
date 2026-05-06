# Chain: Terraform State File Race Condition → Cron-Triggered RCE
Tags: terraform, statefile, cron, rce, linux, iac, race-condition, world-writable, tfstate, privesc
Chain Severity: High
Entry Condition: Shell on Linux host; world-writable `/tmp/terraform.tfstate`; cron runs `terraform apply -auto-approve` as a privileged user (tfuser)

## Node 1 — Cron Race Observation
Technique: [[Linux/Privilege_Escalation#Terraform State File Race Condition RCE]]
Strike Vector: "cron terraform apply observation"
Condition: Shell access; `pspy64` or `/proc` enumeration available
Standalone Severity: Low
Branches:
  - `pspy64` shows periodic `terraform apply -auto-approve` running as tfuser → Node 2
  - No cron observed → check `/etc/cron*`, `systemd` timers, `atq`; if nothing → [TERMINAL] No scheduled exec vector — try other privesc paths

## Node 2 — World-Writable tfstate Discovery
Technique: [[Linux/Privilege_Escalation#Terraform State File Race Condition RCE]]
Strike Vector: "world-writable tfstate file"
Condition: Cron terraform apply confirmed; state file path known from pspy output or Terraform working dir
Standalone Severity: Med
Branches:
  - `/tmp/terraform.tfstate` is world-writable (`-rw-rw-rw-`) → Node 3
  - State file in restricted directory (root-owned, no write) → [TERMINAL] File injection blocked — attempt symlink race if `/tmp` race window exists
  - No state file present (first run) → wait for cron to create it, then check perms

## Node 3 — Malicious statefile-rce Provider Injection
Technique: [[Linux/Privilege_Escalation#Terraform State File Race Condition RCE]]
Strike Vector: "statefile-rce provider injection"
Condition: Write access to tfstate; `offensive-actions/statefile-rce` provider accepted by local Terraform registry or fetched from public registry
Standalone Severity: High
Branches:
  - Write malicious tfstate referencing `offensive-actions/statefile-rce` provider with `command` attribute → Node 4
  - Terraform validates providers against lock file (`.terraform.lock.hcl`) → check if lock file is writable or absent; if locked → [TERMINAL] Provider pinning blocks injection
  - Network-isolated host cannot fetch provider → pre-download provider binary and place in local mirror path

## Node 4 — Cron-Triggered RCE as tfuser
Technique: [[Linux/Privilege_Escalation#Terraform State File Race Condition RCE]]
Strike Vector: "cron-triggered terraform apply RCE"
Condition: Malicious tfstate written before next cron execution; Terraform fetches/executes the `rce` provider
Standalone Severity: High
Branches:
  - Cron fires, Terraform applies malicious state → `command` executes as tfuser → Node 5
  - Race lost (cron ran before write completed) → re-inject and wait for next cron cycle (check period from pspy timing)
  - Terraform errors on invalid state format → validate JSON structure, match `version` and `lineage` to original tfstate

## Node 5 — Flag / Credential Exfil
Technique: [[Linux/Privilege_Escalation#Terraform State File Race Condition RCE]]
Strike Vector: "flag exfil as tfuser"
Condition: RCE confirmed as tfuser; target file known (e.g., `/home/tfuser/flag`)
Standalone Severity: High
Branches:
  - `cat /home/tfuser/flag > /tmp/flag && chmod 777 /tmp/flag` → read flag from shell → [TERMINAL] Chain Complete (High)
  - tfuser has sudo rights → escalate to root, read `/root/flag` → [TERMINAL] Root achieved (Critical)
  - Flag not at expected path → enumerate home dirs, `/root`, `/var/secrets`, `/opt` as tfuser
