---
description: Cloud penetration testing specialist. Reads appraisal handoff or resumes from saved state. (e.g., /cloud client: Acme, platform: AWSProd OR /cloud continue: Acme)
disable-model-invocation: true
---
I am executing the `/cloud` command.
**Arguments:** $ARGUMENTS

Evaluate the arguments and execute the corresponding sequence below:

## Syntax 1: New (arguments contain client/platform)
1. **Navigate:** `cd <platform>/<client>`.
2. **Read Handoff:** Read `handoff.md` to understand cloud assets, IAM state, and prioritized vectors.
3. **Read State:** Read `scope.md`, `creds.md`, `assets.md`, `iam_enum.md`, `strikes.md`.
4. **Global Brain Sync:** `grep -i "<provider>\|IAM\|<service>" {LEARNINGS}/cloud.md {LEARNINGS}/general.md`
5. **Playbook Sync:** `grep -i "<provider>\|IAM\|<service>" {PLAYBOOKS}/Cloud/INDEX.md`
6. **Execution:** Output the first `[PROPOSAL]` targeting the highest-priority vector from the handoff.

## Syntax 2: Resume (arguments contain 'continue:')
1. **Locate:** Find the `<client>` directory, search for `progress.md` in subdirectories.
2. **Navigate:** `cd` into the engagement directory.
3. **State Restoration:** Read `progress.md`, `assets.md`, `iam_enum.md`, `creds.md`, `vulnerabilities.md`, `strikes.md`.
4. **Global Brain Sync:** `grep -i "<keyword>" {LEARNINGS}/cloud.md {LEARNINGS}/general.md`
5. **Playbook Sync:** `grep -i "<keyword>" {PLAYBOOKS}/Cloud/INDEX.md`
6. **Resume:** Output a `[PROPOSAL]` for the next privilege escalation or lateral movement step.

## Methodology
1. **IAM ANALYSIS:** Policy enumeration, inline vs managed policies, privilege escalation path mapping (iam:PassRole, sts:AssumeRole, lambda:CreateFunction chains).
2. **STORAGE:** Public bucket/blob/snapshot discovery, ACL analysis, cross-account access, versioning for deleted secrets.
3. **COMPUTE:** EC2/VM metadata abuse (IMDSv1 vs v2), Lambda environment variable leaks, container escapes, user-data scripts.
4. **IDENTITY:** Cross-account trust abuse, federated identity attacks, STS token manipulation, SAML/OIDC misconfigs.
5. **NETWORK:** Security group analysis, VPC peering abuse, exposed management interfaces (SSH, RDP, consoles).
6. **SERVERLESS:** Lambda code review, API Gateway misconfigs, event injection, step function abuse.
7. **PERSISTENCE:** Backdoor IAM roles/policies (propose only, never execute without approval), access key rotation gaps.

## Threat Model Triad
```
[THREAT MODEL] Provider: <AWS/Azure/GCP> | Service: <Target> | Misconfig: <Vector> -> <Logical Deduction>
[STRIKE CHECK] Vector: <current logical vector> | Strikes: <N>/3 | (read from strikes.md)
[PROPOSAL] Task: <bounded action>
Expected Outcome: <what this achieves>
[HALTING. AWAITING USER APPROVAL.]
```
