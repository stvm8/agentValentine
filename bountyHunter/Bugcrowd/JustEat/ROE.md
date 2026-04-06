# Rules of Engagement & Scope

## In Scope
**Payments:** api-payments-secure-prod.skippayments.com, takeawaypay.azurefd.net/en/takeawaypay/, takeaway.pay-creditcard.takeaway.com, global-payments-web.payments.pmt-1.eu-west-1.production.jet-external.com
**APIs:** rest.api.eu-central-1.production.jet-external.com, uk.api.just-eat.io, aus.api.just-eat.io, api-skipthedishes.skipthedishes.com, i18n.api.just-eat.io, cw-api.takeaway.com
**Web/Wildcard Assets:** *.thuisbezorgd.nl, *.takeaway.com, *.skipthedishes.com, *.just-eat.dk, *.lieferando.de, *.pyszne.pl, *.bistro.sk, *.just-eat.es, *.just-eat.co.uk, *.just-eat.ch, *.10bis.co.il, *.scoober.com, *.just-eat.com, *.skippayments.com, *.justeattakeaway.com, *.just-eat.io, *.justeat-int.com, *.yourdelivery.de, *.just-data.io, *.jet-external.com, github.com/justeattakeaway

## Focus Areas
SQLi, RCE, authorization bypasses, IDORs, PII/data exfiltration, business logic abuse.

## Out of Scope
- *.business.just-eat.co.uk
- Any subdomain pointing to *.leadfamly.com or *.playable.com
- Third-party providers and services
- Any domains, subdomains, or properties not explicitly listed as in scope

## What You Can Do
- Register accounts using your @bugcrowdninja.com email address.
- Add the X-Bug-Bounty:<bugcrowdusername> header to all your HTTP traffic.
- Combine identical vulnerabilities found across multiple domains/environments into a single report.
- Report N-day/3rd party 0-day bugs only after 30 days from their public release.
- Report stolen/breached credentials (eligible for points only, no bounty).
- Stop testing and submit immediately if you identify a vulnerability leading to post-exploitation or data destruction.
- Purchase goods on the platform for testing at your own risk and cost.

## What You Cannot Do (CRITICAL)
- Do not target, manipulate, or access other users' data (only use your own credentials).
- Do not perform DoS, DDoS, network DoS, or volumetric testing (e.g., rate limit bypasses, email bombing).
- Do not execute post-exploitation activities, delete, edit, or destroy site data.
- Do not compromise the stability and integrity of the site (especially production).
- Do not engage in social engineering, phishing, or physical attacks.
- Do not submit reports without a working Proof of Concept (PoC).
- Do not submit vulnerabilities requiring outdated devices/software or significant user action (e.g., disabling browser security).
- Do not submit P5s, open redirects, or best-practice issues (SSL/TLS, DNS, cookie flags, missing session persistence).
