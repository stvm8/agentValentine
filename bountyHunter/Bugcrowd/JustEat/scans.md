# FFUF Report

  Command line : `ffuf -u https://uk.api.just-eat.io/FUZZ -w /home/takashi/Pentester/ptTools/Wordlists/SecLists/Discovery/Web-Content/api/api-seen-in-wild.txt -x http://127.0.0.1:8081 -H X-Bug-Bounty:takashi -H User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 -mc 200,201,301,302,401,403 -t 30 -o /home/takashi/Pentester/AI_Teams/bountyHunter/Bugcrowd/JustEat/scans.md -of md`
  Time: 2026-04-02T20:05:01-05:00

  | FUZZ | URL | Redirectlocation | Position | Status Code | Content Length | Content Words | Content Lines | Content Type | Duration | ResultFile | ScraperData | Ffufhash
  | :- | :-- | :--------------- | :---- | :------- | :---------- | :------------- | :------------ | :--------- | :----------- | :------------ | :-------- |
  | ?: | https://uk.api.just-eat.io/?: | https://uk.api.just-eat.io/docs | 6 | 302 | 46 | 3 | 1 |  | 841.400258ms |  |  | 7e3c66
  | char() | https://uk.api.just-eat.io/char() |  | 805 | 403 | 4515 | 620 | 94 | text/html; charset=UTF-8 | 422.192712ms |  |  | 7e3c6325
  | concat() | https://uk.api.just-eat.io/concat() |  | 1200 | 403 | 4515 | 620 | 94 | text/html; charset=UTF-8 | 498.19242ms |  |  | 7e3c64b0
  2026-04-02  pie                                                 Globally shared packages for PIE
2026-04-02  JustSaying                                          A light-weight message bus on top of AWS services (SNS and SQS).
2026-04-01  ApplePayJSSample                                    A sample implementation of Apple Pay JS using ASP.NET Core
2026-03-31  LocalSqsSnsMessaging                                
2026-03-27  AwsWatchman                                         Because unmonitored infrastructure will bite you
2026-03-26  PackageGenerator                                    A tool to generate Package.swift files.
2026-03-26  pie-aperture                                        External Test Environments for PIE Components
2026-03-25  pie-iconography                                     Shared repository containing all icons for the PIE library
2026-03-22  httpclient-interception                             A .NET library for intercepting server-side HTTP requests
2026-03-18  JustEat.StatsD                                      Our library for publishing metrics to statsd
2026-03-07  Genything                                           Generate Anything
2026-03-02  bq-sql-antipattern-checker                          BigQuery SQL Antipattern Checker and Optimisation Helper
2026-02-26  IntervalAnnotatedString                             A tiny Android utility library that simplifies the process of creating and managing embedded links and styles within a localised text block 🔗
2026-02-24  fozzie-components                                   Public monorepo of tools, services and atomic UI components within the fozzie ecosystem
2025-12-01  pie-illustrations                                   Shared repository containing all illustrations for the PIE library
2025-10-15  ui-coding-exercise                                  Coding exercise used in the recruitment of UI Candidates
2025-08-22  pie-logos                                           Shared repository containing all JET logos included in the PIE libraries
2025-06-18  android-deep-links                                  A simple library to handle the routing of deep links
2025-04-08  scoober-code-challenge-boilerplate                  Template application in Spring Boot 3 to support candidates on Scoober code assignment
2023-10-02  .github                                             Public README for the justeattakeaway organisation
2022-12-07  skipthedishes-react-test                            
2022-08-16  miro-plugin-tag-crawler                             Miro Plugin: Tag Crawler
=== KEYWORD: JE-API-KEY ===
  Hits: 0
=== KEYWORD: X-Flyt-Api-Key ===
  Hits: 0
=== KEYWORD: jwt_secret ===
  Hits: 0
=== KEYWORD: just-eat.io ===
  Hits: 0
=== KEYWORD: jet-external.com ===
  Hits: 0
=== KEYWORD: skippayments ===
  Hits: 0
=== KEYWORD: JE_API_KEY ===
  Hits: 0
=== ApplePayJSSample tree ===
  .editorconfig
  .github/actionlint-matcher.json
  .vscode/extensions.json
  .vscode/launch.json
  .vscode/tasks.json
  NuGet.config
  global.json
  src/ApplePayJS/Properties/launchSettings.json
  src/ApplePayJS/appsettings.json
  src/ApplePayJS/bower.json
  src/ApplePayJS/package-lock.json
  src/ApplePayJS/package.json
  src/ApplePayJS/tsconfig.json
  src/ApplePayJS/tslint.json
  src/ApplePayJS/web.config
  tests/ApplePayJS.Tests/testsettings.json
  tests/ApplePayJS.Tests/xunit.runner.json
=== JustSaying tree ===
  .aspire/settings.json
  .editorconfig
  .github/actionlint-matcher.json
  .github/dependency-review-config.yml
  .vscode/extensions.json
  .vscode/mcp.json
  .vscode/settings.json
  NuGet.config
  docs/babel.config.js
  docs/docs/Configuration.md
  docs/docs/aws-configuration
  docs/docs/aws-configuration/README.md
  docs/docs/aws-configuration/credentials.md
  docs/docs/aws-configuration/regions.md
  docs/docs/aws-configuration/service-endpoints.md
  docs/docs/aws-iam.md
  docs/docs/messaging-configuration
  docs/docs/messaging-configuration/README.md
  docs/docs/messaging-configuration/logging.md
  docs/docs/messaging-configuration/metrics.md
=== ApplePayJS appsettings.json ===
﻿{
  "ApplePay": {
    "DefaultLanguage": "en-GB",
    "StoreName": "Just Eat",
    "UseCertificateStore": false,
    "MerchantCertificate": "",
    "MerchantCertificateFileName": "",
    "MerchantCertificatePassword": "",
    "MerchantCertificateThumbprint": "",
    "UsePolyfill": false,
    "UseTypeScript": false
  },
  "Logging": {
    "IncludeScopes": false,
    "LogLevel": {
      "Default": "Debug",
      "System": "Information",
      "Microsoft": "Information"
    }
  }
}

=== ApplePayJS launchSettings.json ===
{
  "iisSettings": {
    "windowsAuthentication": false,
    "anonymousAuthentication": true,
    "iisExpress": {
      "applicationUrl": "http://localhost:52623/",
      "sslPort": 44399
    }
  },
  "profiles": {
    "IIS Express": {
      "commandName": "IISExpress",
      "ancmHostingModel": "InProcess",
      "launchBrowser": true,
      "launchUrl": "https://localhost:44399/",
      "environmentVariables": {
        "ASPNETCORE_ENVIRONMENT": "Development",
        "ASPNETCORE_HTTPS_PORT": "44399"
      }
    },
    "ApplePayJS": {
      "commandName": "Project",
      "launchBrowser": true,
      "launchUrl": "http://localhost:5000",
      "environmentVariables": {
        "ASPNETCORE_ENVIRONMENT": "Development",
        "ASPNETCORE_HTTPS_PORT": "5001"
      }
    }
  }
}
=== fozzie-components: search for api/auth refs ===
=== pie repo: env/config/secret files ===
  apps/pie-docs/src/_11ty/filters/pieDesignTokenColours.js
  apps/pie-docs/src/_11ty/shortcodes/notifications/globalTokensWarning.js
  apps/pie-docs/src/_11ty/shortcodes/tokensTable
  apps/pie-docs/src/_11ty/shortcodes/tokensTable/handleTokenData.js
  apps/pie-docs/src/_11ty/shortcodes/tokensTable/index.js
  apps/pie-docs/src/_11ty/shortcodes/tokensTable/tokenTypes
  apps/pie-docs/src/_11ty/shortcodes/tokensTable/tokenTypes/blur.js
  apps/pie-docs/src/_11ty/shortcodes/tokensTable/tokenTypes/colour.js
  apps/pie-docs/src/_11ty/shortcodes/tokensTable/tokenTypes/elevation.js
  apps/pie-docs/src/_11ty/shortcodes/tokensTable/tokenTypes/font.js
  apps/pie-docs/src/_11ty/shortcodes/tokensTable/tokenTypes/radius.js
  apps/pie-docs/src/_11ty/shortcodes/tokensTable/tokenTypes/spacing.js
  apps/pie-docs/src/__tests__/_11ty/shortcodes/__snapshots__/tokensTable.test.js.snap
  apps/pie-docs/src/__tests__/_11ty/shortcodes/tokensTable.test.js
  apps/pie-docs/src/_data/designTokenColours.js
  apps/pie-docs/src/_data/normaliseTokens.js
  apps/pie-docs/src/_data/tokenTypes.js
  apps/pie-docs/src/_utilities/tokens.js
  apps/pie-docs/src/assets/img/designers/getting-started/best-practices/token-selection.svg
  apps/pie-docs/src/assets/img/designers/getting-started/best-practices/token-selection_narrow.svg
=== rest.api.eu-central-1 probe ===
HTTP/1.1 200 OK

HTTP/1.1 404 Not Found
Date: Fri, 03 Apr 2026 01:09:55 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 27
Connection: keep-alive
CF-RAY: 9e6430c868276184-ORD
x-je-conversation: 106f9480-2489-4ff5-a577-6b9b58798536
cf-cache-status: DYNAMIC
Set-Cookie: __cf_bm=u1q3D4Mg0uPCVmZ2i7RKc8f9eHng41shg0ycobvIN0o-1775178595-1.0.1.1-trgML6iV7oaDWKpaihbUIS16TJXmHNdwXkx1A_10Ph8jN_IXGwfTz_aj3FYMn8Koy5qdIFF45OJT01RhTvkAPfEQuu21AqOhNT0p07hoS6s; path=/; expires=Fri, 03-Apr-26 01:39:55 GMT; domain=.eu-central-1.production.jet-external.com; HttpOnly; Secure; SameSite=None
Strict-Transport-Security: max-age=0
Server: cloudflare

{"message":"uri not found"}=== api.justeat-int.com probe ===
HTTP/1.1 200 OK

HTTP/1.1 302 Found
Date: Fri, 03 Apr 2026 01:09:55 GMT
Content-Length: 46
Connection: keep-alive
CF-RAY: 9e6430cc2f7df83f-ORD
location: https://uk.api.just-eat.io/docs
x-je-conversation: 9145e724-aa4c-42cd-b3da-cca43b578a6f
cf-cache-status: DYNAMIC
Set-Cookie: __cf_bm=s043nalMwBtaSw7zJApgbFQSSHJUIT90VMHie._v0tM-1775178595-1.0.1.1-kfTqLcmrEWXZOUraBRNjGIqFFZF1zQtTFscTSjBfs1ucbXGlBJNJ64naErHS7A3IZIb1ZKJy9TmWvS5pjTmqsErrf0FE.r3LEu1AYjCZpXI; path=/; expires=Fri, 03-Apr-26 01:39:55 GMT; domain=.justeat-int.com; HttpOnly; Secure; SameSite=None
Strict-Transport-Security: max-age=0
Server: cloudflare

HTTP/1.1 200 OK

HTTP/1.1 200 OK
Date: Fri, 03 Apr 2026 01:09:56 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
CF-RAY: 9e6430cfa912e802-ORD
ratelimit-reset: 1
ratelimit-remaining: 9999
ratelimit-limit: 10000
x-ratelimit-limit-second: 10000
x-ratelimit-remaining-second: 9999
last-modified: Wed, 01 Apr 2026 10:56:46 GMT
x-amz-server-side-encryption: AES256
Accept-Ranges: bytes
Cache-Control: max-age=300
=== rest.api.eu-central-1 path probe ===
=== rest.api.eu-central-1 path probe ===
404 -> /docs
404 -> /openapi.yaml
404 -> /docs/openapi.yaml
404 -> /consumer/me/orders
401 -> /delivery/pools
404 -> /v1/delivery
404 -> /health
404 -> /status
404 -> /restaurants
=== cw-api.takeaway.com deep probe ===
HTTP/1.1 200 OK

HTTP/1.1 403 Forbidden
Date: Fri, 03 Apr 2026 01:10:53 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
X-Frame-Options: SAMEORIGIN
Referrer-Policy: same-origin
Cache-Control: private, max-age=0, no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Expires: Thu, 01 Jan 1970 00:00:01 GMT
Set-Cookie: __cf_bm=egH2W_ALUYN88_c5PzydRWQ8.JH.oc1e8syUjXkaH8M-1775178653-1.0.1.1-aJIJ0xa5_XDZ87eST4o8e44tHhMGKDHsoU49WAzQDHi0WtbVJvKJcEOCJr_UZRJq6nFUCkPE3JS5I8ewYvtlb7qAb3zJK2IJS1hD.33qzOybN2XlIt9vSlse.NvilPno; path=/; expires=Fri, 03-Apr-26 01:40:53 GMT; domain=.takeaway.com; HttpOnly; Secure; SameSite=None
Server: cloudflare
CF-RAY: 9e643235588b13fe-ORD
alt-svc: h3=":443"; ma=86400
Content-Length: 5454

403 -> /
HTTP/1.1 200 OK

HTTP/1.1 403 Forbidden
Date: Fri, 03 Apr 2026 01:10:53 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
X-Frame-Options: SAMEORIGIN
Referrer-Policy: same-origin
Cache-Control: private, max-age=0, no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Expires: Thu, 01 Jan 1970 00:00:01 GMT
Set-Cookie: __cf_bm=n9PyiRJ83.RSkkaoxaGnFQJ9TtdyJ6D30eASvtHuxJY-1775178653-1.0.1.1-AI_T_hTgXufRFBJZihrYALJvXkRKDMfhY_v7i2nlclHpAwDh4JsMa4F6.W3jtzfftfqECtpee1FxJm.0xjdxuH4kCbVC7uElhPfSFZF.y_evwMqJvjv5_aH0BHSyygzW; path=/; expires=Fri, 03-Apr-26 01:40:53 GMT; domain=.takeaway.com; HttpOnly; Secure; SameSite=None
Server: cloudflare
CF-RAY: 9e643235fd8b22d3-ORD
alt-svc: h3=":443"; ma=86400
Content-Length: 5454

403 -> /docs
HTTP/1.1 200 OK

HTTP/1.1 403 Forbidden
Date: Fri, 03 Apr 2026 01:10:53 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
X-Frame-Options: SAMEORIGIN
Referrer-Policy: same-origin
Cache-Control: private, max-age=0, no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Expires: Thu, 01 Jan 1970 00:00:01 GMT
Set-Cookie: __cf_bm=KaTqYAY4TPp7CeuEHHhPC_lBj4svIVmrfVel_u2hZkg-1775178653-1.0.1.1-ivDKVmG6JqrMky4yVFYAiUgHB2R5788yJJpfT5xZrcjzYGA3jdV365epgYmR7lV9H4IDlTzJGFRVcjVWsDprbeIAPjKoBbeT98E701uoSKEHD7Bfrvo_olaoKzD5c1eG; path=/; expires=Fri, 03-Apr-26 01:40:53 GMT; domain=.takeaway.com; HttpOnly; Secure; SameSite=None
Server: cloudflare
CF-RAY: 9e643236a8efe74c-ORD
alt-svc: h3=":443"; ma=86400
Content-Length: 5454

403 -> /openapi.yaml
HTTP/1.1 200 OK

HTTP/1.1 403 Forbidden
Date: Fri, 03 Apr 2026 01:10:53 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
X-Frame-Options: SAMEORIGIN
Referrer-Policy: same-origin
Cache-Control: private, max-age=0, no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Expires: Thu, 01 Jan 1970 00:00:01 GMT
Set-Cookie: __cf_bm=UuliKqeiz.nc5XR4eP8tVqBKi_s1sY1lTGsXSt.CqPY-1775178653-1.0.1.1-oaLxbSGsN6DjsZeRNvby3HzrPuA49KPZpRupFRQES1P7LFPzgATTBbWG0QqELi6Xh4GU4LLin2DzsgR7OLp_Sp.8cxKxk9v3u2yuoU7UiMVyOSZ5mM4mZ20FMfB4afXr; path=/; expires=Fri, 03-Apr-26 01:40:53 GMT; domain=.takeaway.com; HttpOnly; Secure; SameSite=None
Server: cloudflare
CF-RAY: 9e6432375e2ceac0-ORD
alt-svc: h3=":443"; ma=86400
Content-Length: 5454

403 -> /docs/openapi.yaml
HTTP/1.1 200 OK

HTTP/1.1 403 Forbidden
Date: Fri, 03 Apr 2026 01:10:53 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
X-Frame-Options: SAMEORIGIN
Referrer-Policy: same-origin
Cache-Control: private, max-age=0, no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Expires: Thu, 01 Jan 1970 00:00:01 GMT
Set-Cookie: __cf_bm=eOeC8vUT86tHxBacg0QO0ed2eip.4YkxnAOy4QgkWFk-1775178653-1.0.1.1-o7hrtIkFrEx_nhUdz1ZvollSN3qrIDuFot2VEtqodrQerBZYcdd9ucTEmCCiYOGcrXhzsEIpux3TGJA7BqXXNXwQKXJ0ET6NsW7Nz1yIyA66Y3VPrtnE3DswERNk7syN; path=/; expires=Fri, 03-Apr-26 01:40:53 GMT; domain=.takeaway.com; HttpOnly; Secure; SameSite=None
Server: cloudflare
CF-RAY: 9e643237fdf8e824-ORD
alt-svc: h3=":443"; ma=86400
Content-Length: 5454

403 -> /auth/realms/daas
HTTP/1.1 200 OK

HTTP/1.1 403 Forbidden
Date: Fri, 03 Apr 2026 01:10:53 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
X-Frame-Options: SAMEORIGIN
Referrer-Policy: same-origin
Cache-Control: private, max-age=0, no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Expires: Thu, 01 Jan 1970 00:00:01 GMT
Set-Cookie: __cf_bm=7xgAm77KNM7CfKed5FPR2iNKb_uT2SVHvtBF29y20MY-1775178653-1.0.1.1-to2qbwMRnLnyX1kgfkU3vu2n6g9E6aXPN7TzUNTQuw0U_wYJksJo7YuxvRysPNpoLCi1Cibmi2Ywj2vukqF4YWT51cTVrTnnXhT3KPdfxQkBYTNDO6c1.RLSzW4DMv4C; path=/; expires=Fri, 03-Apr-26 01:40:53 GMT; domain=.takeaway.com; HttpOnly; Secure; SameSite=None
Server: cloudflare
CF-RAY: 9e6432388a87eb68-ORD
alt-svc: h3=":443"; ma=86400
Content-Length: 5454

403 -> /auth/realms/daas/protocol/openid-connect/token
HTTP/1.1 200 OK

HTTP/1.1 403 Forbidden
Date: Fri, 03 Apr 2026 01:10:53 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
X-Frame-Options: SAMEORIGIN
Referrer-Policy: same-origin
Cache-Control: private, max-age=0, no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Expires: Thu, 01 Jan 1970 00:00:01 GMT
Set-Cookie: __cf_bm=OPVYzrSAzpcjnJvMGJsIIQw24uue5BKhMwheHUEK3zI-1775178653-1.0.1.1-_kDYpcOTI2.8g0.89FvVQtW.KMdEJkv0tW1_bJ5aq1mgyAXoT6cgaN_BKAOzUlK4WJiy05voUOQULA3PkMLdnXHs7NiEDrYvIBKpqJPxDtphJAWRpqHP7ZZKi4qEPgFE; path=/; expires=Fri, 03-Apr-26 01:40:53 GMT; domain=.takeaway.com; HttpOnly; Secure; SameSite=None
Server: cloudflare
CF-RAY: 9e6432393e333f2a-ORD
alt-svc: h3=":443"; ma=86400
Content-Length: 5454

403 -> /consumer/me/orders
HTTP/1.1 200 OK

HTTP/1.1 403 Forbidden
Date: Fri, 03 Apr 2026 01:10:53 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
X-Frame-Options: SAMEORIGIN
Referrer-Policy: same-origin
Cache-Control: private, max-age=0, no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Expires: Thu, 01 Jan 1970 00:00:01 GMT
Set-Cookie: __cf_bm=_RDj3tvlLt0Pg7AS69t7VSTToeOxOvPATVK6bQsVaAY-1775178653-1.0.1.1-ZjPbhJY3xhyFdPkYvMwBg8kg6d23EUFN1TBf1FJpFv1PlBZOiCMaAQGGd3XH7YiFqhf5Ekq_T2xlUJOREvNLKffxKIE8KVn1mEab8R0X2d9zEB5XXH6IwxZemJQvf6yn; path=/; expires=Fri, 03-Apr-26 01:40:53 GMT; domain=.takeaway.com; HttpOnly; Secure; SameSite=None
Server: cloudflare
CF-RAY: 9e643239eb610bf0-ORD
alt-svc: h3=":443"; ma=86400
Content-Length: 5454

403 -> /delivery/pools
HTTP/1.1 200 OK

HTTP/1.1 403 Forbidden
Date: Fri, 03 Apr 2026 01:10:53 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
X-Frame-Options: SAMEORIGIN
Referrer-Policy: same-origin
Cache-Control: private, max-age=0, no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Expires: Thu, 01 Jan 1970 00:00:01 GMT
Set-Cookie: __cf_bm=0rYxfx1eFY6y7WDgHIFvAdUur99DMdszECsSL2BPNrs-1775178653-1.0.1.1-jgMZ2l2o_AA05JI55FRVpUZywuZUTef31R9FfAXW8EBcVAVdhSGnIJPqhYt6IFnkncOtOXQ9J2IzBbvZ0WzVz8qqq5N4FN7AO.fuHzN3uxOfuGoUAHzvN6C3nvcq6SVU; path=/; expires=Fri, 03-Apr-26 01:40:53 GMT; domain=.takeaway.com; HttpOnly; Secure; SameSite=None
Server: cloudflare
CF-RAY: 9e64323a8bc286e4-ORD
alt-svc: h3=":443"; ma=86400
Content-Length: 5454

403 -> /v1/delivery
HTTP/1.1 200 OK

HTTP/1.1 403 Forbidden
Date: Fri, 03 Apr 2026 01:10:53 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
X-Frame-Options: SAMEORIGIN
Referrer-Policy: same-origin
Cache-Control: private, max-age=0, no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Expires: Thu, 01 Jan 1970 00:00:01 GMT
Set-Cookie: __cf_bm=Nj90AUTdWePMYVXfiCeI3YsQ.gEb_YSkgZiQ4E7qyl8-1775178653-1.0.1.1-3d_KzM.b3oUKSsGG.utJ3MaCZ.SiIOJWUcefoTx98k2IQ0YmC4AWso08dmHGpaO9FUUBM8NgJAKAbCmChXQSCwpDX1c_R86L_FoHDyH.r6UV.zMcXjibc4buuykLL2vP; path=/; expires=Fri, 03-Apr-26 01:40:53 GMT; domain=.takeaway.com; HttpOnly; Secure; SameSite=None
Server: cloudflare
CF-RAY: 9e64323b19b7f32d-ORD
alt-svc: h3=":443"; ma=86400
Content-Length: 5454

403 -> /health
HTTP/1.1 200 OK

HTTP/1.1 403 Forbidden
Date: Fri, 03 Apr 2026 01:10:54 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
X-Frame-Options: SAMEORIGIN
Referrer-Policy: same-origin
Cache-Control: private, max-age=0, no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Expires: Thu, 01 Jan 1970 00:00:01 GMT
Set-Cookie: __cf_bm=071yaW7mOXCxcsJPzWJZDkUenSs6tPlHNfGJnvAUMgQ-1775178654-1.0.1.1-KbY2ECalbtltbjZoBdtV_YPHsBYCOFWNpGIkgX4sNzAk89VPK57JxeJBOu98xeQp6LDc.0PQyLJVvQF997KXPCOeztmHvuEpH5nKb.oBosb7yxAq6wZm4EceMn_OyGDx; path=/; expires=Fri, 03-Apr-26 01:40:54 GMT; domain=.takeaway.com; HttpOnly; Secure; SameSite=None
Server: cloudflare
CF-RAY: 9e64323bbb62620f-ORD
alt-svc: h3=":443"; ma=86400
Content-Length: 5454

403 -> /status
HTTP/1.1 200 OK

HTTP/1.1 403 Forbidden
Date: Fri, 03 Apr 2026 01:10:54 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
X-Frame-Options: SAMEORIGIN
Referrer-Policy: same-origin
Cache-Control: private, max-age=0, no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Expires: Thu, 01 Jan 1970 00:00:01 GMT
Set-Cookie: __cf_bm=EyEwe30ix3R0lX8vWKv8Bvd2y2QMohGlCJCeImB72fk-1775178654-1.0.1.1-MBLxh2Vvrsj9UATREa9KkC4rLU9W3KYuvV3iTONICh.lQ65oyvEpmj_yavuIiyDfrwDW7ELVI4Ta6XvePLze2m85ATzWAFSTaZwWM1nkFD22GMP8WEVtyZCMjuF7DI9Y; path=/; expires=Fri, 03-Apr-26 01:40:54 GMT; domain=.takeaway.com; HttpOnly; Secure; SameSite=None
Server: cloudflare
CF-RAY: 9e64323c6c52e261-ORD
alt-svc: h3=":443"; ma=86400
Content-Length: 5454

403 -> /auth
HTTP/1.1 200 OK

HTTP/1.1 403 Forbidden
Date: Fri, 03 Apr 2026 01:10:54 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
X-Frame-Options: SAMEORIGIN
Referrer-Policy: same-origin
Cache-Control: private, max-age=0, no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Expires: Thu, 01 Jan 1970 00:00:01 GMT
Set-Cookie: __cf_bm=hktIhEjxZ9yW4o72k.gHdIBMDq6xxMQV_MW3dp74FKk-1775178654-1.0.1.1-tARvEGZQ5yQzYeYPHHVQaTxGFLBogqswMbmUv1b_hm6.9z2MpC4YLllYrtUYM5kLAuYv5kynO8nrtj_efu7YGb90Pe2FvkXafYR8RQpuf5cTnag1zWOb0mQZKmdIClqN; path=/; expires=Fri, 03-Apr-26 01:40:54 GMT; domain=.takeaway.com; HttpOnly; Secure; SameSite=None
Server: cloudflare
CF-RAY: 9e64323d0b68ee24-ORD
alt-svc: h3=":443"; ma=86400
Content-Length: 5454

403 -> /auth/realms
HTTP/1.1 200 OK

HTTP/1.1 403 Forbidden
Date: Fri, 03 Apr 2026 01:10:54 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
X-Frame-Options: SAMEORIGIN
Referrer-Policy: same-origin
Cache-Control: private, max-age=0, no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Expires: Thu, 01 Jan 1970 00:00:01 GMT
Set-Cookie: __cf_bm=cD7XMAn5SyqicloZnhoLVrZjWd5t69c1oZ7LbCt.QDQ-1775178654-1.0.1.1-LGcnjYDWwUDpb3rMFJM_HzYNgnGqTpwZ_mOp9Y5wEyiExiOV2CeqRHksbCouTbQibIY7tgYgHuYHxx6uJOjVsStzplo4Im2Ayui01OKbaKbA7SAx3DMxTi8Oq6ZjwHO1; path=/; expires=Fri, 03-Apr-26 01:40:54 GMT; domain=.takeaway.com; HttpOnly; Secure; SameSite=None
Server: cloudflare
CF-RAY: 9e64323daea1b680-ORD
alt-svc: h3=":443"; ma=86400
Content-Length: 5454

403 -> /realms/daas
HTTP/1.1 200 OK

HTTP/1.1 403 Forbidden
Date: Fri, 03 Apr 2026 01:10:54 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
X-Frame-Options: SAMEORIGIN
Referrer-Policy: same-origin
Cache-Control: private, max-age=0, no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Expires: Thu, 01 Jan 1970 00:00:01 GMT
Set-Cookie: __cf_bm=0wsmnHDPNhdNa_y2gstJanC4yyIYKRYlx5ERVbHKYOk-1775178654-1.0.1.1-mhepY0khT.u.R0iSi99reC0JRc6BuLe.nAvr7IlhRC3.bZPAEA2UJx8dyK2Rj.v57fLHe3FVCWn4LkQBuT5uYhG7MTCAnubI5iH0HpSiGhHzDzHQxO7TfPYaG44JQ6kT; path=/; expires=Fri, 03-Apr-26 01:40:54 GMT; domain=.takeaway.com; HttpOnly; Secure; SameSite=None
Server: cloudflare
CF-RAY: 9e64323e587015d9-ORD
alt-svc: h3=":443"; ma=86400
Content-Length: 5454

403 -> /token
