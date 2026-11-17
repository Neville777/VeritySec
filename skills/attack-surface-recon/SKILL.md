---
name: attack-surface-recon
description: >-
  Reconnaissance / attack surface mapping: passive whois/amass/crt.sh/FOFA/Shodan, active subfinder/httpx/naabu/katana/nuclei, DNS geo-differences / CDN / Nginx catch-all / BT Panel / UniApp fingerprints. The first action when starting; record findings in the project blackboard. Use when starting recon, asset mapping, fingerprinting, or CDN/DNS bypass discovery.
metadata:
  tags: [penetration-testing, penetration-testing, red-team]
---

## Reconnaissance / Attack Surface Mapping

```
=== Recon / attack surface mapping (the first action at the start; ~60% of the time is spent here, don't charge into exploitation blind; immediately upsert_project_fact for ports / fingerprints, etc.) ===
Passive first (do not touch the target; run all of these):
  terminal: whois {domain} | grep -iE 'org|name|email|registrant'
  terminal: amass intel -asn {ASN} -d {domain}
  browser_navigate: https://crt.sh/?q=%.{domain} (certificate transparency to find subdomains)
  terminal: curl -s "https://crt.sh/?q=%.{domain}&output=json" | python3 -c "import sys,json;[print(x['name_value']) for x in json.load(sys.stdin)]" | sort -u
  terminal: dig +short {domain} @114.114.114.114; dig +short {domain} @8.8.8.8 (differences between resolvers = CDN)
  terminal: curl -s "https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey" | head -100
  browser_navigate: https://fofa.info/result?qbase64=$(echo -n 'domain="{domain}"' | base64)
  browser_navigate: https://www.shodan.io/search?query=hostname:{domain}
Active pipeline (run step by step):
  terminal: subfinder -d {domain} -silent | tee subs.txt; amass enum -d {domain} -passive >> subs.txt; sort -u subs.txt -o subs.txt
  terminal: cat subs.txt | dnsx -silent | tee alive_subs.txt
  terminal: cat alive_subs.txt | httpx -silent -title -status-code -tech-detect -cdn | tee httpx_out.txt
  terminal: naabu -l alive_subs.txt -top-ports 1000 -silent | tee ports.txt; nmap -sCV -iL <(head -20 alive_subs.txt) -oN nmap_out.txt
  terminal: katana -list alive_subs.txt -silent -d 3 | tee urls.txt; gau {domain} >> urls.txt
  terminal: cat urls.txt | grep -iE '\.(js|json)$' | httpx -silent -mc 200 | while read u; do curl -s "$u" | grep -oiE '(api|secret|key|token|password|aws|endpoint)[^"]*'; done
  terminal: ffuf -u https://{target}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -mc 200,301,302,403 -fs {catch-all-size}
  terminal: nuclei -l alive_subs.txt -t /root/nuclei-templates/ -severity medium,high,critical -o nuclei_results.txt
  → Framework/version identified in httpx output → immediately trigger the `component-vuln-intel` search sequence
🚨 Bypassing DNS geo-restrictions: domestic CDNs (987dns / dnspod / Alibaba Cloud) often return 0.0.0.0 to overseas DNS queries; resolving via 114.114.114.114 yields the real IP. Compare multiple resolvers: dig @1.1.1.1 vs @114.114.114.114 vs @8.8.8.8; differences reveal the CDN's geo policy. The real IP may be hidden in domestic DNS results.
🚨 CDN response filtering bypass (GCCDN / PWS etc.): the CDN returns 502 instead of forwarding the backend response for specific URL patterns (admin paths / actuator):
  Fingerprinting: Server: PWS/x.x.x.x | Via: 1.1 PS-XXX-XXXX:N (W) | X-Px: ms CS-XXX-XXXX none(origin) | wildcard *.gccdn.net CNAME
  502 ≠ does not exist: 502 = backend response filtered by the CDN, 404 = path truly does not exist, 403 = CDN routing denial. Use the 502/404/403 differences to enumerate live endpoints
  Path traversal confirmation: /api/v1/v/..;/..;/actuator/env → 502 (exists but filtered) vs /api/v1/v/..;/..;/xxxx → 404 (natively nonexistent in Tomcat)
  Multiple CDN node ports: scan ports 3000-9200 on the CDN IP (8000/8080/9090 often proxy the same backend but with different rules; 9200 may be a standalone nginx)
  Bypass attempt matrix (all failed in this session; recorded to avoid repetition): URL encoding / double encoding / case changes / semicolon suffixes / TE whitespace smuggling / HTTP pipelining / Accept-Encoding / Range
  Useful information extraction: even with a 502, POST actuator/env may still be executed by the backend (blind attribute write) → needs a refresh trigger (if refresh returns 404, the chain is broken)
🚨 Nginx catch-all trap: a PHP CMS with rewrite rules for all routes → every path returns 200 with the same size = catch-all (this does NOT mean the file exists!). Identification: compare sizes across 3 random paths; if identical = catch-all. Test real live paths with a .php suffix (nginx `location ~ \.php$` passes through to FastCGI, and nonexistent paths return a real 404).
🚨 Pure-FTPd puredb corruption ≠ authentication bypass: "Unable to read the indexed puredb file" = the virtual-user database is corrupted, so every username (including anonymous) triggers a 421 disconnect. PAM system-user authentication also goes through puredb first → everything fails. Not an attack surface; skip it.
🚨 Lateral movement across multiple sites on the same IP: reverse-lookup the IP (SecurityTrails / Threatbook / VirusTotal) to find other domains on the same server → breach a weak site (a standalone nginx config returning a real 404 = enumerable) → BT Panel unified management = lateral access to all sites.
Fingerprint priority: once httpx / wappalyzer identifies a framework version → immediately switch to `component-vuln-intel` for online intelligence. Map the attack surface first, then reason about which edge is juiciest; do not dive into the first vulnerability you see.
🚨 DNS wildcard CDN identification: all subdomains (including random nonexistent subdomains) resolve to the CDN = wildcard DNS (*.domain → CDN CNAME). Enumerating subdomains is meaningless at this point; all IPs are CDN nodes.
  Verification: dig random123456.target.com → if it also has an A record pointing to a known CDN IP = wildcard. The real origin IP must be obtained from other sources (historical DNS / certificate transparency / other domains on the same server / email headers / SSRF)
🚨 BT Panel (Baota) identification: a cookie name that is a 32-character hex hash (e.g. 789d6d2de16419a1e8bbfea926c8996e) + 302 redirect to /login + nginx reverse proxy + "entrance verification failed" page = BT Panel random security entrance
  Windows version: IIS + nginx coexisting, panel on port 8888, phpMyAdmin on port 888 (possibly), /index.html may leak site configuration (reverse proxy target URL / site name)
  Attacks: brute-force the entrance path (8 random alphanumeric characters) | historical CVEs (unauthorized API key / phar deserialization) | reuse default FTP / MySQL accounts from the panel
🚨 Nginx 404 differential fingerprinting: when an nginx catch-all rewrite masks real paths, compare response sizes — a real nginx 404 (146B) = the file exists on disk but the location block denies it; a catch-all (large page) = the route did not match. Batch-probe CMS signature paths (/caches/configs/, /phpcms/modules/, /statics/, etc.) and distinguish response sizes to confirm the CMS type. See 
🚨 UniApp / DCloud APK reverse-engineering fast path: assets/apps/__UNI__*/www/app-service.js = all business logic (JS obfuscated); assets/zlsioh.dat = encrypted configuration (API domain); lib/arm64-v8a/libirzlemnr.so = decryption library. Deobfuscate JS with RC4 + base64 (extract the a0G array + a0m decoder); in the .so, search strings for 16-character random strings = possible keys, and for the `x number.number.number.numberx` format = hardcoded IPs (usually DCloud HTTPDNS infrastructure rather than the target's API). See 
```
