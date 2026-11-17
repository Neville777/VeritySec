---
name: proxy-tool-bootstrap
description: >-
  Self-sourced proxies + self-bootstrapped tools: SOCKS5/HTTP/Tor rerouting sequence, Python tool bootstrapping, self-generated wordlists, OOB infrastructure. Use when blocked by 403/429/WAF/timeout, missing tools, or needing OOB confirmation.
metadata:
  tags: [penetration-testing, penetration-testing, red-team]
---

## Self-Sourced Proxies + Tool Bootstrapping (reroute when blocked; write your own tools when missing)

```
🔴 Proxies (on refusal / rate limiting / timeout → the first reaction is not to retry, it is to reroute. Not rerouting = giving up = violating blackboard trigger 2 (see `pentest-blackboard`)):
  Execution sequence (in order; move to the next step only if the previous one fails):
  ① Probe target region: terminal: curl -s "http://ip-api.com/json/{target IP}" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d['country'],d['countryCode'])"
  ② Fetch SOCKS5 proxies for that region: terminal: curl -s "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&country={countryCode}&timeout=5000" | head -20
  ③ Verify the proxy can reach the target: terminal: curl --socks5 {PROXY_IP:PORT} --connect-timeout 8 -s -o /dev/null -w "%{http_code}" {target URL}
  ④ 200 = usable, immediately re-run the blocked request through this proxy; non-200 = try the next proxy and repeat ③
  ⑤ All SOCKS5 fail → fetch HTTP proxies: terminal: curl -s "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&country={countryCode}&timeout=5000" | head -20
  ⑥ Verify HTTP proxy: terminal: curl --proxy http://{PROXY_IP:PORT} --connect-timeout 8 -s -o /dev/null -w "%{http_code}" {target URL}
  ⑦ All proxies fail → Tor: terminal: curl --socks5 127.0.0.1:9050 --connect-timeout 15 {target URL}
  Pass the proxy parameter to tools uniformly: curl --socks5 / sqlmap --proxy=socks5://{P} / nmap --proxies socks5://{P} / nuclei -proxy socks5://{P} / ffuf -x socks5://{P}
  Rotation policy: on 429/403 → switch to the next proxy immediately; proactively rotate every 20 requests (new IPs can also get banned) | Cloudflare → proxy pool + randomized request intervals of 2-5s
  🚨 HTTP proxy vs SOCKS5: HTTP proxies inject their own error pages (502 / "this page cannot be displayed"), making it impossible to tell the target's actual response → when probing, you must use SOCKS5 (--socks5)
    ProxyScrape SOCKS5: https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&country=CN,JP&timeout=5000
    Verify SOCKS5: curl --socks5 IP:PORT --connect-timeout 5 target | HTTP proxies are only suitable for anonymity/rotation against targets already confirmed reachable
Tool bootstrapping (which X || implement in Python):
  No nmap → socket port scanning | no ffuf → requests-based directory brute force | no sqlmap → manual payload detection | no hydra → requests-based brute force | no nuclei → requests to fire known payloads
  Simulate complex tools in Python: crawler with requests + bs4 / encoding base64/hex / hashing hashlib / encryption pycryptodome / sniffing scapy
Self-generated wordlists: build variants from the target domain / company name | extract keywords from web pages | username + year + special-character combinations | default service credentials
OOB infrastructure (blind vulnerabilities depend on it): interactsh-client to get an oast.fun domain | or a VPS with python3 -m http.server / nc to watch for callbacks | ngrok / cloudflared tunnels
  → Only record a Fact as confirmed once an OOB callback (DNS query / HTTP request) is observed
```
