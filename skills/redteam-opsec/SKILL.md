---
name: redteam-opsec
description: >-
  OPSEC covert operations discipline: IP blacklist bypass, rate and timing control, traffic blending, minimal footprint, anti-forensics, progressive exposure. Use when maintaining stealth, bypassing IP bans, or planning covert red-team operations.
metadata:
  tags: [penetration-testing, penetration-testing, red-team]
---

## OPSEC / Covert Operations Discipline (evasion / stability / stealth)

```
Core: getting in ≠ staying in. Once discovered, the operation is reset to zero. Before every action, ask "what does this step look like from the defender's point of view?"
🚨 IP blacklist bypass (try this immediately after being banned): X-Forwarded-For: random IP (when a CDN trusts this header, it bypasses the application-layer blacklist directly; when the response is code:10010 / blacklisted, try XFF / X-Real-IP / CF-Connecting-IP / True-Client-IP one by one)
  Verification: a normal request returns "blacklisted" + your IP → add the XFF header and it returns a normal 200 → include XFF in all subsequent requests
  Advanced: change the XFF value every N requests (new IPs can also get banned) | some CDNs only trust the first XFF value, others trust the last
Rate and timing: throttle scans (nuclei -rl / nmap -T2 --max-rate / ffuf -p delay) to avoid WAF bans and IDS threshold alerts | high-risk actions at low frequency with random jitter | avoid business peak hours and also late nights (match the target's rhythm to be least conspicuous)
Traffic blending: resemble normal business (common UA / Referer / legitimate paths) | probe defenses before heavy operations (process list / known EDR / SIEM agent signatures) → if present, prioritize quiet techniques; only run automated bulk operations when no monitoring is detected
Minimal footprint: prefer in-memory execution without touching disk (DDexec / memfd / reflective loading) | webshell with strong password + uncommon path + disguised functionality | tunnels over 443 / DNS to blend with common outbound traffic | delete tools immediately after use (/dev/shm RAM disk, leave no residue)
Anti-forensics: command history: unset HISTFILE / set +o history | selectively delete your own log entries (truncating all logs actually triggers alerts) | timestamps: touch -r referencing a neighboring file to preserve persistence mtime | do not touch monitoring/audit services (stopping them is itself an alert)
Progressive exposure: passive reconnaissance (certificate transparency / passive DNS / search engines / asset engines) → confirm there is no strong monitoring → only then actively scan → finally deploy exploitation. Never touch the target directly if public intelligence can provide the information. At each escalation, ask "is this exposure worth it?"
> Stealth is not fastidiousness; it is a red team's survival capability. A single reckless full-port, full-speed scan can reset the entire operation to zero.
```
