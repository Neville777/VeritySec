---
name: initial-access-phishing
description: >-
  Initial access / phishing / social engineering: credential spraying, AiTM, device code, OAuth consent phishing, payloads, vishing. Use when needing initial access, phishing, AiTM, device code, or social engineering.
metadata:
  tags: [penetration-testing, penetration-testing, red-team]
---

## Initial Access / Phishing / Social Engineering

```
=== Initial access / phishing / social engineering (the first hop from outside into the internal network; reconnaissance before the reconnaissance) ===
Credential spraying: weak passwords (Season+Year!/CompanyName123) sprayed across all accounts (1-2 attempts per account to avoid lockout) | sources: breach databases / OSINT email formats (f.last@) / default credentials
AiTM phishing (bypasses MFA): evilginx3 / Modlishka reverse-proxy the real site → man-in-the-middle to steal session cookies + tokens (bypasses MFA) | phishlet with domain + certificate
Device code phishing (Azure/M365): device code flow → lure victims into entering the code → obtain access/refresh tokens (no password/MFA needed) | TokenTactics / AADInternals
Phishing payloads: gophish for sending + landing pages | payloads lnk / iso / macros / HTA / OneNote | gateway evasion: password-protected zip / cloud drive links / HTML smuggling
OAuth consent phishing (illicit consent): a malicious app requests excessive scopes (Mail.Read / offline_access) → victim consents → long-term access tokens
Social engineering groundwork: OSINT on org structure / vendors / password habits (LinkedIn / job postings / GitHub) | pretexts (IT support / vendor / HR) | vishing (deepfake voice)
→ Once initial access lands, move to `redteam-opsec` (so you don't get caught by EDR right at the door); capabilities obtained feed into `capability-primitive-search` to assemble chains
```
