---
name: active-directory-attack
description: >-
  Internal domain attacks: BloodHound, Kerberoast, ADCS ESC1/ESC8, NTLM relay, coercion, DACL, DCSync, Zerologon/NoPac/PrintNightmare, mitm6, LLMNR, Linux internal networks. Use when attacking Active Directory, ADCS, NTLM relay, or the internal domain.
metadata:
  tags: [penetration-testing, penetration-testing, red-team]
---

## Internal Domain Attacks

```
=== Internal domain (the real main battlefield since 2023) ===
Reconnaissance: BloodHound (SharpHound collection → attack paths) | Kerberos: GetNPUsers (AS-REP) / GetUserSPNs (Kerberoast)
🚨 ADCS (one-shot with Certipy): certipy find -vulnerable | ESC1: specify a SAN to request a domain admin certificate | ESC8: relay to the CA to obtain a DC certificate
🚨 NTLM relay (more important than PtH, which EDR often blocks): ntlmrelayx -t ldap --escalate-user / -t http CA --adcs (ESC8) / RBCD
🚨 Forced authentication coercion: PetitPotam (MS-EFSRPC) / coercer full-protocol spray / printerbug → feed into relay
🚨 DACL abuse: WriteDACL → grant yourself DCSync | shadow credentials via certipy shadow (GenericWrite is enough; no password change, leaves no trace)
DCSync: secretsdump -just-dc → krbtgt hash → Golden Ticket
🚨 One-shot domain CVEs (test first; a hit grants domain admin directly): Zerologon (CVE-2020-1472, blank the DC machine account password → DCSync) | NoPac (CVE-2021-42278/42287, rename the machine account to request a DC TGT) | PrintNightmare (CVE-2021-34527, remote print spooler RCE / load a malicious driver) | EternalBlue (MS17-010, direct RCE on legacy SMBv1)
🚨 IPv6 / mitm6 (must-try on default dual-stack internal networks): mitm6 hijacks DHCPv6 + DNS → WPAD → ntlmrelayx to LDAP / ADCS (stealthier than LLMNR; the preferred choice for modern internal networks)
LLMNR / NBT-NS poisoning: responder to capture NetNTLMv2 → crack with hashcat / relay
Linux internal networks: unauthenticated Redis (CONFIG SET dir to write an SSH key) | NFS showmount | Docker 2375
```
