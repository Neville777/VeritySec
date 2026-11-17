---
name: capability-primitive-search
description: >-
  Capability primitives + state-space search: combine primitives such as read/write/exec/ssrf into RCE equations A-F, map low-severity findings, forward and backward search, cross-domain monetization. Use when no single RCE exists, when chaining low-severity vulnerabilities, or when deriving novel attack chains.
metadata:
  tags: [penetration-testing, penetration-testing, red-team]
---

## Capability Primitives + State-Space Search

```
Core idea: RCE is not a single "vulnerability"; it is an emergent result of assembling a set of "capabilities". When there is no single big hole, several info-level / low-severity findings can still be stitched into code execution.
  Inherited thinking (to break): "no RCE / deserialization / upload found → this site cannot be broken." Your job is not "find an RCE vulnerability" but "assemble the primitives required for execution".
  Abstract each Fact into a capability primitive (do not record "found vulnerability X"; record "what capability do I now have, and what are its limits"):
    read(path) write(path) exec(cmd) ssrf(url) sqli redirect(url) eval_expr idor(id) cred(svc,priv) coerce_auth write_acl

RCE only needs to satisfy any one of the following equations; break them into obtainable primitives and assemble:
  A. Can write a file + the file is executed as code                = RCE
  B. Can control config/env + config points to your code            = RCE
  C. Can reach the admin panel + the panel has a built-in execution feature = RCE (not a vulnerability, a feature!)
  D. Has credentials + the service has a legitimate execution entry point   = RCE (abuse a legitimate feature)
  E. Arbitrary read + read credentials + credentials can log in to an execution point = RCE
  F. Can control data + data flows into a dangerous sink (eval / template / SQL) = RCE

Mapping low-severity findings to primitives (translate "useless bugs" into puzzle pieces):
  Info leak (.git / backups / stack traces) → source / paths / keys → feed B / E / F | LFI / arbitrary read → read config keys → E, or log poisoning → A
  SSRF (even just GET) → hit internal Redis / Consul / K8s / cloud metadata → C; cloud metadata yields temporary credentials → D
  Weak / default / reused credentials → log into a backend with task / plugin / webhook / CI features → C | CORS / CSRF / XSS → use the admin's browser to invoke execution-type features → C
  Controllable upload (even with extension restrictions) → combine with path traversal / parser differentials / .htaccess → A | config write → change templates / logs / connection strings → B
  SQLi (even read-only) → read hashes / keys → E, or OUTFILE → A | controllable template → SSTI → F | prototype pollution → pollute downstream properties → F

State-space search (search for yourself when no ready-made chain exists): state = current capability set, action = use capabilities to unlock new capabilities, goal = Goal.
  Forward: for each capability ask "what can it unlock?"; for each pair of capabilities ask "what can they combine into?"
    (read + write = modify config; ssrf + internal redis = RCE; sqli + FILE = webshell; coerce_auth + relay = domain SYSTEM; idor + mass assignment = modify another user's admin rights)
  Backward (primary method when stuck): fix the Goal = execute a command → pick the equation closest to the current state as a template → whichever primitive is missing becomes a subgoal →
    which low-severity / feature / info leak on hand can assemble it? → if none can, recursively decompose or switch equations → when forward and backward searches meet in the middle, the full chain emerges → verify each segment

Breakthrough points (never walk away when you see these):
  · "Features are primitives": background task schedulers / plugins / template editors / SQL consoles / file managers / import-export / webhooks — legitimate features that, once logged into, are ready-made execution or read/write primitives. A pentester does not distinguish between "features" and "vulnerabilities"; there are only "capabilities".
  · Cross-protocol jumps: SSRF with gopher / dict / file turns "can only send HTTP" into "hit Redis / send SMTP / read files".
  · Credential reuse is universal glue: any password/key obtained anywhere is sprayed across all services by default. Lateral movement is often faster than vertical escalation.
  · Parser differentials: upload validation / routing / reverse proxies disagree on interpretation → gaps offer bypasses (double extensions / encoding / Host confusion).
  · Time dimension: TOCTOU / predictable tokens / cache poisoning turn "occasionally" into "reliably", and turn non-exploitable issues into exploitable ones.
  · Cross-domain monetization: for each capability acquired, ask "what is it worth in another domain" — capabilities are a universal currency. Web SSRF → reach cloud metadata to take over an account; hardcoded APK values → connect directly to internal APIs to bypass frontend authentication; supply chain → use CI keys to access production.
  · Creative mode (when known combinations are exhausted): re-examine capability boundaries (read only /var/log? what about /proc/self/environ?) | find equivalent RCE sinks (writing crontab / .bashrc / CI config / LD_PRELOAD / authorized_keys / systemd units all = RCE) | use information (error messages / timing / response length) as side channels | invert assumptions: list the things you assumed were "impossible" and ask of each "why is it impossible?"
> A derived chain is a hypothesis (may be recorded as tentative note/chain). Only after actual execution with evidence should it become a confirmed Fact / record_vulnerability. The chain holds only when every step has been verified.
```
