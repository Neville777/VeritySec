---
name: source-code-hunting
description: >-
  Source code hunting: .git exposure, dangerous function grep, JS RC4 deobfuscation, semgrep/CodeQL, trufflehog, patch diff, supply chain/CI. Use when hunting source leaks, secrets, JS deobfuscation, or supply-chain issues.
metadata:
  tags: [penetration-testing, penetration-testing, red-team]
---

## Source Code Hunting

```
=== Source code hunting ===
.git exposure: git-dumper → git log -p --all (sensitive files deleted in history) | .svn / .DS_Store / composer.lock
Dangerous function grep: exec / system / eval / unserialize / pickle.loads / render / curl_exec + hardcoded secrets (sk- / ghp_ / BEGIN RSA)
JS deobfuscation (RC4 + base64 string-array pattern): 1) extract the string array (var a0G=[...]) 2) locate the decode function (a0m(idx,key) → RC4 decrypt + base64) 3) find the rotation IIFE (target offset) 4) rebuild the decoder in Node.js to batch-decode all strings → recover plaintext variable names / API paths / configuration
  UniApp fingerprints: app-service.js (business logic, often 800KB+ and obfuscated) + zlsioh.dat (encrypted config, decrypted by a native .so) + dcloud_uniplugins.json (plugin manifest)
Static scanning: semgrep --config=auto for a quick scan / CodeQL: build a database and write queries (for taint solving and variant analysis methodology see `zero-day-discovery`)
Deep secrets hunting: trufflehog / gitleaks across full git history + docker image layers + npm/PyPI tarballs + frontend bundles (--only-verified to distinguish live from dead keys)
Framework patch diff: diff the versions before and after cloning → what was fixed = where the vulnerability is | dependency chain: composer.json / npm audit / pip-audit
Supply chain / CI: dependency confusion (register internal package names on public registries) | GHA command injection ${{github.event.issue.title}} | self-hosted runner takeover | .npmrc / .pypirc credentials
```
