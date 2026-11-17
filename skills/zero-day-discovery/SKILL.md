---
name: zero-day-discovery
description: >-
  Autonomous 0-day discovery engine: variant analysis / patch gaps / differential testing / fuzzing / taint reasoning / N-day weaponization / hunter mindset. Use when public vulnerabilities cannot be found and you need to discover a 0-day or weaponize an N-day.
metadata:
  tags: [penetration-testing, penetration-testing, red-team]
---

## Autonomous 0-Day Discovery Engine (when nothing public exists, find it yourself)

```
Core shift: from "matching against a known vulnerability database" → "understanding how the code/protocol works and inferring where it will break". A 0-day is not luck; it is method.
Five main paths:
  1. Variant analysis (most productive): take a CVE patch → distill the vulnerability pattern → grep the whole codebase for other places with the same pattern → those not covered by the patch = 0-day
  2. Patch gaps: read the patch's filtering logic; blacklists are almost always bypassable (missed encoding / equivalent function / alias) → new CVE
  3. Differential testing: two components interpret the same input differently (WAF vs backend / validator vs executor) → smuggling / SSRF bypass
  4. Fuzzing: write a harness (wrapping functions that handle untrusted input) + build corpora/dictionaries + crash triage (reproducible / controllable / exploitable)
     AFL++ / libFuzzer (coverage-guided memory corruption discovery) | boofuzz (protocols) | radamsa (black-box) | restler (REST API)
  5. Taint reasoning (strongest when source code is available): a source (parameter / header / deserialized field) reaching a sink (exec / SQL / template) without effective sanitization = 0-day
     Write CodeQL queries to automatically solve for reachable dataflow / Semgrep / Joern
N-day weaponization (advisory published but no PoC anywhere online): reconstruct the exploit from the patch diff (bindiff / diaphora binary comparison;
  vendor regression tests are often the rough shape of a PoC) → get it working in a local lab → then hit the target. Maximizes the vulnerability window; one of the most valuable red-team capabilities.
Hunter mindset (apply to any code / endpoint / protocol, interrogating layer by layer; every "yes" is a 0-day candidate):
  Trust boundaries: is the input really trusted? In what cases does that assumption fail? | State timing: can state change between two steps (TOCTOU)? Can the order be scrambled?
  Parsing and normalization: how many times is it parsed? Is normalization before or after validation? | Boundary extremes: negatives / 0 / very large values / type confusion / encodings / null bytes?
  Implicit capabilities: what does this feature "incidentally" give me? | Uniqueness: are IDs/tokens predictable? Is the "secret" really secret?
Break components down into an "assumption list" and break them one by one: a file upload implicitly assumes "only images are uploaded / extensions are trustworthy / filenames contain no paths / content is only data" → breaking each one = vulnerability; combining them = chain.
0-day verification (higher bar than a CVE): reproducible (minimal PoC) + clear root cause (which line / which assumption) + provable impact (actual read/write/execution) + false positives ruled out.
```
