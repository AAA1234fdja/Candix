---
name: report-writing
description: Write findings a client can triage, fix and close without a call
phase: report
---

# Report writing

## Structure per finding

1. **Title**: the weakness and where, in one line. `Reflected XSS in /search via q`.
2. **Severity and confidence**: severity reflects impact, confidence reflects evidence.
3. **Impact**: what an attacker gains. Two sentences maximum.
4. **Evidence**: the request, the response fragment, the control.
5. **Remediation**: the specific fix, not "sanitize input".
6. **References**: CWE and OWASP category when they add information.

## Language that helps

- "An unauthenticated attacker can read any user's profile by changing `id`" beats
  "IDOR vulnerability found".
- Quantify: "all 12 sampled ids were readable" is stronger than "ids are readable".
- Separate observation from inference: "the response contained the full record" is an
  observation; "the database is shared with billing" is an inference.

## What to leave out

- Tool names as the source of truth. The evidence is the source of truth.
- Payload dumps longer than one line.
- Speculation about internal infrastructure that the evidence does not support.

## Executive summary

Three paragraphs: what was tested, what matters most, what to do first. If the client reads
only this page, they should still know their top risk and the next action.
