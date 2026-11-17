---
name: evidence-capture
description: Capture exchanges that survive review, replay and a client's questions
phase: verify
---

# Evidence capture

Evidence is what turns a claim into a finding. Capture it while the request is in flight,
not from memory afterwards.

## Minimum for a finding

1. The full request: method, URL, headers that matter (auth context, content type),
   parameter names and the payload.
2. The response: status, relevant headers, and the substring that proves the effect.
3. The control: same request with a benign value, so the difference is visible.
4. Timestamps and the tool version, so a re-run can be compared.

## Redaction

Redact session cookies, bearer tokens and personal data before the evidence leaves the
process. Keep a hash of the raw exchange if the client needs to verify integrity later;
the evidence bundle stores a digest chain for exactly this reason.

## Replay

A replay script should be copy-pasteable and should fail loudly if the target changed.
Store it next to the finding, not inside the narrative:

```bash
curl -sS -X GET 'https://target/api/users?id=2' -H 'Authorization: Bearer $TOKEN'
```

## Quality checklist

- Would a reviewer reproduce this in under two minutes?
- Is the impact stated in terms of data or capability, not in terms of payloads?
- Is the control request included, and does it differ only in the parameter under test?
- Are timestamps present for anything time-sensitive (race conditions, rate limits)?
