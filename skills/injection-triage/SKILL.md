---
name: injection-triage
description: Confirm injection findings before reporting them, and kill false positives early
phase: detect
---

# Injection triage

A reflected payload is not a finding. A payload that changes the response in a way only
the payload could cause is.

## Confirmation matrix

| Class | Weak signal | Proof-grade signal |
| --- | --- | --- |
| SQL injection | generic error page | database error text quoting the payload, or boolean/time differential |
| Reflected XSS | payload appears in the body | payload appears unencoded inside an executable context (`<script>`, event handler, `javascript:`) |
| Command injection | `500` | output of `id`/`whoami`, or a delay equal to your `sleep` |
| SSRF | `400` | content from an internal address you control, or a DNS callback |
| Template injection | `500` | arithmetic evaluated (`49` for `7*7`), or template syntax echoed |
| Path traversal | `Error` | contents of a file you named |

## False-positive filters

1. Compare against a control request with a benign value of the same length.
2. Diff the two bodies. If the only difference is the payload echoed back verbatim, it is
   reflection, not injection.
3. Check the content type. `text/html` with the payload in the body is not enough: it must
   break out of the encoding context.
4. Rerun with an encoded variant (`%27` for `'`). A real SQL error appears for the raw
   quote and disappears when encoded.

## Choosing payloads

- One payload per family, then escalate only when the first one produced a signal.
- Keep payloads inert: no destructive SQL, no `rm`, no writes. `sleep`, `id`, and
  `7*7` are enough to prove impact.
- Never send a payload that could delete or lock data, even if the target looks like a lab.

## Recording

For each confirmed finding, capture the request line, the parameter, the response status,
and the substring in the response that only the payload explains. State the impact in one
sentence: what can an unauthenticated attacker do with this.
