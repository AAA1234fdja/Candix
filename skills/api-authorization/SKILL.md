---
name: api-authorization
description: Test object and function level authorization on JSON APIs without breaking data
phase: detect
---

# API authorization testing

Object-level authorization (IDOR/BOLA) is the most common serious API issue and the
easiest to get wrong when an agent moves fast. Work through this list in order.

## 1. Establish the identity baseline

- Fetch two resources that belong to you and compare their ids. If ids are sequential
  integers or short slugs, note the pattern before sending anything else.
- Record the exact request that succeeds: method, path, headers, cookies, body.
- If the API returns `401` for a missing token and `403` for a foreign token, the check
  exists at the function level. If it returns `200` for both, you have a finding.

## 2. Enumerate reachable ids

Send a small batch (3 to 5) of neighbouring ids with the same credentials. Stop at the
first foreign object you can read and store that exchange as evidence. Do not enumerate
the whole space: one reproducible read is enough to prove impact.

## 3. Compare error shapes

| Response difference | Meaning |
| --- | --- |
| `404` for missing, `200` for foreign | no ownership check |
| `403` for foreign | check present, keep looking elsewhere |
| `200` with empty body | filter present, try a write verb |
| `500` on foreign id | query built without ownership scope |

## 4. Move from read to write only with approval

A write proof (`PUT`/`PATCH`/`DELETE` on a foreign object) is stronger but mutates data.
Request approval, use a record you created yourself, and reverse the change.

## 5. What to record

- The two ids and the two responses (yours and the foreign one).
- The status codes plus the first 200 bytes of the body.
- A one-sentence impact statement: what an attacker with a normal account can read or
  change that belongs to another tenant.

## Common traps

- Testing with an admin token and calling it IDOR.
- Treating a `200` with the caller's own data as a bypass: check the payload contents.
- Forgetting `X-HTTP-Method-Override` and `X-Original-URL` style headers on proxies.
