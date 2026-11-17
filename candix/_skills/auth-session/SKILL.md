---
name: auth-session
description: Assess login, session and token handling without locking anyone out
phase: detect
---

# Authentication and session testing

## Login surface

- Confirm how the application reports failure. A different message for unknown user and
  wrong password is user enumeration; a different status code is a stronger version.
- Try five passwords against one account, then stop. Lockout policies matter more than
  brute force: check whether the sixth attempt returns `429` or a lock message.
- Check that the session id changes after login. A fixed session id is session fixation.

## Tokens

- Decode JWTs (base64 only, never verify with a leaked key). Note `alg`, `exp`, `aud`,
  `iss` and any role claim.
- Test `alg: none` and empty signature once. If the server accepts it, stop there: the
  finding is proven and further token forging adds nothing.
- Expired token replay: use a token with `exp` in the past. A `200` means expiry is not
  enforced.
- Cookies: check `HttpOnly`, `Secure`, `SameSite`. Missing `HttpOnly` on a session cookie
  is low on its own; combined with a confirmed XSS it becomes session theft.

## Password reset

- Submit a reset for your own account and inspect the link. A token in the query string,
  a predictable token, or a reset that accepts an arbitrary email are all reportable.
- Do not reset another user's password, even in a lab, unless the engagement says so.

## Recording

State the preconditions: which account, which role, whether the token was valid. A finding
that only reproduces with an admin account is usually not a finding.
