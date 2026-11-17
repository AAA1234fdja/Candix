---
name: secret-exposure
description: Find exposed files and credentials, then prove the exposure without using the secret
phase: recon
---

# Secret exposure

The finding is the exposure, not the secret. You do not need to authenticate with a leaked
key to prove that it is public.

## High-value paths

Check these with a single `GET` each; they are cheap and almost always forgotten:

- `/.git/config`, `/.git/HEAD`, `/.svn/entries`, `/.hg/`
- `/.env`, `/.env.local`, `/.env.production`, `/.env.backup`
- `/config.json`, `/settings.py`, `/wp-config.php.bak`, `/web.config`
- `/backup.zip`, `/db.sql`, `/dump.sql`, `/site.tar.gz`
- `/server-status`, `/phpinfo.php`, `/.DS_Store`, `/.aws/credentials`
- `/.well-known/security.txt` (not a finding, but shows what they publish)

## Rules

1. Record the status code, content length and a short fingerprint of the body:
   for `.env`, the first key name is enough; never paste the values.
2. Redact the secret in the report. `AWS_ACCESS_KEY_ID=AKIA...REDACTED` proves the point.
3. Do not use the credential. Using it turns a confidentiality finding into an
   unauthorized access incident.
4. Score by what the file gives access to, not by file size. A `.env` with a database URL
   is critical; a `.git/config` alone is usually low unless the repository is private and
   the objects are downloadable.

## Verifying git exposure

- `/.git/HEAD` returning `ref: refs/heads/main` confirms a readable repository.
- Fetching `/.git/config` confirms the remote URL.
- Only if both succeed should you mention that source code may be recoverable; do not
  reconstruct the repository.
