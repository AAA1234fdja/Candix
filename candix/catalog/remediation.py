"""Remediation knowledge base.

Every finding is paired with concrete engineering guidance: what to change,
where, how to verify the fix and which references the owning team should read.
The text is intentionally specific - "sanitise input" is not a remediation.
References point at OWASP cheat sheets and CWE entries, which are stable and
vendor-neutral.
"""

from __future__ import annotations

from candix.core.finding import Remediation

_OWASP = "https://cheatsheetseries.owasp.org/cheatsheets"
_ASVS = "https://owasp.org/www-project-application-security-verification-standard/"

REMEDIATION: dict[str, Remediation] = {
    "sqli": Remediation(
        summary="Eliminate string concatenation in SQL by using parameterised queries everywhere.",
        steps=[
            "Replace dynamic SQL built with string concatenation or formatting with parameterised statements (PDO prepared statements, JDBC PreparedStatement, psycopg placeholders, ORM query builders with bound parameters).",
            "Parameterise every variable position, including ORDER BY and table names: use an allow-list of accepted column names instead of interpolating identifiers.",
            "Remove stacked-query support at the driver level where it is not required (for example PDO::ATTR_EMULATE_PREPARES=false and disabling multiple statements).",
            "Apply least privilege to the database account used by the application: no FILE, no xp_cmdshell, no DDL outside migrations.",
            "Add a WAF rule as defence in depth, never as the primary control.",
            "Enable detailed SQL error logging server-side and return generic errors to clients.",
        ],
        references=[
            f"{_OWASP}/SQL_Injection_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/89.html",
            f"{_ASVS}#v5-3-4",
        ],
        effort="medium",
        verification="Replay the original payload against the fixed endpoint and confirm it is stored/treated as a literal value; check query logs show bound parameters.",
        owner_hint="Backend engineering",
    ),
    "xss": Remediation(
        summary="Apply context-aware output encoding and remove unsafe DOM sinks.",
        steps=[
            "Encode all untrusted data on output using the correct context (HTML entity encoding, attribute encoding, JavaScript string encoding, URL encoding, CSS encoding).",
            "Use an auto-escaping template engine and never disable escaping with raw/nofilter helpers for user data.",
            "Sanitise rich-text input with a maintained allow-list library (DOMPurify or equivalent) on the client and again on the server before storage.",
            "Eliminate DOM sinks that execute strings (innerHTML, outerHTML, document.write, eval, setTimeout with strings); use textContent or safe DOM APIs.",
            "Deploy a strict Content-Security-Policy with nonces or hashes and no 'unsafe-inline'; enable Trusted Types where supported.",
            "Set HttpOnly and SameSite on session cookies to limit impact.",
        ],
        references=[
            f"{_OWASP}/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/79.html",
        ],
        effort="medium",
        verification="Re-send the payload and confirm it is encoded or rejected; verify the CSP header in a browser and check the console for violations.",
        owner_hint="Frontend and backend engineering",
    ),
    "ssti": Remediation(
        summary="Never render user input as a template; pass it as data instead.",
        steps=[
            "Separate template source from user input: templates must be files controlled by developers, and user values passed only as context variables.",
            "Disable dangerous template features (Jinja2 SandboxedEnvironment, Twig sandbox extension, FreeMarker TemplateClassResolver restrictions, Velocity secure uberspector).",
            "Reject or escape template delimiters in input before it reaches any templating layer.",
            "Run the rendering service with a low-privilege account and no access to secrets or cloud metadata endpoints.",
            "Add regression tests that assert a literal '{{7*7}}' renders as text, not 49.",
        ],
        references=[
            "https://portswigger.net/web-security/server-side-template-injection",
            "https://cwe.mitre.org/data/definitions/1336.html",
        ],
        effort="medium",
        verification="Send SSTI probes and confirm they are returned literally or rejected.",
        owner_hint="Backend engineering",
    ),
    "lfi": Remediation(
        summary="Stop deriving filesystem paths from user input; use opaque identifiers.",
        steps=[
            "Replace user-supplied filenames with server-side identifiers that map to a fixed allow-list of files.",
            "Normalise the resolved path (realpath) and verify it remains inside the intended base directory before any file operation.",
            "Reject path separators, null bytes and encoded traversal sequences; decode once and validate the result, not the raw input.",
            "Disable remote file inclusion and dangerous stream wrappers (allow_url_include=Off, restrict php:// and phar:// usage).",
            "Serve user-visible files from object storage with per-object authorization instead of local paths.",
        ],
        references=[
            f"{_OWASP}/File_Path_Traversal.html",
            "https://cwe.mitre.org/data/definitions/22.html",
            "https://cwe.mitre.org/data/definitions/98.html",
        ],
        effort="medium",
        verification="Replay traversal payloads and confirm they return 400/404 with no file content.",
        owner_hint="Backend engineering",
    ),
    "rce": Remediation(
        summary="Remove shell execution from the request path and validate every command argument.",
        steps=[
            "Replace shell invocations with library calls or the subprocess API using an argument vector (shell=False).",
            "If a command must run, build arguments from an allow-list of values and never concatenate user input into a command string.",
            "Run command-capable services in a sandbox with no network egress, read-only filesystem and a dedicated low-privilege account.",
            "Remove unused diagnostic endpoints (ping, nslookup, export, convert) from production builds.",
            "Add integrity monitoring and alert on unexpected child processes spawned by web workers.",
        ],
        references=[
            f"{_OWASP}/OS_Command_Injection_Defense_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/78.html",
        ],
        effort="high",
        verification="Replay the payload and confirm the marker is not echoed; check process accounting logs for child processes.",
        owner_hint="Backend and platform engineering",
    ),
    "ssrf": Remediation(
        summary="Constrain outbound requests with an allow-list and block internal address space.",
        steps=[
            "Do not accept arbitrary URLs from clients. If remote fetch is a feature, require an allow-list of destinations per tenant.",
            "Resolve the hostname once, validate every resolved IP against private, loopback, link-local and metadata ranges, and connect to that IP with the Host header preserved.",
            "Disable unused schemes (file, gopher, dict, ftp, ldap) and block redirects to disallowed destinations.",
            "Enforce IMDSv2 on AWS and equivalent protections on other clouds; block 169.254.169.254 at the network layer.",
            "Egress-filter the application subnet so it can only reach required services.",
        ],
        references=[
            f"{_OWASP}/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/918.html",
        ],
        effort="medium",
        verification="Replay SSRF payloads, including DNS-rebinding and decimal-IP variants, and confirm they are rejected before any connection.",
        owner_hint="Backend and network engineering",
    ),
    "xxe": Remediation(
        summary="Disable external entity processing and DTD support in every XML parser.",
        steps=[
            "Configure the parser to disallow DOCTYPE declarations and external entities (libxml2 XML_PARSE_NONET, Java FEATURE_SECURE_PROCESSING plus disallow-doctype-decl).",
            "Prefer JSON or a schema-validated, hardened parser for new interfaces.",
            "Reject requests whose body contains a DOCTYPE unless the contract explicitly needs it.",
            "Patch or replace libraries with known XXE issues and run dependency scanning.",
            "Restrict the service's filesystem and network access as defence in depth.",
        ],
        references=[
            f"{_OWASP}/XML_External_Entity_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/611.html",
        ],
        effort="low",
        verification="Send a DOCTYPE payload and confirm the parser rejects it or returns the entity name unresolved.",
        owner_hint="Backend engineering",
    ),
    "nosqli": Remediation(
        summary="Type-check query operators and never pass raw client JSON into query filters.",
        steps=[
            "Cast and validate every parameter to its expected scalar type before building the query.",
            "Reject object values where a scalar is expected; strip keys beginning with '$' from user-controlled documents.",
            "Use schema validation (JSON Schema, Mongoose strict schemas) and an allow-list of filterable fields.",
            "Disable server-side JavaScript execution in the database ($where, mapReduce) unless strictly required.",
            "Log and alert on queries containing operators that the API contract does not expose.",
        ],
        references=[
            "https://cwe.mitre.org/data/definitions/943.html",
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection",
        ],
        effort="medium",
        verification="Send operator-injection payloads and confirm they are rejected by validation.",
        owner_hint="Backend engineering",
    ),
    "ldap": Remediation(
        summary="Escape LDAP filter metacharacters and validate identifiers.",
        steps=[
            "Escape the characters \\ * ( ) NUL and / according to RFC 4515 before inserting values into filters.",
            "Reject inputs containing unbalanced parentheses or filter control characters.",
            "Use least-privilege bind accounts and disable anonymous bind.",
            "Prefer a directory API that takes structured filters over string assembly.",
        ],
        references=[
            f"{_OWASP}/LDAP_Injection_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/90.html",
        ],
        effort="low",
        verification="Send wildcard and filter-breaking payloads and confirm authentication is not bypassed.",
        owner_hint="Identity engineering",
    ),
    "xpath": Remediation(
        summary="Parameterise XPath queries or escape user input before interpolation.",
        steps=[
            "Use XPath variables (XPathExpression with a variable resolver) rather than string concatenation.",
            "If variables are unavailable, reject quotes and brackets in identifiers and validate against a strict pattern.",
            "Treat XPath results as untrusted and authorise per record.",
        ],
        references=[
            "https://cwe.mitre.org/data/definitions/643.html",
        ],
        effort="low",
        verification="Send quote-breaking payloads and confirm the query errors instead of returning data.",
        owner_hint="Backend engineering",
    ),
    "crlf": Remediation(
        summary="Strip CR/LF from header-bound values and let the framework build headers.",
        steps=[
            "Reject or encode CR, LF and percent-encoded equivalents in any value written to a response header or cookie.",
            "Use the framework's header APIs with validated values instead of manual string assembly.",
            "Disable response splitting-prone redirects that interpolate the Location from user input.",
            "Ensure the front-end proxy normalises or rejects bare LF in header values.",
        ],
        references=[
            "https://cwe.mitre.org/data/definitions/113.html",
            "https://cwe.mitre.org/data/definitions/93.html",
        ],
        effort="low",
        verification="Send encoded CRLF payloads and confirm no injected header appears.",
        owner_hint="Backend engineering",
    ),
    "open_redirect": Remediation(
        summary="Only redirect to relative paths or allow-listed hostnames.",
        steps=[
            "Accept a redirect target as a relative path and reject values containing a scheme, host or leading double slash.",
            "If external redirects are required, map an opaque key to a server-side allow-list of destinations.",
            "Resolve and compare the final host against an allow-list after URL parsing, not with string prefix checks.",
            "Do not reflect the target in the response body without escaping.",
        ],
        references=[
            f"{_OWASP}/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/601.html",
        ],
        effort="low",
        verification="Send absolute, protocol-relative and backslash variants and confirm the Location header stays on-site.",
        owner_hint="Backend engineering",
    ),
    "cors": Remediation(
        summary="Do not reflect arbitrary origins with credentials enabled.",
        steps=[
            "Return Access-Control-Allow-Origin only for origins on an explicit allow-list.",
            "Never combine Access-Control-Allow-Credentials: true with a reflected or wildcard origin.",
            "Validate the Origin header by exact string match after parsing, not with suffix checks such as .endswith('example.com').",
            "Restrict allowed methods and headers to those actually used.",
            "Add Vary: Origin to prevent cache poisoning of CORS responses.",
        ],
        references=[
            f"{_OWASP}/Cross-Origin_Resource_Sharing_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/942.html",
        ],
        effort="low",
        verification="Send an attacker Origin and confirm response does not echo it with credentials.",
        owner_hint="Backend and platform engineering",
    ),
    "headers": Remediation(
        summary="Add missing security headers and remove version-revealing ones.",
        steps=[
            "Add Content-Security-Policy, X-Content-Type-Options: nosniff, Referrer-Policy, Permissions-Policy and Strict-Transport-Security.",
            "Set frame protection (frame-ancestors in CSP or X-Frame-Options: DENY) for all authenticated pages.",
            "Remove Server, X-Powered-By and framework debug headers in production.",
            "Apply headers at the edge so they cannot be forgotten by individual services.",
            "Test with a header scanner after every deployment.",
        ],
        references=[
            f"{_OWASP}/HTTP_Headers_Cheat_Sheet.html",
            "https://securityheaders.com/",
        ],
        effort="low",
        verification="Re-fetch a response and compare headers against the baseline policy.",
        owner_hint="Platform engineering",
    ),
    "cookies": Remediation(
        summary="Harden session cookies with Secure, HttpOnly, SameSite and adequate entropy.",
        steps=[
            "Set Secure, HttpOnly and SameSite=Lax (or Strict) on every session cookie.",
            "Use the __Host- prefix for cookies that do not need a shared domain.",
            "Generate session identifiers with at least 128 bits of CSPRNG entropy; never derive them from user data or timestamps.",
            "Rotate the session identifier on login, privilege change and logout; expire idle sessions.",
            "Scope the cookie path narrowly and do not set Domain unless cross-subdomain sharing is required.",
        ],
        references=[
            f"{_OWASP}/Session_Management_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/614.html",
        ],
        effort="low",
        verification="Inspect Set-Cookie attributes and confirm identifiers change on login.",
        owner_hint="Backend engineering",
    ),
    "tls": Remediation(
        summary="Disable legacy TLS versions and weak ciphers; automate certificate renewal.",
        steps=[
            "Require TLS 1.2 or 1.3 and disable TLS 1.0/1.1, SSLv3, RC4, 3DES and export ciphers.",
            "Prefer AEAD cipher suites with forward secrecy (ECDHE + AES-GCM or ChaCha20-Poly1305).",
            "Enable HSTS with a long max-age and preload once the whole domain is HTTPS-only.",
            "Automate certificate issuance and renewal, and alert 30 days before expiry.",
            "Monitor the certificate transparency log for unexpected issuance.",
        ],
        references=[
            f"{_OWASP}/Transport_Layer_Security_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/326.html",
        ],
        effort="low",
        verification="Re-scan with an external TLS grader and confirm only 1.2/1.3 are offered.",
        owner_hint="Platform engineering",
    ),
    "idor": Remediation(
        summary="Authorise every object access server-side against the caller's identity.",
        steps=[
            "Enforce object-level authorisation on every read and write, not just at the route level.",
            "Replace sequential identifiers with unguessable ones (UUIDv4/ULID) where enumeration is a risk - but keep the authorisation check regardless.",
            "Derive the tenant or owner scope from the authenticated session, never from a client-supplied parameter.",
            "Return 404 rather than 403 for objects the caller may not know exist, to avoid enumeration oracles.",
            "Add automated tests that attempt cross-tenant access for each endpoint.",
        ],
        references=[
            f"{_OWASP}/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/639.html",
            f"{_ASVS}#v4-1-3",
        ],
        effort="medium",
        verification="Replay the request with a different user's session and confirm access is denied.",
        owner_hint="Backend engineering",
    ),
    "auth": Remediation(
        summary="Fix authentication logic: enumeration, weak credentials and missing lockout.",
        steps=[
            "Return identical responses and comparable timing for valid and invalid accounts.",
            "Enforce a strong password policy and check against breached-password corpora.",
            "Implement account lockout or progressive delays with alerting, keyed by account and by source IP.",
            "Require MFA for privileged and administrative accounts.",
            "Remove default accounts and force a credential change on first login.",
            "Use a vetted identity provider rather than bespoke credential handling where possible.",
        ],
        references=[
            f"{_OWASP}/Authentication_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/287.html",
            "https://cwe.mitre.org/data/definitions/307.html",
        ],
        effort="medium",
        verification="Re-run enumeration and brute-force checks and confirm uniform responses with lockout.",
        owner_hint="Identity engineering",
    ),
    "jwt": Remediation(
        summary="Verify JWT signatures correctly and pin the algorithm.",
        steps=[
            "Always verify the signature with a fixed algorithm allow-list; never accept 'none'.",
            "Do not trust the alg header to select the verification key; select the key by issuer and kid from a trusted store.",
            "Reject tokens whose iss, aud, exp, nbf or iat are missing or invalid.",
            "Use asymmetric keys for multi-service verification so the signing key never leaves the issuer.",
            "Keep token lifetimes short, rotate keys and support revocation for sensitive actions.",
        ],
        references=[
            f"{_OWASP}/JSON_Web_Token_for_Java_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/347.html",
        ],
        effort="medium",
        verification="Replay tokens with modified alg, signature and claims and confirm rejection.",
        owner_hint="Identity engineering",
    ),
    "ratelimit": Remediation(
        summary="Add rate limiting and anti-automation controls on sensitive endpoints.",
        steps=[
            "Apply per-IP, per-account and per-token rate limits with a shared store across instances.",
            "Return 429 with Retry-After and log repeated violations.",
            "Require CAPTCHA or proof-of-work for authentication, registration and password reset after a low threshold.",
            "Use constant-time comparisons and uniform error messages to avoid timing oracles.",
            "Alert on distributed attempts that stay under per-IP thresholds.",
        ],
        references=[
            f"{_OWASP}/Denial_of_Service_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/307.html",
        ],
        effort="low",
        verification="Replay the burst and confirm 429 responses after the configured threshold.",
        owner_hint="Platform engineering",
    ),
    "dirlisting": Remediation(
        summary="Disable directory listing and remove stray files from the web root.",
        steps=[
            "Disable auto-indexing in the web server (Options -Indexes, autoindex off).",
            "Deny requests to dotfiles, backup patterns and configuration extensions at the edge.",
            "Deploy build artifacts outside the document root and use a deployment manifest.",
            "Add a catch-all route that returns 404 for unknown paths.",
        ],
        references=[
            "https://cwe.mitre.org/data/definitions/548.html",
            "https://cwe.mitre.org/data/definitions/538.html",
        ],
        effort="low",
        verification="Request the directory and common backup names and confirm 404/403.",
        owner_hint="Platform engineering",
    ),
    "backup": Remediation(
        summary="Remove backup, source and VCS artifacts from production.",
        steps=[
            "Block .git, .svn, .env, *.bak, *.old, *.sql and archive extensions at the reverse proxy.",
            "Store backups encrypted outside the web root with access controlled by IAM.",
            "Add a pre-deploy check and CI rule that fails if such files exist in the artifact.",
            "Rotate any secret that was exposed by an accessible backup or .env file.",
        ],
        references=[
            "https://cwe.mitre.org/data/definitions/538.html",
            "https://cwe.mitre.org/data/definitions/552.html",
        ],
        effort="low",
        verification="Re-request the discovered paths and confirm they no longer resolve.",
        owner_hint="Platform engineering",
    ),
    "defaultcreds": Remediation(
        summary="Remove default credentials and enforce unique secrets per deployment.",
        steps=[
            "Force a credential change during first boot and refuse to start with vendor defaults.",
            "Generate per-instance random administrative passwords and store them in a secrets manager.",
            "Restrict administrative interfaces to a management network or VPN.",
            "Add MFA and audit logging to administrative consoles.",
        ],
        references=[
            "https://cwe.mitre.org/data/definitions/1392.html",
            "https://cwe.mitre.org/data/definitions/798.html",
        ],
        effort="medium",
        verification="Attempt default credentials again and confirm lockout or rejection.",
        owner_hint="Platform engineering",
    ),
    "info": Remediation(
        summary="Remove verbose errors, stack traces and version banners from production responses.",
        steps=[
            "Return generic error pages with a correlation id; log details server-side only.",
            "Disable debug mode and framework developer pages in production configuration.",
            "Strip Server, X-Powered-By, X-AspNet-Version and similar headers at the edge.",
            "Review the API for fields that leak internal identifiers, password hashes or tokens.",
        ],
        references=[
            "https://cwe.mitre.org/data/definitions/209.html",
            "https://cwe.mitre.org/data/definitions/200.html",
        ],
        effort="low",
        verification="Trigger an error and confirm the response contains no stack trace or version.",
        owner_hint="Backend engineering",
    ),
    "graphql": Remediation(
        summary="Disable introspection in production and enforce per-field authorisation.",
        steps=[
            "Disable introspection and the GraphQL playground in production builds.",
            "Enforce query depth, complexity and alias limits and reject batched abusive queries.",
            "Authorise each resolver against the caller's identity and tenant, not just the top-level query.",
            "Require persisted queries or an allow-list for public APIs.",
            "Log and alert on unusual introspection or field enumeration patterns.",
        ],
        references=[
            f"{_OWASP}/GraphQL_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/200.html",
        ],
        effort="medium",
        verification="Re-send the introspection query and confirm it is disabled.",
        owner_hint="Backend engineering",
    ),
    "hostheader": Remediation(
        summary="Validate the Host header against a fixed allow-list.",
        steps=[
            "Configure the web server or framework with a canonical host allow-list and reject others with 400.",
            "Never build password-reset links or absolute URLs from the request Host header.",
            "Do not trust X-Forwarded-Host unless it is set by a trusted proxy that overwrites client values.",
            "Disable absolute-URI routing at the edge if it is not required.",
        ],
        references=[
            "https://cwe.mitre.org/data/definitions/644.html",
            "https://portswigger.net/web-security/host-header",
        ],
        effort="low",
        verification="Send spoofed Host and X-Forwarded-Host values and confirm rejection or canonical redirect.",
        owner_hint="Platform engineering",
    ),
    "cache": Remediation(
        summary="Do not cache responses influenced by unkeyed input.",
        steps=[
            "Include every input that affects the response in the cache key (Vary or explicit key).",
            "Disable caching on authenticated responses and on responses that reflect headers or query parameters.",
            "Normalise and validate X-Forwarded-* and other routing headers at the edge.",
            "Use cache-busting tests in CI for pages that mix public and private content.",
        ],
        references=[
            "https://cwe.mitre.org/data/definitions/524.html",
            "https://portswigger.net/web-security/web-cache-poisoning",
        ],
        effort="medium",
        verification="Send a poisoned request, then a clean request, and confirm the clean response is unaffected.",
        owner_hint="Platform engineering",
    ),
    "smuggling": Remediation(
        summary="Normalise request framing and reject ambiguous messages at the edge.",
        steps=[
            "Use a single HTTP parser between the edge and the origin, or ensure both agree on Content-Length and Transfer-Encoding handling.",
            "Reject requests that contain both Transfer-Encoding and Content-Length, or with obfuscated Transfer-Encoding values.",
            "Enable HTTP/2 end-to-end where possible and downgrade safely.",
            "Patch proxy and origin server versions with known smuggling defects.",
        ],
        references=[
            "https://portswigger.net/web-security/request-smuggling",
            "https://cwe.mitre.org/data/definitions/444.html",
        ],
        effort="high",
        verification="Replay desync probes and confirm the edge normalises or rejects them.",
        owner_hint="Platform and network engineering",
    ),
    "massassign": Remediation(
        summary="Bind only explicitly allowed fields from request bodies.",
        steps=[
            "Use explicit DTOs or allow-lists of writable fields per role; never bind the raw request body to a model.",
            "Block server-controlled fields (role, isAdmin, tenantId, balance) from client input.",
            "Add validation and reject unknown fields instead of ignoring them.",
            "Test privilege escalation by submitting administrative properties with a low-privilege token.",
        ],
        references=[
            "https://cwe.mitre.org/data/definitions/915.html",
            f"{_OWASP}/Mass_Assignment_Cheat_Sheet.html",
        ],
        effort="medium",
        verification="Submit protected fields and confirm they are ignored or rejected.",
        owner_hint="Backend engineering",
    ),
    "websocket": Remediation(
        summary="Authenticate the WebSocket handshake and validate every message.",
        steps=[
            "Verify Origin and session on the upgrade request; do not rely on network location.",
            "Authorise each message action against the user and resource.",
            "Validate message size, schema and rate; close connections on violations.",
            "Use wss:// exclusively and set short-lived, scoped tokens for the handshake.",
        ],
        references=[
            "https://cwe.mitre.org/data/definitions/1385.html",
            f"{_OWASP}/WebSocket_Security_Cheat_Sheet.html",
        ],
        effort="medium",
        verification="Attempt cross-origin and unauthorised message actions and confirm rejection.",
        owner_hint="Backend engineering",
    ),
    "apikey": Remediation(
        summary="Remove API keys from client-facing bundles and public repositories.",
        steps=[
            "Revoke and rotate every key found in responses, scripts or repositories.",
            "Move privileged calls behind a backend-for-frontend that holds the key server-side.",
            "Scope keys to the minimum permissions and restrict by referrer/IP where supported.",
            "Add secret scanning with pre-commit hooks and CI, and alert on new exposures.",
        ],
        references=[
            "https://cwe.mitre.org/data/definitions/798.html",
            "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
        ],
        effort="low",
        verification="Confirm the key is revoked and no longer present in delivered assets.",
        owner_hint="Platform engineering",
    ),
    "csp": Remediation(
        summary="Deploy a restrictive Content-Security-Policy without unsafe-inline.",
        steps=[
            "Start with a report-only policy, collect violations, then enforce.",
            "Use per-response nonces or hashes for scripts; remove inline event handlers.",
            "Restrict default-src to 'self' and explicitly allow required third parties.",
            "Add frame-ancestors 'none' and object-src 'none'.",
            "Monitor CSP reports for regressions and bypass attempts.",
        ],
        references=[
            f"{_OWASP}/Content_Security_Policy_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/693.html",
        ],
        effort="medium",
        verification="Load the page with the policy enforced and confirm no console violations and no unsafe-inline.",
        owner_hint="Frontend and platform engineering",
    ),
    "csrf": Remediation(
        summary="Require anti-CSRF tokens or SameSite cookies for state-changing requests.",
        steps=[
            "Set SameSite=Lax or Strict on session cookies and use the __Host- prefix.",
            "Require a per-session, unpredictable anti-CSRF token on all state-changing requests, validated server-side.",
            "Verify the Origin and Referer headers for sensitive actions as defence in depth.",
            "Never accept state changes over GET; require POST/PUT/PATCH with JSON content type.",
            "Do not exempt API endpoints from CSRF protection based on path alone.",
        ],
        references=[
            f"{_OWASP}/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/352.html",
        ],
        effort="low",
        verification="Replay a state-changing request without the token and confirm rejection.",
        owner_hint="Backend engineering",
    ),
    "clickjacking": Remediation(
        summary="Prevent framing of sensitive pages.",
        steps=[
            "Send Content-Security-Policy: frame-ancestors 'none' (or an explicit allow-list).",
            "Keep X-Frame-Options: DENY for legacy browser coverage.",
            "Do not rely on JavaScript frame-busting.",
            "Apply the header globally, including error and login pages.",
        ],
        references=[
            f"{_OWASP}/Clickjacking_Defense_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/1021.html",
        ],
        effort="low",
        verification="Attempt to frame the page and confirm the browser blocks it.",
        owner_hint="Platform engineering",
    ),
    "takeover": Remediation(
        summary="Remove dangling DNS records that point at deprovisioned services.",
        steps=[
            "Delete CNAME/A records whose targets are no longer owned or provisioned.",
            "Maintain an inventory that links DNS records to owning teams and cloud resources.",
            "Claim the dangling resource name defensively if the record must remain.",
            "Monitor certificate transparency and DNS changes for reclaimed names.",
        ],
        references=[
            "https://cwe.mitre.org/data/definitions/350.html",
            "https://owasp.org/www-community/attacks/Subdomain_takeover",
        ],
        effort="low",
        verification="Resolve the record and confirm it no longer points to an unclaimed service.",
        owner_hint="Network engineering",
    ),
    "metadata": Remediation(
        summary="Block access to cloud instance metadata from application workloads.",
        steps=[
            "Enforce IMDSv2 with a hop limit of 1 on AWS and equivalent controls on other providers.",
            "Add network policies that deny 169.254.169.254 from application pods except the metadata proxy.",
            "Use workload identity instead of long-lived credentials in the environment.",
            "For SSRF-capable features, validate destinations against a deny-list that includes metadata endpoints.",
        ],
        references=[
            "https://cwe.mitre.org/data/definitions/918.html",
            "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",
        ],
        effort="medium",
        verification="From the workload, attempt metadata access and confirm it is blocked.",
        owner_hint="Cloud platform engineering",
    ),
    "deserialization": Remediation(
        summary="Do not deserialise untrusted data with native object formats.",
        steps=[
            "Replace native serialisation (Java ObjectInputStream, PHP unserialize, Python pickle, .NET BinaryFormatter) with JSON and schema validation.",
            "If native formats are unavoidable, enforce a class allow-list and integrity checks (HMAC) on the serialised payload.",
            "Keep deserialisation libraries patched and enable runtime protections where available.",
            "Run services handling untrusted serialised data with minimal privileges and no network egress.",
        ],
        references=[
            f"{_OWASP}/Deserialization_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/502.html",
        ],
        effort="high",
        verification="Submit a crafted serialised object and confirm it is rejected before instantiation.",
        owner_hint="Backend engineering",
    ),
    "protopollution": Remediation(
        summary="Reject __proto__ and constructor keys and freeze object prototypes.",
        steps=[
            "Validate and sanitise keys during recursive merges; drop __proto__, prototype and constructor.",
            "Use Object.create(null) or Map for user-controlled dictionaries.",
            "Freeze Object.prototype in environments that support it and keep libraries patched.",
            "Add tests with prototype-polluting JSON payloads.",
        ],
        references=[
            "https://cwe.mitre.org/data/definitions/1321.html",
            "https://portswigger.net/web-security/prototype-pollution",
        ],
        effort="medium",
        verification="Submit the pollution payload and confirm no global property changes.",
        owner_hint="Frontend and backend engineering",
    ),
    "fileupload": Remediation(
        summary="Validate uploads by content, randomise names and serve from an isolated origin.",
        steps=[
            "Validate file type by magic bytes and re-encode images; do not trust Content-Type or the filename extension.",
            "Store uploads outside the web root with random names and no executable permission.",
            "Serve user content from a separate domain with Content-Disposition: attachment and a restrictive CSP.",
            "Enforce size limits and scan for malware.",
            "Require authorisation on download and never expose direct filesystem paths.",
        ],
        references=[
            f"{_OWASP}/File_Upload_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/434.html",
        ],
        effort="medium",
        verification="Upload a polyglot or executable payload and confirm it is rejected or neutralised.",
        owner_hint="Backend engineering",
    ),
    "business_logic": Remediation(
        summary="Enforce workflow and value constraints on the server.",
        steps=[
            "Recompute prices, totals and eligibility server-side from trusted data.",
            "Enforce state machines for multi-step flows and reject out-of-order transitions.",
            "Apply per-account and per-resource limits to prevent abuse.",
            "Add idempotency keys and audit trails for financial operations.",
        ],
        references=[
            "https://cwe.mitre.org/data/definitions/840.html",
            "https://owasp.org/www-project-top-ten/2017/A4_2017-Broken_Access_Control",
        ],
        effort="high",
        verification="Replay the manipulated flow and confirm the server rejects or recalculates the value.",
        owner_hint="Product and backend engineering",
    ),
    "logging": Remediation(
        summary="Add security logging, monitoring and alerting for the tested surface.",
        steps=[
            "Log authentication, authorisation, administrative and input-validation failures with correlation ids.",
            "Never log secrets, tokens or full personal data; redact at the logger boundary.",
            "Ship logs to an append-only, access-controlled store with retention aligned to policy.",
            "Alert on spikes of 401/403/429 and on error signatures that indicate injection attempts.",
        ],
        references=[
            f"{_OWASP}/Logging_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/778.html",
        ],
        effort="medium",
        verification="Trigger a denied action and confirm the event appears in the SIEM with the required fields.",
        owner_hint="Security operations",
    ),
    "dependency": Remediation(
        summary="Patch or replace vulnerable software components.",
        steps=[
            "Identify the exact version from banners or static analysis and confirm the vulnerable range.",
            "Upgrade to a fixed version, or apply the vendor mitigation if an upgrade is not yet possible.",
            "Add the component to continuous dependency scanning with an SLA based on severity.",
            "Remove unused components and administrative interfaces from production.",
        ],
        references=[
            "https://owasp.org/www-project-top-ten/2017/A9_2017-Using_Components_with_Known_Vulnerabilities",
            "https://cwe.mitre.org/data/definitions/1104.html",
        ],
        effort="medium",
        verification="Re-fingerprint the component and confirm the fixed version or mitigation is active.",
        owner_hint="Platform engineering",
    ),
    "misconfig": Remediation(
        summary="Harden the service configuration to the vendor baseline.",
        steps=[
            "Apply the vendor hardening guide and the CIS benchmark for the deployed version.",
            "Disable sample applications, default pages and unused modules.",
            "Restrict administrative interfaces by network and require strong authentication.",
            "Store configuration in version control with review, and detect drift in production.",
        ],
        references=[
            "https://www.cisecurity.org/cis-benchmarks",
            "https://cwe.mitre.org/data/definitions/16.html",
        ],
        effort="medium",
        verification="Re-run the configuration checks and confirm deviations are resolved.",
        owner_hint="Platform engineering",
    ),
    "general": Remediation(
        summary="Validate input on the server, encode output and apply least privilege.",
        steps=[
            "Treat all client input as untrusted and validate against an allow-list of expected values.",
            "Encode data for its output context and avoid dynamic code or query construction.",
            "Run the component with the least privilege required and log security-relevant events.",
            "Add an automated regression test for the exact issue before closing it.",
        ],
        references=[
            "https://owasp.org/www-project-application-security-verification-standard/",
            "https://cwe.mitre.org/",
        ],
        effort="medium",
        verification="Reproduce the original proof of concept and confirm it no longer succeeds.",
        owner_hint="Engineering",
    ),
}

_ALIASES: dict[str, str] = {
    "sql-injection": "sqli",
    "sql_injection": "sqli",
    "cross-site scripting": "xss",
    "xss_reflected": "xss",
    "xss_stored": "xss",
    "xss_dom": "xss",
    "command-injection": "rce",
    "command_injection": "rce",
    "code-execution": "rce",
    "path-traversal": "lfi",
    "directory-traversal": "lfi",
    "file-inclusion": "lfi",
    "authentication": "auth",
    "authorization": "idor",
    "access-control": "idor",
    "security-headers": "headers",
    "tls-config": "tls",
    "ssl": "tls",
    "information-disclosure": "info",
    "dir-listing": "dirlisting",
    "directory-listing": "dirlisting",
    "default-credentials": "defaultcreds",
    "weak-password": "auth",
    "open-redirect": "open_redirect",
    "host-header": "hostheader",
    "cache-poisoning": "cache",
    "request-smuggling": "smuggling",
    "mass-assignment": "massassign",
    "prototype-pollution": "protopollution",
    "deserialization": "deserialization",
    "api-key": "apikey",
    "subdomain-takeover": "takeover",
    "cloud-metadata": "metadata",
    "file-upload": "fileupload",
    "business-logic": "business_logic",
    "missing-headers": "headers",
    "weak-tls": "tls",
    "cors-misconfiguration": "cors",
    "nosql-injection": "nosqli",
    "xxe": "xxe",
}


def remediation_for(key: str) -> Remediation:
    """Look up remediation by category, alias or CWE identifier."""

    if not key:
        return REMEDIATION["general"]
    normalized = key.strip().lower().replace(" ", "_")
    if normalized in REMEDIATION:
        return REMEDIATION[normalized]
    alias = _ALIASES.get(normalized) or _ALIASES.get(key.strip().lower())
    if alias and alias in REMEDIATION:
        return REMEDIATION[alias]
    if normalized.startswith("cwe-"):
        return REMEDIATION["general"]
    return REMEDIATION["general"]


def categories() -> list[str]:
    return sorted(REMEDIATION)
