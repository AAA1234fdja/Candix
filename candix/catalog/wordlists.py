"""Built-in wordlists for content discovery and credential testing.

These lists are curated rather than exhaustive: the goal is to find the paths and
parameters that most often expose real weaknesses without generating thousands
of 404s. Operators can point Candix at their own list with ``--wordlist``.
"""

from __future__ import annotations

DIRECTORIES: tuple[str, ...] = (
    "admin", "administrator", "admin.php", "admin/", "login", "logout", "signin", "signup",
    "register", "account", "accounts", "profile", "user", "users", "dashboard", "panel",
    "console", "manage", "management", "manager", "control", "cpanel", "webadmin",
    "api", "api/v1", "api/v2", "api/v3", "api/internal", "api/admin", "api/users", "api/data",
    "rest", "graphql", "graphiql", "swagger", "swagger-ui", "openapi", "docs", "documentation",
    "api-docs", "redoc", "health", "healthz", "readyz", "status", "ping", "version", "info",
    "metrics", "stats", "debug", "trace", "test", "tests", "dev", "staging", "internal",
    "private", "secure", "hidden", "backup", "backups", "bak", "old", "tmp", "temp", "cache",
    "files", "file", "uploads", "upload", "download", "downloads", "media", "assets", "static",
    "public", "images", "img", "css", "js", "scripts", "fonts", "config", "conf", "settings",
    "env", "environment", "secrets", "keys", "certs", "logs", "log", "data", "db", "database",
    "sql", "dump", "export", "import", "migrate", "install", "setup", "upgrade", "update",
    "phpinfo.php", "info.php", "server-status", "server-info", "nginx_status", "actuator",
    "actuator/health", "actuator/env", "actuator/mappings", "actuator/beans", "actuator/configprops",
    "console/login", "jolokia", "solr", "elasticsearch", "_search", "kibana", "grafana",
    "jenkins", "gitlab", "jira", "confluence", "nexus", "artifactory", "sonar", "prometheus",
    "webmail", "mail", "smtp", "ftp", "ssh", "vpn", "proxy", "gateway", "auth", "oauth",
    "oauth2", "sso", "saml", "callback", "redirect", "return", "logout", "reset", "forgot",
    "password", "passwords", "invite", "verify", "confirm", "activate", "unsubscribe",
    "search", "results", "query", "filter", "list", "items", "catalog", "products", "product",
    "order", "orders", "cart", "checkout", "payment", "invoice", "invoices", "billing",
    "report", "reports", "analytics", "track", "tracking", "webhook", "webhooks", "callback",
    "internal/metadata", "metadata", "instance", "cloud", "aws", "gcp", "azure",
    "fetch", "ping", "render", "proxy", "preview", "export", "report/export", "curl",
    "tools", "utils", "utility", "convert", "thumbnail", "resize", "validate",
    "webhook/test", "email/test", "sms", "notify", "invite/accept", "auth/callback",
)

FILES: tuple[str, ...] = (
    ".git/config", ".git/HEAD", ".git/index", ".git/logs/HEAD", ".gitignore",
    ".svn/entries", ".svn/wc.db", ".hg/requires", ".bzr/README",
    ".env", ".env.local", ".env.production", ".env.backup", ".env.example",
    "config.php", "config.php.bak", "config.php~", "config.inc.php", "configuration.php",
    "wp-config.php", "wp-config.php.bak", "settings.py", "settings.py.bak", "local_settings.py",
    "application.yml", "application.properties", "appsettings.json", "web.config",
    "composer.json", "composer.lock", "package.json", "package-lock.json", "yarn.lock",
    "Gemfile", "Gemfile.lock", "requirements.txt", "Pipfile", "go.mod", "pom.xml",
    "backup.zip", "backup.tar.gz", "backup.tar", "backup.sql", "backup.rar", "site.zip",
    "db.sql", "dump.sql", "database.sql", "data.sql", "export.sql", "backup/db.sql",
    "phpinfo.php", "info.php", "test.php", "debug.php", "shell.php", "cmd.php",
    ".DS_Store", "Thumbs.db", "robots.txt", "sitemap.xml", "crossdomain.xml", "clientaccesspolicy.xml",
    "security.txt", ".well-known/security.txt", "humans.txt", "CHANGELOG.md", "README.md",
    "swagger.json", "swagger.yaml", "openapi.json", "openapi.yaml", "api-docs.json",
    "server-status", "server-info", "nginx_status", "actuator", "actuator/env", "actuator/health",
    "graphql", "graphiql", "metrics", "health", "version", "status", "debug", "console",
    "trace", "heapdump", "threaddump", "env", "config", "secrets", "keys", "id_rsa",
    "id_rsa.pub", "credentials", "credentials.json", "service-account.json", "firebase.json",
)

PARAMETERS: tuple[str, ...] = (
    "id", "user_id", "account_id", "order_id", "item_id", "product_id", "file_id", "post_id",
    "q", "query", "search", "keyword", "term", "name", "username", "email", "user", "login",
    "page", "limit", "offset", "size", "count", "start", "end", "sort", "order", "dir", "asc",
    "file", "filename", "path", "folder", "document", "template", "include", "require", "page",
    "url", "uri", "link", "src", "source", "target", "dest", "destination", "redirect", "next",
    "return", "returnUrl", "continue", "callback", "callbackUrl", "host", "domain", "site",
    "cmd", "command", "exec", "execute", "run", "shell", "ping", "ip", "address", "port",
    "debug", "test", "trace", "log", "verbose", "format", "output", "type", "mode", "action",
    "method", "func", "function", "op", "operation", "api_key", "apikey", "key", "token",
    "access_token", "auth", "authorization", "session", "sid", "csrf", "lang", "language",
    "locale", "timezone", "theme", "view", "layout", "style", "version", "v", "t", "cache",
    "nocache", "raw", "download", "preview", "admin", "role", "is_admin", "status", "active",
)

SUBDOMAINS: tuple[str, ...] = (
    "www", "api", "app", "apps", "admin", "administrator", "portal", "dashboard", "console",
    "manage", "management", "internal", "intranet", "extranet", "vpn", "remote", "gateway",
    "auth", "sso", "login", "id", "identity", "accounts", "account", "secure", "ssl", "tls",
    "mail", "webmail", "smtp", "imap", "pop", "mx", "email", "newsletter", "lists",
    "dev", "development", "staging", "stage", "test", "testing", "qa", "uat", "preprod",
    "sandbox", "demo", "beta", "alpha", "canary", "preview", "prod", "production", "live",
    "cdn", "static", "assets", "media", "images", "img", "files", "download", "uploads",
    "docs", "documentation", "wiki", "help", "support", "status", "monitoring", "metrics",
    "grafana", "prometheus", "kibana", "elastic", "logs", "log", "sentry", "jenkins", "ci",
    "build", "git", "gitlab", "github", "bitbucket", "jira", "confluence", "nexus", "registry",
    "docker", "k8s", "kubernetes", "rancher", "consul", "vault", "db", "database", "mysql",
    "postgres", "redis", "mongo", "cache", "queue", "mq", "kafka", "storage", "backup",
    "s3", "bucket", "assets-cdn", "img-cdn", "video", "stream", "api-v1", "api-v2", "rest",
    "graphql", "ws", "websocket", "socket", "push", "notify", "webhooks", "partner", "partners",
    "affiliate", "billing", "pay", "payments", "checkout", "shop", "store", "cart", "orders",
    "crm", "erp", "hr", "finance", "legal", "compliance", "security", "trust", "privacy",
    "careers", "jobs", "blog", "news", "press", "events", "community", "forum", "feedback",
)

USERS: tuple[str, ...] = (
    "admin", "administrator", "root", "user", "test", "guest", "demo", "dev", "developer",
    "support", "helpdesk", "info", "sales", "marketing", "operator", "manager", "supervisor",
    "service", "system", "backup", "postgres", "mysql", "oracle", "redis", "ftp", "ubuntu",
    "deploy", "jenkins", "gitlab", "tomcat", "weblogic", "apache", "nginx", "www-data",
)

PASSWORDS: tuple[str, ...] = (
    "admin", "password", "123456", "12345678", "123456789", "qwerty", "letmein", "welcome",
    "changeme", "secret", "admin123", "password123", "root", "toor", "test", "guest",
    "demo", "default", "pass", "P@ssw0rd", "Passw0rd!", "administrator", "adminadmin",
    "company", "support", "service", "system", "manager", "summer2024", "winter2024",
)


def directory_wordlist(include_extensions: bool = False, extensions: tuple[str, ...] = (".php", ".bak", ".old", ".json")) -> list[str]:
    entries = list(DIRECTORIES)
    if include_extensions:
        for entry in DIRECTORIES[:80]:
            if "." in entry or entry.endswith("/"):
                continue
            for extension in extensions:
                entries.append(entry + extension)
    return list(dict.fromkeys(entries))


DOTFILES: tuple[str, ...] = (
    ".env", ".env.local", ".env.production", ".env.development", ".env.backup", ".env.old",
    ".env.example", ".git/config", ".git/HEAD", ".gitignore", ".svn/entries", ".hg/requires",
    ".DS_Store", ".htaccess", ".htpasswd", ".dockerignore", ".npmrc", ".aws/credentials",
    ".well-known/security.txt", "sitemap.xml", "robots.txt",
)


def file_wordlist(*, include_dotfiles: bool = True) -> list[str]:
    entries = list(FILES)
    if include_dotfiles:
        entries.extend(entry for entry in DOTFILES if entry not in entries)
    return list(dict.fromkeys(entries))


def parameter_wordlist() -> list[str]:
    return list(PARAMETERS)


def subdomain_wordlist() -> list[str]:
    return list(SUBDOMAINS)


def credential_pairs() -> list[tuple[str, str]]:
    pairs = [(user, password) for user in USERS[:10] for password in PASSWORDS[:10]]
    pairs.extend(
        [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "admin123"),
            ("administrator", "administrator"),
            ("root", "root"),
            ("root", "toor"),
            ("test", "test"),
            ("guest", "guest"),
            ("demo", "demo"),
            ("user", "user"),
            ("admin", "changeme"),
            ("admin", "letmein"),
        ]
    )
    return list(dict.fromkeys(pairs))
