"""Technology fingerprint signatures.

Each entry matches a header name/value, a body regular expression or a cookie
name. The catalogue favours high-precision signatures: a wrong guess wastes a
tester's time and can trigger the wrong detector set.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class TechnologySignature:
    name: str
    category: str
    header: str = ""
    pattern: str = ""
    cookie: str = ""
    version_group: int = 1
    confidence: str = "high"

    def as_dict(self) -> dict[str, str]:
        return {
            "name": self.name,
            "category": self.category,
            "confidence": self.confidence,
        }


TECHNOLOGIES: tuple[TechnologySignature, ...] = (
    TechnologySignature("nginx", "web-server", header="server", pattern=r"nginx(?:/([\d.]+))?"),
    TechnologySignature("Apache HTTP Server", "web-server", header="server", pattern=r"Apache(?:/([\d.]+))?"),
    TechnologySignature("Microsoft IIS", "web-server", header="server", pattern=r"Microsoft-IIS/([\d.]+)?"),
    TechnologySignature("LiteSpeed", "web-server", header="server", pattern=r"LiteSpeed"),
    TechnologySignature("Caddy", "web-server", header="server", pattern=r"Caddy"),
    TechnologySignature("OpenResty", "web-server", header="server", pattern=r"openresty(?:/([\d.]+))?"),
    TechnologySignature("gunicorn", "app-server", header="server", pattern=r"gunicorn(?:/([\d.]+))?"),
    TechnologySignature("Werkzeug", "app-server", header="server", pattern=r"Werkzeug(?:/([\d.]+))?"),
    TechnologySignature("Jetty", "app-server", header="server", pattern=r"Jetty(?:\(([\d.]+)\))?"),
    TechnologySignature("Tomcat", "app-server", header="server", pattern=r"Apache-Coyote|Tomcat"),
    TechnologySignature("PHP", "language", header="x-powered-by", pattern=r"PHP/([\d.]+)"),
    TechnologySignature("ASP.NET", "framework", header="x-powered-by", pattern=r"ASP\.NET"),
    TechnologySignature("ASP.NET MVC", "framework", header="x-aspnetmvc-version", pattern=r"([\d.]+)"),
    TechnologySignature("Express", "framework", header="x-powered-by", pattern=r"Express"),
    TechnologySignature("Django", "framework", cookie="csrftoken"),
    TechnologySignature("Flask", "framework", header="server", pattern=r"Werkzeug"),
    TechnologySignature("Laravel", "framework", cookie="laravel_session"),
    TechnologySignature("Symfony", "framework", cookie="symfony"),
    TechnologySignature("Rails", "framework", cookie="_session_id|_rails_session"),
    TechnologySignature("Spring Boot", "framework", header="x-application-context"),
    TechnologySignature("Next.js", "framework", header="x-nextjs-cache"),
    TechnologySignature("Nuxt", "framework", pattern=r"__NUXT__"),
    TechnologySignature("Angular", "javascript-framework", pattern=r"ng-version=\"([\d.]+)\"|angular\.min\.js"),
    TechnologySignature("React", "javascript-framework", pattern=r"data-reactroot|__REACT_DEVTOOLS"),
    TechnologySignature("Vue.js", "javascript-framework", pattern=r"data-v-[0-9a-f]{8}|vue(?:\.min)?\.js"),
    TechnologySignature("jQuery", "javascript-library", pattern=r"jquery(?:\-|\.)([\d.]+)(?:\.min)?\.js"),
    TechnologySignature("Bootstrap", "css-framework", pattern=r"bootstrap(?:\.min)?\.css\?ver=([\d.]+)|bootstrap/([\d.]+)"),
    TechnologySignature("Cloudflare", "cdn-waf", header="server", pattern=r"cloudflare"),
    TechnologySignature("Cloudflare", "cdn-waf", header="cf-ray"),
    TechnologySignature("Akamai", "cdn-waf", header="server", pattern=r"AkamaiGHost"),
    TechnologySignature("Fastly", "cdn-waf", header="x-served-by", pattern=r"cache-"),
    TechnologySignature("Varnish", "cache", header="x-varnish"),
    TechnologySignature("Amazon S3", "storage", header="server", pattern=r"AmazonS3"),
    TechnologySignature("Amazon CloudFront", "cdn-waf", header="x-amz-cf-id"),
    TechnologySignature("Azure Front Door", "cdn-waf", header="x-azure-ref"),
    TechnologySignature("Google Frontend", "cdn-waf", header="server", pattern=r"Google Frontend|gws"),
    TechnologySignature("WordPress", "cms", pattern=r"wp-content/|wp-includes/"),
    TechnologySignature("WordPress", "cms", header="x-powered-by", pattern=r"WordPress"),
    TechnologySignature("Drupal", "cms", header="x-generator", pattern=r"Drupal ([\d.]+)"),
    TechnologySignature("Joomla", "cms", pattern=r"content=\"Joomla!?\s*([\d.]+)?"),
    TechnologySignature("Magento", "ecommerce", cookie="frontend"),
    TechnologySignature("Shopify", "ecommerce", header="x-shopid"),
    TechnologySignature("Ghost", "cms", pattern=r"content=\"Ghost ([\d.]+)?"),
    TechnologySignature("Grafana", "monitoring", pattern=r"grafana(?:\.min)?\.js|Grafana"),
    TechnologySignature("Prometheus", "monitoring", pattern=r"Prometheus"),
    TechnologySignature("Jenkins", "ci", header="x-jenkins", pattern=r"([\d.]+)?"),
    TechnologySignature("GitLab", "devtools", cookie="_gitlab_session"),
    TechnologySignature("Jira", "devtools", pattern=r"ajs-version-number|Jira"),
    TechnologySignature("Confluence", "devtools", pattern=r"Confluence"),
    TechnologySignature("Swagger UI", "documentation", pattern=r"swagger-ui|Swagger UI"),
    TechnologySignature("GraphQL Playground", "documentation", pattern=r"GraphQL Playground|graphiql"),
    TechnologySignature("phpMyAdmin", "admin", pattern=r"phpMyAdmin"),
    TechnologySignature("Elasticsearch", "database", pattern=r"\"cluster_name\".*\"cluster_uuid\""),
    TechnologySignature("Kibana", "monitoring", pattern=r"kibana"),
    TechnologySignature("MinIO", "storage", header="server", pattern=r"MinIO"),
    TechnologySignature("Keycloak", "identity", pattern=r"keycloak"),
    TechnologySignature("Auth0", "identity", header="x-auth0-requestid"),
    TechnologySignature("Okta", "identity", pattern=r"okta"),
    TechnologySignature("Sentry", "monitoring", pattern=r"sentry(?:\.min)?\.js"),
)

COOKIE_SIGNATURES: dict[str, str] = {
    "phpsessid": "PHP",
    "jsessionid": "Java",
    "asp.net_sessionid": "ASP.NET",
    "laravel_session": "Laravel",
    "csrftoken": "Django",
    "symfony": "Symfony",
    "_ga": "Google Analytics",
    "_gid": "Google Analytics",
    "wp-settings": "WordPress",
    "wordpress_logged_in": "WordPress",
    "_shopify_s": "Shopify",
}
