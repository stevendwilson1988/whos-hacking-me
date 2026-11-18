"""Tests for the request rules in classify.py. Paths are real ones from the live log.

Run with: python3 /opt/www-traffic/test_classify.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from classify import classify, hacking_me  # noqa: E402

IP = "45.9.9.9"
BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/156.0 Safari/537.36"

# (path, status, method, agent, expected category)
CASES = [
    # Secret files that used to fall through to Unknown or Login
    ("/settings.py", 404, "", "", "Secret harvesting"),
    ("/settings.json", 404, "", "", "Secret harvesting"),
    ("/auth.json", 404, "", "", "Secret harvesting"),
    ("/.netrc", 404, "", "", "Secret harvesting"),
    ("/.pypirc", 404, "", "", "Secret harvesting"),
    ("/.dockercfg", 404, "", "", "Secret harvesting"),
    ("/.dockerenv", 404, "", "", "Secret harvesting"),
    ("/.amplifyrc", 404, "", "", "Secret harvesting"),
    ("/.hg/requires", 404, "", "", "Secret harvesting"),
    ("/.DS_Store", 404, "", "", "Secret harvesting"),
    ("/web.config", 404, "", "", "Secret harvesting"),
    ("/Dockerfile", 404, "", "", "Secret harvesting"),
    ("/composer.json", 404, "", "", "Secret harvesting"),
    ("/env", 404, "", "", "Secret harvesting"),
    ("/env.txt", 404, "", "", "Secret harvesting"),
    ("/env.json", 404, "", "", "Secret harvesting"),
    ("/firebase-key.json", 404, "", "", "Secret harvesting"),
    ("/gcp-sa.json", 404, "", "", "Secret harvesting"),
    ("/keyfile.json", 404, "", "", "Secret harvesting"),
    ("/google-services.json", 404, "", "", "Secret harvesting"),
    ("/config/master.key", 404, "", "", "Secret harvesting"),
    ("/config/aws.json", 404, "", "", "Secret harvesting"),
    ("/local_settings.py", 404, "", "", "Secret harvesting"),
    ("/config.py", 404, "", "", "Secret harvesting"),
    ("/application.properties", 404, "", "", "Secret harvesting"),
    ("/.azure/credentials", 404, "", "", "Secret harvesting"),
    ("/.env", 404, "", "", "Secret harvesting"),
    ("/.git/config", 301, "", "", "Secret harvesting"),
    # AI tools
    ("/.claude/settings.local.json", 404, "", "", "Exposed AI tools"),
    ("/.cursor/mcp.json", 404, "", "", "Exposed AI tools"),
    ("/mcp", 404, "", "", "Exposed AI tools"),
    # Exploits and devices
    ("/hello.world?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input", 404, "", "", "PHP script probing"),
    ("/index.php/admin", 404, "", "", "PHP script probing"),
    ("/+CSCOE+/logon.html", 404, "", "", "Device or enterprise exploit"),
    ("/mifs/user/login.jsp", 404, "", "", "Device or enterprise exploit"),
    ("/RDWeb/Pages/en-US/login.aspx", 404, "", "", "Device or enterprise exploit"),
    ("/sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/", 400, "", "", "Device or enterprise exploit"),
    ("/webui/", 404, "", "", "Device or enterprise exploit"),
    ("/_profiler/phpinfo", 404, "", "", "Admin tool probing"),
    ("/debug/default/view?panel=config", 404, "", "", "Admin tool probing"),
    ("/server-status", 404, "", "", "Admin tool probing"),
    # Login pages, now matched as whole words only
    ("/login", 404, "", "", "Login page probing"),
    ("/admin/login", 404, "", "", "Login page probing"),
    ("/user/login", 404, "", "", "Login page probing"),
    ("/two-factor-challenge", 404, "", "", "Login page probing"),
    ("/login.jsp", 404, "", "", "Login page probing"),
    ("/login.action", 404, "", "", "Login page probing"),
    # API discovery
    ("/swagger.json", 404, "", "", "API discovery"),
    ("/openapi.json", 404, "", "", "API discovery"),
    ("/api-docs", 404, "", "", "API discovery"),
    ("/graphql", 404, "", "", "API discovery"),
    ("/api", 404, "", "", "API discovery"),
    ("/api/v1/version", 404, "", "", "API discovery"),
    ("/version", 404, "", "", "API discovery"),
    ("/health", 404, "", "", "API discovery"),
    # The site's own pages stay visits
    ("/", 200, "", "", "Site visit"),
    ("/", 200, "GET", BROWSER, "Site visit"),
    ("/podcast/episodes.json", 200, "GET", BROWSER, "Site visit"),
    ("/jonathan-wilson-v2/projects/sodium-vapor/", 200, "GET", BROWSER, "Site visit"),
    ("/careerdesk", 200, "GET", BROWSER, "Site visit"),
    # Agents and methods
    ("/", 200, "GET", "python-requests/2.34.2", "Automated script"),
    ("/", 200, "GET", "-", "Automated script"),
    ("/", 200, "GET", "Go-http-client/1.1", "Automated script"),
    ("/", 405, "POST", BROWSER, "Unknown probe"),
    ("/", 200, "GET", "Mozilla/5.0 (compatible; Googlebot/2.1)", "Search crawler"),
    ("/", 200, "GET", "Mozilla/5.0 (compatible; GPTBot/1.2)", "AI crawler"),
    ("/portfolio", 200, "GET", "Mozilla/5.0 (compatible; ClaudeBot/1.0)", "AI crawler"),
    ("/", 200, "GET", "LinkedInBot/1.0 (compatible; Mozilla/5.0)", "Link preview"),
    ("/", 200, "GET", "Hello from Palo Alto Networks, find out more", "Research scanner"),
    ("/", 200, "GET", "Mozilla/5.0 (compatible; CensysInspect/1.1)", "Research scanner"),
    # An attack path wins over a friendly agent
    ("/.env", 404, "GET", "Mozilla/5.0 (compatible; Googlebot/2.1)", "Secret harvesting"),
    ("/Gemfile.lock", 404, "GET", "Mozilla/5.0 (compatible; Googlebot/2.1)", "Unknown probe"),
    ("/_debugbar/open", 404, "GET", "Mozilla/5.0 (compatible; GPTBot/1.2)", "Unknown probe"),
    ("/nothing-here", 404, "GET", BROWSER, "Unknown probe"),
]


def main():
    failures = 0
    for path, status, method, agent, expected in CASES:
        got, _ = classify(path, status, IP, method, agent)
        if got != expected:
            failures += 1
            print(f"FAIL {path!r} {status} {method} {agent[:30]!r}: got {got!r}, expected {expected!r}")
    for category in {c[-1] for c in CASES} | {"Scanner follow-up"}:
        if hacking_me(category) not in ("Yes", "Maybe", "No"):
            failures += 1
            print(f"FAIL {category!r} has no Hacking Me rating")
    if hacking_me("Scanner follow-up") != "Yes":
        failures += 1
        print("FAIL scanner follow-ups should be Yes")
    print(f"\n{len(CASES) - failures} of {len(CASES)} classify cases passed" if not failures else f"\n{failures} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
