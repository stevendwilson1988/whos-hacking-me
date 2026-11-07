import re
from urllib.parse import unquote

# Labels are educated guesses from the requested address and IP; none are confirmed.
SECRETS = "Secret harvesting"
WORDPRESS = "WordPress attack"
LARAVEL = "Laravel app probing"
AI_TOOLS = "Exposed AI tools"
DEVICE = "Device or enterprise exploit"
ADMIN = "Admin tool probing"
LOGIN = "Login page probing"
PHP = "PHP script probing"
PROXY = "Proxy probing"
RESEARCH = "Research scanner"
CRAWLER = "Search crawler"
MALFORMED = "Malformed traffic"
VISIT = "Site visit"
UNKNOWN = "Unknown probe"
SSH = "SSH login attempt"

# SSH rows use status 0, which no web request can have.
SSH_STATUS = 0
SSH_PREFIX = "SSH: "
SSH_REAL_ACCOUNT = "(real account)"
SSH_NO_NAME = "(no username)"

# First match wins, so specific rules sit above general ones.
PATH_RULES = [
    (r"\.env|_environment", SECRETS, "API keys and passwords in .env files"),
    (r"\.git\b|\.svn\b", SECRETS, "Source code and credentials in an exposed code folder"),
    (r"service-account|firebase-adminsdk|gcp-key|/key\.json|/sa\.json|\.boto\b|\.s3cfg|terraform\.tf", SECRETS, "Cloud account keys"),
    (r"appsettings|laravel\.log", SECRETS, "Passwords in app settings and logs"),
    (r"\.aws\b|\baws[-_]?credentials", SECRETS, "Amazon cloud credentials"),
    (r"\.ssh\b|id_rsa", SECRETS, "Private SSH keys"),
    (r"wp-config", SECRETS, "WordPress database password"),
    (r"\.(sql|bak|old|swp)\b|\b(dump|backup)\b|\.(zip|tar|gz|rar)$", SECRETS, "Leftover backups and database dumps"),
    (r"\.(npmrc|htpasswd|htaccess|docker|kube|vscode)\b|docker-compose|credentials|secrets?\.|config\.(json|ya?ml|php|js)\b|\.ya?ml$",
     SECRETS, "Passwords and keys in config files"),
    (r"^/(api/)?mcp\b|^/sse\b", AI_TOOLS, "Open MCP servers (AI tool connections)"),
    (r"/sdk/weblanguage", DEVICE, "Hikvision cameras (CVE-2021-36260)"),
    (r"/developmentserver/metadatauploader", DEVICE, "SAP NetWeaver servers (CVE-2025-31324)"),
    (r"^/remote/(login|logincheck)", DEVICE, "Fortinet VPN login page"),
    (r"/global-protect|/ssl-?vpn", DEVICE, "Company VPN login pages"),
    (r"/containers/json", ADMIN, "Open Docker servers"),
    (r"/hnap1|/boaform|/gponform|/goform|/datesetting\.cgi|/cgi-bin/|/setup\.cgi|\.cgi$", DEVICE, "Routers, cameras and DVRs"),
    (r"/owa\b|/ecp\b|/autodiscover", DEVICE, "Microsoft Exchange email servers"),
    (r"/livewire\b", LARAVEL, "Livewire remote code bug"),
    (r"/(filament|nova|horizon|telescope|_ignition|pulse)\b", LARAVEL, "Laravel admin panels"),
    (r"/wp-json/batch", WORDPRESS, "WordPress batch API, using tricks to dodge filters"),
    (r"/wp-admin/(setup-config|install)", WORDPRESS, "Unfinished WordPress installs to take over"),
    (r"/wp-login|/xmlrpc\.php", WORDPRESS, "WordPress logins"),
    (r"(/wp-content|/wp-includes|/wp-admin).*\.php|/style\.php", WORDPRESS, "A webshell someone else planted in WordPress"),
    (r"/wp-|rest_route=|[?&]author=|/wlwmanifest", WORDPRESS, "Signs that WordPress is installed"),
    (r"/(phpmyadmin|pma|adminer|myadmin)\b|adminer\.php", ADMIN, "Database admin tools"),
    (r"/actuator\b|/manager/html|/jenkins|/solr\b|/geoserver|/grafana|/console\b|/druid", ADMIN, "Server management consoles"),
    (r"/vendor/phpunit|eval-stdin|phpinfo|\.php\d?(\?|$)", PHP, "Vulnerable or planted PHP scripts"),
    (r"^/(blog|wp|wordpress|cms|site|news|press|shop|old|new|test|demo)/?(\?|$)", WORDPRESS, "A WordPress site in a common folder"),
    (r"^/(admin|administrator|login|register|signin|signup|auth|account|dashboard|forgot-password|password|settings|email/verify)\b|^/login\.html",
     LOGIN, "Login and account pages"),
    (r"^(https?://|[a-z0-9.-]+:\d+$)", PROXY, "Using your server to relay traffic"),
    (r"^/robots\.txt|^/sitemap|^/\.well-known/|^/ads\.txt|^/security\.txt", CRAWLER, "Standard files for crawlers"),
]
PATH_RULES = [(re.compile(p), cat, after) for p, cat, after in PATH_RULES]

SITE_PAGES = {
    "/": "Homepage (could be a person or a bot)",
    "/steve": "Steve page",
    "/portfolio": "Portfolio",
    "/podcast": "Podcast",
    "/podcast/upload": "Podcast upload",
    "/podcast/episodes.json": "Podcast episode list",
    "/careerdesk": "Career Desk",
    "/odyssey": "Super Pixel Odyssey",
    "/arcade": "Pixel Arcade",
    "/jonathan-wilson": "Jonathan Wilson LLC (first version)",
    "/jonathan-wilson-v2": "Jonathan Wilson LLC",
}

# From known scanner ranges, recalled rather than looked up, hence "likely".
RESEARCH_IPS = [
    ("66.132.224.", "Mapping the internet (likely Censys)"),
    ("147.185.133.", "Mapping the internet (likely Palo Alto Networks)"),
    ("198.235.24.", "Mapping the internet (likely Palo Alto Networks)"),
    ("65.49.1.", "Mapping the internet (likely Shadowserver)"),
    ("71.6.155.70", "Mapping the internet (possibly Shodan)"),
]


def classify(path, status, ip):
    """Return (category, what it's after) for one logged request."""
    if status == SSH_STATUS:
        name = path.removeprefix(SSH_PREFIX)
        if name == SSH_REAL_ACCOUNT:
            return SSH, "Logging in to a real account"
        if name == SSH_NO_NAME:
            return SSH, "Logging in with no username"
        return SSH, f"Logging in as {name}"
    if path == "(invalid request)":
        return MALFORMED, "Junk or non-web data sent to the site"
    text = unquote(unquote(path)).lower()
    for pattern, category, after in PATH_RULES:
        if pattern.search(text):
            return category, after
    for prefix, after in RESEARCH_IPS:
        if ip.startswith(prefix):
            return RESEARCH, after
    page = re.sub(r"/index\.html$", "", text.split("?")[0]).rstrip("/") or "/"
    if page in SITE_PAGES and (status < 400 or status == 401):
        return VISIT, SITE_PAGES[page]
    if status in (400, 405):
        return UNKNOWN, "Unclear; the server refused the request"
    if status < 400:
        return VISIT, "Page on the site"
    return UNKNOWN, "Unclear; the page doesn't exist"


def result_label(status):
    """Plain-English outcome of a request, as shown in the Result column."""
    if status == SSH_STATUS:
        return "Rejected"
    if status == 304:
        return "Loaded (cached)"
    if status < 300:
        return "Loaded"
    if status < 400:
        return "Redirected"
    if status == 401:
        return "Login required"
    if status == 404:
        return "Not found"
    return f"Failed ({status})"


# "Yes" means it looks like an attempt, not that it worked.
HACKING_ME = {
    SECRETS: "Yes", WORDPRESS: "Yes", LARAVEL: "Yes", AI_TOOLS: "Yes", DEVICE: "Yes",
    ADMIN: "Yes", PHP: "Yes", PROXY: "Yes", SSH: "Yes",
    LOGIN: "Maybe", MALFORMED: "Maybe", UNKNOWN: "Maybe",
    RESEARCH: "No", CRAWLER: "No", VISIT: "No",
}


def hacking_me(category):
    return HACKING_ME.get(category, "Maybe")
