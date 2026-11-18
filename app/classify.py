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
API_DISCOVERY = "API discovery"
FOLLOW_UP = "Scanner follow-up"
AI_CRAWLER = "AI crawler"
PREVIEW = "Link preview"
SCRIPT = "Automated script"

# SSH rows use status 0, which no web request can have.
SSH_STATUS = 0
SSH_PREFIX = "SSH: "
SSH_REAL_ACCOUNT = "(real account)"
SSH_NO_NAME = "(no username)"

# First match wins, so specific rules sit above general ones.
PATH_RULES = [
    (r"allow_url_include|auto_prepend_file", PHP, "PHP-CGI argument injection (CVE-2024-4577)"),
    (r"/\.claude/|/\.cursor/|\bmcp\.json\b", AI_TOOLS, "AI coding assistant settings and keys"),
    (r"\.env|_environment|^/env(\.\w+)?/?$", SECRETS, "API keys and passwords in .env files"),
    (r"\.git\b|\.svn\b|\.hg\b", SECRETS, "Source code and credentials in an exposed code folder"),
    (r"service-account|firebase-adminsdk|gcp-key|/key\.json|/sa\.json|\.boto\b|\.s3cfg|terraform\.tf"
     r"|[-_](key|sa)\.json|keyfile\.json|google-services\.json|\.azure\b|master\.key", SECRETS, "Cloud account keys"),
    (r"appsettings|laravel\.log|application\.properties|web\.config|(config|settings)\.py$",
     SECRETS, "Passwords in app settings and logs"),
    (r"\.aws\b|\baws[-_]?credentials|/aws\.json", SECRETS, "Amazon cloud credentials"),
    (r"\.ssh\b|id_rsa", SECRETS, "Private SSH keys"),
    (r"wp-config", SECRETS, "WordPress database password"),
    (r"\.(sql|bak|old|swp)\b|\b(dump|backup)\b|\.(zip|tar|gz|rar)$", SECRETS, "Leftover backups and database dumps"),
    (r"\.(npmrc|pypirc|netrc|amplifyrc|htpasswd|htaccess|docker\w*|kube|vscode|ds_store)\b|/\.config/"
     r"|dockerfile|docker-compose|composer\.(json|lock)|credentials|secrets?\.|(config|settings|auth)\.(json|ya?ml|php|js|ini|xml|toml|conf)\b|\.ya?ml$",
     SECRETS, "Passwords and keys in config files"),
    (r"^/(api/)?mcp\b|^/sse\b", AI_TOOLS, "Open MCP servers (AI tool connections)"),
    (r"/sdk/weblanguage", DEVICE, "Hikvision cameras (CVE-2021-36260)"),
    (r"/developmentserver/metadatauploader", DEVICE, "SAP NetWeaver servers (CVE-2025-31324)"),
    (r"^/remote/(login|logincheck)", DEVICE, "Fortinet VPN login page"),
    (r"/global-protect|/ssl-?vpn|/\+cscoe\+/|/dana-na/|^/sra_\{", DEVICE, "Company VPN login pages"),
    (r"/mifs/", DEVICE, "Ivanti phone management servers"),
    (r"^/rdweb\b", DEVICE, "Windows Remote Desktop web login"),
    (r"^/webui\b", DEVICE, "Cisco router web admin (CVE-2023-20198)"),
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
    (r"/actuator\b|/manager/html|/jenkins|/solr\b|/geoserver|/grafana|/console\b|/druid|/web-console\b", ADMIN, "Server management consoles"),
    (r"/_profiler\b|/debug/default/view|^/server-status\b", ADMIN, "Debug pages that leak server details"),
    (r"/vendor/phpunit|eval-stdin|phpinfo|\.php\d?(\?|/|$)", PHP, "Vulnerable or planted PHP scripts"),
    (r"^/(blog|wp|wordpress|cms|site|news|press|shop|old|new|test|demo)/?(\?|$)", WORDPRESS, "A WordPress site in a common folder"),
    (r"^/(admin|administrator|login|register|signin|signup|auth|account|dashboard|forgot-password|password|settings"
     r"|email/verify|two-factor-challenge)(\.(html?|jsp|do|action|aspx?))?(/|\?|$)|/(user|users|account)/(login|signin)\b",
     LOGIN, "Login and account pages"),
    (r"swagger|openapi\.json|api-docs|graphql|^/api(/v\d+)?(/version|/config)?/?$|^/v\d+/?$|^/(version|health|info)/?$",
     API_DISCOVERY, "Looking for API documentation and status pages"),
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


# Scanners that name themselves. Checked once the path rules have found nothing.
RESEARCH_AGENT_RE = re.compile(
    r"hello from palo alto|expanse|censys|shodan|visionheight\.com/scan|internet-measurement|zgrab|cgrab|"
    r"internetdb|leakix|onyphe|netcraft")
# Friendly bots. Probes often borrow these names, so they only count on the site's real pages.
AGENT_RULES = [
    (r"gptbot|chatgpt-user|oai-searchbot|claudebot|claude-user|claude-searchbot|anthropic-ai|perplexitybot|"
     r"ccbot|bytespider|amazonbot|google-extended|meta-externalagent|applebot-extended|diffbot|cohere-ai",
     AI_CRAWLER, "Collecting pages for an AI company"),
    (r"googlebot|bingbot|duckduckbot|applebot|yandexbot|baiduspider|slurp|petalbot|ahrefsbot|semrushbot|mj12bot|dotbot",
     CRAWLER, "Indexing the site for a search engine"),
    (r"linkedinbot|slackbot|facebookexternalhit|discordbot|twitterbot|whatsapp|telegrambot|skypeuripreview|iframely|embedly",
     PREVIEW, "Building a preview card for a shared link"),
]
AGENT_RULES = [(re.compile(p), cat, after) for p, cat, after in AGENT_RULES]
# Programs, not browsers. Only used to relabel what would otherwise be a site visit.
SCRIPT_RE = re.compile(r"^(python|curl|wget|go-http-client|java/|okhttp|libwww|httpclient|axios|node|ruby|php|"
                       r"masscan|nmap|nuclei|httpx|fasthttp|aiohttp|scrapy|-?$)")
# Methods a plain page never needs.
SEND_METHODS = {"POST", "PUT", "DELETE", "PATCH", "PROPFIND", "MKCOL", "COPY", "MOVE"}


def classify(path, status, ip, method="", agent=""):
    """Return (category, what it's after) for one logged request.
    method and agent are blank for rows stored before they were recorded."""
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
    ua = agent.lower()
    if RESEARCH_AGENT_RE.search(ua):
        return RESEARCH, "Mapping the internet (says so in its user agent)"
    for prefix, after in RESEARCH_IPS:
        if ip.startswith(prefix):
            return RESEARCH, after
    page = re.sub(r"/index\.html$", "", text.split("?")[0]).rstrip("/") or "/"
    sending = method in SEND_METHODS and status in (400, 404, 405)
    if page in SITE_PAGES and (status < 400 or status == 401) and not sending:
        return visit(SITE_PAGES[page], method, ua)
    if sending:
        return UNKNOWN, "Sending data to a page that doesn't take any"
    if status in (400, 405):
        return UNKNOWN, "Unclear; the server refused the request"
    if status < 400:
        return visit("Page on the site", method, ua)
    return UNKNOWN, "Unclear; the page doesn't exist"


def visit(after, method, ua):
    """A real page. Before agents were recorded (method is blank), it can't be told apart."""
    for pattern, category, why in AGENT_RULES:
        if pattern.search(ua):
            return category, why
    if method and SCRIPT_RE.match(ua):
        return SCRIPT, after + ", fetched by a program"
    return VISIT, after


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
    ADMIN: "Yes", PHP: "Yes", PROXY: "Yes", SSH: "Yes", FOLLOW_UP: "Yes",
    LOGIN: "Maybe", MALFORMED: "Maybe", UNKNOWN: "Maybe", API_DISCOVERY: "Maybe", SCRIPT: "Maybe",
    RESEARCH: "No", CRAWLER: "No", AI_CRAWLER: "No", PREVIEW: "No", VISIT: "No",
}

# An IP that has made a web request marked Yes is a known attacker. Its other
# requests in these categories become FOLLOW_UP; the rest keep their own label.
FOLLOW_UP_FROM = (UNKNOWN, VISIT, SCRIPT)
FOLLOW_UP_AFTER = "Part of a scan from an IP seen attacking"


def hacking_me(category):
    return HACKING_ME.get(category, "Maybe")
