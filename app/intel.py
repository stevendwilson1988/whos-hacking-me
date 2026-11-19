"""Passive lookups on attacker IPs: who owns the network and what is public about it.

Nothing here contacts the attacker. Every lookup goes to a public registry or
database (local ASN file, reverse DNS, RDAP, Shodan InternetDB, the Tor exit list).
Only IPs marked Hacking Me: Yes are looked up, and only in the background, so
page visitors can't trigger outside requests.
"""
import ipaddress
import json
import logging
import re
import socket
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import maxminddb

BASE = Path("/opt/www-traffic")
ASN_PATH = BASE / "dbip-asn-lite.mmdb"
RDAP_URL = "https://rdap.org/ip/{}"
SHODAN_URL = "https://internetdb.shodan.io/{}"
TOR_URL = "https://check.torproject.org/torbulkexitlist"
USER_AGENT = "whos-hacking-me-intel/1.0 (passive lookups for a public attack log)"
TIMEOUT = 5

REFRESH_AFTER = timedelta(days=7)
RETRY_AFTER = timedelta(hours=1)
TOR_EVERY = 6 * 3600
BATCH = 50
PAUSE = 1.0
IDLE = 60

MAX_LIST = 20
MAX_TEXT = 200
# Strict enough that the address is safe to drop into a mailto: link as is.
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,}$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")

log = logging.getLogger("intel")

SCHEMA = """CREATE TABLE IF NOT EXISTS ip_intel (
    ip TEXT PRIMARY KEY,
    asn INTEGER,
    as_org TEXT NOT NULL DEFAULT '',
    ptr TEXT NOT NULL DEFAULT '',
    rdap_json TEXT NOT NULL DEFAULT '{}',
    shodan_json TEXT NOT NULL DEFAULT '{}',
    tor INTEGER NOT NULL DEFAULT 0,
    checked_at TEXT NOT NULL,
    error TEXT NOT NULL DEFAULT ''
)"""

try:
    asn_db = maxminddb.open_database(str(ASN_PATH))
except (OSError, ValueError):
    asn_db = None

tor_exits = set()
tor_fetched = 0.0


def text(value, limit=MAX_TEXT):
    """Registry and Shodan strings are outside data: keep them short, single-line strings."""
    if not isinstance(value, str):
        return ""
    return " ".join(value.split())[:limit]


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as res:
        return res.read(1_000_000)


def lookup_asn(ip):
    if asn_db is None:
        return None, ""
    try:
        rec = asn_db.get(ip) or {}
    except ValueError:
        return None, ""
    number = rec.get("autonomous_system_number")
    return (number if isinstance(number, int) else None), text(rec.get("autonomous_system_organization"))


def lookup_ptr(ip):
    try:
        return text(socket.gethostbyaddr(ip)[0], 253)
    except (OSError, UnicodeError):
        return ""


def vcard(entity, field):
    try:
        for item in entity.get("vcardArray", [None, []])[1]:
            if item[0] == field:
                return item[3]
    except (AttributeError, IndexError, TypeError):
        pass
    return None


def walk(entities):
    for entity in entities or []:
        if isinstance(entity, dict):
            yield entity
            yield from walk(entity.get("entities"))


def parse_rdap(data):
    """Keep only what the profile shows: network name, owner, country, range and abuse email."""
    out = {"name": text(data.get("name")), "country": text(data.get("country"), 2)}
    start, end = text(data.get("startAddress"), 45), text(data.get("endAddress"), 45)
    cidrs = data.get("cidr0_cidrs") or []
    if cidrs and isinstance(cidrs[0], dict):
        prefix = cidrs[0].get("v4prefix") or cidrs[0].get("v6prefix")
        out["range"] = text(f"{prefix}/{cidrs[0].get('length')}", 50) if prefix else ""
    else:
        out["range"] = f"{start} - {end}" if start and end else ""
    if not out["name"]:
        out["name"] = text(data.get("handle"))
    org, fallback, abuse = "", "", ""
    for entity in walk(data.get("entities")):
        roles = entity.get("roles") or []
        if not org and "registrant" in roles:
            org = text(vcard(entity, "org") or vcard(entity, "fn"))
        # Some registries (AFRINIC) list no registrant; the admin contact's org is the next best owner.
        if not fallback and {"administrative", "technical"} & set(roles):
            fallback = text(vcard(entity, "org") or vcard(entity, "fn"))
        if not abuse and "abuse" in roles:
            email = vcard(entity, "email")
            if isinstance(email, str) and EMAIL_RE.match(email.strip()):
                abuse = email.strip().lower()
    out["org"], out["abuse"] = org or fallback, abuse
    return out


def parse_shodan(data):
    def strings(key, limit=MAX_LIST, size=MAX_TEXT):
        return [text(v, size) for v in (data.get(key) or [])[:limit] if isinstance(v, str)]

    return {
        "ports": sorted({p for p in (data.get("ports") or []) if isinstance(p, int) and 0 < p < 65536})[:50],
        "hostnames": strings("hostnames", size=253),
        "tags": strings("tags", size=40),
        "vulns": sorted(v for v in strings("vulns", limit=200, size=30) if CVE_RE.match(v))[:50],
    }


def lookup_rdap(ip):
    return parse_rdap(json.loads(fetch(RDAP_URL.format(ip))))


def lookup_shodan(ip):
    try:
        return parse_shodan(json.loads(fetch(SHODAN_URL.format(ip))))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:  # Shodan has nothing on this IP.
            return parse_shodan({})
        raise


def refresh_tor():
    global tor_exits, tor_fetched
    if time.time() - tor_fetched < TOR_EVERY:
        return
    tor_fetched = time.time()
    try:
        lines = fetch(TOR_URL).decode("ascii", "replace").split()
        exits = set()
        for line in lines:
            try:
                exits.add(str(ipaddress.ip_address(line)))
            except ValueError:
                pass
        if exits:
            tor_exits = exits
    except Exception as exc:
        log.warning("tor list fetch failed: %s", exc)


def lookup(ip):
    """One profile row. Each source fails on its own; failures are listed in error."""
    asn, as_org = lookup_asn(ip)
    row = {"ip": ip, "asn": asn, "as_org": as_org, "ptr": lookup_ptr(ip),
           "rdap": {}, "shodan": {}, "tor": int(ip in tor_exits), "errors": []}
    for key, name, source in (("rdap", "registry", lookup_rdap), ("shodan", "shodan", lookup_shodan)):
        try:
            row[key] = source(ip)
        except Exception as exc:
            row["errors"].append(name)
            log.info("%s lookup failed for %s: %s", name, ip, exc)
    return row


def save(db, row, now=None):
    now = now or datetime.now(timezone.utc)
    db.execute(
        "INSERT OR REPLACE INTO ip_intel "
        "(ip, asn, as_org, ptr, rdap_json, shodan_json, tor, checked_at, error) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (row["ip"], row["asn"], row["as_org"], row["ptr"], json.dumps(row["rdap"]),
         json.dumps(row["shodan"]), row["tor"], now.replace(microsecond=0).isoformat(),
         ",".join(row["errors"])),
    )


def due(db, limit, now=None):
    """Attacker IPs with no profile yet (newest attackers first), then stale or failed ones.
    Reads public_visits, so the owner's own IPs are never looked up."""
    now = now or datetime.now(timezone.utc)
    stale = (now - REFRESH_AFTER).isoformat()
    retry = (now - RETRY_AFTER).isoformat()
    rows = db.execute(
        "SELECT v.ip, MAX(v.id) AS latest, i.ip AS known FROM public_visits v "
        "LEFT JOIN ip_intel i ON i.ip = v.ip "
        "WHERE v.hacking_me = 'Yes' AND (i.ip IS NULL OR i.checked_at < ? "
        "OR (i.error != '' AND i.checked_at < ?)) "
        "GROUP BY v.ip ORDER BY known IS NOT NULL, latest DESC LIMIT ?",
        (stale, retry, limit),
    ).fetchall()
    out = []
    for r in rows:
        try:
            if ipaddress.ip_address(r[0]).is_global:
                out.append(r[0])
        except ValueError:
            pass
    return out


def load(db, ip):
    """The cached profile for the API, or None if it hasn't been looked up yet."""
    r = db.execute("SELECT * FROM ip_intel WHERE ip = ?", (ip,)).fetchone()
    if r is None:
        return None
    return {
        "asn": r["asn"], "as_org": r["as_org"], "ptr": r["ptr"], "tor": bool(r["tor"]),
        "registry": json.loads(r["rdap_json"] or "{}"), "shodan": json.loads(r["shodan_json"] or "{}"),
        "checked_at": r["checked_at"], "failed": [e for e in r["error"].split(",") if e],
    }


def prune(db):
    db.execute("DELETE FROM ip_intel WHERE ip NOT IN (SELECT ip FROM visits)")


def worker(connect):
    """Runs forever in a daemon thread, about one lookup a second, idling when caught up."""
    while True:
        try:
            refresh_tor()
            with connect() as db:
                ips = due(db, BATCH)
            if not ips:
                time.sleep(IDLE)
                continue
            for ip in ips:
                row = lookup(ip)
                with connect() as db:
                    save(db, row)
                time.sleep(PAUSE)
        except Exception as exc:
            log.exception("intel worker failed: %s", exc)
            time.sleep(IDLE)
