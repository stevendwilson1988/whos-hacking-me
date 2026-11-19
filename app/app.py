import gzip
import glob
import hashlib
import ipaddress
import os
import re
import shutil
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import maxminddb
from flask import Flask, abort, jsonify, request, send_file

import alerts
import intel
from classify import (
    FOLLOW_UP,
    FOLLOW_UP_AFTER,
    FOLLOW_UP_FROM,
    SSH_NO_NAME,
    SSH_PREFIX,
    SSH_REAL_ACCOUNT,
    SSH_STATUS,
    classify,
    hacking_me,
    result_label,
)

BASE = Path("/opt/www-traffic")
DB_PATH = BASE / "traffic.db"
GEO_PATH = BASE / "dbip-city-lite.mmdb"
PAGE = BASE / "page.html"
LOG = "/var/log/nginx/access.log"
SSH_LOG = "/var/log/auth.log"

# Past this size the oldest visits are deleted, down to TRIM_TO of the limit.
# Both are set in /etc/www-traffic/alerts.env (see deploy/alerts.env.example).
MAX_DB_BYTES = int(float(os.environ.get("WHT_MAX_DB_GB", "1")) * 1024 ** 3)
# Below this much free disk, the database stops growing: old visits make room for new ones.
MIN_FREE_BYTES = int(float(os.environ.get("WHT_MIN_FREE_GB", "5")) * 1024 ** 3)
# The write-ahead log shrinks back to this after each checkpoint.
WAL_LIMIT_BYTES = 64 * 1024 ** 2
TRIM_TO = 0.9
TRIM_EVERY = 60

# Columns the page can filter and sort on; names are only ever taken from these.
FILTER_COLUMNS = {"ip", "location", "hacking_me", "category", "after_what", "path", "result"}
SORT_COLUMNS = FILTER_COLUMNS | {"ts"}
MAX_FILTER_VALUES = 4000
MAX_FACET_VALUES = 200
PAGE_LIMIT = 1000
HIDDEN = "Hidden"
SSH_PUBLIC_PATH = "SSH login attempt"
SSH_PUBLIC_AFTER = "Logging in over SSH"

# Chart windows in days; None means all time.
CHART_WINDOWS = {"24h": 1, "7d": 7, "all": None}
# Point size for the over-time chart in each window.
CHART_STEPS = {"24h": "hour", "7d": "hour", "all": "day"}
CHART_CACHE_SECONDS = 60
TOP_CATEGORIES = 6
TOP_USERNAMES = 8
TOP_COUNTRIES = 6
TOP_NETWORKS = 5
USERNAME_DELAY = timedelta(hours=1)
SSH_LABEL = "SSH"
WEB_LABEL = "Web (HTTP)"

# Scripts only from this site; inline styles stay allowed because page.html uses them.
CSP = "; ".join([
    "default-src 'none'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src https://fonts.gstatic.com",
    "connect-src 'self'",
    "img-src 'self'",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
])

# The server's own requests aren't visitors.
IGNORED_IPS = {"127.0.0.1", "::1", "150.136.117.66"}
# Files a page pulls in; one page view shouldn't become many rows.
ASSET_RE = re.compile(
    r"\.(js|css|map|jpe?g|png|gif|svg|webp|ico|woff2?|ttf|mp3|m4a|wav|ogg)$", re.I
)
LINE_RE = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "([^"]*)" (\d{3}) (?:\S+ "[^"]*" "([^"]*)")?')
# Every row is stored as these columns, in this order.
COLUMNS = ("ts, ip, location, path, status, method, user_agent, "
           "category, after_what, result, hacking_me")

SSH_LINE_RE = re.compile(r"^(\S+) \S+ sshd(?:-session)?\[\d+\]: (.*)$")
# Made-up usernames are shown; attempts on real accounts never store the name.
SSH_INVALID_RE = re.compile(r"^Invalid user (.*) from (\S+) port \d+")
SSH_REAL_RE = re.compile(
    r"^(?:Connection closed by|Disconnected from|Connection reset by) "
    r"authenticating user \S+ (\S+) port \d+"
)
SSH_ACCEPTED_RE = re.compile(r"^Accepted \S+ for \S+ from (\S+) port \d+")

app = Flask(__name__)
geo = maxminddb.open_database(str(GEO_PATH))


def connect():
    db = sqlite3.connect(DB_PATH, timeout=30)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute(f"PRAGMA journal_size_limit = {WAL_LIMIT_BYTES}")
    return db


def init_db():
    with connect() as db:
        db.execute(
            """CREATE TABLE IF NOT EXISTS visits (
                id INTEGER PRIMARY KEY,
                ts TEXT NOT NULL,
                ip TEXT NOT NULL,
                location TEXT NOT NULL,
                path TEXT NOT NULL,
                status INTEGER NOT NULL
            )"""
        )
        db.execute(
            "CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY CHECK (id = 1), inode INTEGER, pos INTEGER)"
        )
        db.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)")
        db.execute(
            "CREATE TABLE IF NOT EXISTS log_state (log TEXT PRIMARY KEY, inode INTEGER, pos INTEGER)"
        )
        db.execute("CREATE TABLE IF NOT EXISTS ssh_own_ips (ip TEXT PRIMARY KEY)")
        # Everything public reads this view, so hidden values can't reach a
        # response or be guessed through filters. The owner's rows are left out;
        # anything not marked Yes keeps its row but loses its IP, location and query
        # string. SSH rows lose the username, so nobody can test whether an account exists.
        db.execute("DROP VIEW IF EXISTS public_visits")
        db.execute(
            f"""CREATE VIEW public_visits AS SELECT
                id, ts, status, category, result, hacking_me,
                CASE WHEN status = {SSH_STATUS} THEN '{SSH_PUBLIC_AFTER}'
                     ELSE after_what END AS after_what,
                CASE WHEN hacking_me = 'Yes' THEN ip ELSE '{HIDDEN}' END AS ip,
                CASE WHEN hacking_me = 'Yes' THEN location ELSE '{HIDDEN}' END AS location,
                CASE WHEN status = {SSH_STATUS} THEN '{SSH_PUBLIC_PATH}'
                     WHEN hacking_me != 'Yes' AND instr(path, '?') > 0
                     THEN substr(path, 1, instr(path, '?') - 1) ELSE path END AS path
            FROM visits
            WHERE ip NOT IN (SELECT ip FROM ssh_own_ips)"""
        )
        existing = {r["name"] for r in db.execute("PRAGMA table_info(visits)")}
        for column in ("category", "after_what", "result", "hacking_me"):
            if column not in existing:
                db.execute(f"ALTER TABLE visits ADD COLUMN {column} TEXT")
        # Kept out of public_visits: an agent string can identify a person.
        for column in ("method", "user_agent"):
            if column not in existing:
                db.execute(f"ALTER TABLE visits ADD COLUMN {column} TEXT NOT NULL DEFAULT ''")
        db.execute("CREATE INDEX IF NOT EXISTS visits_ip ON visits (ip)")
        db.execute(intel.SCHEMA)


def labels(path, status, ip, method="", agent=""):
    category, after_what = classify(path, status, ip, method, agent)
    return category, after_what, result_label(status), hacking_me(category)


def apply_ip_context(db, ips=None):
    """Mark the other requests of IPs seen attacking over the web as FOLLOW_UP.
    With ips, only those IPs are checked, which keeps each ingest pass cheap."""
    scope, args = "", []
    if ips is not None:
        ips = list(ips)
        if not ips:
            return
        scope = f"AND ip IN ({','.join('?' * len(ips))})"
        args = ips
    marks = ",".join("?" * len(FOLLOW_UP_FROM))
    db.execute(
        f"UPDATE visits SET category = ?, after_what = ?, hacking_me = ? "
        f"WHERE category IN ({marks}) {scope} AND ip IN ("
        f"SELECT ip FROM visits WHERE hacking_me = 'Yes' AND status != ? AND category != ? {scope})",
        [FOLLOW_UP, FOLLOW_UP_AFTER, hacking_me(FOLLOW_UP), *FOLLOW_UP_FROM, *args,
         SSH_STATUS, FOLLOW_UP, *args],
    )


def relabel(db):
    """Re-apply the rules to every stored visit whenever classify.py changes."""
    version = hashlib.sha256((BASE / "classify.py").read_bytes()).hexdigest()
    row = db.execute("SELECT value FROM meta WHERE key = 'rules'").fetchone()
    if row and row["value"] == version:
        return
    rows = db.execute("SELECT id, path, status, ip, method, user_agent FROM visits").fetchall()
    db.executemany(
        "UPDATE visits SET category = ?, after_what = ?, result = ?, hacking_me = ? WHERE id = ?",
        [(*labels(r["path"], r["status"], r["ip"], r["method"], r["user_agent"]), r["id"]) for r in rows],
    )
    apply_ip_context(db)
    db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('rules', ?)", (version,))


def locate(ip):
    try:
        rec = geo.get(ip)
    except ValueError:
        return "Unknown"
    if not rec:
        return "Unknown"
    parts = [
        rec.get("city", {}).get("names", {}).get("en"),
        (rec.get("subdivisions") or [{}])[0].get("names", {}).get("en"),
        rec.get("country", {}).get("names", {}).get("en"),
    ]
    return ", ".join(p for p in parts if p) or "Unknown"


def parse(line):
    m = LINE_RE.match(line)
    if not m:
        return None
    ip, stamp, req, status, agent = m.groups()
    if ip in IGNORED_IPS:
        return None
    fields = req.split(" ")
    path = fields[1] if len(fields) >= 2 else "(invalid request)"
    if ASSET_RE.search(path.split("?")[0]) or path.startswith(("/www-traffic", "/whos-hacking-me")):
        return None
    ts = datetime.strptime(stamp, "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc)
    method = fields[0][:16] if len(fields) >= 2 else ""
    # nginx writes "-" for a missing agent; "" means the line had no agent field at all.
    agent = "" if agent is None else agent[:300]
    path, status = path[:300], int(status)
    return (ts.isoformat(), ip, locate(ip), path, status, method, agent,
            *labels(path, status, ip, method, agent))


def add_visits(db, rows):
    db.executemany(
        f"INSERT INTO visits ({COLUMNS}) VALUES ({','.join('?' * len(COLUMNS.split(',')))})",
        rows,
    )


def store(db, lines):
    rows = []
    for line in lines:
        row = parse(line)
        if row:
            rows.append(row)
    add_visits(db, rows)
    apply_ip_context(db, {r[1] for r in rows})


def logged_agents(lines):
    """Map (ts, ip, path, status) to (method, agent) for one access log's lines."""
    found = {}
    for line in lines:
        row = parse(line)
        if row and row[6]:
            found[(row[0], row[1], row[3], row[4])] = (row[5], row[6])
    return found


def backfill_agents(db):
    """Once: fill in method and agent for stored rows that nginx still has logs for.
    Older rows keep blank values and are classified as before."""
    if db.execute("SELECT 1 FROM meta WHERE key = 'agents_backfilled'").fetchone():
        return
    found = {}
    for path in sorted(glob.glob(LOG + ".*.gz")):
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
            found.update(logged_agents(f))
    for path in (LOG + ".1", LOG):
        if os.path.exists(path):
            found.update(logged_agents(read_from(path, 0)[0]))
    if found:
        oldest = min(k[0] for k in found)
        rows = db.execute(
            "SELECT id, ts, ip, path, status FROM visits WHERE ts >= ? AND status != ? AND user_agent = ''",
            (oldest, SSH_STATUS),
        ).fetchall()
        db.executemany(
            "UPDATE visits SET method = ?, user_agent = ? WHERE id = ?",
            [(*found[key], r["id"]) for r in rows
             if (key := (r["ts"], r["ip"], r["path"], r["status"])) in found],
        )
    # Rules must run again over the newly filled rows.
    db.execute("DELETE FROM meta WHERE key = 'rules'")
    db.execute("INSERT INTO meta (key, value) VALUES ('agents_backfilled', '1')")


def read_from(path, pos):
    """Return complete lines after pos and the position just past them."""
    with open(path, "rb") as f:
        f.seek(pos)
        data = f.read()
    end = data.rfind(b"\n") + 1
    text = data[:end].decode("utf-8", "replace")
    return text.splitlines(), pos + end


def backfill(db):
    """First run only: load the rotated logs nginx still has, oldest first."""
    gz = sorted(
        glob.glob(LOG + ".*.gz"), key=lambda p: int(p.split(".")[-2]), reverse=True
    )
    for path in gz:
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
            store(db, f)
    if os.path.exists(LOG + ".1"):
        store(db, read_from(LOG + ".1", 0)[0])
    st = os.stat(LOG)
    lines, pos = read_from(LOG, 0)
    store(db, lines)
    db.execute("INSERT INTO state (id, inode, pos) VALUES (1, ?, ?)", (st.st_ino, pos))


def ingest(db):
    state = db.execute("SELECT inode, pos FROM state WHERE id = 1").fetchone()
    if state is None:
        backfill(db)
        return
    st = os.stat(LOG)
    inode, pos = state["inode"], state["pos"]
    if st.st_ino != inode:
        # Log rotated: finish the old file, which is now access.log.1.
        old = LOG + ".1"
        if os.path.exists(old) and os.stat(old).st_ino == inode:
            store(db, read_from(old, pos)[0])
        inode, pos = st.st_ino, 0
    elif st.st_size < pos:
        pos = 0
    lines, pos = read_from(LOG, pos)
    store(db, lines)
    db.execute("UPDATE state SET inode = ?, pos = ? WHERE id = 1", (inode, pos))


def store_ssh(db, lines):
    """Add failed SSH logins. Successful ones are never shown, and they mark
    that IP as the owner's, so its failed attempts are left out as well."""
    own = {r["ip"] for r in db.execute("SELECT ip FROM ssh_own_ips")}
    rows = []
    for line in lines:
        m = SSH_LINE_RE.match(line)
        if not m:
            continue
        stamp, message = m.groups()
        accepted = SSH_ACCEPTED_RE.match(message)
        if accepted:
            ip = accepted.group(1)
            if ip not in own:
                own.add(ip)
                db.execute("INSERT OR IGNORE INTO ssh_own_ips (ip) VALUES (?)", (ip,))
            rows = [r for r in rows if r[1] != ip]
            db.execute("DELETE FROM visits WHERE ip = ? AND status = ?", (ip, SSH_STATUS))
            continue
        invalid = SSH_INVALID_RE.match(message)
        real = SSH_REAL_RE.match(message)
        if invalid:
            name, ip = (invalid.group(1).strip() or SSH_NO_NAME)[:64], invalid.group(2)
        elif real:
            name, ip = SSH_REAL_ACCOUNT, real.group(1)
        else:
            continue
        if ip in own or ip in IGNORED_IPS:
            continue
        ts = datetime.fromisoformat(stamp).astimezone(timezone.utc).replace(microsecond=0)
        path = SSH_PREFIX + name
        rows.append(
            (ts.isoformat(), ip, locate(ip), path, SSH_STATUS, "", "", *labels(path, SSH_STATUS, ip))
        )
    add_visits(db, rows)


def sort_by_time(db):
    """Renumber rows oldest-first, since imported history arrives out of order."""
    rows = [tuple(r) for r in db.execute(f"SELECT {COLUMNS} FROM visits ORDER BY ts, id")]
    db.execute("DELETE FROM visits")
    add_visits(db, rows)


def backfill_ssh(db):
    """First run only: load the rotated auth logs, oldest first."""
    gz = sorted(
        glob.glob(SSH_LOG + ".*.gz"), key=lambda p: int(p.split(".")[-2]), reverse=True
    )
    for path in gz:
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
            store_ssh(db, f)
    if os.path.exists(SSH_LOG + ".1"):
        store_ssh(db, read_from(SSH_LOG + ".1", 0)[0])
    st = os.stat(SSH_LOG)
    lines, pos = read_from(SSH_LOG, 0)
    store_ssh(db, lines)
    db.execute(
        "INSERT INTO log_state (log, inode, pos) VALUES ('ssh', ?, ?)", (st.st_ino, pos)
    )
    sort_by_time(db)


def ingest_ssh(db):
    state = db.execute("SELECT inode, pos FROM log_state WHERE log = 'ssh'").fetchone()
    if state is None:
        backfill_ssh(db)
        return
    st = os.stat(SSH_LOG)
    inode, pos = state["inode"], state["pos"]
    if st.st_ino != inode:
        old = SSH_LOG + ".1"
        if os.path.exists(old) and os.stat(old).st_ino == inode:
            store_ssh(db, read_from(old, pos)[0])
        inode, pos = st.st_ino, 0
    elif st.st_size < pos:
        pos = 0
    lines, pos = read_from(SSH_LOG, pos)
    store_ssh(db, lines)
    db.execute(
        "UPDATE log_state SET inode = ?, pos = ? WHERE log = 'ssh'", (inode, pos)
    )


def used_bytes(db):
    size = db.execute("PRAGMA page_size").fetchone()[0]
    pages = db.execute("PRAGMA page_count").fetchone()[0]
    free = db.execute("PRAGMA freelist_count").fetchone()[0]
    return (pages - free) * size


def free_bytes():
    return shutil.disk_usage(DB_PATH.parent).free


def trim(db, free):
    """Delete the oldest visits when the database passes its ceiling: the cap, or, while
    disk is low, the size it had when disk got low. Deleted rows don't shrink the file,
    but their space is reused, so the file stops growing."""
    used = used_bytes(db)
    ceiling, reason = MAX_DB_BYTES, "size cap reached"
    if free < MIN_FREE_BYTES:
        frozen = db.execute("SELECT value FROM meta WHERE key = 'disk_ceiling'").fetchone()
        if frozen is None:
            frozen = (used,)
            db.execute("INSERT INTO meta (key, value) VALUES ('disk_ceiling', ?)", (str(used),))
        if int(frozen[0]) < ceiling:
            ceiling, reason = int(frozen[0]), "low disk space"
    else:
        db.execute("DELETE FROM meta WHERE key = 'disk_ceiling'")
    if used <= ceiling:
        return {"deleted": 0, "reason": None}
    count = db.execute("SELECT COUNT(*) FROM visits").fetchone()[0]
    remove = int(count * (1 - TRIM_TO * ceiling / used)) + 1
    cutoff = db.execute(
        "SELECT id FROM visits ORDER BY id LIMIT 1 OFFSET ?", (remove,)
    ).fetchone()
    if not cutoff:
        return {"deleted": 0, "reason": None}
    deleted = db.execute("DELETE FROM visits WHERE id < ?", (cutoff["id"],)).rowcount
    intel.prune(db)
    app.logger.warning("trim: deleted %d oldest visits (%s)", deleted, reason)
    return {"deleted": deleted, "reason": reason}


def follow():
    last_trim = 0
    try:
        with connect() as db:
            backfill_agents(db)
            relabel(db)
    except Exception as exc:
        app.logger.exception("relabel failed: %s", exc)
    try:
        with connect() as db:
            alerts.hello(db, MAX_DB_BYTES, MIN_FREE_BYTES)
    except Exception as exc:
        app.logger.exception("alert setup failed: %s", exc)
    last_ok = time.time()
    while True:
        try:
            with connect() as db:
                ingest(db)
                ingest_ssh(db)
            last_ok = time.time()
        except Exception as exc:
            app.logger.exception("ingest failed: %s", exc)
        # Kept apart from ingest, so a broken log read still gets noticed and emailed.
        if time.time() - last_trim >= TRIM_EVERY:
            last_trim = time.time()
            try:
                with connect() as db:
                    free = free_bytes()
                    trimmed = trim(db, free)
                    stalled = int(time.time() - last_ok) if time.time() - last_ok > 30 else 0
                    alerts.check(db, used=used_bytes(db), cap=MAX_DB_BYTES, free=free,
                                 floor=MIN_FREE_BYTES, trimmed=trimmed, stalled=stalled)
            except Exception as exc:
                app.logger.exception("trim or alert check failed: %s", exc)
        time.sleep(2)


@app.after_request
def security_headers(response):
    response.headers["Content-Security-Policy"] = CSP
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.route("/whos-hacking-me", strict_slashes=False)
def page():
    return send_file(PAGE, mimetype="text/html", max_age=0)


def where_clause(body, skip=None):
    """Build the WHERE clause for the page's filters, leaving out column `skip`."""
    clauses, args = ["1"], []
    filters = body.get("filters") or {}
    for column, spec in filters.items():
        if column not in FILTER_COLUMNS:
            abort(400)
        if column == skip:
            continue
        values = spec.get("values") or []
        if len(values) > MAX_FILTER_VALUES:
            abort(400)
        marks = ",".join("?" * len(values))
        if spec.get("mode") == "in":
            clauses.append(f"{column} IN ({marks})")
            args += values
        elif values:
            clauses.append(f"{column} NOT IN ({marks})")
            args += values
    # Both dates arrive as UTC, and the end date is exclusive.
    if body.get("from"):
        clauses.append("ts >= ?")
        args.append(body["from"])
    if body.get("to"):
        clauses.append("ts < ?")
        args.append(body["to"])
    if body.get("hide_failed"):
        clauses.append("status BETWEEN 1 AND 399")
    return " AND ".join(clauses), args


@app.route("/whos-hacking-me/page.js")
def script():
    return send_file(BASE / "page.js", mimetype="text/javascript", max_age=0)


@app.route("/whos-hacking-me/chart.umd.js")
def chart_library():
    return send_file(BASE / "chart.umd.js", mimetype="text/javascript", max_age=3600)


@app.route("/whos-hacking-me/charts.js")
def chart_script():
    return send_file(BASE / "charts.js", mimetype="text/javascript", max_age=0)


@app.route("/whos-hacking-me/api/visits", methods=["POST"])
def visits():
    body = request.get_json(force=True, silent=True) or {}
    where, args = where_clause(body)
    after, before = body.get("after"), body.get("before")
    limit = min(int(body.get("limit", 500)), PAGE_LIMIT)
    offset = int(body.get("offset", 0))
    sort = body.get("sort") or {}
    order = "id DESC"
    if sort.get("col") in SORT_COLUMNS:
        direction = "ASC" if sort.get("dir") == "asc" else "DESC"
        order = f"{sort['col']} {direction}, id DESC"
    query, params = where, list(args)
    if after is not None:
        query += " AND id > ?"
        params.append(int(after))
    if before is not None:
        query += " AND id < ?"
        params.append(int(before))
    with connect() as db:
        rows = db.execute(
            f"SELECT id, ts, ip, location, hacking_me, category, after_what, path, status, result "
            f"FROM public_visits WHERE {query} ORDER BY {order} LIMIT ? OFFSET ?",
            (*params, limit, offset),
        ).fetchall()
        result = {
            "visits": [dict(r) for r in rows],
            "max_id": db.execute("SELECT MAX(id) FROM public_visits").fetchone()[0] or 0,
        }
        # Counting scans the table, so a refresh only recounts when something new matched.
        if body.get("counts") or (after is not None and rows):
            result["total"] = db.execute("SELECT COUNT(*) FROM public_visits").fetchone()[0]
            counts = db.execute(
                f"SELECT COUNT(*) AS matching, "
                f"COUNT(DISTINCT CASE WHEN ip != ? THEN ip END) AS ips "
                f"FROM public_visits WHERE {where}",
                (HIDDEN, *args),
            ).fetchone()
            result.update(dict(counts))
    return jsonify(result)


@app.route("/whos-hacking-me/api/facets", methods=["POST"])
def facets():
    """Values for one column's filter list, narrowed by the other columns' filters."""
    body = request.get_json(force=True, silent=True) or {}
    column = body.get("col")
    if column not in FILTER_COLUMNS:
        abort(400)
    where, args = where_clause(body, skip=column)
    search = (body.get("q") or "").strip()
    if search:
        escaped = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        where += f" AND {column} LIKE ? ESCAPE '\\'"
        args.append(f"%{escaped}%")
    with connect() as db:
        rows = db.execute(
            f"SELECT {column} AS value, COUNT(*) AS n FROM public_visits WHERE {where} "
            f"GROUP BY {column} ORDER BY n DESC, value LIMIT ?",
            (*args, MAX_FACET_VALUES),
        ).fetchall()
        distinct = db.execute(
            f"SELECT COUNT(DISTINCT {column}) FROM public_visits WHERE {where}", args
        ).fetchone()[0]
    return jsonify(values=[dict(r) for r in rows], distinct=distinct)


def round_down(n):
    """Keep two significant figures, so one new username can't be spotted in the count."""
    scale = 10 ** max(len(str(n)) - 2, 0)
    return n // scale * scale


def timeline(db, since, now, step):
    """SSH and web attempts per hour or day, with empty buckets filled in as zero.
    Same rows as the "how" chart, so the totals always match it."""
    width, delta = (13, timedelta(hours=1)) if step == "hour" else (10, timedelta(days=1))
    rows = db.execute(
        "SELECT substr(ts, 1, :n) AS bucket, SUM(status = :ssh) AS ssh, SUM(status != :ssh) AS web "
        "FROM public_visits WHERE hacking_me = 'Yes' AND ts >= :since GROUP BY bucket",
        {"n": width, "ssh": SSH_STATUS, "since": since},
    ).fetchall()
    counts = {r["bucket"]: (r["ssh"], r["web"]) for r in rows}

    def floor(moment):
        moment = moment.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0)
        return moment if step == "hour" else moment.replace(hour=0)

    if since:
        start = floor(datetime.fromisoformat(since))
    elif counts:
        start = floor(datetime.fromisoformat(min(counts) + ("" if step == "hour" else "T00") + ":00+00:00"))
    else:
        start = floor(now)
    points, moment, end = [], start, floor(now)
    while moment <= end:
        ssh, web = counts.get(moment.isoformat()[:width], (0, 0))
        points.append({"t": moment.isoformat(), "ssh": ssh, "web": web})
        moment += delta
    return {"step": step, "points": points}


def chart_data(db, since, names_before, now, step):
    """All charts for one window. Only usernames read past the public view."""
    routes = db.execute(
        "SELECT status = ? AS ssh, COUNT(*) AS count FROM public_visits "
        "WHERE hacking_me = 'Yes' AND ts >= ? GROUP BY ssh ORDER BY count DESC",
        (SSH_STATUS, since),
    ).fetchall()
    how = [{"label": SSH_LABEL if r["ssh"] else WEB_LABEL, "count": r["count"]} for r in routes]

    # Kinds of attack only: a scanner's follow-up requests aren't a kind of attack.
    categories = db.execute(
        "SELECT category AS label, COUNT(*) AS count FROM public_visits "
        "WHERE hacking_me = 'Yes' AND status != ? AND category != ? AND ts >= ? "
        "GROUP BY category ORDER BY count DESC, label",
        (SSH_STATUS, FOLLOW_UP, since),
    ).fetchall()
    slices = [dict(r) for r in categories[:TOP_CATEGORIES]]
    rest = sum(r["count"] for r in categories[TOP_CATEGORIES:])
    if rest:
        slices.append({"label": "Other", "count": rest})

    # Locations read "City, Region, Country"; unplaced IPs count towards Other.
    by_country = {}
    other_places = 0
    places = db.execute(
        "SELECT location, COUNT(*) AS count FROM public_visits "
        "WHERE hacking_me = 'Yes' AND ts >= ? GROUP BY location",
        (since,),
    )
    for place in places:
        country = place["location"].rsplit(", ", 1)[-1]
        if country == "Unknown":
            other_places += place["count"]
        else:
            by_country[country] = by_country.get(country, 0) + place["count"]
    ranked = sorted(by_country.items(), key=lambda item: (-item[1], item[0]))
    countries = [{"label": c, "count": n} for c, n in ranked[:TOP_COUNTRIES]]
    other_places += sum(n for _, n in ranked[TOP_COUNTRIES:])
    if other_places:
        countries.append({"label": "Other", "count": other_places})

    # Real-account attempts count towards Other and are never told apart, because
    # any separate number would show whether a guessed account exists.
    ssh = {
        "real": SSH_PREFIX + SSH_REAL_ACCOUNT,
        "blank": SSH_PREFIX + SSH_NO_NAME,
        "status": SSH_STATUS,
        "since": since,
        "before": names_before,
    }
    scope = (
        "status = :status AND ts >= :since AND ts < :before "
        "AND ip NOT IN (SELECT ip FROM ssh_own_ips)"
    )
    names = db.execute(
        f"SELECT path, COUNT(*) AS count FROM visits WHERE {scope} "
        "AND path NOT IN (:real, :blank) GROUP BY path ORDER BY count DESC, path",
        ssh,
    ).fetchall()
    all_attempts = db.execute(f"SELECT COUNT(*) FROM visits WHERE {scope}", ssh).fetchone()[0]
    top = names[:TOP_USERNAMES]
    username_slices = [
        {"label": r["path"].removeprefix(SSH_PREFIX), "count": r["count"]} for r in top
    ]
    other = all_attempts - sum(r["count"] for r in top)
    if other:
        username_slices.append({"label": "Other", "count": other})
    # Networks by unique attacker IPs, from the local ASN file (no outside calls).
    networks = {}
    attacker_ips = db.execute(
        "SELECT ip, COUNT(*) AS n FROM public_visits WHERE hacking_me = 'Yes' AND ts >= ? GROUP BY ip",
        (since,),
    ).fetchall()
    for r in attacker_ips:
        number, org = intel.lookup_asn(r["ip"])
        if number is None:
            continue
        entry = networks.setdefault(number, {"asn": number, "org": org, "ips": 0, "attempts": 0})
        entry["ips"] += 1
        entry["attempts"] += r["n"]
    asn_rows = sorted(networks.values(), key=lambda e: (-e["ips"], -e["attempts"], e["asn"]))
    return {
        "asns": {"rows": asn_rows[:TOP_NETWORKS], "total_ips": len(attacker_ips), "networks": len(networks)},
        "how": {"slices": how, "total": sum(r["count"] for r in routes)},
        "categories": {"slices": slices, "total": sum(r["count"] for r in categories)},
        "timeline": timeline(db, since, now, step),
        "countries": {"slices": countries, "total": sum(c["count"] for c in countries)},
        "usernames": {
            "slices": username_slices,
            "total": all_attempts,
            "shown": len(top),
            "names_tried": round_down(len(names)),
        },
    }


chart_cache = {}
chart_lock = threading.Lock()


@app.route("/whos-hacking-me/api/charts")
def charts():
    window = request.args.get("window", "7d")
    if window not in CHART_WINDOWS:
        abort(400)
    # Held while querying, so a burst of visitors runs the query only once.
    with chart_lock:
        cached = chart_cache.get(window)
        if cached and time.monotonic() - cached[0] < CHART_CACHE_SECONDS:
            return jsonify(cached[1])
        days = CHART_WINDOWS[window]
        now = datetime.now(timezone.utc).replace(microsecond=0)
        since = (now - timedelta(days=days)).isoformat() if days else ""
        with connect() as db:
            data = chart_data(db, since, (now - USERNAME_DELAY).isoformat(), now, CHART_STEPS[window])
        chart_cache[window] = (time.monotonic(), data)
    return jsonify(data)


TOP_PROFILE = 5


@app.route("/whos-hacking-me/api/ip/<address>")
def ip_profile(address):
    """An attacker's profile: what our logs show plus the cached public lookups.
    Only IPs the table already shows (a Yes row) have one, so this reveals no one else."""
    try:
        ip = str(ipaddress.ip_address(address))
    except ValueError:
        abort(404)
    # Same rows public_visits shows with this IP, but through the ip index.
    mine = "FROM visits WHERE ip = ? AND hacking_me = 'Yes' AND ip NOT IN (SELECT ip FROM ssh_own_ips)"
    with connect() as db:
        stats = db.execute(
            f"SELECT COUNT(*) AS total, MIN(ts) AS first_seen, MAX(ts) AS last_seen, "
            f"SUM(status = ?) AS ssh {mine}",
            (SSH_STATUS, ip),
        ).fetchone()
        if not stats["total"]:
            abort(404)
        categories = db.execute(
            f"SELECT category AS value, COUNT(*) AS n {mine} GROUP BY category ORDER BY n DESC LIMIT ?",
            (ip, TOP_PROFILE),
        ).fetchall()
        paths = db.execute(
            f"SELECT path AS value, COUNT(*) AS n {mine} AND status != ? "
            f"GROUP BY path ORDER BY n DESC LIMIT ?",
            (ip, SSH_STATUS, TOP_PROFILE),
        ).fetchall()
        lookups = intel.load(db, ip)
    response = jsonify(
        ip=ip,
        location=locate(ip),
        attempts={
            "total": stats["total"], "ssh": stats["ssh"] or 0, "web": stats["total"] - (stats["ssh"] or 0),
            "first_seen": stats["first_seen"], "last_seen": stats["last_seen"],
            "categories": [dict(r) for r in categories], "paths": [dict(r) for r in paths],
        },
        lookups=lookups,
    )
    response.headers["Cache-Control"] = "public, max-age=60"
    return response


init_db()
threading.Thread(target=follow, daemon=True).start()
threading.Thread(target=intel.worker, args=(connect,), daemon=True).start()
