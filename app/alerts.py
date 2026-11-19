"""Email alerts about the server's health: database size, trims, low disk, stalled logging.

Settings come from the environment (set by systemd from /etc/www-traffic/alerts.env, kept
out of git). The Gmail app password comes from a systemd credential, so it is never in the
environment or readable by the ubuntu user.

Each condition emails once when it starts and once when it clears, never every minute.
"""
import hashlib
import logging
import os
import smtplib
import ssl
import threading
import time
from email.message import EmailMessage
from pathlib import Path

SMTP_HOST, SMTP_PORT = "smtp.gmail.com", 587
SUBJECT_PREFIX = "[scratchbuild] "
PAGE = "https://scratchbuild.net/whos-hacking-me/"

DB_WARN, DB_CLEAR = 0.80, 0.75            # share of the cap
DISK_CLEAR_EXTRA = 1024 ** 3              # disk must recover 1 GiB past the floor to clear
STALL_AFTER = 10 * 60                     # seconds without a successful log read
TRIM_EMAIL_EVERY = 24 * 3600              # at most one trim email a day

log = logging.getLogger("alerts")


def gib(n):
    return f"{n / 1024 ** 3:.2f} GiB"


def password():
    folder = os.environ.get("CREDENTIALS_DIRECTORY")
    if not folder:
        return ""
    try:
        # Google shows app passwords in groups of four; the spaces aren't part of it.
        return "".join(Path(folder, "smtp-password").read_text().split())
    except OSError:
        return ""


def settings():
    return {"from": os.environ.get("WHT_ALERT_FROM", ""), "to": os.environ.get("WHT_ALERT_TO", "")}


def deliver(subject, body):
    """Send in the background so a slow mail server never holds up logging."""
    cfg, secret = settings(), password()
    if not (cfg["from"] and cfg["to"] and secret):
        log.warning("alert not emailed (alerts not configured): %s", subject)
        return False
    msg = EmailMessage()
    msg["Subject"] = SUBJECT_PREFIX + subject
    msg["From"], msg["To"] = cfg["from"], cfg["to"]
    msg.set_content(body + f"\n\n{PAGE}\n")

    def go():
        try:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as smtp:
                smtp.starttls(context=ssl.create_default_context())
                smtp.login(cfg["from"], secret)
                smtp.send_message(msg)
            log.warning("alert emailed: %s", subject)
        except Exception as exc:
            log.error("alert email failed (%s): %s", subject, exc)

    threading.Thread(target=go, daemon=True).start()
    return True


# Tests replace this to capture emails instead of sending them.
notify = deliver


def get(db, key):
    row = db.execute("SELECT value FROM meta WHERE key = ?", ("alert:" + key,)).fetchone()
    return row[0] if row else None


def put(db, key, value):
    db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", ("alert:" + key, value))


def latch(db, key, on, started, cleared):
    """on: True starts the condition, False clears it, None (in between) keeps it as is."""
    was = get(db, key) == "on"
    if on and not was:
        notify(*started)
        put(db, key, "on")
    elif on is False and was:
        notify(*cleared)
        put(db, key, "off")


def hello(db, cap, floor):
    """One email whenever the alert settings change, which doubles as the setup test."""
    cfg = settings()
    version = hashlib.sha256(f"{cfg['from']}|{cfg['to']}|{cap}|{floor}".encode()).hexdigest()
    if get(db, "hello") == version:
        return
    if notify("Alerts are set up",
              "This is a test from the Who's Hacking Me server. You'll get an email when:\n"
              f"- the database reaches {DB_WARN:.0%} of its {gib(cap)} cap\n"
              "- old visits are deleted to make room (at most one email a day)\n"
              f"- free disk space drops below {gib(floor)}\n"
              f"- the server can't read its logs for {STALL_AFTER // 60} minutes"):
        put(db, "hello", version)


def check(db, *, used, cap, free, floor, trimmed, stalled):
    share = used / cap if cap else 0
    latch(db, "db_size",
          True if share >= DB_WARN else False if share < DB_CLEAR else None,
          (f"Database at {share:.0%} of its cap",
           f"The database holds {gib(used)} of its {gib(cap)} cap. When it's full, the oldest visits "
           f"are deleted to make room. Free disk: {gib(free)}.\n\nTo keep more history, raise "
           "WHT_MAX_DB_GB in /etc/www-traffic/alerts.env and restart www-traffic."),
          ("Database back under its warning level", f"The database holds {gib(used)} of its {gib(cap)} cap."))
    latch(db, "disk",
          True if free < floor else False if free >= floor + DISK_CLEAR_EXTRA else None,
          (f"Low disk space: {gib(free)} free",
           f"Free disk space is {gib(free)}, under the {gib(floor)} floor. The database has stopped "
           "growing: from now on, the oldest visits are deleted to make room for new ones.\n\n"
           "Free up space on the server (old logs, backups) to let it grow again."),
          ("Disk space recovered", f"Free disk space is back to {gib(free)}. The database can grow again."))
    latch(db, "stalled",
          True if stalled >= STALL_AFTER else False if stalled == 0 else None,
          ("Logging has stopped",
           f"The server hasn't read its logs successfully for {stalled // 60} minutes, so new visits "
           "aren't being recorded. Check: journalctl -u www-traffic -n 50"),
          ("Logging is working again", "The server is reading its logs again."))
    if trimmed["deleted"]:
        last = float(get(db, "trim_sent") or 0)
        if time.time() - last >= TRIM_EMAIL_EVERY:
            notify(f"Deleted {trimmed['deleted']:,} old visits ({trimmed['reason']})",
                   f"{trimmed['deleted']:,} of the oldest visits were deleted to make room "
                   f"({trimmed['reason']}). The database now holds {gib(used)}; free disk is {gib(free)}.\n\n"
                   "Further deletions in the next 24 hours won't be emailed.")
            put(db, "trim_sent", str(time.time()))
