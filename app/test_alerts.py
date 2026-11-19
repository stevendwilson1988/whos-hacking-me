"""Tests for storage limits and email alerts. Emails are captured, never sent.

Run with: python3 test_alerts.py
"""
import re
import sys
import tempfile
import types
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import alerts  # noqa: E402

GB = 1024 ** 3


def load_app(db_path):
    source = (HERE / "app.py").read_text()
    source = re.sub(r"^BASE = .*$", f"BASE = Path({str(HERE)!r})", source, flags=re.M)
    source = re.sub(r"^DB_PATH = .*$", f"DB_PATH = Path({str(db_path)!r})", source, flags=re.M)
    source = re.sub(r"^GEO_PATH = .*$", "GEO_PATH = Path('/opt/www-traffic/dbip-city-lite.mmdb')", source, flags=re.M)
    source = re.sub(r"^threading\.Thread\(.*$", "", source, flags=re.M)
    module = types.ModuleType("alerts_test_app")
    exec(compile(source, "app.py", "exec"), module.__dict__)
    return module


def main():
    results = []

    def check(name, passed):
        results.append(bool(passed))
        print(("PASS " if passed else "FAIL ") + name)

    sent = []
    alerts.notify = lambda subject, body: sent.append(subject) or True

    with tempfile.TemporaryDirectory() as tmp:
        app = load_app(Path(tmp) / "t.db")
        ts = datetime.now(timezone.utc).replace(microsecond=0).isoformat()

        def add(db, n):
            db.executemany(
                "INSERT INTO visits (ts, ip, location, path, status, category, after_what, result, hacking_me) "
                "VALUES (?, '45.1.1.1', '', ?, 404, 'Secret harvesting', '', '', 'Yes')",
                [(ts, "/.env?" + "x" * 400) for _ in range(n)])

        def run(db, used=None, cap=10 * GB, free=30 * GB, trimmed=None, stalled=0):
            alerts.check(db, used=used if used is not None else app.used_bytes(db), cap=cap, free=free,
                         floor=5 * GB, trimmed=trimmed or {"deleted": 0, "reason": None}, stalled=stalled)

        with app.connect() as db:
            check("WAL size limit is set", db.execute("PRAGMA journal_size_limit").fetchone()[0] == app.WAL_LIMIT_BYTES)

            # Database size: once at 80%, quiet in between, once when it clears, again on a new rise.
            sent.clear()
            for share in (0.5, 0.81, 0.9, 0.77, 0.76):
                run(db, used=int(share * 10 * GB))
            check("80% alert emails once", sent == ["Database at 81% of its cap"])
            run(db, used=int(0.7 * 10 * GB))
            check("clears below 75%", sent[-1] == "Database back under its warning level" and len(sent) == 2)
            run(db, used=int(0.85 * 10 * GB))
            check("fires again on a new rise", len(sent) == 3)

            # Disk floor, with 1 GiB of slack before clearing.
            run(db, used=0)  # clears the database alert left on above
            sent.clear()
            run(db, used=0, free=4 * GB)
            run(db, used=0, free=3 * GB)
            run(db, used=0, free=int(5.5 * GB))
            check("low disk emails once and holds in the slack band", sent == ["Low disk space: 4.00 GiB free"])
            run(db, used=0, free=7 * GB)
            check("disk recovery emails", sent[-1] == "Disk space recovered")

            # Stalled logging.
            sent.clear()
            run(db, used=0, stalled=300)
            check("short stall is quiet", sent == [])
            run(db, used=0, stalled=700)
            run(db, used=0, stalled=760)
            check("10-minute stall emails once", sent == ["Logging has stopped"])
            run(db, used=0, stalled=0)
            check("recovery emails", sent[-1] == "Logging is working again")

            # Trim emails are limited to one a day.
            sent.clear()
            run(db, used=0, trimmed={"deleted": 1234, "reason": "size cap reached"})
            run(db, used=0, trimmed={"deleted": 50, "reason": "size cap reached"})
            check("trim emails at most once a day", sent == ["Deleted 1,234 old visits (size cap reached)"])

            # Trimming against the cap.
            add(db, 3000)
            used = app.used_bytes(db)
            app.MAX_DB_BYTES = used // 2
            result = app.trim(db, free=30 * GB)
            check("cap trim deletes the oldest visits", result["deleted"] > 0 and result["reason"] == "size cap reached")
            check("cap trim gets under the cap", app.used_bytes(db) <= app.MAX_DB_BYTES)
            check("nothing more to trim right after", app.trim(db, free=30 * GB)["deleted"] == 0)

            # Low disk freezes the database at its current size instead of trimming it at once.
            app.MAX_DB_BYTES = 100 * GB
            first = app.trim(db, free=1 * GB)
            check("low disk doesn't delete straight away", first["deleted"] == 0)
            frozen = int(db.execute("SELECT value FROM meta WHERE key = 'disk_ceiling'").fetchone()[0])
            add(db, 3000)
            grown = app.trim(db, free=1 * GB)
            check("low disk trims growth past the frozen size",
                  grown["deleted"] > 0 and grown["reason"] == "low disk space" and app.used_bytes(db) <= frozen)
            app.trim(db, free=30 * GB)
            check("frozen size is forgotten once disk recovers",
                  db.execute("SELECT 1 FROM meta WHERE key = 'disk_ceiling'").fetchone() is None)

            # Setup email: once per settings, again when they change.
            sent.clear()
            alerts.hello(db, 5 * GB, 5 * GB)
            alerts.hello(db, 5 * GB, 5 * GB)
            check("setup email sends once", sent == ["Alerts are set up"])
            alerts.hello(db, 10 * GB, 5 * GB)
            check("setup email sends again when settings change", len(sent) == 2)

        # Without settings, delivery is skipped quietly.
        alerts.notify = alerts.deliver
        check("unconfigured alerts don't crash or send", alerts.deliver("x", "y") is False)

    check("cap comes from WHT_MAX_DB_GB", "WHT_MAX_DB_GB" in (HERE / "app.py").read_text())

    print(f"{sum(results)}/{len(results)} passed")
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
