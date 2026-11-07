"""Tests for the chart API and the public table, run against a throwaway database.

Run with: python3 /opt/www-traffic/test_charts.py
"""
import json
import re
import sys
import tempfile
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path

BASE = Path("/opt/www-traffic")
HOSTILE = "<img src=x onerror=alert(1)>"
OWN_IP = "68.84.208.100"
REAL = "realaccountname"


def load_app(db_path):
    source = (BASE / "app.py").read_text()
    source = re.sub(r"^DB_PATH = .*$", f"DB_PATH = Path({str(db_path)!r})", source, flags=re.M)
    source = re.sub(r"^threading\.Thread\(.*$", "", source, flags=re.M)
    sys.path.insert(0, str(BASE))
    module = types.ModuleType("chart_test_app")
    exec(compile(source, "app.py", "exec"), module.__dict__)
    return module


def stamp(hours_ago):
    moment = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
    return moment.replace(microsecond=0).isoformat()


def auth_line(hours_ago, message):
    return f"{stamp(hours_ago)} host sshd[1]: {message}\n"


def main():
    results = []

    def check(name, passed):
        results.append(bool(passed))
        print(("PASS " if passed else "FAIL ") + name)

    with tempfile.TemporaryDirectory() as tmp:
        app = load_app(Path(tmp) / "t.db")
        lines = [auth_line(2, f"Invalid user {HOSTILE} from 45.1.1.1 port 5") for _ in range(50)]
        lines += [auth_line(2, "Invalid user admin from 45.1.1.2 port 5") for _ in range(40)]
        for i in range(12):
            lines += [auth_line(2, f"Invalid user name{i:02d} from 45.1.1.3 port 5") for _ in range(12 - i)]
        lines += [auth_line(100, "Invalid user oldname from 45.1.1.4 port 5") for _ in range(30)]
        lines += [auth_line(2, "Invalid user  from 45.1.1.5 port 5") for _ in range(9)]
        lines += [auth_line(0.2, "Invalid user justnow from 45.1.1.8 port 5") for _ in range(200)]
        lines += [auth_line(2, f"Connection closed by authenticating user {REAL} 45.1.1.6 port 5 [preauth]") for _ in range(70)]
        lines += [auth_line(2, f"Invalid user mineonly from {OWN_IP} port 5") for _ in range(90)]
        lines += [auth_line(0, f"Accepted publickey for ubuntu from {OWN_IP} port 5 ssh2")]
        with app.connect() as db:
            app.store_ssh(db, lines)
            web = []
            for path in (["/.env"] * 20 + ["/wp-login.php"] * 15 + ["/x.php"] * 10 + ["/mcp"] * 8
                         + ["/phpmyadmin/"] * 6 + ["/livewire/update"] * 5 + ["/remote/login"] * 4
                         + ["/robots.txt"] * 30 + ["/"] * 30 + ["/nothing-here"] * 30):
                web.append((stamp(1), "45.2.2.2", "Somewhere", path, 404, *app.labels(path, 404, "45.2.2.2")))
            web += [(stamp(1), "45.3.3.3", "Paris, Ile-de-France, France", "/.env", 404, *app.labels("/.env", 404, "45.3.3.3"))] * 25
            web += [(stamp(1), "45.3.3.4", "Lyon, Rhone, France", "/.env", 404, *app.labels("/.env", 404, "45.3.3.4"))] * 5
            web += [(stamp(1), "45.3.3.5", "Unknown", "/.env", 404, *app.labels("/.env", 404, "45.3.3.5"))] * 3
            web += [(stamp(1), "45.3.3.6", "Berlin, Berlin, Germany", "/", 200, *app.labels("/", 200, "45.3.3.6"))] * 99
            app.add_visits(db, web)
        client = app.app.test_client()

        def post(path, body):
            return client.post("/whos-hacking-me/api/" + path, json=body).get_json()

        seven = client.get("/whos-hacking-me/api/charts?window=7d").get_json()
        day = client.get("/whos-hacking-me/api/charts?window=24h").get_json()
        names = seven["usernames"]
        labels = [s["label"] for s in names["slices"]]

        how = {s["label"]: s["count"] for s in seven["how"]["slices"]}
        ssh_rows = 50 + 40 + sum(12 - i for i in range(12)) + 30 + 9 + 200 + 70
        check("chart 1 has exactly SSH and web slices", set(how) == {"SSH", "Web (HTTP)"})
        check("chart 1 counts SSH attempts", how["SSH"] == ssh_rows)
        check("chart 1 total equals its slices", seven["how"]["total"] == sum(how.values()))

        cats = seven["categories"]
        cat_labels = [s["label"] for s in cats["slices"]]
        check("chart 2 excludes SSH entirely", "SSH login attempt" not in cat_labels)
        check("chart 2 total equals web attempts", cats["total"] == how["Web (HTTP)"])
        check("chart 2 is top 6 plus Other", len(cat_labels) == 7 and cat_labels[-1] == "Other")
        check("chart 2 counts only Yes rows", not {"Unknown probe", "Search crawler", "Site visit"} & set(cat_labels))

        named = [l for l in labels if l != "Other"]
        check("chart 3 is top 8 plus Other", len(named) == 8 and labels[-1] == "Other")
        check("hostile username stays exact plain text", labels[0] == HOSTILE)
        check("usernames under an hour old are left out", "justnow" not in labels)
        check("real account names never appear", REAL not in json.dumps(seven) and "(real account)" not in json.dumps(seven))
        check("blank usernames are left out", "(no username)" not in labels)
        check("owner's attempts are left out", "mineonly" not in json.dumps(seven))
        check("no separate real-account figure exists", set(names) == {"slices", "total", "shown", "names_tried"})
        check("real-account attempts fall into Other", names["total"] == ssh_rows - 200
              and names["total"] == sum(s["count"] for s in names["slices"]))
        check("username count is rounded", app.round_down(5203) == 5200 and app.round_down(968) == 960 and app.round_down(7) == 7)
        check("24h window drops older rows", "oldname" not in [s["label"] for s in day["usernames"]["slices"]])
        allt = client.get("/whos-hacking-me/api/charts?window=all").get_json()
        check("all time keeps older rows", "oldname" in [s["label"] for s in allt["usernames"]["slices"]])

        check("usernames tried counts only fake names older than an hour", names["names_tried"] == 15)

        rows = post("visits", {"limit": 1000, "counts": True})
        ssh_public = [v for v in rows["visits"] if v["status"] == 0]
        check("table shows SSH rows", len(ssh_public) == ssh_rows)
        check("table SSH page has no username", {v["path"] for v in ssh_public} == {"SSH login attempt"})
        check("table SSH category has no username", {v["category"] for v in ssh_public} == {"SSH login attempt"})
        check("table SSH detail has no username", {v["after_what"] for v in ssh_public} == {"Logging in over SSH"})
        raw = json.dumps(rows)
        check("table data never mentions a username", not any(x in raw for x in ("SSH: ", "Logging in as", REAL, "real account", "name01", "justnow", "oldname", "onerror")))
        check("real and fake attempts look identical in the table",
              len({(v["path"], v["category"], v["after_what"], v["result"], v["hacking_me"]) for v in ssh_public}) == 1)
        for col, q in (("path", "name01"), ("after_what", "name01"), ("path", "real"), ("after_what", "real")):
            check(f"filter list {col} can't find {q}", post("facets", {"col": col, "q": q})["distinct"] == 0)
        for col, value in (("path", "SSH: admin"), ("path", "SSH: (real account)"), ("after_what", "Logging in as admin"), ("after_what", "Logging in to a real account")):
            check(f"filtering for {value} finds nothing", post("visits", {"filters": {col: {"mode": "in", "values": [value]}}, "counts": True})["matching"] == 0)

        places = {s["label"]: s["count"] for s in seven["countries"]["slices"]}
        check("cities and regions roll up into one country", places.get("France") == 30)
        check("rows not marked Yes aren't counted by country", "Germany" not in places)
        check("Hidden never appears as a place", "Hidden" not in places)
        check("unplaced IPs aren't shown as a country", "Unknown" not in places)
        check("countries are top 6 plus Other at most", len(places) <= 7)
        check("country total matches the Yes total", seven["countries"]["total"] == seven["how"]["total"])

        check("bad window is refused", client.get("/whos-hacking-me/api/charts?window=x").status_code == 400)

        with app.connect() as db:
            app.store_ssh(db, [auth_line(3, "Invalid user brandnew from 45.1.1.7 port 5")] * 500)
        again = client.get("/whos-hacking-me/api/charts?window=7d").get_json()
        check("repeat calls within a minute are served from the cache", again == seven)
        app.chart_cache.clear()
        fresh = client.get("/whos-hacking-me/api/charts?window=7d").get_json()
        check("data refreshes once the cache expires", fresh["usernames"]["slices"][0]["label"] == "brandnew")

        for route in ("/whos-hacking-me/", "/whos-hacking-me/api/charts?window=7d", "/whos-hacking-me/chart.umd.js"):
            headers = client.get(route, follow_redirects=True).headers
            check(f"security headers on {route}", "script-src 'self'" in headers.get("Content-Security-Policy", "")
                  and headers.get("X-Content-Type-Options") == "nosniff")

    script = (BASE / "charts.js").read_text()
    risky = r"innerHTML|outerHTML|insertAdjacentHTML|document\.write"
    check("charts.js uses no HTML-writing calls", not re.search(risky + r"|eval\(", script))
    check("Chart.js library uses no HTML-writing calls", not re.search(risky, (BASE / "chart.umd.js").read_text()))
    page = (BASE / "page.html").read_text()
    check("no CDN scripts on the page", not re.search(r'<script[^>]+src="https?:', page))

    print(f"\n{sum(results)} of {len(results)} passed")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
