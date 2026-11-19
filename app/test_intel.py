"""Tests for attacker profiles: parsing outside data, the lookup queue and the /api/ip gate.

No network: lookups are replaced with canned data. Run with: python3 test_intel.py
"""
import json
import re
import sys
import tempfile
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import intel  # noqa: E402

HOSTILE = "<img src=x onerror=alert(1)>"

RDAP = {
    "name": "COGENT-A", "startAddress": "38.0.0.0", "endAddress": "38.255.255.255",
    "cidr0_cidrs": [{"v4prefix": "38.0.0.0", "length": 8}],
    "entities": [{
        "roles": ["registrant"],
        "vcardArray": ["vcard", [["fn", {}, "text", "Cogent Communications, LLC"]]],
        "entities": [
            {"roles": ["abuse"], "vcardArray": ["vcard", [["email", {}, "text", "Abuse@CogentCo.com"]]]},
            {"roles": ["noc"], "vcardArray": ["vcard", [["email", {}, "text", "noc@cogentco.com"]]]},
        ],
    }],
}
SHODAN = {
    "hostnames": ["vps.example.com", HOSTILE], "ports": [22, 80, 99999, "x"],
    "tags": ["scanner", "self-signed"], "vulns": ["CVE-2026-10822", "not-a-cve", HOSTILE],
}


def load_app(db_path):
    source = (HERE / "app.py").read_text()
    source = re.sub(r"^BASE = .*$", f"BASE = Path({str(HERE)!r})", source, flags=re.M)
    source = re.sub(r"^DB_PATH = .*$", f"DB_PATH = Path({str(db_path)!r})", source, flags=re.M)
    source = re.sub(r"^GEO_PATH = .*$", "GEO_PATH = Path('/opt/www-traffic/dbip-city-lite.mmdb')", source, flags=re.M)
    source = re.sub(r"^threading\.Thread\(.*$", "", source, flags=re.M)
    module = types.ModuleType("intel_test_app")
    exec(compile(source, "app.py", "exec"), module.__dict__)
    return module


def main():
    results = []

    def check(name, passed):
        results.append(bool(passed))
        print(("PASS " if passed else "FAIL ") + name)

    reg = intel.parse_rdap(RDAP)
    check("rdap name", reg["name"] == "COGENT-A")
    check("rdap owner", reg["org"] == "Cogent Communications, LLC")
    check("rdap abuse email from nested entity", reg["abuse"] == "abuse@cogentco.com")
    check("rdap range", reg["range"] == "38.0.0.0/8")
    bad = intel.parse_rdap({"entities": [{"roles": ["abuse"], "vcardArray": ["vcard", [["email", {}, "text", "x@y.com?body=hi"]]]}]})
    check("rdap rejects unsafe abuse email", bad["abuse"] == "")
    afrinic = intel.parse_rdap({"handle": "154.16.44.0 - 154.16.44.255", "entities": [{
        "roles": ["administrative", "technical"],
        "vcardArray": ["vcard", [["fn", {}, "text", "IPXO Incident Response Team"], ["email", {}, "text", "support@ipxo.com"]]]}]})
    check("rdap without registrant falls back to admin org, not abuse",
          afrinic["org"] == "IPXO Incident Response Team" and afrinic["abuse"] == "" and afrinic["name"].startswith("154.16.44.0"))
    check("rdap survives junk", intel.parse_rdap({"entities": [None, {"vcardArray": 5}]})["org"] == "")

    sh = intel.parse_shodan(SHODAN)
    check("shodan ports kept valid only", sh["ports"] == [22, 80])
    check("shodan vulns only CVE ids", sh["vulns"] == ["CVE-2026-10822"])
    check("shodan hostile hostname kept as plain text", HOSTILE in sh["hostnames"])
    check("long text trimmed", len(intel.text("a" * 5000)) == intel.MAX_TEXT)

    with tempfile.TemporaryDirectory() as tmp:
        app = load_app(Path(tmp) / "t.db")
        now = datetime.now(timezone.utc)
        ts = now.replace(microsecond=0).isoformat()
        with app.connect() as db:
            rows = [
                (ts, "38.250.161.179", "/.env", 404, "Secret harvesting", "Yes"),
                (ts, "38.250.161.179", "/.git/config", 404, "Secret harvesting", "Yes"),
                (ts, "38.250.161.179", "SSH", app.SSH_STATUS, "SSH login attempt", "Yes"),
                (ts, "45.138.12.51", "/wp-login.php", 404, "WordPress", "Yes"),
                (ts, "8.8.4.4", "/", 200, "Site visit", "No"),
                (ts, "10.0.0.5", "/.env", 404, "Secret harvesting", "Yes"),
                (ts, "68.84.208.100", "/.env", 404, "Secret harvesting", "Yes"),
            ]
            db.executemany(
                "INSERT INTO visits (ts, ip, location, path, status, category, after_what, result, hacking_me) "
                "VALUES (?, ?, '', ?, ?, ?, '', '', ?)", rows)
            db.execute("INSERT INTO ssh_own_ips VALUES ('68.84.208.100')")

            queue = intel.due(db, 50)
            check("queue holds attacker IPs", set(queue) == {"38.250.161.179", "45.138.12.51"})
            check("queue skips non-attackers, private and own IPs",
                  not {"8.8.4.4", "10.0.0.5", "68.84.208.100"} & set(queue))

            row = {"ip": "38.250.161.179", "asn": 3132, "as_org": "Red Cientifica Peruana", "ptr": HOSTILE,
                   "rdap": reg, "shodan": sh, "tor": 0, "errors": []}
            intel.save(db, row)
            failed = dict(row, ip="45.138.12.51", errors=["shodan"])
            intel.save(db, failed, now - timedelta(hours=2))
            check("fresh profile leaves the queue, failed one retries", intel.due(db, 50) == ["45.138.12.51"])
            intel.save(db, row, now - timedelta(days=8))
            check("stale profile is refreshed", "38.250.161.179" in intel.due(db, 50))
            intel.save(db, row)

        client = app.app.test_client()
        res = client.get("/whos-hacking-me/api/ip/38.250.161.179")
        d = res.get_json()
        check("profile 200", res.status_code == 200)
        check("profile counts", d["attempts"]["total"] == 3 and d["attempts"]["ssh"] == 1 and d["attempts"]["web"] == 2)
        check("profile paths leave out SSH", all(p["value"] != "SSH" for p in d["attempts"]["paths"]))
        check("profile has lookups", d["lookups"]["registry"]["abuse"] == "abuse@cogentco.com")
        check("hostile strings come back as JSON text", d["lookups"]["ptr"] == HOSTILE)
        check("failed source is reported",
              client.get("/whos-hacking-me/api/ip/45.138.12.51").get_json()["lookups"]["failed"] == ["shodan"])
        check("non-attacker IP is 404", client.get("/whos-hacking-me/api/ip/8.8.4.4").status_code == 404)
        check("owner's IP is 404", client.get("/whos-hacking-me/api/ip/68.84.208.100").status_code == 404)
        check("unknown IP is 404", client.get("/whos-hacking-me/api/ip/1.2.3.4").status_code == 404)
        check("invalid IP is 404", client.get("/whos-hacking-me/api/ip/not-an-ip").status_code == 404)
        check("injection attempt is 404",
              client.get("/whos-hacking-me/api/ip/1'%20OR%20'1'='1").status_code == 404)

        with app.connect() as db:
            db.execute("DELETE FROM visits WHERE ip = '45.138.12.51'")
            intel.prune(db)
            left = {r[0] for r in db.execute("SELECT ip FROM ip_intel")}
        check("prune drops profiles of trimmed IPs", left == {"38.250.161.179"})

    print(f"{sum(results)}/{len(results)} passed")
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
