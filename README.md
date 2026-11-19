# Who's Hacking Me

Source for https://scratchbuild.net/whos-hacking-me/: a public, live table of visitors to the
server, with charts. It flags requests and failed SSH logins that look like hacking attempts.

## Layout

| Path | What it is |
|---|---|
| `app/app.py` | Flask app. Reads the nginx access log and `/var/log/auth.log`, stores rows in SQLite, and serves the page plus the `/api/visits`, `/api/facets` and chart APIs |
| `app/classify.py` | Rules that decide "Hacking Me: Yes/No" |
| `app/intel.py` | Attacker profiles: passive lookups (ASN, reverse DNS, RDAP, Shodan InternetDB, Tor exit list) run by a background thread and cached in the `ip_intel` table; served by `/api/ip/<ip>` |
| `app/page.html`, `app/page.js` | The page and its live-updating table |
| `app/charts.js`, `app/chart.umd.js` | Charts (Chart.js is vendored, see `chart.LICENSE.md`) |
| `app/test_charts.py` | Tests. They use a throwaway database but load `app.py` from `/opt/www-traffic` |
| `app/test_classify.py` | Tests for the rules in `classify.py`, using real paths from the log |
| `app/alerts.py` | Email alerts: database at 80% of its cap, old visits deleted, low disk, logging stalled. Sent from Gmail via a systemd credential |
| `app/test_alerts.py` | Tests for the storage limits and alerts (emails are captured, never sent) |
| `deploy/alerts.env.example` | Template for `/etc/www-traffic/alerts.env` (alert addresses, `WHT_MAX_DB_GB`, `WHT_MIN_FREE_GB`) |
| `app/test_intel.py` | Tests for profile parsing, the lookup queue and the `/api/ip` privacy gate (no network) |
| `deploy/www-traffic.service` | systemd unit (`/etc/systemd/system/`) |
| `deploy/nginx-limit.conf` | Rate limit zone (`/etc/nginx/conf.d/whos-hacking-me-limit.conf`) |
| `deploy/nginx-locations.conf` | Reference copy of the location blocks in `/etc/nginx/sites-available/default` |
| `deploy.sh` | Copies `app/` to the server and restarts the service |

## How it runs

- The live copy is in `/opt/www-traffic`, run by gunicorn on `127.0.0.1:5002` as the `www-traffic` service.
- nginx proxies `/whos-hacking-me` to that port and limits each IP to 2 requests/s (burst 20).
- These files stay on the server and are not in git:
  - `traffic.db` (the live data)
  - `dbip-city-lite.mmdb` (the 127 MB GeoIP database from https://db-ip.com)
  - `dbip-asn-lite.mmdb` (the ASN database, from https://download.db-ip.com/free/dbip-asn-lite-YYYY-MM.mmdb.gz). Without it, profiles show the ASN as unknown
  - `/etc/www-traffic/alerts.env` and `/etc/www-traffic/smtp-password` (root-only; alert settings and the Gmail app password)

## Storage and alerts

- The database is capped at `WHT_MAX_DB_GB` (5 GiB). Past it, the oldest visits are deleted down to 90%.
- If free disk drops below `WHT_MIN_FREE_GB` (5 GiB), the database is held at its current size: the oldest visits make room for new ones.
- The write-ahead log shrinks back to 64 MB after checkpoints.
- Each alert emails once when it starts and once when it clears. Changing the settings sends an "Alerts are set up" test email on restart.
- To change a setting: `sudo nano /etc/www-traffic/alerts.env && sudo systemctl restart www-traffic`.

## Attacker profiles

Clicking an attacker's IP opens a profile. Only IPs with a "Yes" row have one, and the API returns 404 for any other IP.
The worker looks up about one IP a second: new attackers first, then profiles older than 7 days, then failed ones after an hour.
Every lookup goes to a public registry or database. Nothing is ever sent to the attacker's own machine.

## Making a change

1. Edit the files under `app/`.
2. Run `./deploy.sh`. It backs up each changed file as `<name>.bak-<timestamp>`, copies the new
   files, runs the tests, restarts the service, and checks that the live page returns 200.
3. Commit.

For a risky change, back up the database first, for example:
`cp /opt/www-traffic/traffic.db /opt/www-traffic/traffic.db.bak-before-<change>`.

The `deploy/` files are copies only. If you change the live nginx or systemd config, copy the
change back here. After an nginx change, run `sudo nginx -t && sudo systemctl reload nginx`.
