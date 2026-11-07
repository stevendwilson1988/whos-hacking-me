# Who's Hacking Me

Source for https://scratchbuild.net/whos-hacking-me/: a public, live table of visitors to the
server, with charts. It flags requests and failed SSH logins that look like hacking attempts.

## Layout

| Path | What it is |
|---|---|
| `app/app.py` | Flask app. Reads the nginx access log and `/var/log/auth.log`, stores rows in SQLite, and serves the page plus the `/api/visits`, `/api/facets` and chart APIs |
| `app/classify.py` | Rules that decide "Hacking Me: Yes/No" |
| `app/page.html`, `app/page.js` | The page and its live-updating table |
| `app/charts.js`, `app/chart.umd.js` | Charts (Chart.js is vendored, see `chart.LICENSE.md`) |
| `app/test_charts.py` | Tests. They use a throwaway database but load `app.py` from `/opt/www-traffic` |
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

## Making a change

1. Edit the files under `app/`.
2. Run `./deploy.sh`. It backs up each changed file as `<name>.bak-<timestamp>`, copies the new
   files, runs the tests, restarts the service, and checks that the live page returns 200.
3. Commit.

For a risky change, back up the database first, for example:
`cp /opt/www-traffic/traffic.db /opt/www-traffic/traffic.db.bak-before-<change>`.

The `deploy/` files are copies only. If you change the live nginx or systemd config, copy the
change back here. After an nginx change, run `sudo nginx -t && sudo systemctl reload nginx`.
