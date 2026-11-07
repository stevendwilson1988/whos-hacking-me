#!/usr/bin/env bash
# Deploy app/ to /opt/www-traffic, restart the service, and check the live page.
# Changed files are backed up first as <name>.bak-YYYYMMDD-HHMMSS (same convention as before).
set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)/app"
DEST=/opt/www-traffic
STAMP=$(date +%Y%m%d-%H%M%S)

changed=0
for f in "$SRC"/*; do
  name=$(basename "$f")
  if [[ -f "$DEST/$name" ]] && cmp -s "$f" "$DEST/$name"; then
    continue
  fi
  [[ -f "$DEST/$name" ]] && cp -p "$DEST/$name" "$DEST/$name.bak-$STAMP"
  cp "$f" "$DEST/$name"
  echo "updated $name"
  changed=1
done

if [[ $changed -eq 0 ]]; then
  echo "No changes; nothing deployed."
  exit 0
fi

echo "Running tests..."
python3 "$DEST/test_charts.py"

echo "Restarting www-traffic..."
sudo systemctl restart www-traffic
sleep 2
systemctl is-active www-traffic

code=$(curl -s -o /dev/null -w '%{http_code}' https://scratchbuild.net/whos-hacking-me/)
echo "https://scratchbuild.net/whos-hacking-me/ -> $code"
[[ "$code" == 200 ]]
