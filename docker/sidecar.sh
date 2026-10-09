#!/bin/sh
# Copies hooks.js into the shared volume, then stays up so that Docker GUIs
# (UGOS, Synology, Portainer) do not show the stack as failed.
#
# Copy on every start: a named volume is only pre-filled once, so an update
# would otherwise keep the old file. Write to a temp name and rename, so n8n
# never reads a half-written file.
set -e

src=/n8n-oidc/hooks.js
out=${OUT_DIR:-/out}

cp "$src" "$out/.hooks.js.tmp"
chmod 644 "$out/.hooks.js.tmp"
mv -f "$out/.hooks.js.tmp" "$out/hooks.js"
echo "n8n-oidc: $(grep -o "HOOK_VERSION = '[^']*'" "$out/hooks.js") copied to $out/hooks.js"

# Idle until stopped. sleep runs in the background so the trap fires at once
# on docker stop instead of after the 10 s kill timeout.
trap 'exit 0' TERM INT
while :; do
	sleep 3600 &
	wait $!
done
