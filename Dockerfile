# Sidecar image: carries hooks.js and nothing else.
#
# It does not change n8n. On start it copies hooks.js into a shared volume and
# exits; the official, unmodified n8n image mounts that volume read-only.
# See "Docker image" in the README.

FROM busybox:1.38.0

ARG VERSION=dev
LABEL org.opencontainers.image.title="n8n-oidc" \
      org.opencontainers.image.description="OIDC login hook for n8n Community Edition (hooks.js only, no n8n inside)" \
      org.opencontainers.image.source="https://github.com/kavdau/n8n-oidc" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}"

COPY --chmod=644 hooks.js /n8n-oidc/hooks.js

# Copy on every start (a named volume is only pre-filled once, so an update would
# otherwise keep the old file). Write to a temp name and rename, so n8n never
# sees a half-written file.
CMD ["sh", "-c", "set -e; cp /n8n-oidc/hooks.js /out/.hooks.js.tmp; chmod 644 /out/.hooks.js.tmp; mv -f /out/.hooks.js.tmp /out/hooks.js; echo \"n8n-oidc: $(grep -o \"HOOK_VERSION = '[^']*'\" /out/hooks.js) copied to /out/hooks.js\""]
