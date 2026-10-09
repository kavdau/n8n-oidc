# Sidecar image: carries hooks.js and nothing else.
#
# It does not change n8n. On start it copies hooks.js into a shared volume and
# then idles; the official, unmodified n8n image mounts that volume read-only.
# See "Docker image" in the README.

FROM busybox:1.38.0

ARG VERSION=dev
LABEL org.opencontainers.image.title="n8n-oidc" \
      org.opencontainers.image.description="OIDC login hook for n8n Community Edition (hooks.js only, no n8n inside)" \
      org.opencontainers.image.source="https://github.com/kavdau/n8n-oidc" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}"

# COPY + RUN chmod instead of COPY --chmod: works with the legacy builder too
# (some NAS systems ship Docker without BuildKit/buildx).
COPY hooks.js /n8n-oidc/hooks.js
COPY docker/sidecar.sh /usr/local/bin/n8n-oidc-sidecar
RUN chmod 644 /n8n-oidc/hooks.js && chmod 755 /usr/local/bin/n8n-oidc-sidecar

# Healthy once the volume holds exactly this image's hooks.js, so n8n can wait
# for it with depends_on: condition: service_healthy.
HEALTHCHECK --interval=5s --timeout=3s --start-period=5s --retries=3 \
  CMD cmp -s /n8n-oidc/hooks.js /out/hooks.js

CMD ["/usr/local/bin/n8n-oidc-sidecar"]
