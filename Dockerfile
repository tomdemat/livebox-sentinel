# Base image pinned by digest: a retagged upstream image cannot slip into a build.
FROM python:3.11-slim@sha256:e88e9763f943ec1834f992a4b51e0f24500486803e8bc534e5767af9ea65f6ce
LABEL org.opencontainers.image.title="Livebox Sentinel" org.opencontainers.image.description="Surveillance locale d’un réseau domestique Livebox" org.opencontainers.image.licenses="MIT" org.opencontainers.image.source="https://github.com/tomdemat/livebox-sentinel"
ARG GITHUB_HOST=github.com
# LiveboxMonitor (MIT, Pierre Dor) provides the Livebox API client: release 1.7, pinned by commit.
ARG LIVEBOX_MONITOR_COMMIT=b2dba5259e12252c4f14b9be2ffd9664539e98c8
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/opt/LiveboxMonitor/src \
    WEB_HOST=0.0.0.0 WEB_PORT=8080 FORWARDED_ALLOW_IPS=127.0.0.1
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && git init -q /opt/LiveboxMonitor \
    && git -C /opt/LiveboxMonitor fetch -q --depth 1 "https://${GITHUB_HOST}/p-dor/LiveboxMonitor.git" "${LIVEBOX_MONITOR_COMMIT}" \
    && git -C /opt/LiveboxMonitor checkout -q FETCH_HEAD \
    && test "$(git -C /opt/LiveboxMonitor rev-parse HEAD)" = "${LIVEBOX_MONITOR_COMMIT}" \
    && rm -rf /opt/LiveboxMonitor/.git \
    && apt-get purge -y git && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.lock .
RUN pip install --no-cache-dir -r requirements.lock
COPY sentinel ./sentinel
COPY tools ./tools
EXPOSE 8080
USER 1000:1000
# Behind an HTTPS reverse proxy, set FORWARDED_ALLOW_IPS to its address so the Secure cookie and Origin checks see https.
CMD uvicorn sentinel.main:app --host "$WEB_HOST" --port "$WEB_PORT" --proxy-headers --forwarded-allow-ips "$FORWARDED_ALLOW_IPS"
