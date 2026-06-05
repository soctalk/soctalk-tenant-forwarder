FROM python:3.13-slim AS base
# Install httpx (pure Python wheels) directly — the only runtime dep.
RUN pip install --no-cache-dir 'httpx>=0.27,<1.0'

WORKDIR /app
COPY app/ /app/

# Unprivileged.
RUN groupadd -g 10001 forwarder && useradd -u 10001 -g forwarder -s /sbin/nologin forwarder
USER 10001:10001

ENTRYPOINT ["python", "/app/main.py"]
