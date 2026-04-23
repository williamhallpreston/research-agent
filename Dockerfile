# ── Stage 1: build dependencies ───────────────────────────────────────────────
FROM python:3.11-slim AS builder

# Install build tools needed for C extensions (reportlab, lxml)
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libxml2-dev \
        libxslt-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY requirements.txt .
# Install into an isolated prefix so we can COPY it into the final stage
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Stage 2: minimal runtime image ────────────────────────────────────────────
FROM python:3.11-slim AS runtime

# SECURITY: Run as a non-root user. Never use root in production containers.
RUN useradd --create-home --shell /bin/bash --uid 1001 agent

# Runtime system deps only (no compilers)
RUN apt-get update && apt-get install -y --no-install-recommends \
        libxml2 \
        libxslt1.1 \
    && rm -rf /var/lib/apt/lists/*

# Copy installed packages from builder
COPY --from=builder /install /usr/local

WORKDIR /app

# Copy source — owned by agent, not root
COPY --chown=agent:agent src/ ./src/

# Create runtime directories with correct ownership
RUN mkdir -p reports cache && chown -R agent:agent reports cache

# Switch to non-root user
USER agent

# SECURITY: Expose only the application port.
# TLS termination is expected at the reverse proxy (nginx/Caddy), not here.
EXPOSE 5000

# SECURITY: Prefer exec-form ENTRYPOINT (no shell interpolation).
# gunicorn is used in production instead of Flask's dev server.
ENTRYPOINT ["python", "-m", "gunicorn"]
CMD [ \
    "--bind", "0.0.0.0:5000", \
    "--workers", "2", \
    "--threads", "4", \
    "--timeout", "300", \
    "--access-logfile", "-", \
    "--error-logfile", "-", \
    "src.research_agent:create_app()" \
]
