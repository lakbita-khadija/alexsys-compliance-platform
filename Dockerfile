# ComplianceIQ Core Service (Phase 5).
#
# Multi-stage so the runtime image carries no build toolchain: fewer
# packages in the final image means fewer CVEs to triage, which matters
# more than usual for a product that scans other people's clouds for
# exactly that class of problem.

FROM python:3.11-slim AS builder

WORKDIR /build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1

# Only the dependency metadata first, so `pip install` is cached and a
# source-only change does not re-resolve every dependency.
COPY pyproject.toml ./
COPY domain ./domain
COPY application ./application
COPY infrastructure ./infrastructure
COPY contracts ./contracts
COPY presentation ./presentation

RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --upgrade pip \
 && /opt/venv/bin/pip install ".[serve]"


FROM python:3.11-slim AS runtime

# Runs as a non-root user. A container that scans cloud infrastructure
# is a high-value target; root inside it turns a container escape from
# difficult into routine.
RUN useradd --create-home --uid 10001 complianceiq

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY --chown=complianceiq:complianceiq domain ./domain
COPY --chown=complianceiq:complianceiq application ./application
COPY --chown=complianceiq:complianceiq infrastructure ./infrastructure
COPY --chown=complianceiq:complianceiq contracts ./contracts
COPY --chown=complianceiq:complianceiq presentation ./presentation
COPY --chown=complianceiq:complianceiq rules ./rules
COPY --chown=complianceiq:complianceiq composition.py alembic.ini ./

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

USER complianceiq
EXPOSE 8000

# No secrets are baked in. JWT_PRIVATE_KEY and the database credentials
# arrive from the environment or a mounted secret at run time — the
# image is identical across every environment, which is what makes it
# promotable from staging to production without a rebuild.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health').status==200 else 1)"

CMD ["uvicorn", "--factory", "composition:build_production_app", \
     "--host", "0.0.0.0", "--port", "8000"]
