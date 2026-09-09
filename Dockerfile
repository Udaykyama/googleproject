# syntax=docker/dockerfile:1.7

# Pinned multi-architecture image index for python:3.12-slim-bookworm.
ARG PYTHON_BASE=python:3.12-slim-bookworm@sha256:782412e85d0f0984994c290652577d4018aff08145c85b262bb63dc0c7522254

FROM ${PYTHON_BASE} AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build

COPY requirements-build.txt requirements-production.txt ./
RUN python -m pip install --requirement requirements-build.txt \
    && python -m pip wheel \
        --wheel-dir /wheels \
        --requirement requirements-production.txt

COPY pyproject.toml README.md LICENSE ./
COPY src/ src/
COPY fake_review_detector/ fake_review_detector/
COPY webui/ webui/
COPY examples/ examples/
COPY data/ data/

RUN python -m pip wheel \
        --no-build-isolation \
        --no-deps \
        --wheel-dir /wheels \
        . \
    && python -m pip install \
        --no-index \
        --find-links /wheels \
        --prefix /install \
        "inboxready[server,dns]==1.0.0"

FROM ${PYTHON_BASE} AS runtime

ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONFAULTHANDLER=1 \
    PYTHONHASHSEED=random \
    TMPDIR=/tmp

RUN groupadd --gid 10001 inboxready \
    && useradd \
        --uid 10001 \
        --gid 10001 \
        --no-create-home \
        --home-dir /nonexistent \
        --shell /usr/sbin/nologin \
        inboxready \
    && mkdir -p /opt/inboxready /var/lib/inboxready /var/backups/inboxready \
    && chown -R 10001:10001 \
        /opt/inboxready /var/lib/inboxready /var/backups/inboxready

COPY --from=builder /install/ /usr/local/

WORKDIR /opt/inboxready
USER 10001:10001

EXPOSE 8000
STOPSIGNAL SIGTERM

CMD ["gunicorn", "--bind=0.0.0.0:8000", "--workers=2", "--threads=4", "--timeout=60", "--graceful-timeout=35", "--access-logfile=-", "--error-logfile=-", "--capture-output", "webui:create_app()"]
