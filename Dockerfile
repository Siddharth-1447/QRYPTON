FROM python:3.13.16-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN groupadd --system qrypton && useradd --system --gid qrypton --home-dir /app qrypton

COPY pyproject.toml README.md ./
COPY src/ ./src/
COPY web/src/app/globals.css ./web/src/app/globals.css
COPY web/public/fonts/ ./web/public/fonts/

RUN python -m pip install --no-cache-dir --upgrade "pip>=26.2" \
    && python -m pip install --no-cache-dir ".[api,ui]" \
    && mkdir /data \
    && chown qrypton:qrypton /data

USER qrypton
WORKDIR /data

ENTRYPOINT ["qrypton"]
CMD ["--help"]
