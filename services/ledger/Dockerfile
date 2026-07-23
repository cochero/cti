# truvo-ledger — build from monorepo root:
#   docker build -f services/ledger/Dockerfile -t truvo/ledger:dev .
FROM python:3.13-slim

WORKDIR /srv

# local libs first (better layer caching; internal truvo-* names must
# resolve from the repo, never PyPI — dependency-confusion guard, T6)
COPY libs/py/truvo_core /srv/libs/truvo_core
COPY libs/py/truvo_secrets /srv/libs/truvo_secrets
COPY libs/py/truvo_svcauth /srv/libs/truvo_svcauth
RUN pip install --no-cache-dir /srv/libs/truvo_core /srv/libs/truvo_secrets \
    /srv/libs/truvo_svcauth

COPY services/ledger /srv/ledger
RUN pip install --no-cache-dir /srv/ledger

# non-root runtime
RUN useradd --system --no-create-home truvo
USER truvo

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--app-dir", "/srv/ledger"]
