"""TRUVO core settings — env-driven, dev defaults match deploy/compose.

Database role model (ADR-0003):
- Runtime services connect as `truvo_app` (RLS enforced).
- Migrations and dev tooling connect as the admin role.
- `TRUVO_DB_URL` selects the role: dev default is the admin URL for
  ergonomics (manage.py, tests); RLS-verifying paths set the app-role URL
  explicitly (see tests_live/).
"""

import os
from pathlib import Path
from urllib.parse import urlsplit

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.environ.get(
    "TRUVO_SECRET_KEY", "dev-only-insecure-key-do-not-deploy"
)
# fails CLOSED: production is the default; dev opts in explicitly with
# TRUVO_DEBUG=1 (security review C3 — an unset variable must never buy
# stack traces and permissive behavior in a deployment)
DEBUG = os.environ.get("TRUVO_DEBUG", "0") == "1"
ALLOWED_HOSTS = os.environ.get("TRUVO_ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")

# Password policy (security review H1): on create/reset via Django flows.
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
     "OPTIONS": {"min_length": 10}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "accounts",
    "tenancy",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "tenancy.middleware.TenantContextMiddleware",  # after auth: needs request.user
]

ROOT_URLCONF = "config.urls"
WSGI_APPLICATION = "config.wsgi.application"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]


def _db_from_url(url: str) -> dict:
    parts = urlsplit(url)
    return {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": parts.path.lstrip("/"),
        "USER": parts.username or "",
        "PASSWORD": parts.password or "",
        "HOST": parts.hostname or "localhost",
        "PORT": str(parts.port or 5432),
    }


DATABASES = {
    "default": _db_from_url(
        os.environ.get(
            "TRUVO_DB_URL",
            "postgresql://truvo:truvo-dev-only@localhost:5432/truvo",
        )
    )
}

AUTH_USER_MODEL = "accounts.User"

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.SessionAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
    "DEFAULT_RENDERER_CLASSES": ["rest_framework.renderers.JSONRenderer"],
    # brute-force backstop (security review H1); account lockout on top
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "anon": "30/min",
        "user": "240/min",
        "auth": "10/min",
    },
}

# Account lockout window (security review H1): failed logins per account
LOCKOUT_MAX_FAILURES = int(os.environ.get("TRUVO_LOCKOUT_MAX", "5"))
LOCKOUT_SECONDS = int(os.environ.get("TRUVO_LOCKOUT_SECONDS", "900"))

# --- SSO (OIDC) — enabled per-deployment via env (Architecture v2 SS11.1).
# Enterprise IdPs (Entra ID, Okta) terminate here; local dev uses session auth.
OIDC_ENABLED = os.environ.get("TRUVO_OIDC_ENABLED", "0") == "1"
if OIDC_ENABLED:
    INSTALLED_APPS.append("mozilla_django_oidc")
    AUTHENTICATION_BACKENDS = [
        "django.contrib.auth.backends.ModelBackend",
        "accounts.oidc.TruvoOIDCBackend",
    ]
    OIDC_RP_CLIENT_ID = os.environ["TRUVO_OIDC_CLIENT_ID"]
    OIDC_RP_CLIENT_SECRET = os.environ["TRUVO_OIDC_CLIENT_SECRET"]
    OIDC_OP_AUTHORIZATION_ENDPOINT = os.environ["TRUVO_OIDC_AUTH_ENDPOINT"]
    OIDC_OP_TOKEN_ENDPOINT = os.environ["TRUVO_OIDC_TOKEN_ENDPOINT"]
    OIDC_OP_USER_ENDPOINT = os.environ["TRUVO_OIDC_USER_ENDPOINT"]
    OIDC_OP_JWKS_ENDPOINT = os.environ["TRUVO_OIDC_JWKS_ENDPOINT"]
    OIDC_RP_SIGN_ALGO = "RS256"

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_TZ = True
STATIC_URL = "static/"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# Security headers — real values even in dev, so prod config is a delta not a rewrite
SESSION_COOKIE_HTTPONLY = True
# csrftoken must be readable by the SPA: it echoes the value in the
# X-CSRFToken header on authenticated POSTs (the standard Django+SPA
# double-submit pattern). The token alone carries no authority without the
# session, so JS readability is by design, not an oversight.
CSRF_COOKIE_HTTPONLY = False
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
if not DEBUG:
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_SSL_REDIRECT = True
    SECURE_HSTS_SECONDS = 31536000
