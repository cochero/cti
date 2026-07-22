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
DEBUG = os.environ.get("TRUVO_DEBUG", "1") == "1"
ALLOWED_HOSTS = os.environ.get("TRUVO_ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")

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
}

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
CSRF_COOKIE_HTTPONLY = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
if not DEBUG:
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_SSL_REDIRECT = True
    SECURE_HSTS_SECONDS = 31536000
