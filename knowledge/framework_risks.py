"""Framework-specific dangerous usage patterns."""
from __future__ import annotations

FRAMEWORK_RISKS: dict[str, dict] = {
    "django": {
        "dangerous_settings": [
            "DEBUG = True",
            "ALLOWED_HOSTS = ['*']",
            "SECRET_KEY.*=.*'django-insecure",
        ],
        "dangerous_patterns": [
            'raw(f"', 'extra(where=[f"',
            'RawSQL(f"', "| safe",
            "mark_safe(request",
        ],
        "missing_protections": [
            "csrf_exempt",
            "permission_classes = []",
            "authentication_classes = []",
        ],
    },
    "flask": {
        "dangerous_settings": [
            "DEBUG = True",
            "SECRET_KEY = 'dev'",
            "WTF_CSRF_ENABLED = False",
        ],
        "dangerous_patterns": [
            "render_template_string(request",
            "send_file(request.args",
            "make_response(request.args",
        ],
        "missing_protections": [
            "@app.route.*methods=\\['GET', 'POST'\\].*# no CSRF",
        ],
    },
    "fastapi": {
        "dangerous_patterns": [
            'allow_origins=["*"]',
            'allow_credentials=True.*allow_origins=\\["\\*\"\\]',
        ],
        "missing_protections": [
            "# no authentication",
        ],
    },
}
