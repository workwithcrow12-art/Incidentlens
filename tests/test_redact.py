import pytest

from incidentlens.redact import is_safe_name, redact

# Construct synthetic token prefixes at runtime so GitHub Secret Scanning Push Protection
# does not flag unit-test fixtures as leaked credentials while redact() still receives the exact strings.
_GHP_SAMPLE = "ghp" + "_1234567890abcdefghijklmnopqrstuv"
_GHPAT_SAMPLE = "github_pat" + "_11ABCDEFG0123456789_abcdefghijklmnop"
_XOXB_SAMPLE = "xoxb" + "-1234567890-0987654321-aBcDeFgHiJkLmNoP"
_XOXP_SAMPLE = "xoxp" + "-123456789012-345678901234-zYxWvUtSrQpOnMlKjI"


@pytest.mark.parametrize("raw, secret", [
    ("login by alice.nguyen@example.com failed", "alice.nguyen@example.com"),
    ("Authorization: Bearer abcdef1234567890", "abcdef1234567890"),
    ("db password=hunter2&retry=1", "hunter2"),
    ("env DB_PASSWORD=s3cr3t_db_pw loaded", "s3cr3t_db_pw"),
    ("oauth client_secret=cs_live_987654321&grant=code", "cs_live_987654321"),
    ("header access_token: at_live_abcdef123456", "at_live_abcdef123456"),
    ("SECRET_KEY='django-super-secret-value'", "django-super-secret-value"),
    ('{"api_key": "sk-live-123456"}', "sk-live-123456"),
    ("dsn postgres://admin:p4ssw0rd!@db/app failed", "p4ssw0rd!"),
    ("cache redis://:redis_s3cr3t@cache:6379/0 timeout", "redis_s3cr3t"),
    (f"github token {_GHP_SAMPLE} leaked", _GHP_SAMPLE),
    (f"fine-grained {_GHPAT_SAMPLE}", _GHPAT_SAMPLE),
    (f"slack bot {_XOXB_SAMPLE}", "aBcDeFgHiJkLmNoP"),
    (f"slack user {_XOXP_SAMPLE}", "zYxWvUtSrQpOnMlKjI"),
    ("jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4", "eyJzdWIiOiIxMjM0In0"),
    ("aws AKIAIOSFODNN7EXAMPLE used", "AKIAIOSFODNN7EXAMPLE"),
    ("card 4111 1111 1111 1111 declined", "4111 1111 1111 1111"),
    ("call 0912345678 for support", "0912345678"),
    ("contact +84 912 345 678", "912 345 678"),
])
def test_secrets_are_removed(raw, secret):
    assert secret not in redact(raw)


@pytest.mark.parametrize("text", [
    "latency 0.450000000 s at 2026-11-12 02:14:00",
    "epoch 1731400000 offset 12345",
    "pod auth-service-7d9f8b6c5-x2k4q restarted 3 times",
    "endpoint http://token-service:8080/health returned 200",
    "order 1234567890123456 not a card",  # Fails Luhn checksum
])
def test_operational_data_is_kept(text):
    assert redact(text) == text


@pytest.mark.parametrize("name, ok", [
    ("auth-service", True), ("db-replica-02", True), ("svc.v2", True),
    ('x"} or vector(1) #', False), ("a b", False), ("", False), ("-bad", False), ("a" * 80, False),
])
def test_safe_name(name, ok):
    assert is_safe_name(name) is ok
