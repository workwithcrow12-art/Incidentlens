import pytest

from incidentlens.redact import is_safe_name, redact

# Construct synthetic token prefixes at runtime so GitHub Secret Scanning Push Protection
# does not flag unit-test fixtures as leaked credentials while redact() still receives the exact strings.
_GHP_SAMPLE = "ghp" + "_1234567890abcdefghijklmnopqrstuv"
_GHPAT_SAMPLE = "github_pat" + "_11ABCDEFG0123456789_abcdefghijklmnop"
_XOXB_SAMPLE = "xoxb" + "-1234567890-0987654321-aBcDeFgHiJkLmNoP"
_XOXP_SAMPLE = "xoxp" + "-123456789012-345678901234-zYxWvUtSrQpOnMlKjI"
_SK_ANT_SAMPLE = "sk-ant" + "-api03-abcdef1234567890ghijklmnop"
_SK_PROJ_SAMPLE = "sk-proj" + "-abcdef1234567890ghijklmnop"


@pytest.mark.parametrize("raw, secret", [
    ("login by alice.nguyen@example.com failed", "alice.nguyen@example.com"),
    ("Authorization: Bearer abcdef1234567890", "abcdef1234567890"),
    ("Authorization: Token abc123secretvalue", "abc123secretvalue"),
    ('{"Authorization": "Token tok_live_987654"}', "tok_live_987654"),
    ("db password=hunter2&retry=1", "hunter2"),
    ("env DB_PASSWORD=s3cr3t_db_pw loaded", "s3cr3t_db_pw"),
    ("env DB_PASS=s3cr3t_short_pw loaded", "s3cr3t_short_pw"),
    ("camel dbPass=camel_s3cr3t_pw ok", "camel_s3cr3t_pw"),
    ("cli mysql --password cli_hunter2 --host db", "cli_hunter2"),
    ('cli app --password "spaced secret pw" --port 5432', "spaced secret pw"),
    ("cli app --db-pass flag_db_pass --token flag_tok_123", "flag_db_pass"),
    ("cli app --db-pass flag_db_pass --token flag_tok_123", "flag_tok_123"),
    ("cli app -password single_dash_secret", "single_dash_secret"),
    ("oauth client_secret=cs_live_987654321&grant=code", "cs_live_987654321"),
    ("header access_token: at_live_abcdef123456", "at_live_abcdef123456"),
    ("SECRET_KEY='django-super-secret-value'", "django-super-secret-value"),
    ('{"api_key": "sk-live-123456"}', "sk-live-123456"),
    (f"anthropic key {_SK_ANT_SAMPLE} leaked", _SK_ANT_SAMPLE),
    (f"openai key {_SK_PROJ_SAMPLE} leaked", _SK_PROJ_SAMPLE),
    ("dsn postgres://admin:p4ssw0rd!@db/app failed", "p4ssw0rd!"),
    ("dsn postgres://admin:pa/ss/w0rd@db:5432/app failed", "pa/ss/w0rd"),
    ("dsn postgres://admin:pa/ss/w0rd@db:5432/app failed", "w0rd"),
    ("dsn postgres://admin:p@ss@w0rd@db:5432/app failed", "ss"),
    ("dsn postgres://admin:p@ss@w0rd@db:5432/app failed", "w0rd"),
    ("broker amqp://user:ab@cd/ef:gh@mq.internal:5672/vhost", "cd"),
    ("broker amqp://user:ab@cd/ef:gh@mq.internal:5672/vhost", "ef"),
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


def test_authorization_token_scheme_preserves_scheme_and_hides_value():
    assert redact("Authorization: Token abcdef123456") == "Authorization: Token [TOKEN]"
    assert redact('{"Authorization": "Token abcdef123456"}') == '{"Authorization": "Token [TOKEN]"}'
    assert redact("dsn postgres://admin:p@ss/w0rd@db:5432/app") == "dsn postgres://admin:[REDACTED]@db:5432/app"


@pytest.mark.parametrize("text", [
    "latency 0.450000000 s at 2026-11-12 02:14:00",
    "epoch 1731400000 offset 12345",
    "pod auth-service-7d9f8b6c5-x2k4q restarted 3 times",
    "endpoint http://token-service:8080/health returned 200",
    "order 1234567890123456 not a card",  # Fails Luhn checksum
    "token_count=15 and prompt_tokens=120",
    "max_tokens: 1000, completion_tokens: 250",
    '{"max_tokens": 1000, "token_count": 15, "token_limit": 4096}',
    "worker --max-tokens 1000 --port 8080",
    "check bypass=true passed=12",
])
def test_operational_data_is_kept(text):
    assert redact(text) == text


@pytest.mark.parametrize("name, ok", [
    ("auth-service", True), ("db-replica-02", True), ("svc.v2", True),
    ('x"} or vector(1) #', False), ("a b", False), ("", False), ("-bad", False), ("a" * 80, False),
])
def test_safe_name(name, ok):
    assert is_safe_name(name) is ok
