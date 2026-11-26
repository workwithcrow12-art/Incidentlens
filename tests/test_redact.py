import pytest

from incidentlens.redact import is_safe_name, redact


@pytest.mark.parametrize("raw, secret", [
    ("login by alice.nguyen@example.com failed", "alice.nguyen@example.com"),
    ("Authorization: Bearer abcdef1234567890", "abcdef1234567890"),
    ("db password=hunter2&retry=1", "hunter2"),
    ('{"api_key": "sk-live-123456"}', "sk-live-123456"),
    ("jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4", "eyJzdWIiOiIxMjM0In0"),
    ("aws AKIAIOSFODNN7EXAMPLE used", "AKIAIOSFODNN7EXAMPLE"),
    ("card 4111 1111 1111 1111 declined", "4111 1111 1111 1111"),
    ("gọi 0912345678 để hỗ trợ", "0912345678"),
    ("contact +84 912 345 678", "912 345 678"),
])
def test_secrets_are_removed(raw, secret):
    assert secret not in redact(raw)


@pytest.mark.parametrize("text", [
    "latency 0.450000000 s at 2026-11-12 02:14:00",
    "epoch 1731400000 offset 12345",
    "pod auth-service-7d9f8b6c5-x2k4q restarted 3 times",
    "order 1234567890123456 not a card",  # không qua kiểm tra Luhn
])
def test_operational_data_is_kept(text):
    assert redact(text) == text


@pytest.mark.parametrize("name, ok", [
    ("auth-service", True), ("db-replica-02", True), ("svc.v2", True),
    ('x"} or vector(1) #', False), ("a b", False), ("", False), ("-bad", False), ("a" * 80, False),
])
def test_safe_name(name, ok):
    assert is_safe_name(name) is ok
