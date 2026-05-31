"""Tests for the core sanitizer."""

import pytest
from gdpr_log_killer.sanitizer import Sanitizer


def sanitizer(**kwargs):
    return Sanitizer(**kwargs)


# ── IP addresses ──────────────────────────────────────────────────────────────

def test_ipv4_replaced():
    s = sanitizer()
    r = s.sanitize("Connection from 192.168.1.42 rejected")
    assert "192.168.1.42" not in r.text
    assert "[IPV4_1]" in r.text
    assert r.stats["IPV4"] == 1


def test_ipv4_consistent_replacement():
    s = sanitizer()
    r = s.sanitize("From 10.0.0.1 to 10.0.0.1 via 10.0.0.2")
    assert r.text.count("[IPV4_1]") == 2
    assert "[IPV4_2]" in r.text
    assert r.stats["IPV4"] == 2


def test_ipv6_replaced():
    s = sanitizer()
    r = s.sanitize("Host 2001:db8::1 connected")
    assert "2001:db8::1" not in r.text
    assert r.stats.get("IPV6", 0) == 1


def test_strip_ips_disabled():
    s = sanitizer(strip_ips=False)
    r = s.sanitize("From 192.168.0.1")
    assert "192.168.0.1" in r.text


# ── Emails ────────────────────────────────────────────────────────────────────

def test_email_replaced():
    s = sanitizer()
    r = s.sanitize("Sent to alice@example.com")
    assert "alice@example.com" not in r.text
    assert r.stats["EMAIL"] == 1


# ── Usernames ─────────────────────────────────────────────────────────────────

def test_inline_user_replaced():
    s = sanitizer()
    r = s.sanitize("username=jsmith login successful")
    assert "jsmith" not in r.text
    assert r.stats["USER"] >= 1


def test_windows_domain_user():
    s = sanitizer()
    r = s.sanitize("LDAP bind for CORP\\jsmith failed")
    assert "CORP\\jsmith" not in r.text
    assert r.stats["USER"] >= 1


def test_for_user_pattern():
    s = sanitizer()
    r = s.sanitize("Authentication failed for user johndoe from 192.168.1.1")
    assert "johndoe" not in r.text


# ── MAC addresses ─────────────────────────────────────────────────────────────

def test_mac_replaced():
    s = sanitizer()
    r = s.sanitize("ARP: 00:1A:2B:3C:4D:5E resolved")
    assert "00:1A:2B:3C:4D:5E" not in r.text
    assert r.stats["MAC"] == 1


# ── Hostnames ─────────────────────────────────────────────────────────────────

def test_hostname_replaced():
    s = sanitizer(internal_domains=["corp.example.com"])
    r = s.sanitize("Connected to dc01.corp.example.com")
    assert "dc01.corp.example.com" not in r.text
    assert r.stats["HOSTNAME"] == 1


def test_hostname_not_replaced_without_domain():
    s = sanitizer(internal_domains=[])
    r = s.sanitize("Connected to dc01.corp.example.com")
    assert "dc01.corp.example.com" in r.text


# ── Auth tokens ───────────────────────────────────────────────────────────────

def test_auth_header_replaced():
    s = sanitizer()
    r = s.sanitize("Authorization: Bearer supersecrettoken123")
    assert "supersecrettoken123" not in r.text
    assert r.stats.get("AUTH_TOKEN", 0) == 1


# ── URL credentials ───────────────────────────────────────────────────────────

def test_url_creds_replaced():
    s = sanitizer()
    r = s.sanitize("Connecting to https://admin:password@internal.server/api")
    assert "admin:password" not in r.text
    assert "https://" in r.text  # scheme preserved
    assert r.stats.get("URL_CREDS", 0) == 1


# ── Phones ────────────────────────────────────────────────────────────────────

def test_phone_replaced():
    s = sanitizer()
    r = s.sanitize("Callback number: +1 (555) 867-5309")
    assert "867-5309" not in r.text


# ── UUIDs (opt-in) ────────────────────────────────────────────────────────────

def test_uuid_not_replaced_by_default():
    s = sanitizer()
    uuid = "550e8400-e29b-41d4-a716-446655440000"
    r = s.sanitize(f"Session id: {uuid}")
    assert uuid in r.text


def test_uuid_replaced_when_enabled():
    s = sanitizer(strip_uuids=True)
    uuid = "550e8400-e29b-41d4-a716-446655440000"
    r = s.sanitize(f"Session id: {uuid}")
    assert uuid not in r.text
    assert r.stats.get("UUID", 0) == 1


# ── Stats & mapping ───────────────────────────────────────────────────────────

def test_stats_summary():
    s = sanitizer()
    r = s.sanitize("From 1.2.3.4 user=alice mail=alice@x.com")
    assert r.stats.get("IPV4", 0) >= 1
    assert r.stats.get("EMAIL", 0) >= 1
    assert r.stats.get("USER", 0) >= 1


def test_mapping_contains_originals():
    s = sanitizer()
    r = s.sanitize("From 1.2.3.4")
    assert "[IPV4_1]" in r.mapping
    assert r.mapping["[IPV4_1]"] == "1.2.3.4"


# ── Full sample log ───────────────────────────────────────────────────────────

def test_sample_log(tmp_path):
    import os
    fixture = os.path.join(os.path.dirname(__file__), "fixtures", "sample.log")
    with open(fixture) as f:
        log = f.read()

    s = sanitizer(internal_domains=["corp.example.com", "internal", "internal.acme.org"])
    r = s.sanitize(log)

    sensitive = [
        "192.168.1.42", "10.0.0.55", "203.0.113.77",
        "jsmith", "john.doe", "CORP\\jsmith",
        "alice@company.com",
        "00:1A:2B:3C:4D:5E",
        "dc01.corp.example.com",
        "admin:s3cr3tP4ss",
        "867-5309",
    ]
    for item in sensitive:
        assert item not in r.text, f"'{item}' was not redacted"
