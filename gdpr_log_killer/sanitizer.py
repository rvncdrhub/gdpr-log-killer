"""
Core sanitization engine.

Each unique sensitive value found in the log text gets a stable, numbered
placeholder (e.g. [IP_1], [HOSTNAME_3]) so that correlations in the sanitized
output are preserved for AI analysis.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import patterns as P


@dataclass
class SanitizeResult:
    text: str
    stats: Dict[str, int] = field(default_factory=dict)
    mapping: Dict[str, str] = field(default_factory=dict)


class Sanitizer:
    """
    Configurable log sanitizer.

    Parameters
    ----------
    strip_ips:          Replace IPv4 and IPv6 addresses.
    strip_emails:       Replace e-mail addresses.
    strip_macs:         Replace MAC addresses.
    strip_hostnames:    Replace internal hostnames (requires internal_domains).
    strip_users:        Replace usernames found in common log field patterns.
    strip_uuids:        Replace UUIDs / session tokens.
    strip_auth_tokens:  Replace Bearer / API tokens in Authorization headers.
    strip_url_creds:    Replace user:pass credentials embedded in URLs.
    strip_phones:       Replace phone numbers.
    internal_domains:   List of internal domain suffixes, e.g. ["corp.acme.com"].
    custom_patterns:    Extra (label, compiled-regex) pairs to apply.
    """

    def __init__(
        self,
        *,
        strip_ips: bool = True,
        strip_emails: bool = True,
        strip_macs: bool = True,
        strip_hostnames: bool = True,
        strip_users: bool = True,
        strip_uuids: bool = False,
        strip_auth_tokens: bool = True,
        strip_url_creds: bool = True,
        strip_phones: bool = True,
        internal_domains: Optional[List[str]] = None,
        custom_patterns: Optional[List[tuple[str, re.Pattern]]] = None,
    ) -> None:
        self.strip_ips = strip_ips
        self.strip_emails = strip_emails
        self.strip_macs = strip_macs
        self.strip_hostnames = strip_hostnames
        self.strip_users = strip_users
        self.strip_uuids = strip_uuids
        self.strip_auth_tokens = strip_auth_tokens
        self.strip_url_creds = strip_url_creds
        self.strip_phones = strip_phones
        self.internal_domains = internal_domains or []
        self.custom_patterns = custom_patterns or []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def sanitize(self, text: str) -> SanitizeResult:
        """Return a SanitizeResult with the scrubbed text and statistics."""
        counters: Dict[str, int] = {}
        # value → placeholder, used for stable/consistent replacement
        cache: Dict[str, str] = {}

        def replace(label: str, value: str) -> str:
            key = f"{label}::{value}"
            if key not in cache:
                n = counters.get(label, 0) + 1
                counters[label] = n
                cache[key] = f"[{label}_{n}]"
            return cache[key]

        # Order matters — more specific patterns run first to avoid
        # partial matches being swallowed by broader patterns.

        # 1. URL credentials  (before hostname / IP patterns eat the URL)
        if self.strip_url_creds:
            def _url_creds(m: re.Match) -> str:
                return m.group(1) + replace("URL_CREDS", m.group(2)) + "@"
            text = P.URL_CREDS.sub(_url_creds, text)

        # 2. Auth header tokens
        if self.strip_auth_tokens:
            def _auth(m: re.Match) -> str:
                full = m.group(0)
                token = m.group(1)
                return full[: m.start(1) - m.start()] + replace("AUTH_TOKEN", token)
            text = P.AUTH_HEADER.sub(_auth, text)

        # 3. Emails  (before hostname so user@host.internal is caught whole)
        if self.strip_emails:
            text = P.EMAIL.sub(lambda m: replace("EMAIL", m.group()), text)

        # 4. Internal hostnames
        if self.strip_hostnames and self.internal_domains:
            hostname_re = P.build_hostname_pattern(self.internal_domains)
            if hostname_re:
                text = hostname_re.sub(lambda m: replace("HOSTNAME", m.group()), text)

        # 5. IPv6  (before IPv4 to avoid clipping embedded IPv4)
        if self.strip_ips:
            text = P.IPV6.sub(lambda m: replace("IPV6", m.group()), text)
            text = P.IPV4.sub(lambda m: replace("IPV4", m.group()), text)

        # 6. MAC addresses
        if self.strip_macs:
            text = P.MAC.sub(lambda m: replace("MAC", m.group()), text)

        # 7. Windows domain\user
        if self.strip_users:
            text = P.WINDOWS_USER.sub(lambda m: replace("USER", m.group()), text)

        # 8. Inline user field  (user=foo, username: foo, …)
        if self.strip_users:
            def _inline_user(m: re.Match) -> str:
                username = m.group(1)
                placeholder = replace("USER", username)
                return m.group(0).replace(username, placeholder)
            text = P.INLINE_USER.sub(_inline_user, text)

        # 9. "for user foo from …" style
        if self.strip_users:
            def _for_user(m: re.Match) -> str:
                username = m.group(1)
                placeholder = replace("USER", username)
                return m.group(0).replace(username, placeholder)
            text = P.FOR_USER.sub(_for_user, text)

        # 10. UUIDs / session tokens
        if self.strip_uuids:
            text = P.UUID.sub(lambda m: replace("UUID", m.group()), text)

        # 11. Phone numbers
        if self.strip_phones:
            text = P.PHONE.sub(lambda m: replace("PHONE", m.group()), text)

        # 12. Custom patterns
        for label, pat in self.custom_patterns:
            text = pat.sub(lambda m, lbl=label: replace(lbl, m.group()), text)

        # Build reverse mapping (placeholder → original) for the report
        reverse_mapping = {v: k.split("::", 1)[1] for k, v in cache.items()}

        return SanitizeResult(
            text=text,
            stats=dict(counters),
            mapping=reverse_mapping,
        )
