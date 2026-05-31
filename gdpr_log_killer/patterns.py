"""
Regex patterns for detecting PII and internal infrastructure identifiers in logs.
"""

import re

# IPv4 address (strict octet validation)
IPV4 = re.compile(
    r"\b(25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)"
    r"\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)"
    r"\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)"
    r"\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\b"
)

# IPv6 address (full and compressed forms)
IPV6 = re.compile(
    r"\b(?:"
    r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|"            # full
    r"(?:[0-9a-fA-F]{1,4}:){1,7}:|"                           # trailing ::
    r":(?::[0-9a-fA-F]{1,4}){1,7}|"                           # leading ::
    r"(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|"
    r"[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|"
    r"::(?:[fF]{4}(?::0{1,4})?:)?"
    r"(?:25[0-5]|(?:2[0-4]|1?\d)?\d)(?:\.(?:25[0-5]|(?:2[0-4]|1?\d)?\d)){3}|"
    r"::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}"
    r")\b"
)

# Email address
EMAIL = re.compile(
    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
)

# MAC address (colon or hyphen separated)
MAC = re.compile(
    r"\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b"
)

# Windows-style domain\username  (e.g. CORP\jsmith)
WINDOWS_USER = re.compile(
    r"\b[A-Za-z0-9_\-]{1,64}\\[A-Za-z0-9_.\-]{1,64}\b"
)

# Common log field patterns:  user=foo  username=foo  usr=foo
#   user: foo   username: foo
#   logged in as foo   authenticated as foo   session for foo
INLINE_USER = re.compile(
    r"(?i)\b(?:user(?:name)?|usr|login|logon|account|principal|subject|authenticated?(?:\s+as)?|session\s+for|logged\s+in\s+as)\s*[:=]\s*([^\s,;\"'\]}\)]+)",
)

# SSH / sudo / PAM style: "for user foo", "for foo from"
FOR_USER = re.compile(
    r"(?i)\bfor\s+(?:user\s+)?([A-Za-z0-9_.\-]{1,64})\s+(?:from|on|by|with|at)\b"
)

# UUID / session token (v1-v5)
UUID = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)

# Generic bearer / API tokens in Authorization headers.
# Optionally skips a scheme keyword (Bearer / Basic / Token / Digest)
# so the captured group is always the actual credential value, not the keyword.
AUTH_HEADER = re.compile(
    r"(?i)\b(?:Authorization|X-Api-Key|X-Auth-Token|api[_-]?key)\s*[:=]\s*"
    r"(?:(?:Bearer|Basic|Token|Digest)\s+)?"
    r"([A-Za-z0-9\-._~+/]{6,}=*)"
)

# HTTP Basic auth credentials embedded in a URL
URL_CREDS = re.compile(
    r"(?i)(https?://)([A-Za-z0-9_.\-]+:[A-Za-z0-9_.\-!@#$%^&*()]+)@"
)

# Phone numbers (E.164 and common local formats)
PHONE = re.compile(
    r"(?<!\d)(?:\+\d{1,3}[\s\-]?)?"
    r"(?:\(?\d{3}\)?[\s\-]?)"
    r"\d{3}[\s\-]?\d{4}"
    r"(?!\d)"
)


def build_hostname_pattern(domains: list[str]) -> re.Pattern | None:
    """
    Build a pattern that matches fully-qualified hostnames ending in any of the
    supplied internal domain suffixes, e.g. ["corp.example.com", "internal"].
    Returns None when the domain list is empty.
    """
    if not domains:
        return None
    escaped = [re.escape(d.lstrip("*.")) for d in domains]
    suffix = "|".join(escaped)
    return re.compile(
        rf"(?i)\b[A-Za-z0-9](?:[A-Za-z0-9\-]{{0,61}}[A-Za-z0-9])?"
        rf"(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{{0,61}}[A-Za-z0-9])?)*"
        rf"\.(?:{suffix})\b"
    )
