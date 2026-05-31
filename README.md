# GDPR Log Killer

Strip personally identifiable information (PII) and internal infrastructure identifiers from log files before sharing them with public AI tools.

## What it removes

| Category | Examples |
|---|---|
| IPv4 / IPv6 | `192.168.1.42`, `2001:db8::1` |
| Hostnames | `dc01.corp.acme.com` (configure your domains) |
| Usernames | `user=jsmith`, `CORP\jsmith`, `logged in as alice` |
| Email addresses | `alice@company.com` |
| MAC addresses | `00:1A:2B:3C:4D:5E` |
| Auth tokens | `Authorization: Bearer <token>` |
| URL credentials | `https://admin:secret@host/` |
| Phone numbers | `+1 (555) 867-5309` |
| UUIDs / Session IDs | opt-in |

Values are replaced with stable numbered placeholders like `[IPV4_1]`, `[USER_2]`, so correlations in the log are preserved for AI analysis.

---

## Quick start

### Web interface

```bash
pip install -r requirements.txt
python web/app.py
# Open http://localhost:5000
```

### CLI

```bash
pip install -e .

# Sanitize a file
gdpr-log-killer app.log > clean.log

# Add internal domain stripping
gdpr-log-killer -d corp.acme.com -d internal app.log > clean.log

# Pipe from stdin
journalctl -n 500 | gdpr-log-killer -d corp.acme.com --stdin

# Print a replacement summary to stderr
gdpr-log-killer --report app.log > clean.log

# Also show original→placeholder mapping
gdpr-log-killer --report --show-mapping app.log > clean.log
```

### CLI flags

| Flag | Default | Description |
|---|---|---|
| `-d / --domain` | *(none)* | Internal domain suffix (repeatable) |
| `--no-ips` | off | Skip IP scrubbing |
| `--no-emails` | off | Skip email scrubbing |
| `--no-macs` | off | Skip MAC scrubbing |
| `--no-users` | off | Skip username scrubbing |
| `--no-phones` | off | Skip phone scrubbing |
| `--strip-uuids` | off | Also replace UUIDs |
| `--report` | off | JSON summary to stderr |
| `--show-mapping` | off | Include placeholder↔original map |

---

## Python API

```python
from gdpr_log_killer import Sanitizer

s = Sanitizer(
    internal_domains=["corp.acme.com", "internal"],
    strip_uuids=True,
)

result = s.sanitize(log_text)
print(result.text)   # sanitized log
print(result.stats)  # {"IPV4": 3, "USER": 2, ...}
print(result.mapping)  # {"[IPV4_1]": "10.0.0.55", ...}
```

---

## Development

```bash
pip install -e ".[dev]"
pytest
pytest --cov=gdpr_log_killer
```

---

## REST API

`POST /api/sanitize`

```json
{
  "text": "<raw log text>",
  "options": {
    "strip_ips": true,
    "strip_emails": true,
    "strip_macs": true,
    "strip_hostnames": true,
    "strip_users": true,
    "strip_uuids": false,
    "strip_auth_tokens": true,
    "strip_url_creds": true,
    "strip_phones": true,
    "domains": "corp.acme.com\ninternal"
  }
}
```

Response:

```json
{
  "sanitized": "...",
  "stats": { "IPV4": 3, "USER": 2 },
  "total": 5
}
```

---

## Security note

This tool processes log data server-side in your own environment.  
**No data is ever sent to any third party.**
