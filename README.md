# TLS Certificate Monitor

A Python tool to monitor TLS certificates from a JSON list of domains, send expiry alerts, and optionally schedule renewal reminders via email and ICS calendar invites.

## Features
- Quiet by default: **sends emails only**, no console noise.
- HTML alert emails via **Jinja2** templates.
- **Expiring soon / Expired** detection (≤ 14 days / < 0 days).
- **ICS reminder** option: sends a calendar invite for 5 days before expiry (deduplicated by `ending_date` in `sites.json`).
- Robust JSON validation & sensible defaults (port defaults to **443**).
- Optional console outputs: **table+summary** (`-S`) or **summary dict** (`-J`).
- Exit codes for automation: `0` (OK), `2` (soon), `1` (expired/error).

## Requirements
- Python 3.9+
- Install deps:
  ```bash
  pip install -r requirements.txt
  ```

## Files
```
check_tls_expiry.py
sites.json
templates/
  ├─ expiressoon.html
  └─ expired.html
```

### Example `sites.json`
```json
[
  { "sitename": "push.ransomware.live", "port": 443, "contact": "ops@ransomware.live", "enable": true, "ending_date": "2025-11-28" },
  { "sitename": "www.ransomware.live", "port": 443, "contact": "ops@ransomware.live", "enable": true }
]
```
- `sitename` (string, required): hostname to check.
- `port` (int, optional): defaults to **443** if omitted.
- `contact` (string, optional): email to notify. If missing, no email is sent for that entry.
- `enable` (bool, optional): default **true**; set to false to skip.
- `ending_date` (string `YYYY-MM-DD`, optional): used **only** with `-R` to deduplicate reminder sends across renewal cycles. The script updates this to the current cert’s expiry date after sending an ICS reminder.

### Email Templates (HTML)
`templates/expiressoon.html`
```html
<html><body style="font-family: Arial, sans-serif;">
  <h2 style="color: orange;">⚠️ TLS Certificate Expiring Soon</h2>
  <p>The TLS certificate for <strong>{{ sitename }}</strong> will expire soon.</p>
  <ul>
    <li><b>Expiration date:</b> {{ not_after }}</li>
    <li><b>Days left:</b> {{ days_left }}</li>
  </ul>
  <p>Please renew the certificate before it expires.</p>
</body></html>
```

`templates/expired.html`
```html
<html><body style="font-family: Arial, sans-serif;">
  <h2 style="color: red;">❌ TLS Certificate Expired</h2>
  <p>The TLS certificate for <strong>{{ sitename }}</strong> has expired.</p>
  <ul>
    <li><b>Expiration date:</b> {{ not_after }}</li>
    <li><b>Expired since:</b> {{ abs(days_left) }} day(s) ago</li>
  </ul>
  <p>Please replace the certificate immediately.</p>
</body></html>
```

## SMTP Configuration
Edit these constants at the top of `check_tls_expiry.py` to match your mail relay:
```python
SMTP_SERVER = "localhost"
SMTP_PORT   = 25
SMTP_FROM   = "cert-monitor@yourdomain.com"
```
> The script uses a relay (no auth). If you need authenticated SMTP (Gmail/Office 365), adapt the `send_*` functions accordingly.

## Usage
> By default, the script is **quiet** (no console output) and **sends emails** when a cert is expiring soon or expired.

- Quiet emails-only:
  ```bash
  python3 check_tls_expiry.py
  ```

- Table + Summary (emails still sent):
  ```bash
  python3 check_tls_expiry.py -S
  ```
  Output format:
  ```
  SITENAME                       PORT  STATUS          EXPIRES                        DAYS LEFT
  ---------------------------------------------------------------------------------------------------------
  push.ransomware.live           443   OK              Nov 28 06:12:04 2025 GMT               89
  www.ransomware.live            443   OK              Oct 27 06:53:25 2025 GMT               57

  Summary:
    OK          : 2
  ```

- Summary dict only (emails still sent):
  ```bash
  python3 check_tls_expiry.py -J
  ```
  Example:
  ```
  {'OK': 6, 'EXPIRES SOON': 0, 'EXPIRED': 0, 'ERROR': 0}
  ```

- Disable all emails (alerts & ICS) and auto-show results:
  ```bash
  python3 check_tls_expiry.py --no-mail
  ```
  *(Equivalent to `--no-mail -S` unless you also pass `-J`.)*

- Send **ICS renewal reminder** (5 days before expiry), one per cycle:
  ```bash
  python3 check_tls_expiry.py -R
  ```
  - Requires a `contact` email.
  - Deduplicated by `ending_date` in `sites.json`: ICS is only sent if **now is after** the stored `ending_date`. After sending, the script updates `ending_date` to the current cert’s expiry date.

## Exit Codes
- `0`: All OK.
- `2`: No expired/error, but at least one **expiring soon** (≤ 14 days).
- `1`: At least one **expired** or **error** occurred.

## Automating (cron/systemd)
Check daily and email only when needed:
```cron
0 8 * * * /usr/bin/python3 /path/check_tls_expiry.py >> /var/log/cert-monitor.log 2>&1
```

## Notes & Limitations
- Uses system trust store to fetch and parse peer cert via SNI (`ssl.create_default_context()`).
- If you monitor internal servers with self-signed certs, you may need to relax verification (adjust `get_cert_info()` accordingly).
- Time math is done in UTC; outputs use the cert’s `notAfter` textual format.

## License
MIT (or your preferred license)
