#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import socket
import ssl
import smtplib
import sys
import os
from collections import Counter
from datetime import datetime, timezone, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from jinja2 import Environment, FileSystemLoader

JSON_FILE = "sites.json"
DATE_FMT = "%b %d %H:%M:%S %Y %Z"  # e.g. "Nov 28 06:12:04 2025 GMT"

# SMTP CONFIG (adapt as needed)
SMTP_SERVER = "localhost"
SMTP_PORT = 25
SMTP_FROM = "cert-monitor@yourdomain.com"

# Jinja2 templates (in ./templates/)
env = Environment(loader=FileSystemLoader("templates"))

def parse_args():
    p = argparse.ArgumentParser(description="TLS cert checker: quiet by default (emails only).")
    p.add_argument("--no-mail", action="store_true", help="Do not send ANY emails (alerts or reminders)")
    p.add_argument("--summary", "-S", action="store_true", help="Print per-site table + Summary block")
    p.add_argument("--json", "-J", action="store_true", help="Print only the summary dict (Python-style repr)")
    p.add_argument("--reminder", "-R", action="store_true", help="Send an ICS reminder (5 days before expiry); dedup via ending_date in sites.json")
    return p.parse_args()

def load_sites(path: str):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"ERROR: JSON file '{path}' not found.", file=sys.stderr)
        return []
    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid JSON in '{path}': {e}", file=sys.stderr)
        return []

    if not isinstance(data, list):
        print("ERROR: JSON root should be a list of site objects.", file=sys.stderr)
        return []

    valid = []
    for i, site in enumerate(data, 1):
        if not isinstance(site, dict):
            print(f"ERROR: Entry #{i} is not an object. Skipped.", file=sys.stderr)
            continue
        name = site.get("sitename")
        if not name or not isinstance(name, str):
            print(f"ERROR: Entry #{i} missing valid 'sitename'. Skipped.", file=sys.stderr)
            continue
        if "enable" in site and not isinstance(site["enable"], bool):
            print(f"ERROR: Entry #{i} 'enable' must be boolean. Skipped.", file=sys.stderr)
            continue
        valid.append(site)
    return valid

def save_sites(path: str, sites):
    # simple safe write with backup
    bak = path + ".bak"
    try:
        if os.path.exists(path):
            os.replace(path, bak)
    except Exception:
        pass
    with open(path, "w", encoding="utf-8") as f:
        json.dump(sites, f, ensure_ascii=False, indent=2)
        f.write("\n")

def get_cert_info(host: str, port: int, timeout: float = 5.0):
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
            not_after = cert.get("notAfter")
            not_before = cert.get("notBefore")
            na_dt = datetime.strptime(not_after, DATE_FMT).replace(tzinfo=timezone.utc)
            _ = datetime.strptime(not_before, DATE_FMT).replace(tzinfo=timezone.utc)
            days_left = (na_dt - datetime.now(timezone.utc)).days
            return not_before, not_after, days_left, na_dt

def status_label(days_left: int) -> str:
    if days_left < 0:
        return "EXPIRED"
    elif days_left <= 14:
        return "EXPIRES SOON"
    else:
        return "OK"

def send_alert_email(contact: str, sitename: str, not_after: str, days_left: int):
    # HTML alert using templates
    if days_left < 0:
        template = env.get_template("expired.html")
        subject = f"[ALERT] TLS certificate expired for {sitename}"
    else:
        template = env.get_template("expiressoon.html")
        subject = f"[ALERT] TLS certificate expiring soon for {sitename}"

    html_body = template.render(sitename=sitename, not_after=not_after, days_left=days_left)
    msg = MIMEText(html_body, "html")
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM
    msg["To"] = contact

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.sendmail(SMTP_FROM, [contact], msg.as_string())

def fmt_ics_dt(dt: datetime) -> str:
    # ICS timestamps must be UTC in YYYYMMDDTHHMMSSZ
    return dt.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

def build_ics(sitename: str, start: datetime, end: datetime, expiry: datetime, organizer: str, attendee: str) -> str:
    uid = f"{sitename}-{expiry.strftime('%Y%m%dT%H%M%SZ')}@cert-monitor"
    dtstamp = fmt_ics_dt(datetime.now(timezone.utc))
    dtstart = fmt_ics_dt(start)
    dtend = fmt_ics_dt(end)
    summary = f"Renew TLS certificate: {sitename}"
    description = f"Certificate for {sitename} expires on {expiry.strftime('%Y-%m-%d %H:%M:%S %Z')}."

    ics = (
        "BEGIN:VCALENDAR\r\n"
        "PRODID:-//cert-monitor//EN\r\n"
        "VERSION:2.0\r\n"
        "METHOD:REQUEST\r\n"
        "BEGIN:VEVENT\r\n"
        f"UID:{uid}\r\n"
        f"DTSTAMP:{dtstamp}\r\n"
        f"DTSTART:{dtstart}\r\n"
        f"DTEND:{dtend}\r\n"
        f"SUMMARY:{summary}\r\n"
        f"DESCRIPTION:{description}\r\n"
        f"ORGANIZER:MAILTO:{organizer}\r\n"
        f"ATTENDEE;CN={attendee}:MAILTO:{attendee}\r\n"
        "SEQUENCE:0\r\n"
        "STATUS:CONFIRMED\r\n"
        "TRANSP:OPAQUE\r\n"
        "END:VEVENT\r\n"
        "END:VCALENDAR\r\n"
    )
    return ics

def send_reminder_ics(contact: str, sitename: str, expiry_dt: datetime):
    # Event 5 days before expiry, 30 minutes duration
    start = expiry_dt - timedelta(days=5)
    end = start + timedelta(minutes=30)
    ics_str = build_ics(sitename, start, end, expiry_dt, SMTP_FROM, contact)

    msg = MIMEMultipart("mixed")
    msg["Subject"] = f"[REMINDER] Renew TLS certificate: {sitename}"
    msg["From"] = SMTP_FROM
    msg["To"] = contact

    # Plain text body
    body = MIMEText(
        f"A calendar reminder is attached.\n\n"
        f"{sitename} certificate expires on {expiry_dt.strftime('%Y-%m-%d %H:%M:%S %Z')}.\n"
        f"Reminder scheduled for {start.strftime('%Y-%m-%d %H:%M:%S %Z')} (5 days before).",
        "plain"
    )
    msg.attach(body)

    # ICS attachment
    ics_part = MIMEBase("text", "calendar", **{"method": "REQUEST", "name": f"renew-{sitename}.ics"})
    ics_part.set_payload(ics_str)
    encoders.encode_base64(ics_part)
    ics_part.add_header("Content-Disposition", "attachment", filename=f"renew-{sitename}.ics")
    ics_part.add_header("Content-Class", "urn:content-classes:calendarmessage")
    msg.attach(ics_part)

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.sendmail(SMTP_FROM, [contact], msg.as_string())

def main():
    args = parse_args()
    # If --no-mail alone, auto-show table+summary; if -J present, print dict instead.
    if args.no_mail and not (args.summary or args.json):
        args.summary = True

    sites = load_sites(JSON_FILE)
    if not sites:
        return 1

    rows = []
    statuses = []
    need_save = False  # if we update ending_date for any site

    now = datetime.now(timezone.utc)

    for s in sites:
        if not s.get("enable", True):
            continue

        host = s.get("sitename").strip()
        port = int(s["port"]) if "port" in s and s["port"] else 443
        contact = s.get("contact")

        try:
            _, na, days, na_dt = get_cert_info(host, port)
            label = status_label(days)
            statuses.append(label)
            rows.append({
                "sitename": host,
                "port": port,
                "status": label,
                "not_after": na,
                "days_left": days
            })

            # Alerts (expiring soon/expired) unless disabled
            if (not args.no_mail) and contact and (label in ("EXPIRES SOON", "EXPIRED")):
                try:
                    send_alert_email(contact, host, na, days)
                except Exception as e:
                    print(f"ERROR: Failed to send alert email to {contact} for {host}: {e}", file=sys.stderr)
                    statuses.append("ERROR")

            # Reminder ICS (-R): send once per expiry cycle using ending_date dedup
            if args.reminder and (not args.no_mail) and contact:
                # parse existing dedup field if present
                ending_date_str = s.get("ending_date")  # ISO 'YYYY-MM-DD', optional
                can_send = True
                if ending_date_str:
                    try:
                        ending_dt = datetime.strptime(ending_date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                        # Only send if NOW is AFTER stored ending_date (i.e., new cycle)
                        if now <= ending_dt:
                            can_send = False
                    except ValueError:
                        # bad format, ignore and proceed to send (will overwrite properly)
                        pass

                # Optional: don't send if the reminder time is already in the past
                reminder_time = na_dt - timedelta(days=5)
                if reminder_time <= now:
                    # Reminder would be in the past; skip silently
                    can_send = False

                if can_send:
                    try:
                        send_reminder_ics(contact, host, na_dt)
                        # update dedup field to current expiry date
                        s["ending_date"] = na_dt.strftime("%Y-%m-%d")
                        need_save = True
                    except Exception as e:
                        print(f"ERROR: Failed to send ICS reminder to {contact} for {host}: {e}", file=sys.stderr)
                        statuses.append("ERROR")

        except Exception as e:
            print(f"ERROR: {host}:{port} -> {e}", file=sys.stderr)
            statuses.append("ERROR")

    # Persist updated ending_date if we changed any
    if need_save:
        try:
            save_sites(JSON_FILE, sites)
        except Exception as e:
            print(f"ERROR: Failed to update '{JSON_FILE}': {e}", file=sys.stderr)
            statuses.append("ERROR")

    # Output modes
    counts = Counter(statuses)
    order = ["OK", "EXPIRES SOON", "EXPIRED", "ERROR"]
    summary = {k: counts.get(k, 0) for k in order}

    if args.json:
        print(summary)
    elif args.summary:
        # Table
        h1, h2, h3, h4, h5 = "SITENAME", "PORT", "STATUS", "EXPIRES", "DAYS LEFT"
        print(f"{h1:30} {h2:5}  {h3:14} {h4:30} {h5:10}")
        print("-" * 105)
        for r in rows:
            print(f"{r['sitename']:30} {r['port']:<5}  {r['status']:14} {r['not_after']:30} {r['days_left']:10}")
        print("\nSummary:")
        for k in order:
            if summary.get(k, 0):
                print(f"  {k:12}: {summary[k]}")

    # Exit codes
    if any(s in ("EXPIRED", "ERROR") for s in statuses):
        return 1
    if any(s == "EXPIRES SOON" for s in statuses):
        return 2
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
