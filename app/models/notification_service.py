"""
VPRP — Notification Service
Sends SLA breach alerts and remediation updates via Microsoft Teams and Email.
"""
import json
import logging
import os
import smtplib
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

import requests
import pandas as pd
from sqlalchemy import and_, func

from app.models.database import get_session
from app.models.schemas import Finding

logger = logging.getLogger(__name__)

# ── Configuration from environment ───────────────────────
TEAMS_WEBHOOK_URL = os.environ.get("TEAMS_WEBHOOK_URL", "")
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SMTP_FROM = os.environ.get("SMTP_FROM", "vprp@company.com")
SMTP_USE_TLS = os.environ.get("SMTP_USE_TLS", "true").lower() == "true"
NOTIFICATION_RECIPIENTS = os.environ.get("NOTIFICATION_RECIPIENTS", "").split(",")
VPRP_BASE_URL = os.environ.get("VPRP_BASE_URL", "https://localhost")


# ── SLA Analysis ─────────────────────────────────────────
def get_sla_alerts(session=None) -> dict:
    """Identify SLA breaches and upcoming deadlines."""
    _session = session or get_session()
    try:
        now = datetime.now(timezone.utc)
        week_ahead = now + timedelta(days=7)

        # Currently breached (open/in_progress only)
        breached = _session.query(Finding).filter(
            Finding.sla_breached == True,
            Finding.remediation_status.in_(["open", "in_progress"]),
        ).all()

        # Approaching SLA (within 7 days, not yet breached)
        approaching = _session.query(Finding).filter(
            Finding.sla_breached == False,
            Finding.sla_deadline <= week_ahead,
            Finding.sla_deadline > now,
            Finding.remediation_status.in_(["open", "in_progress"]),
        ).all()

        # Group breached by team
        team_breaches = {}
        for f in breached:
            team = f.assigned_team or "Unassigned"
            if team not in team_breaches:
                team_breaches[team] = []
            team_breaches[team].append({
                "cve_id": f.cve_id,
                "device_name": f.device_name,
                "severity": f.vulnerability_severity,
                "risk_score": f.risk_score,
                "sla_deadline": str(f.sla_deadline) if f.sla_deadline else "N/A",
                "status": f.remediation_status,
                "days_overdue": (now - f.sla_deadline).days if f.sla_deadline else 0,
            })

        # Group approaching by team
        team_approaching = {}
        for f in approaching:
            team = f.assigned_team or "Unassigned"
            if team not in team_approaching:
                team_approaching[team] = []
            team_approaching[team].append({
                "cve_id": f.cve_id,
                "device_name": f.device_name,
                "severity": f.vulnerability_severity,
                "risk_score": f.risk_score,
                "sla_deadline": str(f.sla_deadline) if f.sla_deadline else "N/A",
                "days_remaining": (f.sla_deadline - now).days if f.sla_deadline else 0,
            })

        return {
            "timestamp": now.isoformat(),
            "total_breached": len(breached),
            "total_approaching": len(approaching),
            "team_breaches": team_breaches,
            "team_approaching": team_approaching,
            "breached_critical": sum(1 for f in breached if f.vulnerability_severity == "critical"),
            "breached_high": sum(1 for f in breached if f.vulnerability_severity == "high"),
        }
    finally:
        if not session:
            _session.close()


# ── Microsoft Teams Notification ─────────────────────────
def send_teams_notification(title: str, message: str, color: str = "FF0000",
                            facts: list = None) -> bool:
    """Send adaptive card to Microsoft Teams via webhook."""
    if not TEAMS_WEBHOOK_URL:
        logger.warning("Teams webhook URL not configured")
        return False

    # Build MessageCard format (works with most Teams webhooks)
    card = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": color,
        "summary": title,
        "sections": [{
            "activityTitle": f"🛡️ VPRP — {title}",
            "activitySubtitle": datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
            "facts": facts or [],
            "text": message,
            "markdown": True,
        }],
        "potentialAction": [{
            "@type": "OpenUri",
            "name": "Open VPRP Dashboard",
            "targets": [{"os": "default", "uri": VPRP_BASE_URL}],
        }],
    }

    try:
        resp = requests.post(
            TEAMS_WEBHOOK_URL,
            json=card,
            headers={"Content-Type": "application/json"},
            timeout=15,
        )
        if resp.status_code == 200:
            logger.info(f"Teams notification sent: {title}")
            return True
        else:
            logger.error(f"Teams webhook failed: {resp.status_code} — {resp.text}")
            return False
    except Exception as e:
        logger.error(f"Teams notification error: {e}")
        return False


def send_teams_sla_alert(alerts: dict) -> bool:
    """Format and send SLA breach alert to Teams."""
    if alerts["total_breached"] == 0 and alerts["total_approaching"] == 0:
        logger.info("No SLA alerts to send")
        return True

    color = "FF0000" if alerts["total_breached"] > 0 else "FFA500"
    title = "SLA Breach Alert" if alerts["total_breached"] > 0 else "SLA Warning"

    facts = [
        {"name": "Total Breached", "value": str(alerts["total_breached"])},
        {"name": "Critical Breached", "value": str(alerts["breached_critical"])},
        {"name": "High Breached", "value": str(alerts["breached_high"])},
        {"name": "Approaching SLA (7 days)", "value": str(alerts["total_approaching"])},
    ]

    # Build team summary
    lines = []
    for team, items in alerts["team_breaches"].items():
        lines.append(f"**{team}**: {len(items)} breached")
        for item in items[:5]:  # top 5 per team
            lines.append(f"  - {item['cve_id']} on {item['device_name']} "
                        f"({item['severity']}, {item['days_overdue']}d overdue)")
        if len(items) > 5:
            lines.append(f"  - ... and {len(items)-5} more")

    if alerts["team_approaching"]:
        lines.append("\n**Approaching SLA:**")
        for team, items in alerts["team_approaching"].items():
            lines.append(f"**{team}**: {len(items)} approaching")
            for item in items[:3]:
                lines.append(f"  - {item['cve_id']} — {item['days_remaining']}d remaining")

    message = "\n".join(lines) if lines else "All findings within SLA."

    return send_teams_notification(title, message, color, facts)


# ── Email Notification ───────────────────────────────────
def send_email(subject: str, html_body: str, recipients: list = None) -> bool:
    """Send HTML email via SMTP."""
    if not SMTP_HOST:
        logger.warning("SMTP not configured")
        return False

    to_addrs = recipients or [r.strip() for r in NOTIFICATION_RECIPIENTS if r.strip()]
    if not to_addrs:
        logger.warning("No email recipients configured")
        return False

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[VPRP] {subject}"
    msg["From"] = SMTP_FROM
    msg["To"] = ", ".join(to_addrs)

    html_part = MIMEText(html_body, "html")
    msg.attach(html_part)

    try:
        if SMTP_USE_TLS:
            server = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
            server.starttls()
        else:
            server = smtplib.SMTP(SMTP_HOST, SMTP_PORT)

        if SMTP_USER and SMTP_PASSWORD:
            server.login(SMTP_USER, SMTP_PASSWORD)

        server.sendmail(SMTP_FROM, to_addrs, msg.as_string())
        server.quit()
        logger.info(f"Email sent to {to_addrs}: {subject}")
        return True
    except Exception as e:
        logger.error(f"Email send failed: {e}")
        return False


def send_email_sla_alert(alerts: dict, recipients: list = None) -> bool:
    """Format and send SLA breach alert email."""
    if alerts["total_breached"] == 0 and alerts["total_approaching"] == 0:
        return True

    subject = (f"SLA BREACH: {alerts['total_breached']} findings overdue"
               if alerts["total_breached"] > 0
               else f"SLA Warning: {alerts['total_approaching']} findings approaching deadline")

    # Build HTML email
    rows_html = ""
    for team, items in alerts["team_breaches"].items():
        for item in items:
            rows_html += f"""<tr style="background:#fee2e2">
                <td>{item['cve_id']}</td><td>{item['device_name']}</td>
                <td>{item['severity']}</td><td>{item['risk_score']}</td>
                <td><b>{item['days_overdue']}d overdue</b></td>
                <td>{team}</td><td>{item['status']}</td>
            </tr>"""

    for team, items in alerts["team_approaching"].items():
        for item in items:
            rows_html += f"""<tr style="background:#fef3c7">
                <td>{item['cve_id']}</td><td>{item['device_name']}</td>
                <td>{item['severity']}</td><td>{item['risk_score']}</td>
                <td>{item['days_remaining']}d remaining</td>
                <td>{team}</td><td>approaching</td>
            </tr>"""

    html = f"""
    <html><body style="font-family:Arial,sans-serif">
    <h2 style="color:#dc2626">🛡️ VPRP — SLA Alert Report</h2>
    <p>Generated: {alerts['timestamp']}</p>
    <table style="border-collapse:collapse;width:100%">
        <tr style="background:#1e293b;color:white">
            <th style="padding:8px;text-align:left">CVE</th>
            <th style="padding:8px;text-align:left">Device</th>
            <th style="padding:8px;text-align:left">Severity</th>
            <th style="padding:8px;text-align:left">Risk</th>
            <th style="padding:8px;text-align:left">SLA Status</th>
            <th style="padding:8px;text-align:left">Team</th>
            <th style="padding:8px;text-align:left">Remediation</th>
        </tr>
        {rows_html}
    </table>
    <br>
    <p><b>Summary:</b> {alerts['total_breached']} breached | {alerts['total_approaching']} approaching</p>
    <p><a href="{VPRP_BASE_URL}/Remediation">Open VPRP Remediation Dashboard</a></p>
    </body></html>
    """

    return send_email(subject, html, recipients)


# ── Remediation Status Change Notification ───────────────
def notify_status_change(cve_id: str, device_name: str, old_status: str,
                         new_status: str, performed_by: str, team: str = None) -> bool:
    """Send notification when a finding status changes."""
    color_map = {
        "remediated": "22C55E", "in_progress": "F59E0B",
        "open": "EF4444", "exception": "A855F7",
        "accepted_risk": "6366F1", "false_positive": "64748B",
    }
    color = color_map.get(new_status, "3B82F6")

    title = f"Status Change: {cve_id}"
    message = (f"**{cve_id}** on **{device_name}**\n\n"
               f"Status: {old_status} → **{new_status}**\n"
               f"Team: {team or 'N/A'}\n"
               f"Updated by: {performed_by}")

    facts = [
        {"name": "CVE", "value": cve_id},
        {"name": "Device", "value": device_name},
        {"name": "Transition", "value": f"{old_status} → {new_status}"},
        {"name": "By", "value": performed_by},
    ]

    teams_ok = send_teams_notification(title, message, color, facts) if TEAMS_WEBHOOK_URL else True
    return teams_ok


# ── Scheduled Alert Runner ───────────────────────────────
def run_sla_check_and_notify() -> dict:
    """Run full SLA check and send notifications. Call from cron/scheduler."""
    logger.info("Running scheduled SLA check...")
    alerts = get_sla_alerts()

    results = {
        "total_breached": alerts["total_breached"],
        "total_approaching": alerts["total_approaching"],
        "teams_sent": False,
        "email_sent": False,
    }

    if alerts["total_breached"] > 0 or alerts["total_approaching"] > 0:
        results["teams_sent"] = send_teams_sla_alert(alerts)
        results["email_sent"] = send_email_sla_alert(alerts)

    logger.info(f"SLA check complete: {results}")
    return results
