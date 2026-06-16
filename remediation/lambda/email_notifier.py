"""
Email Notifier
Sends HTML-formatted security alert emails via SES.
Includes severity-appropriate templates for each alert type.
"""

import boto3
import json
import logging
import os
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from alert_router import SecurityAlert

logger = logging.getLogger(__name__)

ses = boto3.client("ses", region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))

# Severity → email styling
SEVERITY_STYLES = {
    "CRITICAL": {
        "color":      "#d13212",
        "bg":         "#fdf3f1",
        "border":     "#d13212",
        "badge_text": "⚠ CRITICAL",
    },
    "HIGH": {
        "color":      "#ff9900",
        "bg":         "#fff8f0",
        "border":     "#ff9900",
        "badge_text": "▲ HIGH",
    },
    "MEDIUM": {
        "color":      "#dfb52c",
        "bg":         "#fffdf0",
        "border":     "#dfb52c",
        "badge_text": "● MEDIUM",
    },
    "INFO": {
        "color":      "#0073bb",
        "bg":         "#f0f8ff",
        "border":     "#0073bb",
        "badge_text": "ℹ INFO",
    },
}


class EmailNotifier:

    def __init__(self, from_address: str):
        self.from_address = from_address

    def send(self, alert: "SecurityAlert", to: str, urgent: bool = True):
        """Send HTML alert email via SES."""
        from alert_router import AlertType

        subject = self._build_subject(alert)
        html    = self._build_html(alert)
        text    = self._build_text(alert)

        ses.send_email(
            Source=self.from_address,
            Destination={"ToAddresses": [to]},
            Message={
                "Subject": {
                    "Data":    subject,
                    "Charset": "UTF-8"
                },
                "Body": {
                    "Text": {"Data": text,    "Charset": "UTF-8"},
                    "Html": {"Data": html,    "Charset": "UTF-8"},
                }
            },
            # SES configuration set for tracking
            ConfigurationSetName=os.environ.get(
                "SES_CONFIG_SET", "security-alerts"
            ),
        )

        logger.info(
            "Email sent — Subject: %s | To: %s",
            subject, to
        )

    # ─────────────────────────────────────────────────
    # SUBJECT LINE
    # ─────────────────────────────────────────────────

    def _build_subject(self, alert: "SecurityAlert") -> str:
        prefix_map = {
            "CRITICAL": "🚨 [CRITICAL]",
            "HIGH":     "⚠️ [HIGH]",
            "MEDIUM":   "🔶 [MEDIUM]",
            "INFO":     "📊 [INFO]",
        }
        prefix = prefix_map.get(alert.severity, "[ALERT]")
        return f"{prefix} {alert.title} — {os.environ.get('PROJECT_NAME', 'Cloud Security')}"

    # ─────────────────────────────────────────────────
    # HTML BODY
    # ─────────────────────────────────────────────────

    def _build_html(self, alert: "SecurityAlert") -> str:
        sty     = SEVERITY_STYLES.get(alert.severity, SEVERITY_STYLES["INFO"])
        event   = alert.raw_event or {}
        project = os.environ.get("PROJECT_NAME", "Cloud Security Guardrails")

        # Build details rows
        details_rows = self._build_details_rows(alert)

        # Build findings section for scan complete alerts
        from alert_router import AlertType
        extra_section = ""
        if alert.alert_type == AlertType.CSPM_SCAN_COMPLETE:
            extra_section = self._build_scan_summary_html(event, sty)
        elif alert.remediation:
            extra_section = f"""
            <tr>
              <td style="padding:12px 0;border-bottom:1px solid #eee;">
                <strong style="color:#666;">Remediation</strong><br>
                <span style="color:#333;">{alert.remediation}</span>
              </td>
            </tr>"""

        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{alert.title}</title>
</head>
<body style="margin:0;padding:0;background:#f5f5f5;font-family:Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0"
         style="background:#f5f5f5;padding:20px 0;">
    <tr>
      <td align="center">
        <table width="600" cellpadding="0" cellspacing="0"
               style="background:#fff;border-radius:8px;
                      box-shadow:0 2px 8px rgba(0,0,0,0.1);
                      overflow:hidden;">

          <!-- Header bar -->
          <tr>
            <td style="background:{sty['color']};padding:4px 0;"></td>
          </tr>

          <!-- Title block -->
          <tr>
            <td style="padding:28px 32px 16px;
                       background:{sty['bg']};
                       border-left:4px solid {sty['border']};">
              <span style="display:inline-block;
                           background:{sty['color']};
                           color:#fff;
                           padding:4px 12px;
                           border-radius:4px;
                           font-size:12px;
                           font-weight:bold;
                           letter-spacing:0.5px;
                           margin-bottom:12px;">
                {sty['badge_text']}
              </span>
              <h1 style="margin:0;font-size:20px;
                         color:#232f3e;line-height:1.3;">
                {alert.title}
              </h1>
              <p style="margin:8px 0 0;color:#666;font-size:14px;">
                {alert.description}
              </p>
            </td>
          </tr>

          <!-- Details table -->
          <tr>
            <td style="padding:24px 32px;">
              <table width="100%" cellpadding="0" cellspacing="0">
                {details_rows}
                {extra_section}
              </table>
            </td>
          </tr>

          <!-- CTA button -->
          <tr>
            <td style="padding:0 32px 24px;" align="center">
              <a href="{event.get('dashboard_url', '#')}"
                 style="display:inline-block;
                        background:{sty['color']};
                        color:#fff;
                        padding:12px 28px;
                        border-radius:4px;
                        text-decoration:none;
                        font-weight:bold;
                        font-size:14px;">
                View Security Dashboard
              </a>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="background:#f8f8f8;
                       padding:16px 32px;
                       border-top:1px solid #eee;">
              <p style="margin:0;font-size:12px;color:#999;text-align:center;">
                {project} Security Alerts  |
                {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}  |
                Region: {alert.region}
                <br>
                This is an automated security notification.
                Do not reply to this email.
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""

    def _build_details_rows(self, alert: "SecurityAlert") -> str:
        """Build HTML table rows for alert metadata."""
        rows = [
            ("Severity",   alert.severity),
            ("Resource",   alert.resource_id),
            ("Region",     alert.region),
            ("Check ID",   alert.check_id   or "N/A"),
            ("Scan ID",    alert.scan_id    or "N/A"),
            ("Source",     alert.source),
            ("Timestamp",  alert.timestamp),
        ]

        html = ""
        for label, value in rows:
            html += f"""
            <tr>
              <td style="padding:10px 0;
                         border-bottom:1px solid #eee;
                         width:30%;">
                <strong style="color:#666;font-size:13px;">
                  {label}
                </strong>
              </td>
              <td style="padding:10px 0;
                         border-bottom:1px solid #eee;
                         color:#333;font-size:13px;">
                <code style="background:#f5f5f5;
                             padding:2px 6px;
                             border-radius:3px;">
                  {value}
                </code>
              </td>
            </tr>"""
        return html

    def _build_scan_summary_html(self, event: dict, sty: dict) -> str:
        """Extra HTML section for CSPM scan summary emails."""
        score    = event.get("score",    "N/A")
        critical = event.get("critical", 0)
        high     = event.get("high",     0)
        medium   = event.get("medium",   0)
        passed   = event.get("passed",   0)
        total    = event.get("total",    0)

        return f"""
        <tr>
          <td colspan="2" style="padding:16px 0 8px;">
            <strong style="color:#232f3e;font-size:15px;">
              Findings Summary
            </strong>
          </td>
        </tr>
        <tr>
          <td colspan="2">
            <table width="100%" cellpadding="8" cellspacing="4">
              <tr>
                <td style="background:#fdf3f1;border-radius:6px;text-align:center;">
                  <div style="font-size:24px;font-weight:bold;color:#d13212;">
                    {critical}
                  </div>
                  <div style="font-size:11px;color:#666;">Critical</div>
                </td>
                <td style="background:#fff8f0;border-radius:6px;text-align:center;">
                  <div style="font-size:24px;font-weight:bold;color:#ff9900;">
                    {high}
                  </div>
                  <div style="font-size:11px;color:#666;">High</div>
                </td>
                <td style="background:#fffdf0;border-radius:6px;text-align:center;">
                  <div style="font-size:24px;font-weight:bold;color:#dfb52c;">
                    {medium}
                  </div>
                  <div style="font-size:11px;color:#666;">Medium</div>
                </td>
                <td style="background:#f0fff4;border-radius:6px;text-align:center;">
                  <div style="font-size:24px;font-weight:bold;color:#1d8102;">
                    {passed}
                  </div>
                  <div style="font-size:11px;color:#666;">Passed</div>
                </td>
              </tr>
            </table>
          </td>
        </tr>"""

    # ─────────────────────────────────────────────────
    # PLAIN TEXT FALLBACK
    # ─────────────────────────────────────────────────

    def _build_text(self, alert: "SecurityAlert") -> str:
        """Plain text fallback for email clients that don't render HTML."""
        return f"""
SECURITY ALERT — {alert.severity}
{'=' * 50}

{alert.title}

{alert.description}

DETAILS
-------
Severity:   {alert.severity}
Check ID:   {alert.check_id or 'N/A'}
Resource:   {alert.resource_id}
Region:     {alert.region}
Source:     {alert.source}
Timestamp:  {alert.timestamp}

{'Remediation: ' + alert.remediation if alert.remediation else ''}

{'=' * 50}
Project: {os.environ.get('PROJECT_NAME', 'Cloud Security Guardrails')}
This is an automated security notification.
"""
