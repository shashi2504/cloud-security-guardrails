"""
Slack Notifier
Sends formatted security alerts to Slack channels.
Webhook URL stored in Secrets Manager — never hardcoded.
"""

import boto3
import json
import logging
import urllib.request
import urllib.error
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from alert_router import SecurityAlert, AlertSeverity, AlertType

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────
# SEVERITY → SLACK VISUAL MAPPING
# ─────────────────────────────────────────────────────────

SEVERITY_CONFIG = {
    "CRITICAL": {
        "color":  "#d13212",    # AWS red
        "emoji":  "🚨",
        "label":  "CRITICAL",
        "mention": "<!channel>",    # @channel for critical
    },
    "HIGH": {
        "color":  "#ff9900",    # AWS orange
        "emoji":  "⚠️",
        "label":  "HIGH",
        "mention": "<!here>",       # @here for high
    },
    "MEDIUM": {
        "color":  "#dfb52c",    # AWS yellow
        "emoji":  "🔶",
        "label":  "MEDIUM",
        "mention": "",
    },
    "LOW": {
        "color":  "#1d8102",    # AWS green
        "emoji":  "ℹ️",
        "label":  "LOW",
        "mention": "",
    },
    "INFO": {
        "color":  "#0073bb",    # AWS blue
        "emoji":  "📊",
        "label":  "INFO",
        "mention": "",
    },
}

TYPE_EMOJI = {
    "CLOUDTRAIL_ALARM":   "🔔",
    "CSPM_FINDING":       "🔍",
    "CSPM_SCAN_COMPLETE": "📋",
    "REMEDIATION_ACTION": "🔧",
    "MANUAL":             "📣",
}


class SlackNotifier:

    def __init__(self, secret_arn: str):
        self.secret_arn     = secret_arn
        self._webhook_cache = None    # Cache — only fetch once per Lambda warm start
        self._secrets       = boto3.client("secretsmanager")

    @property
    def webhook_url(self) -> str:
        """Fetch webhook URL from Secrets Manager — cached per Lambda instance."""
        if not self._webhook_cache:
            secret   = self._secrets.get_secret_value(SecretId=self.secret_arn)
            payload  = json.loads(secret["SecretString"])
            self._webhook_cache = payload["slack_webhook_url"]
        return self._webhook_cache

    # ─────────────────────────────────────────────────
    # PUBLIC API
    # ─────────────────────────────────────────────────

    def send(self, alert: "SecurityAlert", channel: str, urgent: bool = True):
        """
        Send formatted alert to Slack.
        Selects block template based on alert type.
        """
        from alert_router import AlertType

        if alert.alert_type == AlertType.CSPM_SCAN_COMPLETE:
            blocks = self._build_scan_summary_blocks(alert)
        elif alert.alert_type == AlertType.CLOUDTRAIL_ALARM:
            blocks = self._build_alarm_blocks(alert)
        elif alert.alert_type == AlertType.REMEDIATION_ACTION:
            blocks = self._build_remediation_blocks(alert)
        else:
            blocks = self._build_finding_blocks(alert)

        payload = {
            "channel":  channel,
            "username": "Security Bot",
            "icon_emoji": ":lock:",
            "blocks":   blocks,
            # Fallback text for notifications
            "text": f"{SEVERITY_CONFIG[alert.severity]['emoji']} [{alert.severity}] {alert.title}",
        }

        self._post(payload)

    # ─────────────────────────────────────────────────
    # BLOCK BUILDERS
    # Each alert type gets its own Slack Block Kit layout
    # ─────────────────────────────────────────────────

    def _build_alarm_blocks(self, alert: "SecurityAlert") -> list:
        """CloudWatch alarm — real-time violation detected."""
        cfg     = SEVERITY_CONFIG[alert.severity]
        mention = f"{cfg['mention']} " if cfg["mention"] else ""

        return [
            # Header
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{cfg['emoji']} Security Alarm Triggered",
                    "emoji": True,
                }
            },

            # Mention + title
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"{mention}*{alert.title}*\n{alert.description}"
                }
            },

            # Details grid
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Severity*\n`{cfg['label']}`"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Region*\n`{alert.region}`"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Resource*\n`{alert.resource_id}`"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Time*\n`{alert.timestamp}`"
                    },
                ]
            },

            # Divider
            {"type": "divider"},

            # Context footer
            {
                "type": "context",
                "elements": [{
                    "type": "mrkdwn",
                    "text": (
                        f"🔍 Source: CloudTrail → CloudWatch Alarm  |  "
                        f"📁 Project: {_project()}  |  "
                        f"🕐 {_now()}"
                    )
                }]
            }
        ]

    def _build_finding_blocks(self, alert: "SecurityAlert") -> list:
        """Individual CSPM finding from Prowler."""
        cfg     = SEVERITY_CONFIG[alert.severity]
        mention = f"{cfg['mention']} " if cfg["mention"] else ""

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{cfg['emoji']} Security Finding Detected",
                    "emoji": True,
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"{mention}*{alert.title}*"
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Severity*\n`{cfg['label']}`"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Check ID*\n`{alert.check_id or 'N/A'}`"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Resource*\n`{alert.resource_id}`"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Region*\n`{alert.region}`"
                    },
                ]
            },
        ]

        # Add description if present
        if alert.description:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Description*\n{alert.description[:300]}"
                }
            })

        # Add remediation if present
        if alert.remediation:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Remediation*\n{alert.remediation[:300]}"
                }
            })

        blocks += [
            {"type": "divider"},
            {
                "type": "context",
                "elements": [{
                    "type": "mrkdwn",
                    "text": (
                        f"🔍 Source: Prowler CSPM  |  "
                        f"📁 Scan: {alert.scan_id or 'N/A'}  |  "
                        f"🕐 {_now()}"
                    )
                }]
            }
        ]

        return blocks

    def _build_scan_summary_blocks(self, alert: "SecurityAlert") -> list:
        """Daily CSPM scan completion summary."""
        cfg   = SEVERITY_CONFIG[alert.severity]
        event = alert.raw_event or {}

        score    = event.get("score",    "N/A")
        critical = event.get("critical", 0)
        high     = event.get("high",     0)
        medium   = event.get("medium",   0)
        passed   = event.get("passed",   0)
        total    = event.get("total",    0)
        rating   = event.get("rating",   "N/A")
        delta    = event.get("delta",    None)

        # Score bar — visual indicator
        score_bar = _score_bar(float(score) if score != "N/A" else 0)

        # Delta string
        if delta is not None:
            delta_f   = float(delta)
            delta_str = f"{'↑' if delta_f >= 0 else '↓'} {abs(delta_f):.1f} pts vs last scan"
        else:
            delta_str = "First scan"

        return [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "📋 Daily Security Scan Complete",
                    "emoji": True,
                }
            },

            # Score hero
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*Security Score: {score}/100 — {rating}*\n"
                        f"{score_bar}\n"
                        f"_{delta_str}_"
                    )
                }
            },

            {"type": "divider"},

            # Findings breakdown
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*🔴 Critical*\n`{critical}`"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*🟠 High*\n`{high}`"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*🟡 Medium*\n`{medium}`"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*✅ Passed*\n`{passed}/{total}`"
                    },
                ]
            },

            {"type": "divider"},

            # Action buttons
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "📊 View Dashboard",
                            "emoji": True,
                        },
                        "url":   event.get("dashboard_url", "#"),
                        "style": "primary",
                    },
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "📄 Full Report",
                            "emoji": True,
                        },
                        "url": event.get("report_url", "#"),
                    },
                ]
            },

            {
                "type": "context",
                "elements": [{
                    "type": "mrkdwn",
                    "text": (
                        f"🔍 Source: Prowler CSPM  |  "
                        f"📁 Scan: {alert.scan_id or 'N/A'}  |  "
                        f"🕐 {_now()}"
                    )
                }]
            }
        ]

    def _build_remediation_blocks(self, alert: "SecurityAlert") -> list:
        """Auto-remediation action confirmation."""
        event = alert.raw_event or {}

        return [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🔧 Auto-Remediation Applied",
                    "emoji": True,
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*{alert.title}*\n{alert.description}"
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Action*\n`{event.get('remediation_action', 'N/A')}`"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Resource*\n`{alert.resource_id}`"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Status*\n`{event.get('status', 'APPLIED')}`"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Region*\n`{alert.region}`"
                    },
                ]
            },
            {
                "type": "context",
                "elements": [{
                    "type": "mrkdwn",
                    "text": f"🔧 Auto-Remediation  |  📁 Project: {_project()}  |  🕐 {_now()}"
                }]
            }
        ]

    # ─────────────────────────────────────────────────
    # HTTP POST
    # ─────────────────────────────────────────────────

    def _post(self, payload: dict):
        """POST payload to Slack webhook."""
        data = json.dumps(payload).encode("utf-8")
        req  = urllib.request.Request(
            self.webhook_url,
            data    = data,
            headers = {"Content-Type": "application/json"},
            method  = "POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                body = response.read().decode()
                if body != "ok":
                    logger.warning("Slack unexpected response: %s", body)
        except urllib.error.HTTPError as e:
            logger.error("Slack HTTP error %d: %s", e.code, e.read().decode())
            raise
        except urllib.error.URLError as e:
            logger.error("Slack URL error: %s", str(e))
            raise


# ─────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────

def _score_bar(score: float, width: int = 20) -> str:
    """Build a visual score bar using Slack-compatible characters."""
    filled = int((score / 100) * width)
    empty  = width - filled

    if score >= 90:
        char = "🟢"
    elif score >= 75:
        char = "🟡"
    elif score >= 60:
        char = "🟠"
    else:
        char = "🔴"

    return f"{char * filled}{'⬜' * empty} `{score:.0f}/100`"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _project() -> str:
    return os.environ.get("PROJECT_NAME", "cloud-sec-guardrails")


import os
