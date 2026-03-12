"""
Integration connectors for the workflow engine.
Real implementations for Jira, ServiceNow, Email (SMTP), Slack, and Teams.
Each connector reads its config from the IntegrationConfig table.
"""
import json
import logging
import os
import sys
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Optional

import requests
from sqlalchemy.orm import Session

# Add repo root to path so hakuna package is importable from backend/
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from hakuna.utils.token_tracker import get_tracker, track_tokens

from models.models import IntegrationConfig

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# Config helpers
# ─────────────────────────────────────────────

def get_integration_config(db: Session, provider: str) -> Optional[dict]:
    """Load config dict for a given integration provider."""
    cfg = db.query(IntegrationConfig).filter(
        IntegrationConfig.provider == provider,
        IntegrationConfig.is_enabled == True,
    ).first()
    if not cfg:
        return None
    return cfg.config or {}


def test_integration(db: Session, provider: str) -> dict:
    """Test connectivity for a given integration (works even if disabled)."""
    row = db.query(IntegrationConfig).filter(
        IntegrationConfig.provider == provider,
    ).first()
    if not row or not row.config:
        return {"status": "error", "detail": f"{provider} not configured"}
    cfg = row.config

    try:
        if provider == "jira":
            return _test_jira(cfg)
        elif provider == "servicenow":
            return _test_servicenow(cfg)
        elif provider == "email":
            return _test_email(cfg)
        elif provider == "slack":
            return _test_slack(cfg)
        elif provider == "teams":
            return _test_teams(cfg)
        elif provider == "anthropic":
            return _test_anthropic(cfg)
        elif provider == "openai":
            return _test_openai(cfg)
        elif provider == "google_gemini":
            return _test_google_gemini(cfg)
        elif provider == "groq":
            return _test_groq(cfg)
        return {"status": "error", "detail": f"Unknown provider: {provider}"}
    except Exception as e:
        return {"status": "error", "detail": str(e)}


# ─────────────────────────────────────────────
# Jira Connector
# ─────────────────────────────────────────────

def create_jira_ticket(db: Session, config: dict, items: list) -> dict:
    """Create Jira issue(s) from workflow items.

    config keys:
      project, issue_type, title_template, description_template,
      assignee, labels, priority, group_by
    """
    int_cfg = get_integration_config(db, "jira")
    if not int_cfg:
        raise ConnectionError("Jira integration not configured")

    base_url = int_cfg["base_url"].rstrip("/")
    email = int_cfg["email"]
    api_token = int_cfg["api_token"]
    auth = (email, api_token)
    headers = {"Content-Type": "application/json"}

    group_by = config.get("group_by", "one_per_finding")
    groups = _group_items(items, group_by)
    created = []

    for group_key, group_items in groups.items():
        title = _render(config.get("title_template", "[{severity_label}] {plugin_name}"),
                        group_items[0], count=len(group_items))
        description = _render(
            config.get("description_template",
                        "Remediation required for {count} finding(s).\n\n"
                        "Severity: {severity_label}\nPlugin: {plugin_name}\n"
                        "Asset: {asset_ip} ({asset_hostname})\n\nSolution: {solution}"),
            group_items[0], count=len(group_items))

        # Jira API v3 create issue
        payload = {
            "fields": {
                "project": {"key": config.get("project", int_cfg.get("default_project", "SEC"))},
                "summary": title[:255],
                "description": {
                    "type": "doc", "version": 1,
                    "content": [{"type": "paragraph", "content": [{"type": "text", "text": description}]}],
                },
                "issuetype": {"name": config.get("issue_type", "Task")},
            }
        }

        # Optional fields
        priority = config.get("priority")
        if priority:
            prio_map = {"highest": "Highest", "high": "High", "medium": "Medium", "low": "Low", "lowest": "Lowest"}
            payload["fields"]["priority"] = {"name": prio_map.get(priority, priority.title())}

        assignee = config.get("assignee")
        if assignee:
            payload["fields"]["assignee"] = {"accountId": assignee} if "@" not in assignee else {"emailAddress": assignee}

        labels = config.get("labels", "")
        if labels:
            payload["fields"]["labels"] = [l.strip() for l in labels.split(",") if l.strip()]

        try:
            r = requests.post(
                f"{base_url}/rest/api/3/issue",
                auth=auth, headers=headers,
                json=payload, timeout=15,
            )
            r.raise_for_status()
            data = r.json()
            created.append({
                "key": data.get("key"),
                "id": data.get("id"),
                "url": f"{base_url}/browse/{data.get('key')}",
                "items_count": len(group_items),
            })
        except requests.RequestException as e:
            logger.error(f"Jira ticket creation failed: {e}")
            error_detail = ""
            if hasattr(e, 'response') and e.response is not None:
                error_detail = e.response.text[:200]
            created.append({"error": str(e), "detail": error_detail, "items_count": len(group_items)})

    return {"tickets_created": len([c for c in created if "key" in c]), "results": created}


def _test_jira(cfg: dict) -> dict:
    r = requests.get(
        f"{cfg['base_url'].rstrip('/')}/rest/api/3/myself",
        auth=(cfg["email"], cfg["api_token"]),
        timeout=10,
    )
    r.raise_for_status()
    user = r.json()
    return {"status": "ok", "user": user.get("displayName", "connected")}


# ─────────────────────────────────────────────
# ServiceNow Connector
# ─────────────────────────────────────────────

def create_servicenow_ticket(db: Session, config: dict, items: list) -> dict:
    """Create ServiceNow incident(s) from workflow items.

    config keys:
      table (default: incident), title_template, description_template,
      assignment_group, category, urgency, impact, group_by
    """
    int_cfg = get_integration_config(db, "servicenow")
    if not int_cfg:
        raise ConnectionError("ServiceNow integration not configured")

    instance_url = int_cfg["instance_url"].rstrip("/")
    auth = (int_cfg["username"], int_cfg["password"])
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    table = config.get("table", "incident")

    group_by = config.get("group_by", "one_per_finding")
    groups = _group_items(items, group_by)
    created = []

    for group_key, group_items in groups.items():
        title = _render(config.get("title_template", "[{severity_label}] {plugin_name}"),
                        group_items[0], count=len(group_items))
        description = _render(
            config.get("description_template",
                        "Vulnerability remediation required.\n\n"
                        "Findings: {count}\nSeverity: {severity_label}\n"
                        "Asset: {asset_ip}\nPlugin: {plugin_name}\n\nSolution: {solution}"),
            group_items[0], count=len(group_items))

        payload = {
            "short_description": title[:160],
            "description": description,
            "urgency": config.get("urgency", "2"),
            "impact": config.get("impact", "2"),
        }
        if config.get("assignment_group"):
            payload["assignment_group"] = config["assignment_group"]
        if config.get("category"):
            payload["category"] = config["category"]

        try:
            r = requests.post(
                f"{instance_url}/api/now/table/{table}",
                auth=auth, headers=headers,
                json=payload, timeout=15,
            )
            r.raise_for_status()
            data = r.json().get("result", {})
            created.append({
                "number": data.get("number"),
                "sys_id": data.get("sys_id"),
                "url": f"{instance_url}/nav_to.do?uri=incident.do?sys_id={data.get('sys_id')}",
                "items_count": len(group_items),
            })
        except requests.RequestException as e:
            logger.error(f"ServiceNow ticket creation failed: {e}")
            created.append({"error": str(e), "items_count": len(group_items)})

    return {"tickets_created": len([c for c in created if "number" in c]), "results": created}


def _test_servicenow(cfg: dict) -> dict:
    r = requests.get(
        f"{cfg['instance_url'].rstrip('/')}/api/now/table/sys_user?sysparm_limit=1",
        auth=(cfg["username"], cfg["password"]),
        headers={"Accept": "application/json"},
        timeout=10,
    )
    r.raise_for_status()
    return {"status": "ok", "instance": cfg["instance_url"]}


# ─────────────────────────────────────────────
# Email (SMTP) Connector
# ─────────────────────────────────────────────

def send_email(db: Session, config: dict, items: list) -> dict:
    """Send an email notification with findings summary.

    config keys:
      to, subject, body_template, include_findings_table
    """
    int_cfg = get_integration_config(db, "email")
    if not int_cfg:
        raise ConnectionError("Email (SMTP) integration not configured")

    smtp_host = int_cfg["smtp_host"]
    smtp_port = int(int_cfg.get("smtp_port", 587))
    smtp_user = int_cfg.get("smtp_user", "")
    smtp_pass = int_cfg.get("smtp_pass", "")
    from_addr = int_cfg.get("from_address", smtp_user)
    use_tls = int_cfg.get("use_tls", True)

    to_addrs = [a.strip() for a in config.get("to", "").split(",") if a.strip()]
    if not to_addrs:
        raise ValueError("No recipient email addresses specified")

    subject = _render(config.get("subject", "Nessus Remediation Alert"), items[0] if items else {}, count=len(items))
    body = _render(config.get("body_template", "Found {count} findings requiring attention."),
                   items[0] if items else {}, count=len(items))

    # Build findings table if requested
    if config.get("include_findings_table") and items:
        table_lines = ["\n\n--- Findings Summary ---\n"]
        table_lines.append(f"{'Severity':<10} {'Plugin':<40} {'Asset':<20}")
        table_lines.append("-" * 70)
        for item in items[:50]:  # cap at 50
            sev = item.get("severity_label", "?")
            plugin = (item.get("plugin_name", ""))[:38]
            asset = item.get("asset_ip", "")
            table_lines.append(f"{sev:<10} {plugin:<40} {asset:<20}")
        if len(items) > 50:
            table_lines.append(f"\n... and {len(items) - 50} more findings")
        body += "\n".join(table_lines)

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = ", ".join(to_addrs)
    msg.attach(MIMEText(body, "plain"))

    try:
        if use_tls:
            server = smtplib.SMTP(smtp_host, smtp_port)
            server.starttls()
        else:
            server = smtplib.SMTP(smtp_host, smtp_port)
        if smtp_user and smtp_pass:
            server.login(smtp_user, smtp_pass)
        server.sendmail(from_addr, to_addrs, msg.as_string())
        server.quit()
        return {"status": "sent", "recipients": to_addrs, "items_count": len(items)}
    except Exception as e:
        logger.error(f"Email send failed: {e}")
        raise


def _test_email(cfg: dict) -> dict:
    smtp_host = cfg["smtp_host"]
    smtp_port = int(cfg.get("smtp_port", 587))
    use_tls = cfg.get("use_tls", True)
    server = smtplib.SMTP(smtp_host, smtp_port, timeout=10)
    if use_tls:
        server.starttls()
    if cfg.get("smtp_user") and cfg.get("smtp_pass"):
        server.login(cfg["smtp_user"], cfg["smtp_pass"])
    server.quit()
    return {"status": "ok", "host": smtp_host}


# ─────────────────────────────────────────────
# Slack Connector (Incoming Webhook)
# ─────────────────────────────────────────────

def send_slack_notification(db: Session, config: dict, items: list) -> dict:
    """Send a Slack message via incoming webhook.

    config keys:
      webhook_url (can override integration default), channel, message_template, include_summary
    """
    int_cfg = get_integration_config(db, "slack")
    webhook_url = config.get("webhook_url") or (int_cfg or {}).get("webhook_url")
    if not webhook_url:
        raise ConnectionError("Slack webhook URL not configured")

    message = _render(config.get("message_template", ":warning: Found {count} findings requiring attention"),
                      items[0] if items else {}, count=len(items))

    payload = {"text": message}
    channel = config.get("channel") or (int_cfg or {}).get("default_channel")
    if channel:
        payload["channel"] = channel

    # Add summary blocks if requested
    if config.get("include_summary") and items:
        sev_counts = {}
        for item in items:
            sl = item.get("severity_label", "Unknown")
            sev_counts[sl] = sev_counts.get(sl, 0) + 1
        summary = " | ".join(f"*{k}*: {v}" for k, v in sorted(sev_counts.items(), reverse=True))

        # Unique assets
        assets = set(item.get("asset_ip", "") for item in items if item.get("asset_ip"))

        payload["blocks"] = [
            {"type": "section", "text": {"type": "mrkdwn", "text": message}},
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*Findings:* {len(items)}"},
                {"type": "mrkdwn", "text": f"*Assets:* {len(assets)}"},
            ]},
            {"type": "section", "text": {"type": "mrkdwn", "text": summary}},
        ]

    r = requests.post(webhook_url, json=payload, timeout=10)
    r.raise_for_status()
    return {"status": "sent", "items_count": len(items)}


def _test_slack(cfg: dict) -> dict:
    webhook_url = cfg.get("webhook_url")
    if not webhook_url:
        return {"status": "error", "detail": "No webhook URL"}
    r = requests.post(webhook_url, json={"text": "Nessus Remediation Platform — connection test"}, timeout=10)
    r.raise_for_status()
    return {"status": "ok"}


# ─────────────────────────────────────────────
# Microsoft Teams Connector (Incoming Webhook)
# ─────────────────────────────────────────────

def send_teams_notification(db: Session, config: dict, items: list) -> dict:
    """Send a Teams message via incoming webhook.

    config keys:
      webhook_url (can override), message_template, include_summary
    """
    int_cfg = get_integration_config(db, "teams")
    webhook_url = config.get("webhook_url") or (int_cfg or {}).get("webhook_url")
    if not webhook_url:
        raise ConnectionError("Teams webhook URL not configured")

    message = _render(config.get("message_template", "Found {count} findings requiring attention"),
                      items[0] if items else {}, count=len(items))

    # Adaptive Card format
    card = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": "dc2626",
        "summary": message[:100],
        "sections": [{
            "activityTitle": "Nessus Remediation Alert",
            "text": message,
        }],
    }

    if config.get("include_summary") and items:
        sev_counts = {}
        for item in items:
            sl = item.get("severity_label", "Unknown")
            sev_counts[sl] = sev_counts.get(sl, 0) + 1
        assets = set(item.get("asset_ip", "") for item in items if item.get("asset_ip"))

        card["sections"][0]["facts"] = [
            {"name": "Findings", "value": str(len(items))},
            {"name": "Assets", "value": str(len(assets))},
        ] + [{"name": k, "value": str(v)} for k, v in sorted(sev_counts.items(), reverse=True)]

    r = requests.post(webhook_url, json=card, timeout=10)
    r.raise_for_status()
    return {"status": "sent", "items_count": len(items)}


def _test_teams(cfg: dict) -> dict:
    webhook_url = cfg.get("webhook_url")
    if not webhook_url:
        return {"status": "error", "detail": "No webhook URL"}
    card = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "summary": "Connection test",
        "sections": [{"text": "Nessus Remediation Platform — connection test"}],
    }
    r = requests.post(webhook_url, json=card, timeout=10)
    r.raise_for_status()
    return {"status": "ok"}


# ─────────────────────────────────────────────
# Generic Webhook Connector
# ─────────────────────────────────────────────

def send_webhook(config: dict, items: list) -> dict:
    """Send data to any external URL.

    config keys:
      url, method, headers, include_findings
    """
    url = config.get("url")
    if not url:
        raise ValueError("Webhook URL required")

    method = config.get("method", "POST").upper()
    custom_headers = {"Content-Type": "application/json"}
    if config.get("headers"):
        try:
            extra = json.loads(config["headers"]) if isinstance(config["headers"], str) else config["headers"]
            custom_headers.update(extra)
        except (json.JSONDecodeError, TypeError):
            pass

    payload = {"timestamp": datetime.utcnow().isoformat(), "count": len(items)}
    if config.get("include_findings"):
        payload["findings"] = items

    r = requests.request(method, url, headers=custom_headers, json=payload, timeout=15)
    r.raise_for_status()
    return {"status": "sent", "status_code": r.status_code, "items_count": len(items)}


# ─────────────────────────────────────────────
# Template rendering & grouping helpers
# ─────────────────────────────────────────────

def _render(template: str, item: dict, count: int = 0) -> str:
    """Simple {var} template rendering from a workflow item dict."""
    if not template:
        return ""
    result = template
    result = result.replace("{count}", str(count))
    result = result.replace("{{count}}", str(count))

    # Standard item fields
    for key in ("severity_label", "plugin_name", "plugin_id", "plugin_family",
                "asset_ip", "asset_hostname", "asset_os", "solution",
                "severity", "cvss3_score", "vpr_score", "priority_score"):
        val = str(item.get(key, "")) if item else ""
        result = result.replace(f"{{{key}}}", val)
        result = result.replace(f"{{{{{key}}}}}", val)

    # Computed
    if item:
        assets = set()
        assets.add(item.get("asset_ip", ""))
        result = result.replace("{assets}", str(len(assets)))
        result = result.replace("{{assets}}", str(len(assets)))

    return result


def _group_items(items: list, group_by: str) -> dict:
    """Group workflow items for ticket creation."""
    if group_by == "one_for_all":
        return {"all": items}
    elif group_by == "one_per_asset":
        groups = {}
        for item in items:
            key = item.get("asset_id") or item.get("asset_ip", "unknown")
            groups.setdefault(str(key), []).append(item)
        return groups
    else:  # one_per_finding
        return {str(item.get("finding_id", i)): [item] for i, item in enumerate(items)}


# ─────────────────────────────────────────────
# Anthropic (Claude AI) Connector
# ─────────────────────────────────────────────

def _test_anthropic(cfg: dict) -> dict:
    """Test Anthropic API key by making a minimal API call."""
    api_key = cfg.get("api_key")
    if not api_key:
        return {"status": "error", "detail": "API key not set"}
    try:
        from anthropic import Anthropic
        client = Anthropic(api_key=api_key)
        # Use Haiku for connectivity tests — same validation at 73% lower cost
        test_model = "claude-haiku-4-5-20251001"
        resp = client.messages.create(
            model=test_model,
            max_tokens=10,
            messages=[{"role": "user", "content": "Hi"}],
        )
        # ── Token tracking ────────────────────────────────────────────
        get_tracker().track_call(
            agent_name="connectivity_test",
            model=test_model,
            input_tokens=resp.usage.input_tokens,
            output_tokens=resp.usage.output_tokens,
            cached_tokens=getattr(resp.usage, "cache_read_input_tokens", 0),
            call_metadata={"function": "_test_anthropic"},
        )
        return {"status": "ok", "detail": f"Connected — model: {resp.model}"}
    except Exception as e:
        return {"status": "error", "detail": str(e)}


def _test_openai(cfg: dict) -> dict:
    """Test OpenAI API key by making a minimal API call."""
    api_key = cfg.get("api_key")
    if not api_key:
        return {"status": "error", "detail": "API key not set"}
    try:
        from openai import OpenAI
        client = OpenAI(api_key=api_key)
        resp = client.chat.completions.create(
            model=cfg.get("default_model") or "gpt-4o-mini",
            max_tokens=10,
            messages=[{"role": "user", "content": "Hi"}],
        )
        return {"status": "ok", "detail": f"Connected — model: {resp.model}"}
    except Exception as e:
        return {"status": "error", "detail": str(e)}


def _test_google_gemini(cfg: dict) -> dict:
    """Test Google Gemini API key."""
    api_key = cfg.get("api_key")
    if not api_key:
        return {"status": "error", "detail": "API key not set"}
    try:
        from google import genai
        from google.genai import types as genai_types
        client = genai.Client(api_key=api_key)
        resp = client.models.generate_content(
            model=cfg.get("default_model") or "gemini-2.0-flash",
            contents="Hi",
            config=genai_types.GenerateContentConfig(max_output_tokens=10),
        )
        return {"status": "ok", "detail": f"Connected — Gemini API ready"}
    except Exception as e:
        return {"status": "error", "detail": str(e)}


def _test_groq(cfg: dict) -> dict:
    """Test Groq API key by making a minimal API call."""
    api_key = cfg.get("api_key")
    if not api_key:
        return {"status": "error", "detail": "API key not set"}
    try:
        from groq import Groq
        client = Groq(api_key=api_key)
        resp = client.chat.completions.create(
            model=cfg.get("default_model") or "llama-3.1-8b-instant",
            max_tokens=10,
            messages=[{"role": "user", "content": "Hi"}],
        )
        return {"status": "ok", "detail": f"Connected — model: {resp.model}"}
    except Exception as e:
        return {"status": "error", "detail": str(e)}
