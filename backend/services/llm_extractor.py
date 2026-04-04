"""LLM Extractor — reusable AI-powered extraction of security findings from unstructured text.

Used by:
- FileTransport for pentest report PDFs/DOCX
- RunEngine for unstructured API sources (Confluence, Slack, Google Docs, etc.)
"""

import json
import logging
import re
from typing import List

from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────
# Extraction prompts
# ─────────────────────────────────────────────────────────

PENTEST_EXTRACT_PROMPT = """Extract ALL vulnerability findings from this penetration test report.

Return ONLY a JSON array — no markdown fences, no preamble. Use compact single-line JSON (no pretty-printing) to minimize output size.

Each finding object fields (omit if not mentioned):
finding_id, title, severity (critical/high/medium/low/info), cvss_score (number), cvss_vector, cve_id, affected_host, hostname, port, protocol, description (max 300 chars), evidence (max 200 chars), recommendation (max 200 chars), references, exploit_available (bool)

Rules:
- Extract EVERY finding, not just a summary
- Map severity consistently
- Keep description/evidence/recommendation concise — capture the key point, not verbatim paragraphs

Report text:
"""

UNSTRUCTURED_EXTRACT_PROMPT = """You are a security analyst extracting actionable security findings from unstructured content (wiki pages, chat messages, documents, notes).

Analyze the following content and extract ALL security-relevant findings, vulnerabilities, misconfigurations, risks, compliance gaps, or remediation items mentioned.

Return ONLY a JSON array — no markdown fences, no preamble. Use compact single-line JSON.

Each finding object fields (omit if not mentioned):
- finding_id: a short unique slug derived from the content (e.g. "weak-ssh-config-prod-01")
- title: concise finding title (max 120 chars)
- severity: critical | high | medium | low | info
- cvss_score: number if mentioned or estimable
- cve_id: CVE identifier if mentioned
- affected_host: hostname or IP if mentioned
- hostname: hostname if mentioned
- port: port number if mentioned
- protocol: protocol if mentioned
- description: what the issue is (max 300 chars)
- evidence: supporting evidence or quote from the source (max 200 chars)
- recommendation: suggested fix or remediation (max 200 chars)
- references: URLs or document references if mentioned
- exploit_available: boolean if mentioned
- source_title: title of the page/message/document this was extracted from
- source_url: URL of the source if available

Rules:
- Extract EVERY security-relevant item, not just vulnerabilities — include misconfigurations, policy gaps, todo items, risk acceptances
- If a message thread discusses a vulnerability, capture it even if informal (e.g. "we still haven't patched log4j on prod-web-03")
- Assign severity based on context clues (urgency language, asset criticality, exploit availability)
- If no security-relevant content is found, return an empty array []
- Do NOT fabricate findings — only extract what is explicitly mentioned or strongly implied

Content:
"""


# ─────────────────────────────────────────────────────────
# Core extraction functions
# ─────────────────────────────────────────────────────────

def extract_findings_with_llm(db: Session, text: str, prompt_type: str = "unstructured") -> List[dict]:
    """Use the configured LLM provider to extract structured findings from text.

    Args:
        db: Database session for resolving LLM provider config.
        text: Raw text content to extract findings from.
        prompt_type: "pentest" for pentest reports, "unstructured" for general content.

    Returns:
        List of finding dicts extracted by the LLM.
    """
    from agents.agent_engine import (
        get_default_model, detect_provider,
        _get_anthropic_client, _get_openai_client, _get_gemini_client,
        _get_vertex_client, _get_groq_client, _get_ollama_client,
    )

    model = get_default_model(db)
    provider = detect_provider(model)

    # Select prompt
    base_prompt = PENTEST_EXTRACT_PROMPT if prompt_type == "pentest" else UNSTRUCTURED_EXTRACT_PROMPT

    # Truncate to fit context window — keep first 150k chars
    truncated = text[:150_000]
    prompt = base_prompt + truncated

    logger.info("LLM extraction using provider=%s model=%s prompt_type=%s text_len=%d",
                provider, model, prompt_type, len(truncated))

    if provider == "anthropic":
        client = _get_anthropic_client(db)
        message = client.messages.create(
            model=model, max_tokens=8000,
            messages=[{"role": "user", "content": prompt}],
        )
        response_text = message.content[0].text.strip()

    elif provider in ("openai", "groq", "ollama"):
        if provider == "openai":
            client = _get_openai_client(db)
        elif provider == "groq":
            client = _get_groq_client(db)
        else:
            client = _get_ollama_client(db)
        api_model = model.replace("ollama/", "") if model.startswith("ollama/") else model
        resp = client.chat.completions.create(
            model=api_model, max_tokens=8000,
            messages=[{"role": "user", "content": prompt}],
        )
        response_text = resp.choices[0].message.content.strip()

    elif provider in ("google_gemini", "vertex_ai"):
        if provider == "vertex_ai":
            client = _get_vertex_client(db)
            api_model = model.replace("vertex/", "")
        else:
            client = _get_gemini_client(db)
            api_model = model
        resp = client.models.generate_content(
            model=api_model, contents=prompt,
        )
        response_text = resp.text.strip()

    else:
        raise ValueError(f"Unsupported LLM provider for extraction: {provider}")

    # Strip markdown fences if present
    if response_text.startswith("```"):
        response_text = re.sub(r'^```\w*\n?', '', response_text)
        response_text = re.sub(r'\n?```$', '', response_text)

    findings = parse_llm_json(response_text)

    if not isinstance(findings, list):
        raise ValueError("LLM returned non-array response")

    logger.info("LLM extracted %d findings (prompt_type=%s)", len(findings), prompt_type)
    return findings


def parse_llm_json(text: str) -> list:
    """Parse JSON from LLM output with repair for common issues."""
    # First try direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Try to extract the JSON array from surrounding text
    match = re.search(r'\[.*\]', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass

    # Repair common LLM issues: control chars, trailing commas
    repaired = text
    repaired = re.sub(r'[\x00-\x1f](?<![\n\r\t])', ' ', repaired)  # strip control chars
    repaired = re.sub(r',\s*([}\]])', r'\1', repaired)  # trailing commas
    try:
        return json.loads(repaired)
    except json.JSONDecodeError:
        pass

    # Last resort: parse individual objects between { }
    objects = []
    for m in re.finditer(r'\{[^{}]*\}', text, re.DOTALL):
        try:
            objects.append(json.loads(m.group()))
        except json.JSONDecodeError:
            continue
    if objects:
        return objects

    raise ValueError(f"Could not parse LLM response as JSON. First 200 chars: {text[:200]}")


def prepare_text_for_extraction(records: List[dict], text_field: str, title_field: str = None,
                                 url_field: str = None, max_chars: int = 150_000) -> str:
    """Concatenate text from multiple records into a single extraction input.

    Args:
        records: List of raw records from the transport.
        text_field: Dot-path to the text content field in each record.
        title_field: Optional dot-path to a title/subject field for context.
        url_field: Optional dot-path to source URL for traceability.
        max_chars: Maximum total characters to include.

    Returns:
        Concatenated text ready for LLM extraction.
    """
    parts = []
    total_chars = 0

    for i, record in enumerate(records):
        # Resolve dot-path fields
        text = _resolve_field(record, text_field) or ""
        title = _resolve_field(record, title_field) if title_field else None
        url = _resolve_field(record, url_field) if url_field else None

        if not text:
            continue

        # Build section header
        header_parts = []
        if title:
            header_parts.append(f"Title: {title}")
        if url:
            header_parts.append(f"Source: {url}")
        header = "\n".join(header_parts)

        section = f"\n{'='*60}\n"
        if header:
            section += f"{header}\n{'-'*40}\n"
        section += f"{text}\n"

        if total_chars + len(section) > max_chars:
            remaining = max_chars - total_chars
            if remaining > 200:  # only include if meaningful
                section = section[:remaining]
                parts.append(section)
            break

        parts.append(section)
        total_chars += len(section)

    return "".join(parts)


def _resolve_field(record: dict, field_path: str):
    """Resolve a dot-path like 'body.storage.value' from a nested dict."""
    if not field_path or not record:
        return None
    parts = field_path.split(".")
    current = record
    for part in parts:
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list) and part.isdigit():
            idx = int(part)
            current = current[idx] if idx < len(current) else None
        else:
            return None
    return current
