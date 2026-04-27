"""
Enhanced system prompts for agent templates.

Prompts are stored as standalone Markdown files under `prompts/`:

    prompts/<key>.md                          standalone agents (daily_triage, …)
    prompts/audit/<proto>/_preamble.md        shared preamble for a protocol family
    prompts/audit/<proto>/<mission>.md        per-mission prompt for that family

The loader builds `ENHANCED_PROMPTS` at import time so existing callers
(`ENHANCED_PROMPTS["daily_triage"]`, `ENHANCED_PROMPTS.get(mission.prompt_key)`)
continue to work unchanged. Mission files containing the literal `{preamble}`
marker have it replaced with their family's `_preamble.md` contents.
"""
from pathlib import Path

PROMPTS_DIR = Path(__file__).parent / "prompts"
AUDIT_PROTOCOLS = (
    "wmi", "ldap", "smb", "snmp", "ssh",
    "aws", "azure", "gcp", "exposed_datastore",
)


def _read(path: Path) -> str:
    """Read a prompt file, stripping the trailing newline that text editors add."""
    text = path.read_text()
    if text.endswith("\n"):
        text = text[:-1]
    return text


def _load_prompts() -> dict[str, str]:
    prompts: dict[str, str] = {}

    for path in PROMPTS_DIR.glob("*.md"):
        prompts[path.stem] = _read(path)

    audit_dir = PROMPTS_DIR / "audit"
    for proto in AUDIT_PROTOCOLS:
        proto_dir = audit_dir / proto
        if not proto_dir.is_dir():
            continue
        preamble_path = proto_dir / "_preamble.md"
        preamble = _read(preamble_path) if preamble_path.exists() else ""
        if preamble:
            prompts[f"_{proto}_audit_preamble"] = preamble
        for path in proto_dir.glob("*.md"):
            if path.name == "_preamble.md":
                continue
            text = _read(path)
            if preamble and "{preamble}" in text:
                text = text.replace("{preamble}", preamble)
            prompts[f"{proto}_audit_{path.stem}"] = text

    return prompts


ENHANCED_PROMPTS: dict[str, str] = _load_prompts()
