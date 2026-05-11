"""Derive plausible corporate email addresses from a display name + domain.

Used by ``breach_correlation`` to enumerate the email candidates a
discovered identity might use at their company. We can't *know* the right
format without enumerating against the org's mail provider (which would
be intrusive and detectable); the goal is to surface the most likely 3–6
shapes so an analyst can confirm + rotate.

Returned in highest-likelihood-first order so the UI shows the most
plausible candidate first.
"""

from __future__ import annotations

import re
import unicodedata

# Strip these noise tokens before splitting into first/last.
_TITLE_TOKENS = {
    "mr", "mr.", "ms", "ms.", "mrs", "mrs.", "dr", "dr.", "prof", "prof.",
    "phd", "ph.d.", "ph.d", "cissp", "ccsp", "cism", "ceh", "oscp", "pmp",
    "ma", "mba", "bsc", "msc", "jr", "jr.", "sr", "sr.", "esq", "esq.",
    "i", "ii", "iii", "iv", "v",
}

# Single letters or letter-with-dot are initials, not real surnames —
# permuting against these produces too many false candidates.
_INITIAL_RE = re.compile(r"^[a-z]\.?$")


def _ascii_fold(s: str) -> str:
    """Normalize Unicode to ASCII so ``José Pérez`` → ``jose perez``.

    LinkedIn names use a lot of accented characters; corporate email
    addresses almost universally don't, so we normalize away.
    """
    decomposed = unicodedata.normalize("NFKD", s or "")
    return "".join(c for c in decomposed if not unicodedata.combining(c))


def _tokenize_name(display_name: str | None) -> tuple[str, str] | None:
    """Return ``(first, last)`` lowercased ASCII, or None if unparseable.

    Drops honorifics/suffixes, treats single-letter "surnames" as initials
    rather than real tokens. Returns None when we can't extract at least
    a usable first name.
    """
    if not display_name:
        return None
    cleaned = _ascii_fold(display_name).lower()
    # Strip credentials after a comma — "Joseph South CISSP, CCSP" → first part.
    cleaned = cleaned.split(",")[0]
    raw_tokens = re.findall(r"[a-z][a-z'\-]*\.?", cleaned)
    tokens = [t for t in raw_tokens if t not in _TITLE_TOKENS]
    # Drop trailing initials and middle-initial tokens — they pollute
    # permutations without adding signal.
    tokens = [t for t in tokens if not _INITIAL_RE.match(t)]
    if not tokens:
        return None
    if len(tokens) == 1:
        # Single-token names ("Cher", "Madonna") still produce a first-only
        # email; downstream callers handle that case.
        return tokens[0], ""
    return tokens[0], tokens[-1]


def permute_corporate_emails(
    display_name: str | None, domain: str | None,
    *, max_results: int = 6,
) -> list[str]:
    """Generate plausible corporate email addresses for ``display_name`` at
    ``domain``, highest-likelihood-first, deduplicated, capped at ``max_results``.

    Returns ``[]`` when the name can't be parsed or the domain is missing.
    """
    if not domain:
        return []
    parsed = _tokenize_name(display_name)
    if not parsed:
        return []
    first, last = parsed
    domain = domain.strip().lower()
    if domain.startswith("www."):
        domain = domain[4:]

    candidates: list[str] = []
    if last:
        # "John Patton" → john.patton, jpatton, john_patton, johnpatton,
        # john, patton, johnp. Ordered by what real shops actually use
        # (per surveys of common corp-email patterns — first.last leads
        # by a wide margin in the US/EU; given-name-only in startups).
        candidates.extend([
            f"{first}.{last}",
            f"{first[0]}{last}",
            f"{first}_{last}",
            f"{first}{last}",
            f"{first}",
            f"{last}",
            f"{first}{last[0]}",
        ])
    else:
        # Single-word name — only one shape worth guessing.
        candidates.append(first)

    seen: set[str] = set()
    out: list[str] = []
    for local in candidates:
        local = local.strip(".-_")
        if not local or local in seen:
            continue
        seen.add(local)
        out.append(f"{local}@{domain}")
        if len(out) >= max_results:
            break
    return out
