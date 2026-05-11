"""LinkedIn URL canonicalization.

Identities dedupe on a single string — the slug. Many shapes resolve to
the same person:

* ``https://www.linkedin.com/in/jane-doe-12345/``
* ``http://linkedin.com/in/Jane-Doe-12345``
* ``linkedin.com/in/jane-doe-12345?trk=public_profile``
* ``https://il.linkedin.com/in/jane-doe-12345``

All of these are the same person ``jane-doe-12345``. Canonicalize to:

* lowercased
* no scheme, host, country subdomain, trailing slash, or query string
* slug only (the segment after ``/in/``)

If the input isn't a recognizable LinkedIn profile URL, return ``None`` —
callers must treat that as "not a valid identity" rather than guessing.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse, unquote

# ``/in/<slug>`` where slug is conventional URL-safe characters. Anchored
# so we don't grab embedded paths from a URL with extra segments.
_SLUG_RE = re.compile(r"/in/([A-Za-z0-9\-._%]+)/?", re.IGNORECASE)


def extract_linkedin_slug(value: str | None) -> str | None:
    """Pull the raw slug segment from a string that *might* be a LinkedIn URL.

    Returns ``None`` when the input doesn't contain a LinkedIn ``/in/<slug>``
    path. Does NOT canonicalize — see ``canonicalize_linkedin_slug``.
    """
    if not value or not isinstance(value, str):
        return None

    # Tolerate inputs without a scheme — urlparse needs one to populate
    # netloc, but slug extraction is regex-driven anyway.
    candidate = value.strip()
    if not candidate:
        return None

    # urlparse keeps the path intact even without a scheme as long as we
    # have at least the path. Probe the netloc to confirm it's a LinkedIn
    # host (or no host, which means a plain ``/in/foo`` path).
    parsed = urlparse(candidate if "://" in candidate else f"//{candidate}", scheme="")
    host = (parsed.netloc or "").lower()
    if host and "linkedin.com" not in host:
        return None

    match = _SLUG_RE.search(parsed.path or candidate)
    if not match:
        return None

    return match.group(1)


def canonicalize_linkedin_slug(value: str | None) -> str | None:
    """Return the canonical form of a LinkedIn slug or URL.

    Canonical form:
    * lowercased
    * percent-decoded (``%C3%A9`` → ``é``)
    * trailing slash stripped
    * no query string, no host, no scheme

    Returns ``None`` if the input isn't a recognizable LinkedIn profile.
    """
    raw = extract_linkedin_slug(value)
    if raw is None:
        return None
    return unquote(raw).strip("/").lower()
