"""DDGS-backed LinkedIn identity source.

Approach (per the POC in ``test.py``): query DDGS for
``site:linkedin.com/in/ "{company_name}"`` and parse the SERP results.
Each hit's URL is the LinkedIn profile; the title carries the display
name and (often) job title.

Rate-limit posture: DDGS has no documented SLA and will return empty
result sets without distinguishing "rate limited" from "no matches". We
treat any transport error and any empty-with-no-error response as
"no signal" (``records=None``) so the upstream lifecycle does not prune
identities on a bad day. A meaningful empty result would require
multiple consecutive no-error empty responses, which the discovery
service is responsible for tracking, not this source.
"""

from __future__ import annotations

import logging
import re
from typing import Iterable

from .canonicalize import canonicalize_linkedin_slug
from .sources import IdentityRecord, IdentitySource, SourceResult

logger = logging.getLogger(__name__)

# Title line shapes we see from LinkedIn SERP entries:
#   "Jane Doe - Director of Engineering - Acme | LinkedIn"
#   "Jane Doe – Director of Engineering – Acme - LinkedIn"
#   "Jane Doe | LinkedIn"
_TITLE_TAIL = re.compile(r"\s*[-–|]\s*LinkedIn\s*$", re.IGNORECASE)
_NAME_TITLE_SPLIT = re.compile(r"\s+[-–]\s+")


def _parse_title(title: str | None) -> tuple[str | None, str | None]:
    """Best-effort split into (display_name, job_title). Returns
    ``(None, None)`` for unparseable input."""
    if not title:
        return None, None
    cleaned = _TITLE_TAIL.sub("", title).strip()
    if not cleaned:
        return None, None
    parts = _NAME_TITLE_SPLIT.split(cleaned, maxsplit=1)
    if len(parts) == 1:
        return parts[0].strip() or None, None
    return parts[0].strip() or None, parts[1].strip() or None


class DdgLinkedInSource(IdentitySource):
    name = "linkedin"

    def __init__(self, ddgs_factory=None):
        """``ddgs_factory`` is a zero-arg callable returning a DDGS context
        manager. Default is the real ``ddgs.DDGS``; tests inject a fake.
        Injecting at construction time avoids importing DDGS at module
        import — keeps the conftest test boot light and the dependency
        truly optional.
        """
        self._ddgs_factory = ddgs_factory

    def _new_ddgs(self):
        if self._ddgs_factory is not None:
            return self._ddgs_factory()
        from ddgs import DDGS  # local import; keeps optional
        return DDGS()

    def discover(self, company_name: str, *, max_results: int = 25) -> SourceResult:
        company = (company_name or "").strip()
        if not company:
            return SourceResult(records=None, error="empty_company_name")

        # The POC query — site-scoped to LinkedIn profile slugs, with the
        # company name in quotes so we get hits whose page text mentions
        # the company. Drops generic results that just happen to live on
        # linkedin.com.
        query = f'site:linkedin.com/in/ "{company}"'

        try:
            with self._new_ddgs() as ddgs:
                # Materialize the iterator inside the context so we don't
                # outlive the session. Older versions return a generator,
                # newer versions a list — both are iterable.
                raw_results: Iterable[dict] = list(
                    ddgs.text(query, max_results=max_results) or []
                )
        except Exception as exc:
            logger.warning(
                "DDGS LinkedIn search failed for company=%r: %s", company, exc,
            )
            return SourceResult(records=None, raw_query=query, error=str(exc))

        if not raw_results:
            # No-signal: empty SERP from DDGS is almost always a soft block,
            # not a real "no employees". Upstream decides whether multiple
            # consecutive no-signal runs should prune.
            return SourceResult(records=None, raw_query=query, metadata={"empty": True})

        records: list[IdentityRecord] = []
        seen_slugs: set[str] = set()
        for r in raw_results:
            url = r.get("href") or r.get("url") or ""
            slug = canonicalize_linkedin_slug(url)
            if not slug:
                continue
            if slug in seen_slugs:
                continue
            seen_slugs.add(slug)
            display_name, title = _parse_title(r.get("title"))
            records.append(IdentityRecord(
                slug=slug,
                source=self.name,
                url=url,
                display_name=display_name,
                title=title,
            ))

        # Note: an *unparseable* result page (no canonical slugs at all)
        # is also no-signal — DDGS returned non-LinkedIn hits, which
        # usually means our site-scoping was reformulated server-side.
        if not records:
            return SourceResult(
                records=None, raw_query=query,
                metadata={"unparseable_results": len(list(raw_results))},
            )

        return SourceResult(records=records, raw_query=query)
