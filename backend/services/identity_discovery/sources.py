"""``IdentitySource`` interface and result types.

Every provider (DDGS-via-LinkedIn, Hunter, Apollo, manual upload) exposes
the same shape so the discovery service can swap them without rewiring.

A critical invariant: distinguish "no data this run" from "empty result
set". A rate-limited or blocked search returns ``SourceResult(records=None)``,
not ``records=[]``. The discovery service uses this distinction to decide
whether to age out missing identities — an empty list means "we looked,
nobody is there, prune signal"; ``None`` means "we don't know, do NOT prune".
This is the safeguard against an unannounced DDGS block silently deleting
every identity for every org.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass(frozen=True)
class IdentityRecord:
    """A single discovered identity in a source-agnostic shape."""

    slug: str                  # canonical, lowercased, source-scoped
    source: str                # "linkedin", "hunter", ...
    url: str                   # original profile URL
    display_name: str | None = None
    title: str | None = None


@dataclass
class SourceResult:
    """Outcome of one discovery run for one company on one source.

    ``records=None`` means "no signal" (rate limit, transport error, soft
    block). Callers must NOT interpret it as "this company has no people".
    ``records=[]`` is a real, empty answer — used in tests; in practice
    LinkedIn surfaces are dense enough that empty is rare and should
    still be treated cautiously upstream.
    """

    records: list[IdentityRecord] | None
    raw_query: str = ""
    error: str | None = None
    metadata: dict = field(default_factory=dict)

    @property
    def is_no_signal(self) -> bool:
        return self.records is None


class IdentitySource(ABC):
    """Pluggable identity-discovery provider."""

    name: str

    @abstractmethod
    def discover(self, company_name: str, *, max_results: int = 25) -> SourceResult:
        """Run one discovery query. Implementations must not raise — wrap
        transport errors into ``SourceResult(records=None, error=...)``.
        """
        ...
