"""Recover liveness_score values that the scoring ratchet pinned at zero.

Migration 019 introduced a 0–100 liveness score with a +5 bump per
confirmed check against -15/-25 decays. Recovery was three times slower
than decay, so any host whose probes were occasionally flaky (CDN-fronted
hosts that drop SYN, rate-limited httpx batches) lost ground faster than
it could regain it and eventually pinned at 0 — while still being
validated as ``confirmed_alive`` every cycle. In production this dragged
132k of 154k assets below the 30 suppression threshold, and because the
backend gated *all* EASM finding generation on that score, every EASM scan
stopped producing findings.

The scoring asymmetry is fixed in ``app.ingest.liveness`` (bump raised to
20, and a confirmed_alive verdict now floors the score at the suppression
threshold so the score can't contradict the state), and the backend gate no
longer suppresses on the score alone. Neither of those rewrites history, so
this migration repairs the rows already stuck: any asset the scanner
currently considers alive is lifted to the same floor rather than waiting
for its next validation pass to climb out. Assets that are genuinely
unconfirmed or likely_dead keep their score and continue to decay normally.

Data-only and idempotent — re-running it is a no-op.

Revision ID: 023
Revises: 022
Create Date: 2026-09-02
"""
from typing import Sequence, Union

from alembic import op


revision: str = "023"
down_revision: Union[str, None] = "022"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Keep in sync with liveness._LIVENESS_ALIVE_FLOOR.
_ALIVE_FLOOR = 30


def upgrade() -> None:
    op.execute(
        f"""
        UPDATE assets
        SET liveness_score = {_ALIVE_FLOOR}
        WHERE liveness_state = 'confirmed_alive'
          AND liveness_score < {_ALIVE_FLOOR}
        """
    )


def downgrade() -> None:
    # The pre-migration scores were an artifact of the ratchet bug and
    # aren't recoverable (nothing recorded what they were). Restoring them
    # would only re-suppress live assets, so this is deliberately a no-op.
    pass
