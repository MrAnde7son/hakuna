"""Shared helper for safely encoding Python objects as Postgres jsonb input.

Postgres' jsonb cannot store U+0000 — asyncpg surfaces this as
``UntranslatableCharacterError`` on ``cast($x as jsonb)``. Scraped HTML/CSS
bodies (notably icon-font CSS like ``content:"\\u0000..."``) and raw
banner/cert bytes routinely carry NULs, so every jsonb write that originates
from external scanner output must go through this helper.
"""

import json


def jsonb_dumps(obj) -> str:
    """``json.dumps`` + strip NUL chars that Postgres jsonb cannot store."""
    return json.dumps(obj, ensure_ascii=False).replace("\\u0000", "").replace("\x00", "")
