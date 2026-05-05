from datetime import datetime, timezone
from typing import Optional


def iso_utc(dt: Optional[datetime]) -> Optional[str]:
    """Serialize a datetime as ISO-8601 UTC with a trailing Z.

    Naive datetimes are assumed to be UTC (legacy `datetime.utcnow` convention).
    Aware datetimes are converted to UTC before formatting.
    Returns None when dt is None.
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.isoformat() + "Z"
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
