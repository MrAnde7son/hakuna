"""SQL Transport — query databases via SQLAlchemy."""

import re
import logging
from typing import AsyncIterator

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from .base import BaseTransport, ConnectResult

logger = logging.getLogger(__name__)

_TEMPLATE_RE = re.compile(r'\{\{params\.(\w+)\}\}')


def _substitute_params(query: str, params: dict) -> str:
    """Replace {{params.X}} with :X for parameterized queries."""
    def replacer(m):
        key = m.group(1)
        return f":{key}"
    return _TEMPLATE_RE.sub(replacer, query)


def _extract_param_values(query: str, params: dict) -> dict:
    """Extract param values that are referenced in the query."""
    used = set(_TEMPLATE_RE.findall(query))
    return {k: v for k, v in params.items() if k in used}


class SqlTransport(BaseTransport):

    async def connect(self, config: dict, credentials: dict) -> ConnectResult:
        """Execute a LIMIT 10 version of the query and return rows."""
        try:
            connection_string = credentials.get("connection_string", "")
            if not connection_string:
                return ConnectResult(success=False, error="No connection_string in credentials")

            query = config.get("query", "")
            if not query:
                return ConnectResult(success=False, error="No SQL query configured")

            row_limit = config.get("row_limit", 10)
            params = config.get("params", {})

            # Build limited query for preview
            limited_query = f"SELECT * FROM ({query}) _sub LIMIT {row_limit}"
            parameterized = _substitute_params(limited_query, params)
            param_values = _extract_param_values(query, params)

            engine = create_engine(connection_string)
            with engine.connect() as conn:
                result = conn.execute(text(parameterized), param_values)
                columns = list(result.keys())
                rows = [dict(zip(columns, row)) for row in result.fetchall()]

            engine.dispose()

            return ConnectResult(
                success=True,
                sample_records=rows[:10],
                raw_response={"columns": columns, "row_count": len(rows)},
            )
        except Exception as e:
            logger.exception("SqlTransport.connect failed")
            return ConnectResult(success=False, error=str(e))

    async def fetch_all(self, config: dict, credentials: dict, params: dict = None) -> AsyncIterator:
        """Stream all rows using server-side cursor."""
        connection_string = credentials.get("connection_string", "")
        query = config.get("query", "")
        row_limit = config.get("row_limit", 10000)
        all_params = {**(config.get("params", {})), **(params or {})}

        parameterized = _substitute_params(query, all_params)
        param_values = _extract_param_values(query, all_params)

        engine = create_engine(connection_string)
        batch_size = 500
        count = 0

        try:
            with engine.connect() as conn:
                result = conn.execution_options(stream_results=True).execute(
                    text(parameterized), param_values
                )
                columns = list(result.keys())
                while True:
                    rows = result.fetchmany(batch_size)
                    if not rows:
                        break
                    for row in rows:
                        if count >= row_limit:
                            return
                        yield dict(zip(columns, row))
                        count += 1
        finally:
            engine.dispose()
