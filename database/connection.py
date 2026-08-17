"""MySQL-only database layer for SecureRotate. No SQLite."""
from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Any, Generator, Iterable, Optional

import pymysql
from pymysql.cursors import DictCursor
from pymysql.err import Error as PyMySQLError

from config import (
    MYSQL_DATABASE,
    MYSQL_HOST,
    MYSQL_PASSWORD,
    MYSQL_PORT,
    MYSQL_USER,
    SCHEMA_PATH,
)

logger = logging.getLogger("securerotate.db")


class DatabaseError(Exception):
    """Raised when MySQL is unavailable or a query fails critically."""


def get_connection() -> pymysql.Connection:
    """Open a new MySQL connection. Raises DatabaseError if MySQL is unreachable."""
    try:
        conn = pymysql.connect(
            host=MYSQL_HOST,
            port=MYSQL_PORT,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD,
            database=MYSQL_DATABASE,
            cursorclass=DictCursor,
            autocommit=False,
            charset="utf8mb4",
            connect_timeout=10,
        )
        return conn
    except PyMySQLError as exc:
        logger.error("MySQL connection failed: %s", exc)
        raise DatabaseError(
            f"Cannot connect to MySQL at {MYSQL_HOST}:{MYSQL_PORT}/{MYSQL_DATABASE}. "
            f"Ensure MySQL is running and MYSQL_* environment variables are set. Detail: {exc}"
        ) from exc


@contextmanager
def db_cursor(commit: bool = True) -> Generator[Any, None, None]:
    """Context manager: yields a DictCursor, commits on success, rolls back on error."""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            yield cur
            if commit:
                conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@contextmanager
def db_connection() -> Generator[pymysql.Connection, None, None]:
    """Context manager yielding a raw connection (caller manages commit/rollback)."""
    conn = get_connection()
    try:
        yield conn
    finally:
        conn.close()


def execute(sql: str, params: Optional[Iterable[Any]] = None, fetch: str = "none") -> Any:
    """
    Run a parameterized query.
    fetch: 'none' | 'one' | 'all' | 'lastrowid'
    """
    with db_cursor(commit=True) as cur:
        cur.execute(sql, params or ())
        if fetch == "one":
            return cur.fetchone()
        if fetch == "all":
            return cur.fetchall()
        if fetch == "lastrowid":
            return cur.lastrowid
        return cur.rowcount


def executemany(sql: str, seq_of_params: Iterable[Iterable[Any]]) -> int:
    with db_cursor(commit=True) as cur:
        cur.executemany(sql, list(seq_of_params))
        return cur.rowcount


def _split_sql_statements(sql_text: str) -> list[str]:
    """Split SQL script into statements without breaking on semicolons inside quotes."""
    statements: list[str] = []
    buf: list[str] = []
    in_single = False
    in_double = False
    i = 0
    while i < len(sql_text):
        ch = sql_text[i]
        if ch == "'" and not in_double:
            # handle escaped '' inside single-quoted string
            if in_single and i + 1 < len(sql_text) and sql_text[i + 1] == "'":
                buf.append("''")
                i += 2
                continue
            in_single = not in_single
            buf.append(ch)
        elif ch == '"' and not in_single:
            in_double = not in_double
            buf.append(ch)
        elif ch == ";" and not in_single and not in_double:
            stmt = "".join(buf).strip()
            if stmt:
                statements.append(stmt)
            buf = []
        else:
            buf.append(ch)
        i += 1
    tail = "".join(buf).strip()
    if tail:
        statements.append(tail)
    return statements


def init_schema() -> None:
    """Apply schema_mysql.sql if tables are missing. Safe to call on every startup."""
    if not SCHEMA_PATH.exists():
        raise DatabaseError(f"Schema file not found: {SCHEMA_PATH}")

    sql_text = SCHEMA_PATH.read_text(encoding="utf-8")
    statements = _split_sql_statements(sql_text)

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            for stmt in statements:
                # Skip pure comment / empty blocks
                lines = [ln.strip() for ln in stmt.splitlines()]
                if all((not ln) or ln.startswith("--") for ln in lines):
                    continue
                try:
                    cur.execute(stmt)
                except PyMySQLError as exc:
                    code = getattr(exc, "args", [None])[0]
                    # 1050 = table already exists
                    if code == 1050:
                        continue
                    # Real syntax/structural errors must not be silent
                    logger.error("Schema statement failed: %s | SQL snippet: %s", exc, stmt[:120])
                    raise DatabaseError(f"Schema initialization failed: {exc}") from exc
        conn.commit()
        logger.info("MySQL schema initialized/verified successfully.")
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def ping() -> bool:
    """Return True if MySQL is reachable."""
    try:
        with db_cursor(commit=False) as cur:
            cur.execute("SELECT 1 AS ok")
            row = cur.fetchone()
            return bool(row and row.get("ok") == 1)
    except Exception as exc:
        logger.error("MySQL ping failed: %s", exc)
        return False
