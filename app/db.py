"""SQLite connection management — one connection per request via flask.g.

Reports do NOT store a denormalised "status" or "review_verdict". The current
infection state is computed live from the blocklists every time a report is
fetched. That way, removing a rule from a blocklist instantly un-marks every
report that depended on it — no stale state.

What we DO store on the report is a snapshot of the match that triggered AT
SCAN TIME (match_reason, match_pattern, match_label) for historical context,
plus the full analysis (packages, urls, hash) so we can re-evaluate later.
"""
import sqlite3

from flask import g

from .config import Config


SCHEMA = """
CREATE TABLE IF NOT EXISTS malicious_hashes (
  hash       TEXT    PRIMARY KEY,
  label      TEXT    NOT NULL DEFAULT '',
  source     TEXT    NOT NULL DEFAULT '',
  added_at   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS allowed_hashes (
  hash       TEXT    PRIMARY KEY,
  label      TEXT    NOT NULL DEFAULT '',
  source     TEXT    NOT NULL DEFAULT '',
  added_at   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS malicious_packages (
  pattern    TEXT    PRIMARY KEY,
  label      TEXT    NOT NULL DEFAULT '',
  added_at   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS malicious_urls (
  pattern    TEXT    PRIMARY KEY,
  label      TEXT    NOT NULL DEFAULT '',
  added_at   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS reports (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  hash            TEXT    NOT NULL,
  filename        TEXT    NOT NULL,
  file_size       INTEGER NOT NULL,
  email           TEXT,
  ip              TEXT,
  user_agent      TEXT,
  -- match snapshot AT TIME OF SCAN (for history; the live status is computed)
  match_reason    TEXT,
  match_pattern   TEXT,
  match_label     TEXT,
  -- analysis blobs for live re-evaluation against current blocklists
  packages_json   TEXT,
  urls_json       TEXT,
  -- on-disk path of the stored .jar (only kept if not infected at scan time)
  file_path       TEXT,
  -- free-form admin notes (optional)
  admin_notes     TEXT,
  created_at      INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_reports_hash    ON reports(hash);
CREATE INDEX IF NOT EXISTS idx_reports_created ON reports(created_at);

CREATE TABLE IF NOT EXISTS cpus (
  passmark_id   INTEGER PRIMARY KEY,
  name          TEXT    NOT NULL,
  single_thread INTEGER,
  cpu_mark      INTEGER,
  rank          INTEGER,
  price         TEXT,
  release_year  INTEGER,
  updated_at    INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_cpus_name ON cpus(name);
CREATE INDEX IF NOT EXISTS idx_cpus_st   ON cpus(single_thread);

CREATE TABLE IF NOT EXISTS scrape_meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
"""


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        conn = sqlite3.connect(Config.DB_PATH, isolation_level=None)  # autocommit
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA foreign_keys = ON")
        g.db = conn
    return g.db


def close_db(_exception=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def _migrate(conn: sqlite3.Connection) -> None:
    """Drop legacy denormalised status columns (status/review_*) if present.
    Safe to run repeatedly. Requires SQLite >= 3.35 (Python 3.10+ ships with it).
    """
    cols = {row[1] for row in conn.execute("PRAGMA table_info(reports)")}
    for old in ("status", "reviewed_at", "review_verdict", "review_notes"):
        if old in cols:
            try:
                conn.execute(f"ALTER TABLE reports DROP COLUMN {old}")
            except sqlite3.OperationalError:
                pass  # older sqlite without DROP COLUMN; non-fatal
    # legacy index
    try:
        conn.execute("DROP INDEX IF EXISTS idx_reports_status")
    except sqlite3.OperationalError:
        pass
    cpu_cols = {row[1] for row in conn.execute("PRAGMA table_info(cpus)")}
    if "release_year" not in cpu_cols:
        conn.execute("ALTER TABLE cpus ADD COLUMN release_year INTEGER")


def _migrate_db_path() -> None:
    """Rename legacy virusparcial.sqlite → tools.sqlite if needed."""
    if Config.DB_PATH.exists() or not Config.LEGACY_DB_PATH.exists():
        return
    Config.LEGACY_DB_PATH.rename(Config.DB_PATH)


def connect_db() -> sqlite3.Connection:
    """Standalone connection (background jobs, init). Not tied to flask.g."""
    conn = sqlite3.connect(Config.DB_PATH, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_schema(app):
    _migrate_db_path()
    conn = connect_db()
    try:
        conn.executescript(SCHEMA)
        _migrate(conn)
        conn.commit()
    finally:
        conn.close()
