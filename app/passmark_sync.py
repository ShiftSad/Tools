"""Background PassMark sync — runs inside the Flask process lifecycle."""
from __future__ import annotations

import logging
import threading
import time

from .config import Config
from .db import connect_db
from .passmark_scraper import scrape_all

log = logging.getLogger(__name__)

_lock = threading.Lock()
_started = False


def _meta_get(conn, key: str) -> str | None:
    row = conn.execute("SELECT value FROM scrape_meta WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else None


def _meta_set(conn, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO scrape_meta(key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )


def enrich_years_only() -> dict:
    """Fill release_year on existing cpus rows (no chart re-scrape)."""
    if not _lock.acquire(blocking=False):
        return {"status": "busy"}

    try:
        conn = connect_db()
        try:
            ids = [
                r["passmark_id"]
                for r in conn.execute(
                    "SELECT passmark_id FROM cpus WHERE release_year IS NULL"
                ).fetchall()
            ]
            if not ids:
                total = conn.execute("SELECT COUNT(*) AS n FROM cpus").fetchone()["n"]
                with_year = conn.execute(
                    "SELECT COUNT(*) AS n FROM cpus WHERE release_year IS NOT NULL"
                ).fetchone()["n"]
                return {"status": "ok", "updated": 0, "cpu_count": total, "with_year": with_year}

            from .passmark_scraper import _fetch_release_year

            updated = 0
            workers = max(1, Config.PASSMARK_YEAR_WORKERS)
            from concurrent.futures import ThreadPoolExecutor, as_completed

            log.info("passmark: enriching years for %d cpus", len(ids))
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = {pool.submit(_fetch_release_year, pid): pid for pid in ids}
                done = 0
                for fut in as_completed(futures):
                    pid = futures[fut]
                    try:
                        year = fut.result()
                    except Exception:
                        year = None
                    if year is not None:
                        conn.execute(
                            "UPDATE cpus SET release_year = ? WHERE passmark_id = ?",
                            (year, pid),
                        )
                        updated += 1
                    done += 1
                    if done % 500 == 0 or done == len(ids):
                        log.info("passmark years enrich: %d/%d", done, len(ids))

            with_year = conn.execute(
                "SELECT COUNT(*) AS n FROM cpus WHERE release_year IS NOT NULL"
            ).fetchone()["n"]
            return {"status": "ok", "updated": updated, "with_year": with_year}
        finally:
            conn.close()
    finally:
        _lock.release()


def sync_passmark(force: bool = False) -> dict:
    """Scrape PassMark and upsert into SQLite. Returns status summary."""
    if not _lock.acquire(blocking=False):
        return {"status": "busy"}

    try:
        conn = connect_db()
        try:
            now = int(time.time())
            last = _meta_get(conn, "passmark_last_sync")
            if not force and last:
                elapsed = now - int(last)
                if elapsed < Config.PASSMARK_SYNC_INTERVAL:
                    count = conn.execute("SELECT COUNT(*) AS n FROM cpus").fetchone()["n"]
                    return {
                        "status": "skipped",
                        "reason": "interval",
                        "cpu_count": count,
                        "next_sync_in": Config.PASSMARK_SYNC_INTERVAL - elapsed,
                    }

            _meta_set(conn, "passmark_sync_status", "running")
            _meta_set(conn, "passmark_sync_started_at", str(now))

            rows = scrape_all()
            conn.execute("BEGIN")
            try:
                conn.execute("DELETE FROM cpus")
                conn.executemany(
                    """
                    INSERT INTO cpus(
                      passmark_id, name, single_thread, cpu_mark, rank, price,
                      release_year, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            r.passmark_id,
                            r.name,
                            r.single_thread,
                            r.cpu_mark,
                        r.rank,
                        r.price,
                        r.release_year,
                        now,
                    )
                        for r in rows
                    ],
                )
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise

            finished = int(time.time())
            _meta_set(conn, "passmark_last_sync", str(finished))
            _meta_set(conn, "passmark_sync_status", "ok")
            _meta_set(conn, "passmark_cpu_count", str(len(rows)))

            log.info("passmark sync ok: %d cpus", len(rows))
            return {"status": "ok", "cpu_count": len(rows), "duration_s": finished - now}
        except Exception:
            _meta_set(conn, "passmark_sync_status", "error")
            log.exception("passmark sync failed")
            raise
        finally:
            conn.close()
    finally:
        _lock.release()


def _loop(app) -> None:
    with app.app_context():
        while True:
            try:
                sync_passmark(force=False)
            except Exception:
                log.exception("passmark background sync error")
            time.sleep(Config.PASSMARK_SYNC_INTERVAL)


def start_background_sync(app) -> None:
    """Start daemon thread once per process (skip Flask reloader parent)."""
    global _started
    if _started:
        return
    _started = True

    import os

    # Avoid double thread when Flask debug reloader spawns parent + child.
    if app.debug and os.environ.get("WERKZEUG_RUN_MAIN") != "true":
        return

    def _bootstrap():
        time.sleep(2)
        try:
            conn = connect_db()
            count = conn.execute("SELECT COUNT(*) AS n FROM cpus").fetchone()["n"]
            conn.close()
            if count == 0:
                log.info("passmark: empty DB, running initial sync")
                sync_passmark(force=True)
        except Exception:
            log.exception("passmark bootstrap sync failed")

        _loop(app)

    t = threading.Thread(target=_bootstrap, name="passmark-sync", daemon=True)
    t.start()
    log.info(
        "passmark background sync started (interval=%ds)",
        Config.PASSMARK_SYNC_INTERVAL,
    )
