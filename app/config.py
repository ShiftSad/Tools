"""Centralised env-driven config."""
import os
import pathlib


class Config:
    SESSION_SECRET = os.environ.get("SESSION_SECRET", "")
    ADMIN_PASSWORD_HASH = os.environ.get("ADMIN_PASSWORD_HASH", "")
    DATA_DIR = pathlib.Path(os.environ.get("DATA_DIR", "./data")).resolve()
    MAX_UPLOAD_BYTES = int(os.environ.get("MAX_UPLOAD_BYTES", str(50 * 1024 * 1024)))
    MAX_CONTENT_LENGTH = MAX_UPLOAD_BYTES + 4096  # tiny slack for multipart overhead
    UPLOAD_DIR = DATA_DIR / "uploads"
    DB_PATH = DATA_DIR / "tools.sqlite"
    LEGACY_DB_PATH = DATA_DIR / "virusparcial.sqlite"

    # Passmark sync — intervalo entre execuções (default 7 dias).
    PASSMARK_SYNC_INTERVAL = int(
        os.environ.get("PASSMARK_SYNC_INTERVAL", str(7 * 24 * 3600))
    )
    # Delay entre requests ao cpubenchmark.net (segundos).
    PASSMARK_REQUEST_DELAY = float(os.environ.get("PASSMARK_REQUEST_DELAY", "0.35"))
    # Busca "First Seen on Charts" em cpu.php para preencher release_year (mais requests).
    PASSMARK_FETCH_YEARS = os.environ.get("PASSMARK_FETCH_YEARS", "1") == "1"
    PASSMARK_YEAR_WORKERS = int(os.environ.get("PASSMARK_YEAR_WORKERS", "8"))
    # match the volume layout: data dir exists, uploads inside it.
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
