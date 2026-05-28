"""Manual PassMark sync — python scripts/sync_passmark.py [--force]"""
import argparse
import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv

load_dotenv(ROOT / ".env")

from app.config import Config
from app.db import connect_db, init_schema
from app.passmark_sync import sync_passmark

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--force", action="store_true", help="Ignora intervalo mínimo")
    parser.add_argument(
        "--years-only",
        action="store_true",
        help="Só preenche release_year nos CPUs já no banco",
    )
    args = parser.parse_args()
    Config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    init_schema(None)
    if args.years_only:
        from app.passmark_sync import enrich_years_only

        result = enrich_years_only()
    else:
        result = sync_passmark(force=args.force)
    print(result)
