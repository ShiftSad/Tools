"""Public scan endpoints.

Two-step flow to save bandwidth (Railway charges per GB):
  1. POST /api/scan/check {hash}          — hash-only lookup, ~70B payload
  2. POST /api/scan       multipart file  — full upload + analysis

The frontend always tries step 1 first and only uploads the full file if the
hash isn't already known to be malicious OR explicitly allowed.

Auto-cache: when a file is detected as malicious via package/URL match (which
requires the full file), the hash is also added to the malicious blocklist
with a `source` tagging the rule that caused it. That way, future scans of
the same .jar are caught instantly by hash with zero upload.
"""
import json
import re
import time

from flask import Blueprint, jsonify, request

from . import limiter
from .analysis import analyze, check_allowed_hash, check_blocklists, check_hash_only
from .config import Config
from .db import get_db

bp = Blueprint("scan", __name__)

EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


@bp.post("/scan/check")
@limiter.limit("120 per hour")
def scan_check():
    """Cheap hash-only check. Saves bandwidth when the hash is already known.
    Returns one of:
      - {status: "infected", label}    → in malicious blocklist
      - {status: "clean", label}       → in allowlist (admin-vouched)
      - {status: "unknown"}             → not seen, please upload via /api/scan
    """
    body = request.get_json(silent=True) or {}
    digest = (body.get("hash") or "").strip().lower()
    if not HEX64_RE.match(digest):
        return jsonify(error="hash inválido (sha256 hex)"), 400

    db = get_db()
    if (allow := check_allowed_hash(digest, db)):
        return jsonify(status="clean", hash=digest, label=allow["label"] or None)
    if (match := check_hash_only(digest, db)):
        return jsonify(status="infected", hash=digest, label=match["label"] or None)
    return jsonify(status="unknown", hash=digest)


@bp.post("/scan")
@limiter.limit("8 per hour;30 per day")
def scan():
    """Full upload + analysis. Stores the file (if clean) and records a report.

    Tight rate limit on this endpoint specifically — uploads are the only
    expensive thing in terms of bandwidth.
    """
    f = request.files.get("file")
    if not f:
        return jsonify(error="nenhum arquivo enviado"), 400

    fname = (f.filename or "").strip()
    if not fname.lower().endswith(".jar"):
        return jsonify(error="só aceito arquivos .jar"), 400

    data = f.read(Config.MAX_UPLOAD_BYTES + 1)
    if len(data) > Config.MAX_UPLOAD_BYTES:
        mb = Config.MAX_UPLOAD_BYTES // (1024 * 1024)
        return jsonify(error=f"arquivo grande demais (limite {mb}MB)"), 413
    if not data:
        return jsonify(error="arquivo vazio"), 400

    email = (request.form.get("email") or "").strip()[:254] or None
    if email and not EMAIL_RE.match(email):
        return jsonify(error="e-mail inválido"), 400

    # Cheap hash + allowlist check before doing zip walk + URL regex.
    from .analysis import sha256
    digest = sha256(data)
    db = get_db()
    if (allow := check_allowed_hash(digest, db)):
        # admin-vouched — don't analyze, don't store, don't even create a report
        return jsonify(
            status="clean",
            hash=digest,
            filename=fname,
            size=len(data),
            label=allow["label"] or None,
        )

    try:
        analysis = analyze(data)
    except ValueError as e:
        return jsonify(error=str(e)), 400

    match = check_blocklists(analysis, db)

    if match:
        # known bad — don't waste disk on it
        file_path = None
        # auto-cache: if matched by package/URL (which needed the full file),
        # also add the hash to the malicious blocklist so the next scan of the
        # same file gets caught via /api/scan/check with zero upload.
        if match["reason"] in ("package", "url"):
            db.execute(
                """INSERT INTO malicious_hashes (hash, label, source, added_at)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(hash) DO NOTHING""",
                (
                    analysis["sha256"],
                    match["label"] or "",
                    f"auto:{match['reason']}:{match['pattern']}",
                    int(time.time() * 1000),
                ),
            )
    else:
        # dedup by hash: same file uploaded twice writes to disk once
        path = Config.UPLOAD_DIR / f"{analysis['sha256']}.jar"
        if not path.exists():
            path.write_bytes(data)
        file_path = str(path)

    db.execute(
        """INSERT INTO reports
           (hash, filename, file_size, email, ip, user_agent,
            match_reason, match_pattern, match_label,
            packages_json, urls_json, file_path, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            analysis["sha256"],
            fname,
            len(data),
            email,
            request.remote_addr,
            (request.headers.get("User-Agent") or "")[:500],
            match["reason"] if match else None,
            match["pattern"] if match else None,
            match["label"] if match else None,
            json.dumps(analysis["packages"]),
            json.dumps(analysis["urls"]),
            file_path,
            int(time.time() * 1000),
        ),
    )

    return jsonify(
        status="infected" if match else "clean",
        hash=analysis["sha256"],
        filename=fname,
        size=len(data),
        # only the public label is exposed — never the pattern or which list matched
        label=(match["label"] if match else None) or None,
    )


@bp.errorhandler(429)
def _too_many(e):
    return jsonify(error="muitas tentativas — tente de novo daqui a pouco"), 429
