"""Admin endpoints — login + manage reports and blocklists.

Reports don't store a denormalised 'status'. The current infection state is
computed live every time the admin views them, by running the stored analysis
(hash, packages, urls) against the CURRENT blocklists. Remove a rule and
everything that depended on it un-marks itself instantly.

Allowlist (`allowed_hashes`) takes precedence over everything: if a hash is
explicitly allowed, the report is shown as clean no matter what the
malicious-list rules would say.

Auto-cache cleanup: hashes auto-added to the malicious list by a package/URL
match carry a `source` like `auto:package:<pattern>`. When the originating
rule is deleted, the auto-cached hashes are deleted too — so removing a rule
truly un-marks everything that depended on it.
"""
import json
import re
import time
from pathlib import Path

from flask import Blueprint, jsonify, request, send_file

from . import limiter
from .analysis import package_matches, url_matches
from .auth import require_admin, sign_session, verify_password
from .db import get_db

bp = Blueprint("admin", __name__)

HEX64 = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)


# ── auth ────────────────────────────────────────────────────────────
@bp.post("/login")
@limiter.limit("8 per minute")
def login():
    body = request.get_json(silent=True) or {}
    password = (body.get("password") or "").strip()
    if not password or not verify_password(password):
        return jsonify(error="senha incorreta"), 401
    return jsonify(token=sign_session(), expires_in_hours=12)


@bp.get("/me")
@require_admin
def me():
    return jsonify(ok=True)


# ── live-match helpers ──────────────────────────────────────────────
def _fetch_lists(db):
    allowed = {r["hash"]: r["label"] for r in db.execute("SELECT hash, label FROM allowed_hashes")}
    hashes = {r["hash"]: r["label"] for r in db.execute("SELECT hash, label FROM malicious_hashes")}
    packages = [(r["pattern"], r["label"]) for r in db.execute("SELECT pattern, label FROM malicious_packages")]
    urls = [(r["pattern"], r["label"]) for r in db.execute("SELECT pattern, label FROM malicious_urls")]
    return allowed, hashes, packages, urls


def _compute_match(hash_hex, packages_json, urls_json, allowed, hashes, package_rules, url_rules):
    """Returns (current_match, in_allowed). Allowlist wins over everything."""
    if hash_hex in allowed:
        return None, True
    if hash_hex in hashes:
        return {"reason": "hash", "label": hashes[hash_hex] or "", "pattern": hash_hex}, False
    try:
        pkgs = json.loads(packages_json or "[]")
    except Exception:
        pkgs = []
    for pat, lbl in package_rules:
        for pkg in pkgs:
            if package_matches(pat, pkg):
                return {"reason": "package", "label": lbl or "", "pattern": pat}, False
    try:
        us = json.loads(urls_json or "[]")
    except Exception:
        us = []
    for pat, lbl in url_rules:
        for u in us:
            if url_matches(pat, u):
                return {"reason": "url", "label": lbl or "", "pattern": pat}, False
    return None, False


# ── reports ─────────────────────────────────────────────────────────
@bp.get("/reports/groups")
@require_admin
def report_groups():
    """One row per unique hash. Live current_match + at-scan snapshot."""
    db = get_db()
    rows = db.execute(
        """
        SELECT
            r.hash,
            COUNT(*) AS count,
            MIN(r.created_at) AS first_seen,
            MAX(r.created_at) AS last_seen,
            MAX(r.file_size) AS file_size,
            GROUP_CONCAT(DISTINCT r.email) AS emails,
            MAX(r.match_reason) AS at_scan_reason,
            MAX(r.match_pattern) AS at_scan_pattern,
            MAX(r.match_label) AS at_scan_label,
            MAX(r.packages_json) AS packages_json,
            MAX(r.urls_json) AS urls_json,
            MAX(CASE WHEN r.file_path IS NOT NULL THEN 1 ELSE 0 END) AS has_file
        FROM reports r
        GROUP BY r.hash
        ORDER BY last_seen DESC
        LIMIT 500
        """
    ).fetchall()

    allowed, hashes, packages, urls = _fetch_lists(db)
    groups = []
    for row in rows:
        d = dict(row)
        current, in_allowed = _compute_match(
            d["hash"], d.pop("packages_json"), d.pop("urls_json"),
            allowed, hashes, packages, urls,
        )
        at_scan = {
            "reason": d.pop("at_scan_reason"),
            "pattern": d.pop("at_scan_pattern"),
            "label": d.pop("at_scan_label"),
        }
        d["current_match"] = current
        d["currently_infected"] = current is not None
        d["in_allowed_list"] = in_allowed
        d["in_hash_list"] = d["hash"] in hashes
        d["at_scan_match"] = at_scan if at_scan["reason"] else None
        d["has_file"] = bool(d.get("has_file"))
        groups.append(d)

    return jsonify(groups=groups)


@bp.get("/reports")
@require_admin
def list_reports():
    db = get_db()
    hash_filter = (request.args.get("hash") or "").strip().lower() or None
    limit = min(int(request.args.get("limit", "200") or 200), 1000)

    sql = "SELECT * FROM reports"
    params: list = []
    if hash_filter:
        sql += " WHERE hash = ?"
        params.append(hash_filter)
    sql += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)

    rows = db.execute(sql, params).fetchall()
    allowed, hashes, packages, urls = _fetch_lists(db)
    out = []
    for row in rows:
        d = dict(row)
        current, in_allowed = _compute_match(
            d["hash"], d.get("packages_json"), d.get("urls_json"),
            allowed, hashes, packages, urls,
        )
        d["current_match"] = current
        d["in_allowed_list"] = in_allowed
        d["at_scan_match"] = (
            {"reason": d["match_reason"], "pattern": d["match_pattern"], "label": d["match_label"]}
            if d.get("match_reason") else None
        )
        d["has_file"] = bool(d.get("file_path"))
        d.pop("file_path", None)
        d.pop("packages_json", None)
        d.pop("urls_json", None)
        out.append(d)
    return jsonify(reports=out)


@bp.get("/reports/<int:report_id>")
@require_admin
def get_report(report_id):
    db = get_db()
    row = db.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
    if not row:
        return jsonify(error="report não encontrado"), 404
    d = dict(row)
    allowed, hashes, packages, urls = _fetch_lists(db)
    current, in_allowed = _compute_match(
        d["hash"], d.get("packages_json"), d.get("urls_json"),
        allowed, hashes, packages, urls,
    )
    d["current_match"] = current
    d["in_allowed_list"] = in_allowed
    d["at_scan_match"] = (
        {"reason": d["match_reason"], "pattern": d["match_pattern"], "label": d["match_label"]}
        if d.get("match_reason") else None
    )
    d["has_file"] = bool(d.get("file_path"))
    d.pop("file_path", None)
    try:
        d["packages"] = json.loads(d.pop("packages_json") or "[]")
    except Exception:
        d["packages"] = []
    try:
        d["urls"] = json.loads(d.pop("urls_json") or "[]")
    except Exception:
        d["urls"] = []
    return jsonify(report=d)


@bp.get("/reports/<int:report_id>/file")
@require_admin
def download_report(report_id):
    db = get_db()
    row = db.execute(
        "SELECT file_path, filename FROM reports WHERE id = ?", (report_id,)
    ).fetchone()
    if not row or not row["file_path"]:
        return jsonify(error="arquivo não armazenado"), 404
    try:
        return send_file(
            row["file_path"],
            as_attachment=True,
            download_name=row["filename"] or "plugin.jar",
            mimetype="application/java-archive",
        )
    except FileNotFoundError:
        return jsonify(error="arquivo removido do disco"), 410


# ── groups: virus / allow / delete ──────────────────────────────────
@bp.post("/groups/<hash_hex>/mark-virus")
@require_admin
def mark_group_virus(hash_hex):
    """Add the group's hash to the malicious_hashes blocklist."""
    hash_hex = hash_hex.strip().lower()
    if not HEX64.match(hash_hex):
        return jsonify(error="hash inválido"), 400
    body = request.get_json(silent=True) or {}
    label = (body.get("label") or "").strip()[:200]
    db = get_db()
    # if it was previously allowed, remove from allowlist (mutually exclusive)
    db.execute("DELETE FROM allowed_hashes WHERE hash = ?", (hash_hex,))
    db.execute(
        """INSERT INTO malicious_hashes (hash, label, source, added_at)
           VALUES (?, ?, ?, ?)
           ON CONFLICT(hash) DO UPDATE SET label = excluded.label, source = excluded.source""",
        (hash_hex, label, "manual", int(time.time() * 1000)),
    )
    return jsonify(ok=True, hash=hash_hex)


@bp.post("/groups/<hash_hex>/mark-clean")
@require_admin
def mark_group_clean(hash_hex):
    """Add the group's hash to the allowlist. Also removes from malicious
    blocklist if it was there (mutually exclusive lists)."""
    hash_hex = hash_hex.strip().lower()
    if not HEX64.match(hash_hex):
        return jsonify(error="hash inválido"), 400
    body = request.get_json(silent=True) or {}
    label = (body.get("label") or "").strip()[:200]
    db = get_db()
    db.execute("DELETE FROM malicious_hashes WHERE hash = ?", (hash_hex,))
    db.execute(
        """INSERT INTO allowed_hashes (hash, label, source, added_at)
           VALUES (?, ?, ?, ?)
           ON CONFLICT(hash) DO UPDATE SET label = excluded.label, source = excluded.source""",
        (hash_hex, label, "manual", int(time.time() * 1000)),
    )
    return jsonify(ok=True, hash=hash_hex)


@bp.delete("/groups/<hash_hex>")
@require_admin
def delete_group(hash_hex):
    """Delete all reports for a hash and the stored .jar on disk.
    Doesn't touch the blocklists — use those tabs for that."""
    hash_hex = hash_hex.strip().lower()
    if not HEX64.match(hash_hex):
        return jsonify(error="hash inválido"), 400
    db = get_db()
    paths = [
        r["file_path"]
        for r in db.execute(
            "SELECT DISTINCT file_path FROM reports WHERE hash = ? AND file_path IS NOT NULL",
            (hash_hex,),
        ).fetchall()
    ]
    db.execute("DELETE FROM reports WHERE hash = ?", (hash_hex,))
    for p in paths:
        try:
            Path(p).unlink(missing_ok=True)
        except OSError:
            pass
    return jsonify(ok=True)


# ── blocklists CRUD ─────────────────────────────────────────────────
def _list_table(table):
    db = get_db()
    rows = db.execute(f"SELECT * FROM {table} ORDER BY added_at DESC").fetchall()
    return jsonify(items=[dict(r) for r in rows])


@bp.get("/hashes")
@require_admin
def list_hashes(): return _list_table("malicious_hashes")


@bp.post("/hashes")
@require_admin
def add_hash():
    body = request.get_json(silent=True) or {}
    h = (body.get("hash") or "").strip().lower()
    label = (body.get("label") or "").strip()[:200]
    source = (body.get("source") or "").strip()[:200] or "manual"
    if not HEX64.match(h):
        return jsonify(error="hash deve ser sha256 (64 hex chars)"), 400
    db = get_db()
    db.execute("DELETE FROM allowed_hashes WHERE hash = ?", (h,))  # mutually exclusive
    db.execute(
        """INSERT INTO malicious_hashes (hash, label, source, added_at)
           VALUES (?, ?, ?, ?)
           ON CONFLICT(hash) DO UPDATE SET label=excluded.label, source=excluded.source""",
        (h, label, source, int(time.time() * 1000)),
    )
    return jsonify(ok=True, hash=h)


@bp.delete("/hashes/<h>")
@require_admin
def delete_hash(h):
    h = h.strip().lower()
    db = get_db()
    db.execute("DELETE FROM malicious_hashes WHERE hash = ?", (h,))
    return jsonify(ok=True)


@bp.get("/allowed")
@require_admin
def list_allowed(): return _list_table("allowed_hashes")


@bp.post("/allowed")
@require_admin
def add_allowed():
    body = request.get_json(silent=True) or {}
    h = (body.get("hash") or "").strip().lower()
    label = (body.get("label") or "").strip()[:200]
    source = (body.get("source") or "").strip()[:200] or "manual"
    if not HEX64.match(h):
        return jsonify(error="hash deve ser sha256 (64 hex chars)"), 400
    db = get_db()
    db.execute("DELETE FROM malicious_hashes WHERE hash = ?", (h,))  # mutually exclusive
    db.execute(
        """INSERT INTO allowed_hashes (hash, label, source, added_at)
           VALUES (?, ?, ?, ?)
           ON CONFLICT(hash) DO UPDATE SET label=excluded.label, source=excluded.source""",
        (h, label, source, int(time.time() * 1000)),
    )
    return jsonify(ok=True, hash=h)


@bp.delete("/allowed/<h>")
@require_admin
def delete_allowed(h):
    h = h.strip().lower()
    db = get_db()
    db.execute("DELETE FROM allowed_hashes WHERE hash = ?", (h,))
    return jsonify(ok=True)


@bp.get("/packages")
@require_admin
def list_packages(): return _list_table("malicious_packages")


@bp.post("/packages")
@require_admin
def add_package():
    body = request.get_json(silent=True) or {}
    pattern = (body.get("pattern") or "").strip().lower()
    label = (body.get("label") or "").strip()[:200]
    if not pattern or len(pattern) > 200 or not re.match(r"^[a-z0-9_.\-*]+$", pattern):
        return jsonify(error="pattern inválido (use ex.: me.monkey ou me.monkey.*)"), 400
    db = get_db()
    db.execute(
        """INSERT INTO malicious_packages (pattern, label, added_at)
           VALUES (?, ?, ?)
           ON CONFLICT(pattern) DO UPDATE SET label=excluded.label""",
        (pattern, label, int(time.time() * 1000)),
    )
    return jsonify(ok=True, pattern=pattern)


@bp.delete("/packages/<path:pattern>")
@require_admin
def delete_package(pattern):
    db = get_db()
    db.execute("DELETE FROM malicious_packages WHERE pattern = ?", (pattern,))
    # also remove hashes that were auto-cached by this rule
    db.execute("DELETE FROM malicious_hashes WHERE source = ?", (f"auto:package:{pattern}",))
    return jsonify(ok=True)


@bp.get("/urls")
@require_admin
def list_urls(): return _list_table("malicious_urls")


@bp.post("/urls")
@require_admin
def add_url():
    body = request.get_json(silent=True) or {}
    pattern = (body.get("pattern") or "").strip()
    label = (body.get("label") or "").strip()[:200]
    if not pattern or len(pattern) > 500:
        return jsonify(error="pattern vazio ou longo demais"), 400
    db = get_db()
    db.execute(
        """INSERT INTO malicious_urls (pattern, label, added_at)
           VALUES (?, ?, ?)
           ON CONFLICT(pattern) DO UPDATE SET label=excluded.label""",
        (pattern, label, int(time.time() * 1000)),
    )
    return jsonify(ok=True, pattern=pattern)


@bp.delete("/urls/<path:pattern>")
@require_admin
def delete_url(pattern):
    db = get_db()
    db.execute("DELETE FROM malicious_urls WHERE pattern = ?", (pattern,))
    db.execute("DELETE FROM malicious_hashes WHERE source = ?", (f"auto:url:{pattern}",))
    return jsonify(ok=True)


# ── summary ─────────────────────────────────────────────────────────
@bp.get("/summary")
@require_admin
def summary():
    db = get_db()
    rows = db.execute(
        """SELECT r.hash, MAX(r.packages_json) AS p, MAX(r.urls_json) AS u
             FROM reports r GROUP BY r.hash"""
    ).fetchall()
    allowed, hashes, packages, urls = _fetch_lists(db)
    infected = 0
    allowed_groups = 0
    for r in rows:
        current, in_allow = _compute_match(r["hash"], r["p"], r["u"], allowed, hashes, packages, urls)
        if in_allow:
            allowed_groups += 1
        elif current:
            infected += 1
    total = db.execute("SELECT COUNT(*) AS c FROM reports").fetchone()["c"]
    unique = len(rows)
    bl = db.execute(
        """SELECT
              (SELECT COUNT(*) FROM malicious_hashes)   AS hashes,
              (SELECT COUNT(*) FROM malicious_packages) AS packages,
              (SELECT COUNT(*) FROM malicious_urls)     AS urls,
              (SELECT COUNT(*) FROM allowed_hashes)     AS allowed"""
    ).fetchone()
    return jsonify(
        reports=dict(
            total=total,
            unique_hashes=unique,
            infected_groups=infected,
            allowed_groups=allowed_groups,
            clean_groups=unique - infected - allowed_groups,
        ),
        blocklists=dict(bl),
    )
