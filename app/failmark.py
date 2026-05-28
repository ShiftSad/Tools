"""FailMark API — CPU search backed by local PassMark scrape."""
from __future__ import annotations

import re

from flask import Blueprint, jsonify, request

from .db import get_db

bp = Blueprint("failmark", __name__)

def _infer_segment(name: str) -> str:
    n = name.lower()
    if "xeon" in n or "epyc" in n or "threadripper pro" in n:
        return "servidor"
    if "atom" in n or "celeron n" in n or "pentium n" in n:
        return "laptop"
    if "apple m" in n or "apple a" in n:
        return "laptop"
    if "mobile" in n or "u@" in n or "h@" in n:
        return "laptop"
    return "consumer"


def _row_to_json(row) -> dict:
    st = row["single_thread"]
    return {
        "id": row["passmark_id"],
        "name": row["name"],
        "year": row["release_year"],
        "segment": _infer_segment(row["name"]),
        "st": st,
        "mt": row["cpu_mark"],
        "rank": row["rank"],
        "price": row["price"],
    }


def _search_score(name: str, query: str) -> int:
    score = 0
    for token in query.split():
        if token and token in name:
            score += len(token)
    return score


@bp.get("/failmark/meta")
def meta():
    db = get_db()
    meta_rows = {
        r["key"]: r["value"]
        for r in db.execute("SELECT key, value FROM scrape_meta").fetchall()
    }
    count = db.execute("SELECT COUNT(*) AS n FROM cpus").fetchone()["n"]
    with_st = db.execute(
        "SELECT COUNT(*) AS n FROM cpus WHERE single_thread IS NOT NULL"
    ).fetchone()["n"]
    return jsonify(
        {
            "cpu_count": count,
            "with_single_thread": with_st,
            "last_sync": int(meta_rows["passmark_last_sync"])
            if meta_rows.get("passmark_last_sync")
            else None,
            "sync_status": meta_rows.get("passmark_sync_status", "unknown"),
        }
    )


@bp.get("/failmark/search")
def search():
    q = (request.args.get("q") or "").strip().lower()
    if len(q) < 2:
        return jsonify(results=[])

    limit = min(int(request.args.get("limit", 7)), 20)
    db = get_db()
    # Pull candidates with a broad LIKE prefilter, rank in Python.
    tokens = [t for t in q.split() if t]
    if not tokens:
        return jsonify(results=[])

    clauses = " AND ".join("LOWER(name) LIKE ?" for _ in tokens)
    params = [f"%{t}%" for t in tokens]
    rows = db.execute(
        f"""
        SELECT passmark_id, name, single_thread, cpu_mark, rank, price, release_year
        FROM cpus
        WHERE {clauses}
        ORDER BY single_thread DESC NULLS LAST, name
        LIMIT 200
        """,
        params,
    ).fetchall()

    ranked = sorted(
        ((_search_score(r["name"].lower(), q), r) for r in rows),
        key=lambda x: (-x[0], x[1]["name"].lower()),
    )
    results = [_row_to_json(r) for _, r in ranked[:limit] if _ > 0]
    if not results and rows:
        results = [_row_to_json(ranked[0][1])]
    return jsonify(results=results)


@bp.get("/failmark/cpu/<int:cpu_id>")
def cpu_detail(cpu_id: int):
    db = get_db()
    row = db.execute(
        """
        SELECT passmark_id, name, single_thread, cpu_mark, rank, price, release_year
        FROM cpus WHERE passmark_id = ?
        """,
        (cpu_id,),
    ).fetchone()
    if not row:
        return jsonify(error="processador não encontrado"), 404
    return jsonify(cpu=_row_to_json(row))


@bp.get("/failmark/cpu/<int:cpu_id>/peers")
def cpu_peers(cpu_id: int):
    db = get_db()
    target = db.execute(
        "SELECT passmark_id, name, single_thread, cpu_mark, rank, price, release_year FROM cpus WHERE passmark_id = ?",
        (cpu_id,),
    ).fetchone()
    if not target:
        return jsonify(error="processador não encontrado"), 404
    if target["single_thread"] is None:
        return jsonify(cpu=_row_to_json(target), peers=[])

    st = target["single_thread"]
    peers = db.execute(
        """
        SELECT passmark_id, name, single_thread, cpu_mark, rank, price, release_year
        FROM cpus
        WHERE passmark_id != ? AND single_thread IS NOT NULL
        ORDER BY ABS(single_thread - ?) ASC, name
        LIMIT 10
        """,
        (cpu_id, st),
    ).fetchall()

    all_rows = list(peers) + [target]
    all_rows.sort(
        key=lambda r: (r["release_year"] or 9999, r["single_thread"] or 0)
    )

    return jsonify(
        cpu=_row_to_json(target),
        peers=[_row_to_json(r) for r in peers],
        table=[_row_to_json(r) for r in all_rows],
    )
