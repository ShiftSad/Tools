"""Scrape public PassMark chart pages (cpubenchmark.net) into normalized CPU rows.

Uses chart list pages for bulk single-thread / multi-thread scores and
cpu_list.php for rank + price enrichment.
"""
from __future__ import annotations

import logging
import re
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from .config import Config

log = logging.getLogger(__name__)

BASE = "https://www.cpubenchmark.net"
UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)
MAX_CHART_PAGES = 80
FIRST_SEEN_RE = re.compile(
    r"CPU First Seen on Charts:</strong>\s*([^<]+)", re.IGNORECASE
)
YEAR_IN_TEXT_RE = re.compile(r"\b((?:19|20)\d{2})\b")


@dataclass
class CpuRow:
    passmark_id: int
    name: str
    single_thread: int | None = None
    cpu_mark: int | None = None
    rank: int | None = None
    price: str | None = None
    release_year: int | None = None


def _fetch(path: str) -> str:
    url = path if path.startswith("http") else f"{BASE}{path}"
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    delay = Config.PASSMARK_REQUEST_DELAY
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=45) as resp:
                data = resp.read().decode("utf-8", "replace")
            time.sleep(delay)
            return data
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
            if attempt == 3:
                raise
            wait = delay * (attempt + 2)
            log.warning("passmark fetch retry %s (%s)", url, exc)
            time.sleep(wait)
    raise RuntimeError(f"unreachable: {url}")


def _parse_chart_page(html: str) -> dict[int, tuple[str, int]]:
    out: dict[int, tuple[str, int]] = {}
    for block in re.findall(r"<li[^>]*>(.*?)</li>", html, re.S):
        if "prdname" not in block:
            continue
        id_m = re.search(r"id=(\d+)", block)
        name_m = re.search(r'class="prdname">([^<]+)', block)
        if not (id_m and name_m):
            continue
        pid = int(id_m.group(1))
        # Each CPU appears twice: benchmark score and "value" score.
        # Prefer the entry whose primary score is in .count (no .mark-neww).
        if "mark-neww" in block:
            if pid not in out:
                mark_m = re.search(r'class="mark-neww">([\d,]+)', block)
                if mark_m:
                    out[pid] = (
                        name_m.group(1).strip(),
                        int(mark_m.group(1).replace(",", "")),
                    )
            continue
        score_m = re.search(r'class="count">([\d,]+)', block)
        if not score_m:
            continue
        score_text = score_m.group(1).replace(",", "")
        if "." in score_text:
            continue
        out[pid] = (name_m.group(1).strip(), int(score_text))
    return out


def _scrape_chart(base_path: str) -> dict[int, tuple[str, int]]:
    merged: dict[int, tuple[str, int]] = {}
    for page in range(1, MAX_CHART_PAGES + 1):
        path = base_path if page == 1 else f"{base_path}/page{page}"
        data = _parse_chart_page(_fetch(path))
        if not data:
            break
        before = len(merged)
        for pid, val in data.items():
            if pid not in merged:
                merged[pid] = val
        added = len(merged) - before
        log.info("passmark %s: +%d new (total %d)", path, added, len(merged))
        if added == 0:
            break  # pagination repeats — no new CPUs
    return merged


def _cell_text(cell: str) -> str:
    return re.sub(r"<[^>]+>", "", cell).strip()


def _parse_int_cell(text: str) -> int | None:
    text = text.replace(",", "")
    if text.isdigit():
        return int(text)
    return None


def _scrape_cpu_list() -> dict[int, tuple[str, int | None, int | None, str | None]]:
    html = _fetch("/cpu_list.php")
    out: dict[int, tuple[str, int | None, int | None, str | None]] = {}
    for row in re.findall(r"<tr[^>]*>(.*?)</tr>", html, re.S):
        if "<td" not in row:
            continue
        id_m = re.search(r"id=(\d+)[^>]*>([^<]+)</a>", row)
        if not id_m:
            continue
        cells = [_cell_text(c) for c in re.findall(r"<td[^>]*>(.*?)</td>", row, re.S)[1:]]
        nums = [_parse_int_cell(t) for t in cells]
        nums = [n for n in nums if n is not None]
        price = next((t for t in cells if "$" in t), None)
        out[int(id_m.group(1))] = (
            id_m.group(2).strip(),
            nums[0] if nums else None,
            nums[1] if len(nums) > 1 else None,
            price,
        )
    log.info("passmark cpu_list: %d rows", len(out))
    return out


def _parse_release_year(html: str) -> int | None:
    m = FIRST_SEEN_RE.search(html)
    if not m:
        return None
    ym = YEAR_IN_TEXT_RE.search(m.group(1))
    return int(ym.group(1)) if ym else None


def _fetch_release_year(passmark_id: int) -> int | None:
    try:
        html = _fetch(f"/cpu.php?id={passmark_id}")
    except Exception:
        log.debug("passmark year fetch failed id=%s", passmark_id, exc_info=True)
        return None
    return _parse_release_year(html)


def _enrich_release_years(rows: list[CpuRow]) -> None:
    if not Config.PASSMARK_FETCH_YEARS:
        return
    workers = max(1, Config.PASSMARK_YEAR_WORKERS)
    log.info("passmark: fetching release years for %d cpus (%d workers)", len(rows), workers)
    by_id = {r.passmark_id: r for r in rows}
    done = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_fetch_release_year, pid): pid for pid in by_id
        }
        for fut in as_completed(futures):
            pid = futures[fut]
            try:
                by_id[pid].release_year = fut.result()
            except Exception:
                log.debug("passmark year future failed id=%s", pid, exc_info=True)
            done += 1
            if done % 500 == 0 or done == len(rows):
                log.info("passmark years: %d/%d", done, len(rows))
    with_year = sum(1 for r in rows if r.release_year)
    log.info("passmark years done: %d/%d have release_year", with_year, len(rows))


def scrape_all() -> list[CpuRow]:
    """Download and merge PassMark chart + list data."""
    mt = _scrape_chart("/multithread")
    st = _scrape_chart("/single-thread")
    lst = _scrape_cpu_list()

    rows: list[CpuRow] = []
    for pid in sorted(set(mt) | set(st) | set(lst)):
        name = (
            (mt.get(pid) or st.get(pid) or (lst.get(pid, ("", None, None, None))[0], None))[0]
        )
        if not name:
            continue
        lst_mark = lst_rank = lst_price = None
        if pid in lst:
            name, lst_mark, lst_rank, lst_price = lst[pid]
        rows.append(
            CpuRow(
                passmark_id=pid,
                name=name,
                single_thread=st[pid][1] if pid in st else None,
                cpu_mark=(mt[pid][1] if pid in mt else None) or lst_mark,
                rank=lst_rank,
                price=lst_price if lst_price and lst_price != "NA" else None,
            )
        )

    _enrich_release_years(rows)

    log.info(
        "passmark scrape done: %d cpus (%d with st, %d with mt, %d with year)",
        len(rows),
        sum(1 for r in rows if r.single_thread),
        sum(1 for r in rows if r.cpu_mark),
        sum(1 for r in rows if r.release_year),
    )
    return rows
