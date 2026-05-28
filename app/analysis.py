"""JAR analysis: hash, package extraction, URL/string extraction, blocklist match.

A .jar is just a zip; the directory layout inside IS the package tree
(e.g. me/monkey/util/Foo.class → package `me.monkey.util`). No decompilation
needed to detect malicious package signatures.

For URLs we do a quick regex scan over the raw bytes of every .class plus
resource files (plugin.yml, MANIFEST.MF, etc.). String literals in classfiles
are UTF-8 with a 2-byte length prefix — the URL text itself is intact, so
plain regex catches the vast majority of cases.

Works for any .jar — Bukkit/Paper plugins, Forge mods, Fabric mods, whatever.
"""
import hashlib
import io
import re
import zipfile

from .config import Config

CLASS_EXT = ".class"
RESOURCE_EXTS = (".yml", ".yaml", ".json", ".properties", ".txt", ".mf", ".xml", ".cfg", ".conf", ".toml")

# Local file header — standard ZIP/JAR start (not executable-wrapped jars).
ZIP_MAGIC = b"PK\x03\x04"

URL_RE = re.compile(
    rb"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+",
    re.IGNORECASE,
)
TRIM_PUNCT = ".,;:!?)]}>\"'"

_READ_CHUNK = 64 * 1024


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_jar_magic(data: bytes) -> None:
    """Reject non-ZIP payloads before parsing (extension alone is not enough)."""
    if len(data) < 4:
        raise ValueError("arquivo muito pequeno ou inválido")
    if not data.startswith(ZIP_MAGIC):
        raise ValueError(
            "arquivo não é um .jar/zip válido (assinatura PK\\x03\\x04 ausente)"
        )


def _safe_zip_name(name: str) -> bool:
    """Block path traversal entries inside the archive."""
    if not name or name.startswith("/"):
        return False
    parts = name.replace("\\", "/").split("/")
    return ".." not in parts


def _entry_suspicious(info: zipfile.ZipInfo) -> str | None:
    """Header-based checks before reading entry body (zip bomb hints)."""
    uncompressed = info.file_size
    compressed = info.compress_size
    if uncompressed > Config.MAX_ZIP_ENTRY_READ_BYTES:
        return (
            f"entrada '{info.filename}' declara {uncompressed} bytes descomprimidos "
            f"(limite {Config.MAX_ZIP_ENTRY_READ_BYTES})"
        )
    if compressed > 0 and uncompressed > 0:
        ratio = uncompressed / compressed
        if ratio > Config.MAX_ZIP_COMPRESSION_RATIO:
            return (
                f"entrada '{info.filename}' com taxa de compressão suspeita "
                f"({ratio:.0f}:1, limite {Config.MAX_ZIP_COMPRESSION_RATIO}:1)"
            )
    return None


def _read_bounded(stream, per_entry_cap: int, budget: int) -> tuple[bytes, int]:
    """Read at most per_entry_cap bytes from stream, decrementing shared budget."""
    limit = min(per_entry_cap, budget)
    if limit <= 0:
        raise ValueError("limite de leitura do .jar excedido")

    chunks: list[bytes] = []
    total = 0
    while total < limit:
        chunk = stream.read(min(_READ_CHUNK, limit - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)

    if total >= limit and stream.read(1):
        raise ValueError(
            f"conteúdo descomprimido excede o limite de {per_entry_cap} bytes por entrada"
        )

    return b"".join(chunks), budget - total


def _extract_urls(data: bytes):
    for m in URL_RE.finditer(data):
        url = m.group(0).decode("utf-8", errors="replace")
        url = url.rstrip(TRIM_PUNCT)
        if 8 <= len(url) <= 2048:
            yield url


def analyze(jar_bytes: bytes) -> dict:
    """Parse the jar and return all the artefacts we care about for matching.

    Raises ValueError if the file isn't a readable zip or exceeds safety limits.
    """
    validate_jar_magic(jar_bytes)

    digest = sha256(jar_bytes)
    packages: set[str] = set()
    urls: set[str] = set()
    class_count = 0
    entry_count = 0
    resource_count = 0
    read_budget = Config.MAX_ZIP_TOTAL_READ_BYTES

    try:
        zf = zipfile.ZipFile(io.BytesIO(jar_bytes))
    except zipfile.BadZipFile as e:
        raise ValueError("arquivo não é um .jar/zip válido") from e

    with zf:
        entries = zf.infolist()
        if len(entries) > Config.MAX_ZIP_ENTRIES:
            raise ValueError(
                f".jar com entradas demais ({len(entries)}, "
                f"limite {Config.MAX_ZIP_ENTRIES})"
            )

        for info in entries:
            entry_count += 1
            if info.is_dir():
                continue
            name = info.filename
            if not _safe_zip_name(name):
                continue

            suspicious = _entry_suspicious(info)
            if suspicious:
                raise ValueError(f"arquivo .jar rejeitado: {suspicious}")

            lname = name.lower()
            scan_content = lname.endswith(CLASS_EXT) or lname.endswith(RESOURCE_EXTS)

            if lname.endswith(CLASS_EXT):
                class_count += 1
                if "/" in name:
                    pkg = name.rsplit("/", 1)[0].replace("/", ".")
                    if pkg and not pkg.startswith("META-INF"):
                        packages.add(pkg)
            elif lname.endswith(RESOURCE_EXTS):
                resource_count += 1
            else:
                continue

            if not scan_content:
                continue

            try:
                with zf.open(info) as fh:
                    data, read_budget = _read_bounded(
                        fh,
                        Config.MAX_ZIP_ENTRY_READ_BYTES,
                        read_budget,
                    )
                    urls.update(_extract_urls(data))
            except (KeyError, zipfile.BadZipFile, RuntimeError, OSError):
                pass

    return {
        "sha256": digest,
        "packages": sorted(packages),
        "urls": sorted(urls),
        "class_count": class_count,
        "entry_count": entry_count,
        "resource_count": resource_count,
    }


def package_matches(pattern: str, package: str) -> bool:
    """Match pattern against a fully-qualified package name.

    `me.monkey`    matches `me.monkey` and any sub-package `me.monkey.x.y`
    `me.monkey.*`  same — the `.*` suffix is sugar
    """
    pat = pattern.strip().strip(".")
    if pat.endswith(".*"):
        pat = pat[:-2]
    if not pat:
        return False
    return package == pat or package.startswith(pat + ".")


def url_matches(pattern: str, url: str) -> bool:
    """Substring match (case-insensitive). Pattern is meant to be a host
    or path fragment like `evil.example.com` or `/install.sh`."""
    if not pattern:
        return False
    return pattern.strip().lower() in url.lower()


def check_allowed_hash(digest: str, db) -> dict | None:
    """Check if a hash is in the explicit allowlist (admin-vouched). When
    present, the file is treated as clean regardless of other matches."""
    if not digest:
        return None
    row = db.execute(
        "SELECT label FROM allowed_hashes WHERE hash = ?", (digest,)
    ).fetchone()
    if row:
        return {"label": row["label"] or "", "pattern": digest}
    return None


def check_hash_only(digest: str, db) -> dict | None:
    """Lightweight check used by the /api/scan/check endpoint — looks at
    just the malicious-hash blocklist (the client only sends the hash, no file).
    Does NOT check the allowlist — callers handle allowlist precedence."""
    if not digest:
        return None
    row = db.execute(
        "SELECT label FROM malicious_hashes WHERE hash = ?", (digest,)
    ).fetchone()
    if row:
        return {"reason": "hash", "label": row["label"] or "", "pattern": digest}
    return None


def check_blocklists(analysis: dict, db) -> dict | None:
    """Run analysis against all three malicious blocklists. Returns the first
    match, or None if nothing matched. Allowlist is NOT checked here — callers
    must handle that precedence (allowlist wins over any match)."""
    if (m := check_hash_only(analysis.get("sha256", ""), db)):
        return m

    for row in db.execute("SELECT pattern, label FROM malicious_packages").fetchall():
        for pkg in analysis.get("packages") or []:
            if package_matches(row["pattern"], pkg):
                return {"reason": "package", "label": row["label"] or "", "pattern": row["pattern"]}

    url_rows = db.execute("SELECT pattern, label FROM malicious_urls").fetchall()
    for url in analysis.get("urls") or []:
        for row in url_rows:
            if url_matches(row["pattern"], url):
                return {"reason": "url", "label": row["label"] or "", "pattern": row["pattern"]}

    return None
