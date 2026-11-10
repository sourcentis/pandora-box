"""Publication of signature sets (pandora-box-signatures publish).

Downloads the signatures of every engine from their sources, checks that the
engines of a kiosk can load them, then builds and signs a signature set
(pandora_box.sigsets) ready to be copied onto a signature update device:

    clamav/          ClamAV databases, updated by freshclam (which verifies
                     their Cisco Talos signature)
    yara/yara-forge/ YARA Forge "core" rule package (GitHub release)
    yara/signature-base/  signature-base rules (opt-in: included in YARA Forge)
    malwarebazaar/   MalwareBazaar full SHA-256 export (free abuse.ch Auth-Key)
    hashlookup/      CIRCL hashlookup Bloom filter (about 1 GB, monthly)

Downloads are HTTPS only, with a cache: a source that did not change
(ETag, Last-Modified) is not downloaded again. A set that does not pass the
checks is never signed: a broken set, validly signed, would make every kiosk
that installs it unable to scan.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import IO

from pandora_box import sigsets
from pandora_box.config import SIGNATURE_SOURCES

YARA_FORGE = (
    "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip"
)
SIGNATURE_BASE = "https://github.com/Neo23x0/signature-base/archive/refs/heads/master.tar.gz"
# The abuse.ch Auth-Key is part of the path: {auth_key} is replaced by it (the
# former https://bazaar.abuse.ch/export/txt/sha256/full/ answers HTTP 410)
MALWAREBAZAAR = "https://mb-api.abuse.ch/v2/files/exports/{auth_key}/sha256_full.txt.zip"
AUTH_KEY_PLACEHOLDER = "{auth_key}"
HASHLOOKUP = "https://cra.circl.lu/hashlookup/hashlookup-full.bloom"
CLAMAV_MIRROR = "database.clamav.net"

SOURCES = SIGNATURE_SOURCES
# signature-base is opt-in: YARA Forge already includes its rules
DEFAULT_SOURCES = ("clamav", "yara-forge", "malwarebazaar", "hashlookup")

# Paths of the default kiosk configuration, below the set
YARA_FORGE_RULES = "yara/yara-forge/yara-rules-core.yar"
SIGNATURE_BASE_RULES = "yara/signature-base"
MALWAREBAZAAR_DB = "malwarebazaar/malwarebazaar.sha256.bin"
HASHLOOKUP_BLOOM = "hashlookup/hashlookup-full.bloom"
CLAMAV_FOLDER = "clamav"
CLAMAV_DATABASES = ("main", "daily", "bytecode")

FRESHCLAM = "/usr/bin/freshclam"
CLAMSCAN = "/usr/bin/clamscan"
_CHUNK = 1024 * 1024


class PublishError(Exception):
    pass


@dataclass(frozen=True)
class Download:
    path: Path
    sha256: str
    # Not modified since the previous download (served from the cache)
    cached: bool
    # When it was downloaded (ISO 8601): unchanged for a cached file
    date: str = ""


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    """Follow redirects to HTTPS URLs only (urllib also follows ftp and http)."""

    def __init__(self, allow_http: bool) -> None:
        self.schemes = ("https://", "http://") if allow_http else ("https://",)

    def redirect_request(  # type: ignore[no-untyped-def]
        self, req, fp, code, msg, headers, newurl
    ) -> urllib.request.Request | None:
        if not newurl.startswith(self.schemes):
            raise PublishError(f"{req.full_url}: redirect to {newurl} refused")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class Downloader:
    """HTTPS downloads, cached with their ETag and Last-Modified headers.

    proxy: the only proxy used ("": direct, never the proxy of the
    environment). allow_http: also http:// URLs (mirrors configured on a
    kiosk).
    """

    def __init__(
        self,
        cache: Path,
        log: Callable[[str], None] = print,
        proxy: str = "",
        timeout: float = 300.0,
        allow_http: bool = False,
    ) -> None:
        self.cache = cache
        self.log = log
        self.timeout = timeout
        self.schemes = ("https://", "http://") if allow_http else ("https://",)
        proxies = {"http": proxy, "https": proxy} if proxy else {}
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler(proxies), _SafeRedirect(allow_http)
        )

    def open(self, url: str, headers: Mapping[str, str]) -> IO[bytes]:
        """Open url; raise urllib.error.HTTPError (304 when not modified)."""
        if not url.startswith(self.schemes):
            raise PublishError(f"not an HTTPS URL: {url}")
        request = urllib.request.Request(url, headers=dict(headers))  # noqa: S310  (checked)
        response: IO[bytes] = self.opener.open(request, timeout=self.timeout)
        return response

    def fetch(
        self,
        url: str,
        name: str,
        headers: Mapping[str, str] | None = None,
        shown_url: str | None = None,
    ) -> Download:
        """Download url into the cache as name.

        shown_url: the URL written in the logs, errors and cache metadata, in
        place of url (a URL holding a secret).
        """
        shown_url = url if shown_url is None else shown_url
        self.cache.mkdir(parents=True, exist_ok=True)
        target = self.cache / name
        meta_path = self.cache / f"{name}.json"
        try:
            meta = json.loads(meta_path.read_text())
        except (OSError, ValueError):
            meta = {}
        request_headers = {"User-Agent": "pandora-box-publish", **(headers or {})}
        if target.exists() and meta.get("url") == shown_url:
            if meta.get("etag"):
                request_headers["If-None-Match"] = meta["etag"]
            if meta.get("last_modified"):
                request_headers["If-Modified-Since"] = meta["last_modified"]
        try:
            response = self.open(url, request_headers)
        except urllib.error.HTTPError as ex:
            if ex.code == 304 and target.exists():
                self.log(f"{name}: not modified")
                return Download(
                    target, str(meta.get("sha256", "")), cached=True, date=str(meta.get("date", ""))
                )
            raise PublishError(f"{shown_url}: HTTP {ex.code}") from ex
        except (urllib.error.URLError, OSError) as ex:
            raise PublishError(f"{shown_url}: {ex}") from ex
        self.log(f"{name}: downloading {shown_url}")
        digest = hashlib.sha256()
        partial = target.with_name(f".{name}.part")
        with response, partial.open("wb") as out:
            while chunk := response.read(_CHUNK):
                digest.update(chunk)
                out.write(chunk)
            response_headers = getattr(response, "headers", {})
            etag = response_headers.get("ETag", "")
            last_modified = response_headers.get("Last-Modified", "")
        partial.replace(target)
        meta = {
            "url": shown_url,
            "etag": etag,
            "last_modified": last_modified,
            "sha256": digest.hexdigest(),
            "date": datetime.now(UTC).isoformat(timespec="seconds"),
        }
        meta_path.write_text(json.dumps(meta, indent=1) + "\n")
        return Download(target, digest.hexdigest(), cached=False, date=meta["date"])


def _describe(folder: Path, name: str, source: str, version: str = "") -> None:
    """Record the source and version of a file (the manifest.json of its folder)."""
    path = folder / sigsets.MANIFEST
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        data = {}
    data[name] = {
        "source": source,
        "version": version or datetime.now(UTC).strftime("%Y-%m-%d"),
        "date": datetime.now(UTC).isoformat(timespec="seconds"),
    }
    path.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n")


# -- sources -------------------------------------------------------------------------


def fetch_yara_forge(downloader: Downloader, output: Path, url: str = YARA_FORGE) -> None:
    archive = downloader.fetch(url, "yara-forge-rules-core.zip")
    target = output / YARA_FORGE_RULES
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        with zipfile.ZipFile(archive.path) as z:
            member = next(n for n in z.namelist() if n.endswith("yara-rules-core.yar"))
            target.write_bytes(z.read(member))
    except (zipfile.BadZipFile, StopIteration) as ex:
        raise PublishError("YARA Forge: no yara-rules-core.yar in the archive") from ex
    _describe(target.parent, target.name, url, archive.sha256[:16])


def fetch_signature_base(downloader: Downloader, output: Path, url: str = SIGNATURE_BASE) -> None:
    archive = downloader.fetch(url, "signature-base.tar.gz")
    folder = output / SIGNATURE_BASE_RULES
    folder.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive.path) as tar:
        for member in tar.getmembers():
            parts = PurePosixPath(member.name).parts
            # Only the regular .yar files of the yara/ folder, without path tricks
            if len(parts) != 3 or parts[1] != "yara" or not member.isfile():
                continue
            if not parts[2].endswith((".yar", ".yara")):
                continue
            try:
                sigsets.validate_path(f"x/{parts[2]}")
            except sigsets.SignatureSetError:
                continue
            source = tar.extractfile(member)
            if source is not None:
                (folder / parts[2]).write_bytes(source.read())
    _describe(folder.parent, folder.name, url, archive.sha256[:16])


def malwarebazaar_url(url: str, auth_key: str) -> str:
    """url with its {auth_key} placeholder replaced by the abuse.ch Auth-Key."""
    return url.replace(AUTH_KEY_PLACEHOLDER, urllib.parse.quote(auth_key, safe=""))


def fetch_malwarebazaar(
    downloader: Downloader, output: Path, auth_key: str, url: str = MALWAREBAZAAR
) -> None:
    from pandora_box.hashdb import HashDatabaseError, read_export, write_database

    if not auth_key:
        raise PublishError(
            "MalwareBazaar needs an abuse.ch Auth-Key (free: https://auth.abuse.ch/): "
            "set ABUSECH_AUTH_KEY, or leave malwarebazaar out of --sources"
        )
    # The key in the path (abuse.ch) and in the Auth-Key header (a mirror), never
    # in the logs nor in the manifest of the set: url keeps the placeholder
    export = downloader.fetch(
        malwarebazaar_url(url, auth_key),
        "malwarebazaar-full-sha256.zip",
        {"Auth-Key": auth_key},
        shown_url=url,
    )
    target = output / MALWAREBAZAAR_DB
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        digests, source_sha256 = read_export(export.path)
        # Dated by the download: an unchanged export gives the same database
        created = int(datetime.fromisoformat(export.date).timestamp()) if export.date else None
        count = write_database(digests, target, source_sha256, created)
    except HashDatabaseError as ex:
        raise PublishError(f"MalwareBazaar: {ex}") from ex
    _describe(target.parent, target.name, url, f"{count} hashes")


def fetch_hashlookup(downloader: Downloader, output: Path, url: str = HASHLOOKUP) -> None:
    bloom = downloader.fetch(url, "hashlookup-full.bloom")
    target = output / HASHLOOKUP_BLOOM
    target.parent.mkdir(parents=True, exist_ok=True)
    _link_or_copy(bloom.path, target)
    _describe(target.parent, target.name, url, bloom.sha256[:16])


def fetch_clamav(
    cache: Path,
    output: Path,
    freshclam: str = FRESHCLAM,
    mirror: str = "",
    proxy: str = "",
    test_databases: bool = True,
) -> None:
    """Update the ClamAV databases of the cache with freshclam, then copy them.

    mirror: a private mirror in place of the ClamAV mirror. test_databases:
    freshclam loads the new databases to check them (as much memory as clamd).
    """
    datadir = cache / "clamav"
    datadir.mkdir(parents=True, exist_ok=True)
    lines = [f"DatabaseDirectory {datadir}", "Foreground yes"]
    lines.append(f"PrivateMirror {mirror}" if mirror else f"DatabaseMirror {CLAMAV_MIRROR}")
    if proxy:
        parts = urllib.parse.urlsplit(proxy)
        lines.append(f"HTTPProxyServer {parts.scheme}://{parts.hostname}")
        lines.append(f"HTTPProxyPort {parts.port or 3128}")
    if not test_databases:
        lines.append("TestDatabases no")
    config = cache / "freshclam.conf"
    config.write_text("\n".join(lines) + "\n")
    result = subprocess.run(  # noqa: S603  (fixed command, no shell)
        [freshclam, f"--config-file={config}", f"--datadir={datadir}", "--stdout"],
        capture_output=True,
        text=True,
        check=False,
        timeout=3600,
    )
    if result.returncode != 0:
        raise PublishError(f"freshclam failed: {(result.stdout + result.stderr).strip()[-2000:]}")
    folder = output / CLAMAV_FOLDER
    folder.mkdir(parents=True, exist_ok=True)
    for name in CLAMAV_DATABASES:
        found = [datadir / f"{name}.{ext}" for ext in ("cvd", "cld")]
        found = [p for p in found if p.exists()]
        if not found:
            raise PublishError(f"ClamAV: no {name} database after freshclam")
        _link_or_copy(found[0], folder / found[0].name)
        _describe(folder, found[0].name, mirror or f"https://{CLAMAV_MIRROR}/")


def _link_or_copy(source: Path, target: Path) -> None:
    target.unlink(missing_ok=True)
    try:
        os.link(source, target)
    except OSError:
        shutil.copyfile(source, target)


# -- checks -------------------------------------------------------------------------


def check_set(output: Path, sources: Sequence[str], clamscan: str = CLAMSCAN) -> list[str]:
    """Load the set with the engines of a kiosk; return the warnings.

    Raise PublishError when an engine cannot load its files.
    """
    from pandora_box.config import YaraConfig, YaraRuleSet
    from pandora_box.engines import EngineError
    from pandora_box.engines.hashes import HashlookupEngine, MalwareBazaarEngine
    from pandora_box.engines.yara import YaraEngine

    warnings = []
    try:
        if "malwarebazaar" in sources:
            MalwareBazaarEngine(output / MALWAREBAZAAR_DB).load()
        if "hashlookup" in sources:
            HashlookupEngine(output / HASHLOOKUP_BLOOM).load()
        rules = []
        if "yara-forge" in sources:
            rules.append(YaraRuleSet("yara-forge", output / YARA_FORGE_RULES))
        if "signature-base" in sources:
            rules.append(YaraRuleSet("signature-base", output / SIGNATURE_BASE_RULES))
        if rules:
            # The default kiosk configuration refuses rules that do not compile
            YaraEngine(YaraConfig(rules=tuple(rules), cache_dir=None)).load()
    except EngineError as ex:
        raise PublishError(f"the set cannot be loaded: {ex}") from ex
    if "clamav" in sources:
        if Path(clamscan).exists():
            # Scanning an empty file loads every database
            with tempfile.NamedTemporaryFile(suffix=".txt") as empty:
                result = subprocess.run(  # noqa: S603  (fixed command, no shell)
                    [clamscan, "--no-summary", f"--database={output / CLAMAV_FOLDER}", empty.name],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=1800,
                )
            if result.returncode != 0:
                raise PublishError(f"clamscan cannot load the ClamAV databases: {result.stderr}")
        else:
            warnings.append("clamscan not installed: the ClamAV databases were not loaded")
    return warnings


# -- publication ---------------------------------------------------------------------


# Folder of the files of each source, in a set
SOURCE_FOLDERS = {
    "clamav": f"{CLAMAV_FOLDER}/",
    "yara-forge": "yara/yara-forge/",
    "signature-base": f"{SIGNATURE_BASE_RULES}/",
    "malwarebazaar": "malwarebazaar/",
    "hashlookup": "hashlookup/",
}


def keep_files(installed: Path, staging: Path, sources: Sequence[str]) -> int:
    """Copy the files of the installed set that the sources do not replace.

    A kiosk that downloads some sources only (or that has no abuse.ch key)
    keeps the other signatures, from its last signature update device.
    Return the number of files kept.
    """
    manifest = sigsets.parse_manifest((installed / sigsets.MANIFEST).read_bytes())
    replaced = tuple(SOURCE_FOLDERS[source] for source in sources)
    kept = 0
    for entry in manifest.files:
        if entry.path.startswith(replaced):
            continue
        target = staging / entry.path
        target.parent.mkdir(parents=True, exist_ok=True)
        _link_or_copy(installed / entry.path, target)
        kept += 1
    return kept


def publish(
    output: Path,
    sources: Sequence[str],
    cache: Path,
    key: Path | None,
    serial: int | None = None,
    auth_key: str = "",
    downloader: Downloader | None = None,
    freshclam: str = FRESHCLAM,
    clamscan: str = CLAMSCAN,
    log: Callable[[str], None] = print,
    mirrors: Mapping[str, str] | None = None,
    keep_from: Path | None = None,
    proxy: str = "",
    test_databases: bool = True,
) -> sigsets.Manifest:
    """Build the set in a new folder, check it, sign it, then replace output.

    mirrors: URLs in place of those of the sources. keep_from: an installed
    set whose files the sources do not replace are kept. key None: not
    signed (a kiosk signs the set it builds with its own key).
    """
    unknown = set(sources) - set(SOURCES)
    if unknown or not sources:
        raise PublishError(f"unknown sources: {', '.join(sorted(unknown))}")
    mirrors = mirrors or {}
    downloader = downloader or Downloader(cache / "downloads", log, proxy)
    staging = output.with_name(f".{output.name}.staging")
    shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(parents=True)
    try:
        if "clamav" in sources:
            log("clamav: freshclam")
            fetch_clamav(
                cache, staging, freshclam, mirrors.get("clamav", ""), proxy, test_databases
            )
        if "yara-forge" in sources:
            fetch_yara_forge(downloader, staging, mirrors.get("yara-forge", YARA_FORGE))
        if "signature-base" in sources:
            fetch_signature_base(downloader, staging, mirrors.get("signature-base", SIGNATURE_BASE))
        if "malwarebazaar" in sources:
            fetch_malwarebazaar(
                downloader, staging, auth_key, mirrors.get("malwarebazaar", MALWAREBAZAAR)
            )
        if "hashlookup" in sources:
            fetch_hashlookup(downloader, staging, mirrors.get("hashlookup", HASHLOOKUP))
        if keep_from is not None:
            log(f"{keep_files(keep_from, staging, sources)} files kept from the installed set")
        log("checking the set with the kiosk engines")
        for warning in check_set(staging, sources, clamscan):
            log(f"WARNING: {warning}")
        manifest = sigsets.build(staging, serial)
        if key is not None:
            sigsets.sign(staging, key)
        old = output.with_name(f".{output.name}.old")
        shutil.rmtree(old, ignore_errors=True)
        if output.exists():
            output.rename(old)
        staging.rename(output)
        shutil.rmtree(old, ignore_errors=True)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return manifest


def read_auth_key(path: Path | None) -> str:
    if path is not None:
        return path.read_text().strip()
    return os.environ.get("ABUSECH_AUTH_KEY", "")


def development_config(output: Path, sources: Sequence[str]) -> str:
    """The configuration of a development kiosk using an unsigned set."""
    lines = ["[signatures]", "# Not signed: development only", "verify = false", ""]
    for name, key, path in (
        ("malwarebazaar", "database", MALWAREBAZAAR_DB),
        ("hashlookup", "bloom", HASHLOOKUP_BLOOM),
    ):
        lines.append(f"[engines.{name}]")
        lines.append(f'{key} = "{output / path}"' if name in sources else "enabled = false")
        lines.append("")
    rules = [
        (n, output / p)
        for n, p in (("yara-forge", YARA_FORGE_RULES), ("signature-base", SIGNATURE_BASE_RULES))
        if n in sources
    ]
    lines.append("[engines.yara]")
    if rules:
        lines.append("rules = [")
        lines += [f'    {{ name = "{n}", path = "{p}" }},' for n, p in rules]
        lines.append("]")
    else:
        lines.append("enabled = false")
    if "clamav" in sources:
        lines += ["", f"# clamd.conf: DatabaseDirectory {output / CLAMAV_FOLDER}"]
    return "\n".join(lines) + "\n"
