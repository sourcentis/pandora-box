from __future__ import annotations

import hashlib
import io
import json
import tarfile
import urllib.error
import zipfile
from collections.abc import Mapping
from email.message import Message
from pathlib import Path
from typing import IO

import pytest

from pandora_box import sigsets
from pandora_box.bloom import write_filter
from pandora_box.publish import (
    HASHLOOKUP,
    HASHLOOKUP_BLOOM,
    MALWAREBAZAAR,
    MALWAREBAZAAR_DB,
    SIGNATURE_BASE,
    YARA_FORGE,
    YARA_FORGE_RULES,
    Downloader,
    PublishError,
    development_config,
    malwarebazaar_url,
    publish,
)

from .test_sigsets import make_key

RULE = b'rule Test_Rule { meta: score = 80 strings: $a = "PUBLISH-TEST" condition: $a }\n'
SAMPLE_SHA256 = hashlib.sha256(b"sample").hexdigest()


def zip_of(name: str, content: bytes) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as z:
        z.writestr(name, content)
    return buffer.getvalue()


def bloom_bytes(tmp_path: Path) -> bytes:
    path = tmp_path / "filter.bloom"
    write_filter(path, [hashlib.sha1(b"known").hexdigest().upper().encode()])
    return path.read_bytes()


class Response(io.BytesIO):
    def __init__(self, data: bytes, etag: str) -> None:
        super().__init__(data)
        self.headers = Message()
        self.headers["ETag"] = etag


class FakeDownloader(Downloader):
    """Serves fixed contents; answers 304 to a request with the current ETag."""

    def __init__(self, cache: Path, contents: dict[str, bytes]) -> None:
        super().__init__(cache, log=lambda _: None)
        self.contents = contents
        self.downloads: list[str] = []

    def open(self, url: str, headers: Mapping[str, str]) -> IO[bytes]:
        etag = hashlib.sha256(self.contents[url]).hexdigest()[:16]
        if headers.get("If-None-Match") == etag:
            raise urllib.error.HTTPError(url, 304, "Not Modified", Message(), None)
        self.downloads.append(url)
        return Response(self.contents[url], etag)


@pytest.fixture
def contents(tmp_path: Path) -> dict[str, bytes]:
    return {
        YARA_FORGE: zip_of("packages/core/yara-rules-core.yar", RULE),
        malwarebazaar_url(MALWAREBAZAAR, "secret"): zip_of(
            "full_sha256.txt", f"# export\n{SAMPLE_SHA256}\n".encode()
        ),
        HASHLOOKUP: bloom_bytes(tmp_path),
    }


@pytest.fixture
def freshclam(tmp_path: Path) -> str:
    """A fake freshclam writing the three ClamAV databases into --datadir."""
    script = tmp_path / "freshclam"
    script.write_text(
        "#!/bin/sh\n"
        'for a in "$@"; do case "$a" in --datadir=*) d="${a#--datadir=}";; esac; done\n'
        'for n in main daily bytecode; do echo "$n" > "$d/$n.cvd"; done\n'
    )
    script.chmod(0o755)
    return str(script)


SOURCES = ["clamav", "yara-forge", "malwarebazaar", "hashlookup"]


def run_publish(
    tmp_path: Path, contents: dict[str, bytes], freshclam: str, key: Path | None, **kwargs: object
) -> tuple[sigsets.Manifest, FakeDownloader]:
    downloader = FakeDownloader(tmp_path / "cache" / "downloads", contents)
    manifest = publish(
        tmp_path / "set",
        kwargs.pop("sources", SOURCES),  # type: ignore[arg-type]
        tmp_path / "cache",
        key,
        auth_key="secret",
        downloader=downloader,
        freshclam=freshclam,
        clamscan="/nonexistent/clamscan",
        log=lambda _: None,
        **kwargs,  # type: ignore[arg-type]
    )
    return manifest, downloader


def test_publish_a_signed_set(tmp_path: Path, contents: dict[str, bytes], freshclam: str) -> None:
    key = make_key(tmp_path / "keys", "update")
    manifest, downloader = run_publish(tmp_path, contents, freshclam, key, serial=7)
    folder = tmp_path / "set"
    assert manifest.serial == 7
    # The set verifies like on a kiosk
    verified, _, _ = sigsets.read_set(folder, sigsets.trusted_keys(key.parent))
    assert verified == manifest
    paths = {f.path for f in manifest.files}
    assert {YARA_FORGE_RULES, MALWAREBAZAAR_DB, HASHLOOKUP_BLOOM} <= paths
    assert {"clamav/main.cvd", "clamav/daily.cvd", "clamav/bytecode.cvd"} <= paths
    assert (folder / YARA_FORGE_RULES).read_bytes() == RULE
    entry = manifest.entry(MALWAREBAZAAR_DB)
    assert entry is not None
    assert (entry.source, entry.version) == (MALWAREBAZAAR, "1 hashes")
    assert sorted(downloader.downloads) == sorted(contents)
    assert not list(tmp_path.glob(".set.*"))


def test_unchanged_sources_are_not_downloaded_again(
    tmp_path: Path, contents: dict[str, bytes], freshclam: str
) -> None:
    run_publish(tmp_path, contents, freshclam, None, serial=1)
    contents[YARA_FORGE] = zip_of("yara-rules-core.yar", RULE + b"// updated\n")
    manifest, downloader = run_publish(tmp_path, contents, freshclam, None, serial=2)
    assert downloader.downloads == [YARA_FORGE]
    assert manifest.serial == 2
    assert (tmp_path / "set" / YARA_FORGE_RULES).read_bytes().endswith(b"// updated\n")
    assert (tmp_path / "set" / HASHLOOKUP_BLOOM).exists()


def test_a_set_that_does_not_load_is_not_published(
    tmp_path: Path, contents: dict[str, bytes], freshclam: str
) -> None:
    run_publish(tmp_path, contents, freshclam, None, serial=1)
    contents[YARA_FORGE] = zip_of("yara-rules-core.yar", b"rule broken {")
    with pytest.raises(PublishError, match="the set cannot be loaded: yara"):
        run_publish(tmp_path, contents, freshclam, None, serial=2)
    # The previous set is unchanged, the staging folder removed
    assert json.loads((tmp_path / "set" / sigsets.MANIFEST).read_text())["serial"] == 1
    assert not list(tmp_path.glob(".set.*"))


def test_malwarebazaar_needs_an_auth_key(
    tmp_path: Path, contents: dict[str, bytes], freshclam: str
) -> None:
    downloader = FakeDownloader(tmp_path / "cache", contents)
    with pytest.raises(PublishError, match="Auth-Key"):
        publish(tmp_path / "set", ["malwarebazaar"], tmp_path / "cache", None,
                downloader=downloader, log=lambda _: None)  # fmt: skip


def test_the_auth_key_is_not_disclosed(
    tmp_path: Path, contents: dict[str, bytes], freshclam: str
) -> None:
    secret = "auth-key-0123456789"  # noqa: S105  (test value)
    contents = {url.replace("secret", secret): data for url, data in contents.items()}
    downloader = FakeDownloader(tmp_path / "cache" / "downloads", contents)
    logs: list[str] = []
    publish(tmp_path / "set", ["malwarebazaar"], tmp_path / "cache", None, auth_key=secret,
            downloader=downloader, log=logs.append, test_databases=False)  # fmt: skip
    # Sent in the path of the URL (abuse.ch)
    assert downloader.downloads == [malwarebazaar_url(MALWAREBAZAAR, secret)]
    assert secret in downloader.downloads[0]
    # Neither in the logs, nor in the set, nor in the cache
    assert logs and not any(secret in line for line in logs)
    for path in [*(tmp_path / "set").rglob("*"), *(tmp_path / "cache").rglob("*.json")]:
        if path.is_file():
            assert secret.encode() not in path.read_bytes(), path


def test_malwarebazaar_url() -> None:
    assert malwarebazaar_url(MALWAREBAZAAR, "a/b c") == (
        "https://mb-api.abuse.ch/v2/files/exports/a%2Fb%20c/sha256_full.txt.zip"
    )
    # A mirror without the placeholder only gets the Auth-Key header
    assert malwarebazaar_url("https://mirror.example/full.zip", "k") == (
        "https://mirror.example/full.zip"
    )


def test_signature_base_only_keeps_yara_files(tmp_path: Path, freshclam: str) -> None:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for name, data in (
            ("signature-base-master/yara/apt_test.yar", RULE),
            ("signature-base-master/yara/README.md", b"not a rule"),
            ("signature-base-master/iocs/hash.txt", b"not a rule"),
            ("signature-base-master/yara/../../evil.yar", RULE),
        ):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    manifest, _ = run_publish(
        tmp_path, {SIGNATURE_BASE: buffer.getvalue()}, freshclam, None,
        sources=["signature-base"], serial=1,
    )  # fmt: skip
    assert [f.path for f in manifest.files if f.path.endswith(".yar")] == [
        "yara/signature-base/apt_test.yar"
    ]
    assert not (tmp_path / "evil.yar").exists()


def test_downloads_are_https_only(tmp_path: Path) -> None:
    with pytest.raises(PublishError, match="not an HTTPS URL"):
        Downloader(tmp_path).fetch("http://example.org/rules.zip", "rules.zip")


def test_development_config(tmp_path: Path) -> None:
    config = development_config(tmp_path / "set", ["yara-forge", "hashlookup"])
    assert "verify = false" in config
    assert f'bloom = "{tmp_path}/set/{HASHLOOKUP_BLOOM}"' in config
    assert "[engines.malwarebazaar]\nenabled = false" in config
