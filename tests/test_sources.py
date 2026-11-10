"""A kiosk that downloads the signatures from their sources (updates.sources)."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from pandora_box.config import Config, parse_config
from pandora_box.kiosk import check_signatures
from pandora_box.online import build_from_sources, download
from pandora_box.publish import (
    MALWAREBAZAAR,
    MALWAREBAZAAR_DB,
    YARA_FORGE,
    YARA_FORGE_RULES,
    PublishError,
    keep_files,
    malwarebazaar_url,
)
from pandora_box.sigsets import (
    MANIFEST,
    SIGNATURE,
    current_set,
    install,
    installed_manifest,
    local_public_keys,
    main,
    read_set,
    trusted_keys,
    verify_installed,
)

from .test_publish import RULE, FakeDownloader, zip_of
from .test_sigsets import make_key, make_set

pytestmark = pytest.mark.skipif(not Path("/usr/bin/openssl").exists(), reason="no openssl")

# The set of the last signature update device: ClamAV is not downloaded
INSTALLED = {"clamav/test.hdb": b"clamav db\n", "yara/yara-forge/yara-rules-core.yar": b"old"}
SOURCES = '["yara-forge", "malwarebazaar"]'
SAMPLE = "a" * 64


def write_config(tmp_path: Path, sources: str = SOURCES) -> Path:
    path = tmp_path / "pandora-box.toml"
    path.write_text(
        f"""
[kiosk]
name = "test"
fake_scan = false

[scan]
sandbox = false

[signatures]
folder = "{tmp_path / "signatures"}"
keys = "{tmp_path / "keys"}"

[engines.malwarebazaar]
database = "{tmp_path / "signatures/current" / MALWAREBAZAAR_DB}"

[engines.hashlookup]
enabled = false

[engines.clamav]
enabled = false

[engines.yara]
rules = [{{ name = "yara-forge", path = "{tmp_path / "signatures/current" / YARA_FORGE_RULES}" }}]

[updates]
enabled = true
sources = {sources}
"""
    )
    return path


def load(path: Path) -> Config:
    import tomllib

    return parse_config(tomllib.loads(path.read_text()))


@pytest.fixture
def kiosk(tmp_path: Path) -> Path:
    """A kiosk configuration, with the set of a signature update device installed."""
    key = make_key(tmp_path / "keys", "update")
    install(make_set(tmp_path / "usb-set", INSTALLED, 1, key), tmp_path / "signatures",
            trusted_keys(tmp_path / "keys"))  # fmt: skip
    return write_config(tmp_path)


def downloader(tmp_path: Path, malwarebazaar: str = SAMPLE) -> FakeDownloader:
    return FakeDownloader(
        tmp_path / "update" / "staging-sources" / "downloads",
        {
            YARA_FORGE: zip_of("packages/core/yara-rules-core.yar", RULE),
            malwarebazaar_url(MALWAREBAZAAR, "secret"): zip_of(
                "full_sha256.txt", f"# export\n{malwarebazaar}\n".encode()
            ),
        },
    )


def build(tmp_path: Path, config: Config, auth_key: str = "secret", **options: object) -> object:
    options.setdefault("downloader", downloader(tmp_path))
    return build_from_sources(
        config,
        tmp_path / "update" / "staging",
        log=lambda _: None,
        auth_key=auth_key,
        clamscan="/nonexistent/clamscan",
        **options,
    )


def install_staged(tmp_path: Path, config_path: Path) -> int:
    return main(
        ["install", str(tmp_path / "update" / "staging"), "--staged",
         "--keys", str(tmp_path / "keys"), "--target", str(tmp_path / "signatures"),
         "--config", str(config_path)]
    )  # fmt: skip


def test_build_from_sources_then_install(tmp_path: Path, kiosk: Path) -> None:
    config = load(kiosk)
    manifest = build(tmp_path, config)
    staging = tmp_path / "update" / "staging"
    assert manifest is not None
    # Not signed by the update service: it has no key
    assert (staging / MANIFEST).exists() and not (staging / SIGNATURE).exists()
    assert (staging / YARA_FORGE_RULES).read_bytes() == RULE
    # ClamAV is not a source of this kiosk: kept from the installed set
    assert (staging / "clamav/test.hdb").read_bytes() == b"clamav db\n"

    assert install_staged(tmp_path, kiosk) == 0
    folder = tmp_path / "signatures"
    assert list(staging.iterdir()) == []
    # Signed with the key of the kiosk, created for it, root only
    local = folder / "local-key"
    assert (local / "local.key").stat().st_mode & 0o777 == 0o600
    assert local_public_keys(folder) == [local / "local.pem"]
    installed = verify_installed(
        folder, trusted_keys(tmp_path / "keys") + local_public_keys(folder)
    )
    assert installed.serial == manifest.serial  # type: ignore[attr-defined]
    with pytest.raises(Exception, match="not signed by a trusted key"):
        read_set(current_set(folder), trusted_keys(tmp_path / "keys"))  # type: ignore[arg-type]
    # The kiosk trusts its own key at start
    assert check_signatures(config) is not None


def test_unchanged_sources_build_nothing(tmp_path: Path, kiosk: Path) -> None:
    config = load(kiosk)
    fake = downloader(tmp_path)
    build(tmp_path, config, downloader=fake)
    assert install_staged(tmp_path, kiosk) == 0
    serial = installed_manifest(tmp_path / "signatures").serial  # type: ignore[union-attr]
    # The same downloads a second later (the database is dated by the download)
    time.sleep(1.1)
    assert build(tmp_path, config, downloader=fake) is None
    assert install_staged(tmp_path, kiosk) == 0  # nothing staged
    assert installed_manifest(tmp_path / "signatures").serial == serial  # type: ignore[union-attr]
    # A source that changed: a new set
    assert build(tmp_path, config, downloader=downloader(tmp_path, "b" * 64)) is not None


def test_without_auth_key_malwarebazaar_is_kept(tmp_path: Path, kiosk: Path) -> None:
    config = load(kiosk)
    manifest = build(tmp_path, config, auth_key="")
    assert manifest is not None
    paths = {f.path for f in manifest.files}  # type: ignore[attr-defined]
    assert MALWAREBAZAAR_DB not in paths
    assert "clamav/test.hdb" in paths


def test_download_dispatches_to_the_sources(
    tmp_path: Path, kiosk: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = []
    monkeypatch.setattr(
        "pandora_box.online.build_from_sources",
        lambda config, staging, log: calls.append(staging),
    )
    download(load(kiosk), tmp_path / "update" / "staging", log=lambda _: None)
    assert calls == [tmp_path / "update" / "staging"]


def test_unsigned_staged_set_is_refused_without_sources(tmp_path: Path, kiosk: Path) -> None:
    # A kiosk that installs published sets never signs a staged set itself
    config = load(kiosk)
    build(tmp_path, config)
    published = tmp_path / "published.toml"
    published.write_text(kiosk.read_text().replace(f"sources = {SOURCES}", 'url = "https://x/"'))
    assert install_staged(tmp_path, published) == 1
    assert not (tmp_path / "signatures" / "local-key").exists()
    assert installed_manifest(tmp_path / "signatures").serial == 1  # type: ignore[union-attr]


def test_keep_files_only_keeps_the_other_sources(tmp_path: Path, kiosk: Path) -> None:
    staging = tmp_path / "staging"
    staging.mkdir()
    assert keep_files(tmp_path / "signatures" / "current", staging, ["yara-forge"]) == 1
    assert sorted(p.relative_to(staging).as_posix() for p in staging.rglob("*.*")) == [
        "clamav/test.hdb"
    ]


def test_mirror_over_http_needs_to_be_configured(tmp_path: Path) -> None:
    from pandora_box.publish import Downloader

    with pytest.raises(PublishError, match="not an HTTPS URL"):
        Downloader(tmp_path).open("http://mirror/x", {})
