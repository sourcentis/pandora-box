from __future__ import annotations

import dataclasses
import json
import logging
from collections.abc import Iterator
from pathlib import Path

import pytest

from pandora_box import __version__
from pandora_box.config import Config, parse_config
from pandora_box.device import ENUMERATED_AGAIN, REMOVED, UsbDevice, UsbIdentity
from pandora_box.engines import EngineError, EngineSpec
from pandora_box.kiosk import BEHAVIOR_REASONS, Kiosk, NoEngineError, build_engines, build_pool
from pandora_box.monitor import Action, DeviceEvent
from pandora_box.ui.base import Screen
from pandora_box.workers import WorkerPool

from .conftest import DirectoryMounter, ListSource, RecordingDisplay, started_pool
from .engines import MisbehavingEngine, SuspiciousEngine

DEVICE = UsbDevice("/dev/sdb1", "vfat", "KEY")


@pytest.fixture
def pool(config: Config) -> Iterator[WorkerPool]:
    with build_pool(config) as pool:
        yield pool


def make_kiosk(
    config: Config,
    display: RecordingDisplay,
    mounter: DirectoryMounter,
    events: list[DeviceEvent],
    pool: WorkerPool,
) -> Kiosk:
    return Kiosk(config, display, ListSource(events), pool, mounter)


def test_infected_device_is_cleaned(
    config: Config, display: RecordingDisplay, usb_tree: Path, tmp_path: Path, pool: WorkerPool
) -> None:
    mounter = DirectoryMounter(usb_tree)
    make_kiosk(config, display, mounter, [DeviceEvent(Action.ADD, DEVICE)], pool).run()

    assert not (usb_tree / "docs" / "eicar.com").exists()
    assert (usb_tree / "readme.txt").exists()
    assert display.confirmations == 1
    assert "Device cleaned! You can remove the device." in display.messages
    assert display.percents[-1] == 100
    assert not mounter.mounted
    # What the graphical interface shows: the files before they are removed
    assert [screen for screen, _ in display.screens] == [
        Screen.READY,
        Screen.SCANNING,
        Screen.THREATS,
        Screen.CLEANING,
        Screen.CLEANED,
    ]
    assert display.screens[2][1] == ["docs/eicar.com"]
    assert display.screens[4][1] == ["docs/eicar.com"]
    assert display.scanned[-1][1:] == (len(display.scanned), len(display.scanned))
    assert display.info[0].startswith("PandoraBox ")
    manifests = list((tmp_path / "quarantine").glob("*/manifest.json"))
    assert json.loads(manifests[0].read_text())["files"][0]["original_path"] == "docs/eicar.com"


def test_clean_device(
    config: Config, display: RecordingDisplay, tmp_path: Path, pool: WorkerPool
) -> None:
    root = tmp_path / "media"
    root.mkdir()
    (root / "file.txt").write_text("hello")
    make_kiosk(
        config, display, DirectoryMounter(root), [DeviceEvent(Action.ADD, DEVICE)], pool
    ).run()

    assert display.confirmations == 0
    assert "No infected file found. You can remove the device." in display.messages
    assert not (tmp_path / "quarantine").exists()
    assert display.screens[-1] == (Screen.CLEAN, [])


def test_device_removed_before_clean(
    config: Config, display: RecordingDisplay, usb_tree: Path, pool: WorkerPool
) -> None:
    mounter = DirectoryMounter(usb_tree)
    kiosk = make_kiosk(config, display, mounter, [DeviceEvent(Action.ADD, DEVICE)], pool)
    original_confirm = display.confirm

    def remove_device(prompt: str) -> None:
        original_confirm(prompt)
        mounter.present = False

    display.confirm = remove_device  # type: ignore[method-assign]
    kiosk.run()

    assert (usb_tree / "docs" / "eicar.com").exists()
    assert "Device removed before cleaning: NOT CLEANED" in display.messages
    assert display.screens[-1] == (Screen.NOT_CLEANED, ["docs/eicar.com"])


def test_scan_is_read_only(
    config: Config, display: RecordingDisplay, usb_tree: Path, pool: WorkerPool
) -> None:
    mounter = DirectoryMounter(usb_tree)
    modes: list[bool | None] = []
    original_progress = display.progress

    def record(percent: int) -> None:
        modes.append(mounter.read_only)
        original_progress(percent)

    display.progress = record  # type: ignore[method-assign]
    make_kiosk(config, display, mounter, [DeviceEvent(Action.ADD, DEVICE)], pool).run()
    assert modes and all(modes)
    assert mounter.read_only is False  # remounted read-write to clean


def test_rejected_filesystem(
    config: Config, display: RecordingDisplay, tmp_path: Path, pool: WorkerPool
) -> None:
    from pandora_box.device import Mounter

    (tmp_path / "media").mkdir()
    mounter = Mounter(tmp_path / "media", ["vfat"])
    event = DeviceEvent(Action.ADD, UsbDevice("/dev/sdb1", "ntfs"))
    Kiosk(config, display, ListSource([event]), pool, mounter).run()
    assert "Cannot mount device: filesystem not allowed: ntfs" in display.messages
    assert "Error: please remove the device." in display.messages
    assert display.screens[-1] == (Screen.ERROR, [])


def test_device_removed(
    config: Config, display: RecordingDisplay, tmp_path: Path, pool: WorkerPool
) -> None:
    mounter = DirectoryMounter(tmp_path)
    make_kiosk(config, display, mounter, [DeviceEvent(Action.REMOVE, DEVICE)], pool).run()
    assert display.devices == [None]
    assert "Device removed" in display.messages
    assert display.screens[-1] == (Screen.READY, [])


def test_fake_scan_banner(
    config: Config, display: RecordingDisplay, tmp_path: Path, pool: WorkerPool
) -> None:
    make_kiosk(config, display, DirectoryMounter(tmp_path), [], pool).run()
    # The versions first, then the banner
    assert display.messages[0] == f"PandoraBox {__version__} (development)"
    assert display.messages[1] == "Signatures: none installed"
    assert display.messages[2] == "Engines: fake (fake)"
    assert display.messages[3].startswith("FAKE SCAN MODE")


def test_no_engine_without_fake_scan() -> None:
    with pytest.raises(EngineError):
        build_engines(parse_config({"kiosk": {"fake_scan": False}}))
    engines = {
        name: {"enabled": False} for name in ("malwarebazaar", "hashlookup", "clamav", "yara")
    }
    with pytest.raises(NoEngineError):
        build_engines(parse_config({"engines": engines}))


def run_with_policy(policy: str, config: Config, display: RecordingDisplay, root: Path) -> None:
    config = dataclasses.replace(config, scan=dataclasses.replace(config.scan, suspicious=policy))
    source = ListSource([DeviceEvent(Action.ADD, DEVICE)])
    with started_pool([EngineSpec("fake", SuspiciousEngine)]) as pool:
        Kiosk(config, display, source, pool, DirectoryMounter(root)).run()


def test_suspicious_block(
    config: Config, display: RecordingDisplay, usb_tree: Path, tmp_path: Path
) -> None:
    (usb_tree / "macro.suspect").write_text("x")
    run_with_policy("block", config, display, usb_tree)

    assert not (usb_tree / "macro.suspect").exists()
    assert not (usb_tree / "docs" / "eicar.com").exists()
    assert "2 infected files detected:" in display.messages
    manifest = next((tmp_path / "quarantine").glob("*/manifest.json"))
    quarantined = {e["original_path"] for e in json.loads(manifest.read_text())["files"]}
    assert quarantined == {"docs/eicar.com", "macro.suspect"}


def test_suspicious_warn(
    config: Config, display: RecordingDisplay, usb_tree: Path, tmp_path: Path
) -> None:
    (usb_tree / "macro.suspect").write_text("x")
    run_with_policy("warn", config, display, usb_tree)

    assert (usb_tree / "macro.suspect").exists()
    assert not (usb_tree / "docs" / "eicar.com").exists()
    assert "WARNING: 1 suspicious files, use with caution:" in display.messages
    assert "macro.suspect" in display.messages
    assert "1 infected files detected:" in display.messages
    # Cleaned, but the suspicious file is kept: a warning
    assert display.screens[-1] == (Screen.WARNING, ["macro.suspect"])
    manifest = next((tmp_path / "quarantine").glob("*/manifest.json"))
    quarantined = {e["original_path"] for e in json.loads(manifest.read_text())["files"]}
    assert quarantined == {"docs/eicar.com"}


def test_suspicious_warn_only(config: Config, display: RecordingDisplay, tmp_path: Path) -> None:
    root = tmp_path / "media"
    root.mkdir()
    (root / "macro.suspect").write_text("x")
    run_with_policy("warn", config, display, root)

    assert (root / "macro.suspect").exists()
    assert display.confirmations == 0
    assert "WARNING: 1 suspicious files, use with caution:" in display.messages
    assert "No infected file found. You can remove the device." in display.messages
    assert display.screens[-1] == (Screen.WARNING, ["macro.suspect"])


def run_with_errors(on_error: str, config: Config, display: RecordingDisplay, root: Path) -> None:
    config = dataclasses.replace(config, scan=dataclasses.replace(config.scan, on_error=on_error))
    source = ListSource([DeviceEvent(Action.ADD, DEVICE)])
    specs = [
        EngineSpec("fake", SuspiciousEngine),
        EngineSpec("m", MisbehavingEngine, ("raise", "bad-")),
    ]
    with started_pool(specs) as pool:
        Kiosk(config, display, source, pool, DirectoryMounter(root)).run()


def test_on_error_block(config: Config, display: RecordingDisplay, tmp_path: Path) -> None:
    root = tmp_path / "media"
    root.mkdir()
    (root / "bad-file.txt").write_text("x")
    (root / "good.txt").write_text("x")
    run_with_errors("block", config, display, root)

    # The unscanned file is reported, never removed, and the device is rejected
    assert (root / "bad-file.txt").exists()
    assert "1 files could not be fully scanned:" in display.messages
    assert "bad-file.txt" in display.messages
    assert display.messages[-1] == "DEVICE NOT VERIFIED: do not use it. Remove the device."
    assert display.confirmations == 0
    assert display.screens[-1] == (Screen.NOT_VERIFIED, ["bad-file.txt"])


def test_on_error_block_with_infected_file(
    config: Config, display: RecordingDisplay, usb_tree: Path
) -> None:
    (usb_tree / "bad-file.txt").write_text("x")
    run_with_errors("block", config, display, usb_tree)
    assert not (usb_tree / "docs" / "eicar.com").exists()
    assert (usb_tree / "bad-file.txt").exists()
    assert display.messages[-1] == (
        "Device cleaned, but NOT VERIFIED: do not use it. Remove the device."
    )
    assert display.screens[-1] == (Screen.NOT_VERIFIED, ["bad-file.txt"])


def test_on_error_warn(config: Config, display: RecordingDisplay, tmp_path: Path) -> None:
    root = tmp_path / "media"
    root.mkdir()
    (root / "bad-file.txt").write_text("x")
    run_with_errors("warn", config, display, root)
    assert "WARNING: 1 files could not be fully scanned, use with caution:" in display.messages
    assert display.messages[-1] == "No infected file found. You can remove the device."


def test_limit_overrun_is_not_verified(
    config: Config, display: RecordingDisplay, tmp_path: Path, pool: WorkerPool
) -> None:
    root = tmp_path / "media"
    root.mkdir()
    (root / "big.iso").write_bytes(b"x" * 100)
    config = dataclasses.replace(
        config, limits=dataclasses.replace(config.limits, max_file_size=10)
    )
    make_kiosk(
        config, display, DirectoryMounter(root), [DeviceEvent(Action.ADD, DEVICE)], pool
    ).run()
    assert "1 files could not be fully scanned:" in display.messages
    assert display.messages[-1] == "DEVICE NOT VERIFIED: do not use it. Remove the device."


class FailingDriverMounter(DirectoryMounter):
    """The filesystem driver stops during the scan: some files are missing."""

    @property
    def failure(self) -> str | None:
        return "ntfs-3g stopped (exit status 139)"


def test_stopped_filesystem_driver_is_not_verified(
    config: Config, display: RecordingDisplay, tmp_path: Path, pool: WorkerPool
) -> None:
    root = tmp_path / "media"
    root.mkdir()
    (root / "file.txt").write_text("hello")
    make_kiosk(
        config, display, FailingDriverMounter(root), [DeviceEvent(Action.ADD, DEVICE)], pool
    ).run()
    assert "Cannot read device: ntfs-3g stopped (exit status 139)" in display.messages
    assert "Not scanned: filesystem driver: ntfs-3g stopped (exit status 139)" in display.messages
    assert display.messages[-1] == "DEVICE NOT VERIFIED: do not use it. Remove the device."


def test_progress_messages(
    config: Config, display: RecordingDisplay, usb_tree: Path, pool: WorkerPool
) -> None:
    make_kiosk(
        config, display, DirectoryMounter(usb_tree), [DeviceEvent(Action.ADD, DEVICE)], pool
    ).run()
    progress = [m for m in display.messages if m.startswith("[")]
    assert [m.split("]")[0] for m in progress] == ["[1/3", "[2/3", "[3/3"]


def test_stale_signatures(config: Config) -> None:
    from datetime import UTC, datetime

    from pandora_box.engines import EngineKind, SignatureInfo
    from pandora_box.kiosk import stale_signatures
    from pandora_box.workers import EngineInfo

    old = SignatureInfo("daily", "1", datetime(2020, 1, 1, tzinfo=UTC))
    new = SignatureInfo("daily", "2", datetime.now(UTC))
    engines = [
        EngineInfo("clamav", EngineKind.CONTENT, "ClamAV", 60.0, (old,)),
        EngineInfo("yara", EngineKind.CONTENT, "YARA-X", 60.0, (new,)),
        EngineInfo("hashlookup", EngineKind.HASH, "", 10.0, (SignatureInfo("bloom"),)),
        EngineInfo("fake", EngineKind.CONTENT, "", 1.0, (old,)),
    ]
    warnings, undated = stale_signatures(config, engines)
    assert len(warnings) == 1
    assert warnings[0].startswith("clamav: signatures daily are old (")
    assert warnings[0].endswith(" days)")
    # Without a date: logged, not shown
    assert undated == ["hashlookup: bloom"]


def test_auto_mount(
    config: Config,
    display: RecordingDisplay,
    usb_tree: Path,
    pool: WorkerPool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import subprocess

    commands: list[str] = []
    from pandora_box.device import SystemMountWatcher

    config = dataclasses.replace(config, device=dataclasses.replace(config.device, auto_mount=True))
    # The device node must exist: the kiosk checks it before cleaning
    node = usb_tree.parent / "sdb1"
    node.touch()
    mounts = usb_tree.parent / "mounts"
    mounted = f"{node} {usb_tree} vfat rw,nosuid,nodev 0 0\n"
    mounts.write_text(mounted)

    def udisksctl(argv: list[str], **kwargs: object) -> None:
        # Simulate udisks: update the mount table
        commands.append(argv[1])
        mounts.write_text("" if argv[1] == "unmount" else mounted)

    monkeypatch.setattr(subprocess, "run", udisksctl)
    watcher = SystemMountWatcher(["vfat"], mounts=mounts)
    source = ListSource([DeviceEvent(Action.ADD, UsbDevice(str(node), "vfat", "KEY"))])
    Kiosk(config, display, source, pool, watcher).run()
    assert display.messages[4].startswith("AUTO-MOUNT MODE")
    assert not (usb_tree / "docs" / "eicar.com").exists()
    assert "Device cleaned! You can remove the device." in display.messages
    # Unmounted before the confirmation, mounted again to clean, unmounted, ejected
    assert commands == ["unmount", "mount", "unmount", "power-off"]


def test_unmounted_while_waiting_for_the_user(
    config: Config, display: RecordingDisplay, usb_tree: Path, pool: WorkerPool
) -> None:
    mounter = DirectoryMounter(usb_tree)
    states: list[tuple[bool, bool | None]] = []
    original_confirm = display.confirm

    def record(prompt: str) -> None:
        states.append((mounter.mounted, mounter.read_only))
        original_confirm(prompt)

    display.confirm = record  # type: ignore[method-assign]
    make_kiosk(config, display, mounter, [DeviceEvent(Action.ADD, DEVICE)], pool).run()
    # Not mounted during the confirmation, then mounted read-write to clean
    assert states == [(False, True)]
    assert mounter.read_only is False
    assert not mounter.mounted
    assert not (usb_tree / "docs" / "eicar.com").exists()


def test_file_changed_before_clean(
    config: Config, display: RecordingDisplay, usb_tree: Path, pool: WorkerPool
) -> None:
    mounter = DirectoryMounter(usb_tree)
    original_confirm = display.confirm

    def swap_device(prompt: str) -> None:
        original_confirm(prompt)
        # Another device with a file at the same path is inserted
        (usb_tree / "docs" / "eicar.com").write_text("someone else's document")

    display.confirm = swap_device  # type: ignore[method-assign]
    make_kiosk(config, display, mounter, [DeviceEvent(Action.ADD, DEVICE)], pool).run()
    assert (usb_tree / "docs" / "eicar.com").read_text() == "someone else's document"
    assert "Not removed, changed since the scan: docs/eicar.com" in display.messages
    assert "Device NOT cleaned: 1 files remain" in display.messages


def test_eject_after_clean(
    config: Config, display: RecordingDisplay, usb_tree: Path, pool: WorkerPool
) -> None:
    mounter = DirectoryMounter(usb_tree)
    ejected_at_confirm: list[list[str]] = []
    original_confirm = display.confirm

    def confirm(prompt: str) -> None:
        ejected_at_confirm.append(list(mounter.ejected))
        original_confirm(prompt)

    display.confirm = confirm  # type: ignore[method-assign]
    make_kiosk(config, display, mounter, [DeviceEvent(Action.ADD, DEVICE)], pool).run()
    # Only unmounted while asking (it must be mounted again), ejected at the end
    assert ejected_at_confirm == [[]]
    assert mounter.ejected == ["/dev/sdb1"]


def test_eject_clean_device(
    config: Config, display: RecordingDisplay, tmp_path: Path, pool: WorkerPool
) -> None:
    root = tmp_path / "media"
    root.mkdir()
    (root / "file.txt").write_text("hello")
    mounter = DirectoryMounter(root)
    make_kiosk(config, display, mounter, [DeviceEvent(Action.ADD, DEVICE)], pool).run()
    assert mounter.ejected == ["/dev/sdb1"]


def test_no_eject(
    config: Config, display: RecordingDisplay, usb_tree: Path, pool: WorkerPool
) -> None:
    config = dataclasses.replace(config, device=dataclasses.replace(config.device, eject=False))
    mounter = DirectoryMounter(usb_tree)
    make_kiosk(config, display, mounter, [DeviceEvent(Action.ADD, DEVICE)], pool).run()
    assert mounter.ejected == []


def test_device_removed_is_not_ejected(
    config: Config, display: RecordingDisplay, usb_tree: Path, pool: WorkerPool
) -> None:
    mounter = DirectoryMounter(usb_tree)
    original_confirm = display.confirm

    def remove_device(prompt: str) -> None:
        original_confirm(prompt)
        mounter.present = False

    display.confirm = remove_device  # type: ignore[method-assign]
    make_kiosk(config, display, mounter, [DeviceEvent(Action.ADD, DEVICE)], pool).run()
    assert "Device removed before cleaning: NOT CLEANED" in display.messages
    assert mounter.ejected == []


def test_describe_engines() -> None:
    from pandora_box.engines import EngineKind
    from pandora_box.kiosk import describe_engines
    from pandora_box.workers import EngineInfo

    engines = [
        EngineInfo("malwarebazaar", EngineKind.HASH, "1", 10.0),
        EngineInfo("hashlookup", EngineKind.HASH, "DCSO bloom v1", 10.0),
        EngineInfo("clamav", EngineKind.CONTENT, "ClamAV 1.4.3", 60.0),
        EngineInfo("yara", EngineKind.CONTENT, "YARA-X 1.21.0", 60.0),
        EngineInfo("heuristics", EngineKind.CONTENT, "1", 60.0),
    ]
    assert describe_engines(engines) == (
        "malwarebazaar, hashlookup, clamav (ClamAV 1.4.3), yara (YARA-X 1.21.0), heuristics"
    )
    assert describe_engines([]) == "none loaded (no valid signatures)"


def test_device_verdict_sums_up_the_scan(
    config: Config,
    display: RecordingDisplay,
    usb_tree: Path,
    pool: WorkerPool,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """One event per key for the dashboards of a SIEM, tied to the other events by report_id."""
    with caplog.at_level(logging.INFO, logger="pandora_box"):
        make_kiosk(config, display, DirectoryMounter(usb_tree), [DeviceEvent(Action.ADD, DEVICE)],
                   pool).run()  # fmt: skip
    events = {r.getMessage(): getattr(r, "fields", {}) for r in caplog.records}
    verdict = events["device_verdict"]
    report = json.loads(next((config.report.folder).glob("*.json")).read_text())
    assert verdict["report_id"] == report["report_id"]
    assert verdict["verdict"] == "malicious" and verdict["complete"] is True
    assert (verdict["files"], verdict["infected"], verdict["suspicious"]) == (3, 1, 0)
    assert verdict["not_scanned"] == 0 and verdict["duration"] >= 0 and verdict["used"] > 0
    assert len(verdict["detections"]) == 1 and verdict["detections"][0].startswith("fake: ")
    # No name of a file in the summary
    assert "eicar.com" not in json.dumps(verdict)
    assert events["device_cleaned"]["report_id"] == report["report_id"]


class ChangingKeyMounter(DirectoryMounter):
    """A key on USB that leaves, or comes back as another device, during its scan."""

    def __init__(self, mount_point: Path, behavior: str, after: int) -> None:
        super().__init__(mount_point)
        self.behavior = behavior
        # Checks before the key changes
        self.after = after
        self.checks = 0

    def usb_identity(self, device: UsbDevice) -> UsbIdentity | None:
        return UsbIdentity("devices/pci0000:00/usb1/1-2", 1, 7)

    def identity_change(self, device: UsbDevice, before: UsbIdentity) -> str | None:
        self.checks += 1
        if self.checks <= self.after:
            return None
        if self.behavior == REMOVED:
            self.present = False
        return self.behavior


@pytest.mark.parametrize("behavior", [REMOVED, ENUMERATED_AGAIN])
def test_key_changed_during_the_scan(
    config: Config,
    display: RecordingDisplay,
    usb_tree: Path,
    pool: WorkerPool,
    caplog: pytest.LogCaptureFixture,
    behavior: str,
) -> None:
    """A suspicious behavior: not verified, neither cleaned nor quarantined, reported."""
    # Unchanged at the start of the scan, changed once it is done
    mounter = ChangingKeyMounter(usb_tree, behavior, after=1)
    with caplog.at_level(logging.INFO, logger="pandora_box"):
        make_kiosk(config, display, mounter, [DeviceEvent(Action.ADD, DEVICE)], pool).run()
    events = {r.getMessage(): getattr(r, "fields", {}) for r in caplog.records}
    assert events["device_suspicious_behavior"]["behavior"] == behavior
    assert events["device_suspicious_behavior"]["devnum"] == 7
    verdict = events["device_verdict"]
    # The EICAR file is still found, the key is not verified all the same
    assert verdict["verdict"] == "malicious" and verdict["complete"] is False
    assert verdict["suspicious_behaviors"] == [behavior]
    report = json.loads(next(config.report.folder.glob("*.json")).read_text())
    assert report["verdict"]["suspicious_behaviors"] == [behavior]
    assert report["verdict"]["incomplete_reasons"] == [BEHAVIOR_REASONS[behavior]]
    # Never cleaned, nothing quarantined
    assert (usb_tree / "docs" / "eicar.com").exists()
    assert display.confirmations == 0
    assert "device_cleaned" not in events
    assert not (config.quarantine.folder).exists()
    assert display.screens[-1][0] is Screen.KEY_CHANGED
    assert f"SUSPICIOUS: {BEHAVIOR_REASONS[behavior]}" in display.messages
    assert "SUSPICIOUS DEVICE, NOT VERIFIED: do not use it. Remove the device." in display.messages


def test_key_changed_before_its_partition(
    config: Config, display: RecordingDisplay, usb_tree: Path, pool: WorkerPool
) -> None:
    # Changed before the scan of its first partition: not scanned, a verdict all the same
    mounter = ChangingKeyMounter(usb_tree, ENUMERATED_AGAIN, after=0)
    make_kiosk(config, display, mounter, [DeviceEvent(Action.ADD, DEVICE)], pool).run()
    report = json.loads(next(config.report.folder.glob("*.json")).read_text())
    assert report["verdict"]["device"] == "not_verified"
    assert report["verdict"]["statistics"]["files"] == 0
    assert display.screens[-1][0] is Screen.KEY_CHANGED


def test_key_not_on_usb_is_not_checked(
    config: Config, display: RecordingDisplay, usb_tree: Path, pool: WorkerPool
) -> None:
    # DirectoryMounter: a directory, not a USB device
    make_kiosk(
        config, display, DirectoryMounter(usb_tree), [DeviceEvent(Action.ADD, DEVICE)], pool
    ).run()
    report = json.loads(next(config.report.folder.glob("*.json")).read_text())
    assert report["verdict"]["suspicious_behaviors"] == []


KEYBOARD = UsbDevice("/devices/pci0000:00/usb1/1-2", model="USB Keyboard", vendor="046d:c31c")


def test_refused_device_is_explained(
    config: Config, display: RecordingDisplay, tmp_path: Path, pool: WorkerPool
) -> None:
    events = [
        DeviceEvent(Action.REFUSED, KEYBOARD),
        DeviceEvent(Action.REFUSED_REMOVED, UsbDevice(KEYBOARD.node)),
        DeviceEvent(Action.REFUSED, KEYBOARD, composite=True),
    ]
    make_kiosk(config, display, DirectoryMounter(tmp_path), events, pool).run()
    assert [screen for screen, _ in display.screens] == [
        Screen.READY,
        Screen.REFUSED,
        Screen.READY,
        Screen.REFUSED_COMPOSITE,
    ]
    assert "USB device refused: USB Keyboard 046d:c31c" in display.messages
    assert "USB key that is also another device refused: USB Keyboard 046d:c31c" in display.messages
    assert display.devices[0] == KEYBOARD


def test_refused_device_with_a_key(
    config: Config, display: RecordingDisplay, tmp_path: Path, pool: WorkerPool
) -> None:
    # A key is inserted: its screen stays, the refusal is only a message
    (tmp_path / "media").mkdir()
    (tmp_path / "media" / "file.txt").write_text("hello")
    events = [
        DeviceEvent(Action.ADD, DEVICE),
        DeviceEvent(Action.REFUSED, KEYBOARD),
        DeviceEvent(Action.REFUSED_REMOVED, UsbDevice(KEYBOARD.node)),
    ]
    make_kiosk(config, display, DirectoryMounter(tmp_path / "media"), events, pool).run()
    assert display.screens[-1] == (Screen.CLEAN, [])
    assert "USB device refused: USB Keyboard 046d:c31c" in display.messages
