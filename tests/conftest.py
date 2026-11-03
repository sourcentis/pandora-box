from __future__ import annotations

from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from pandora_box.config import Config, parse_config
from pandora_box.device import Mounter, UsbDevice, UsbIdentity
from pandora_box.engines import EngineSpec, FakeEngine
from pandora_box.engines.fake import EICAR
from pandora_box.monitor import DeviceEvent
from pandora_box.pipeline import PipelineOptions
from pandora_box.results import FileResult
from pandora_box.ui.base import Screen
from pandora_box.workers import WorkerPool


@dataclass
class RecordingDisplay:
    """Display that records everything and confirms immediately."""

    messages: list[str] = field(default_factory=list)
    devices: list[UsbDevice | None] = field(default_factory=list)
    percents: list[int] = field(default_factory=list)
    confirmations: int = 0
    screens: list[tuple[Screen, list[str]]] = field(default_factory=list)
    info: list[str] = field(default_factory=list)
    scanned: list[tuple[str, int, int]] = field(default_factory=list)

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass

    def message(self, text: str) -> None:
        self.messages.append(text)

    def show(self, screen: Screen, files: Sequence[FileResult] = ()) -> None:
        self.screens.append((screen, [f.display_path for f in files]))

    def show_info(self, lines: Sequence[str]) -> None:
        self.info = list(lines)

    def file_scanned(self, result: FileResult, done: int, total: int) -> None:
        self.scanned.append((result.rel_path, done, total))

    def show_device(self, device: UsbDevice | None) -> None:
        self.devices.append(device)

    def show_usage(self, size: int, used: int) -> None:
        pass

    def progress(self, percent: int) -> None:
        self.percents.append(percent)

    def confirm(self, prompt: str) -> None:
        self.confirmations += 1
        self.messages.append(prompt)


class ListSource:
    """Device source replaying a fixed list of events, then stopping."""

    def __init__(self, events: list[DeviceEvent]) -> None:
        self.events = list(events)

    def wait_event(self) -> DeviceEvent | None:
        return self.events.pop(0) if self.events else None


class DirectoryMounter(Mounter):
    """Mounter that 'mounts' a directory already populated by the test."""

    def __init__(self, mount_point: Path) -> None:
        super().__init__(mount_point, ["vfat"])
        self.mounted = False
        self.read_only: bool | None = None
        self.present = True
        self.ejected: list[str] = []

    def mount(self, device: UsbDevice, read_only: bool = True) -> None:
        self.device = device
        self.mounted = True
        self.read_only = read_only

    def unmount(self) -> None:
        self.mounted = False
        self.device = None

    def is_mounted(self) -> bool:
        return self.mounted

    def device_present(self, device: UsbDevice) -> bool:
        return self.present

    def usb_identity(self, device: UsbDevice) -> UsbIdentity | None:
        # A directory, not a USB device
        return None

    def eject(self, device: UsbDevice) -> None:
        assert not self.mounted, "ejected while mounted"
        if self.present:
            self.ejected.append(device.node)


@contextmanager
def started_pool(
    specs: list[EngineSpec],
    workers: int = 2,
    file_timeout: float = 60.0,
    options: PipelineOptions | None = None,
    engine_grace: float = 0.5,
) -> Iterator[WorkerPool]:
    pool = WorkerPool(
        specs, options or PipelineOptions(), workers, file_timeout, engine_grace=engine_grace
    )
    pool.start()
    try:
        yield pool
    finally:
        pool.stop()


FAKE = [EngineSpec("fake", FakeEngine)]


@pytest.fixture
def fake_pool() -> Iterator[WorkerPool]:
    with started_pool(FAKE) as pool:
        yield pool


@pytest.fixture
def display() -> RecordingDisplay:
    return RecordingDisplay()


@pytest.fixture
def config(tmp_path: Path) -> Config:
    return parse_config(
        {
            "kiosk": {"name": "test", "fake_scan": True, "interface": "console"},
            "device": {"mount_point": str(tmp_path / "media")},
            # Sandboxed workers need root: see tests/e2e and the image tests
            "scan": {"workers": 2, "sandbox": False},
            "quarantine": {"folder": str(tmp_path / "quarantine")},
            "report": {"folder": str(tmp_path / "reports")},
            "signatures": {
                "folder": str(tmp_path / "signatures"),
                "keys": str(tmp_path / "keys"),
            },
            "logging": {"file": ""},
        }
    )


@pytest.fixture
def usb_tree(tmp_path: Path) -> Path:
    """A fake device content: two clean files and an EICAR file in a sub folder."""
    root = tmp_path / "media"
    (root / "docs").mkdir(parents=True)
    (root / "readme.txt").write_text("hello")
    (root / "docs" / "report.pdf").write_bytes(b"%PDF-1.4 harmless")
    (root / "docs" / "eicar.com").write_bytes(EICAR)
    return root
