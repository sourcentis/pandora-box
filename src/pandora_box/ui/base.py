"""Interface between the kiosk state machine and its display."""

from __future__ import annotations

import re
from collections.abc import Sequence
from enum import StrEnum
from typing import Protocol

from pandora_box.device import UsbDevice
from pandora_box.results import FileResult

# Mode of the screen on the kernel command line, e.g. video=1024x600M@60 or
# video=HDMI-A-1:1024x600
_VIDEO = re.compile(r"(?:^|\s)video=(?:[\w-]+:)?(\d+)x(\d+)")


def video_mode(cmdline: str) -> tuple[int, int] | None:
    """Width and height in pixels of the screen set on the kernel command line."""
    match = _VIDEO.search(cmdline)
    if match is None:
        return None
    return int(match[1]), int(match[2])


class Screen(StrEnum):
    """What the kiosk is doing, for the graphical interface."""

    # Waiting for a device
    READY = "ready"
    # No valid signatures: only a signature update device is accepted
    UNAVAILABLE = "unavailable"
    SCANNING = "scanning"
    # Files to remove are listed: a touch starts the cleaning
    THREATS = "threats"
    CLEANING = "cleaning"
    # Results, shown until the device is removed
    CLEAN = "clean"
    # Clean, but suspicious or unscanned files are kept (warn policies)
    WARNING = "warning"
    CLEANED = "cleaned"
    NOT_CLEANED = "not_cleaned"
    NOT_VERIFIED = "not_verified"
    # The key was removed or enumerated again during its scan: not verified
    KEY_CHANGED = "key_changed"
    ERROR = "error"
    # A device refused by USBGuard: not a USB key, or a key that is also
    # another device (a keyboard)
    REFUSED = "refused"
    REFUSED_COMPOSITE = "refused_composite"
    # Maintenance, signature or image update device
    SERVICE = "service"
    # airgap: the clean files of the key are copied to a server
    TRANSFERRING = "transferring"
    TRANSFERRED = "transferred"
    TRANSFER_FAILED = "transfer_failed"


# Screens of a scan result: kept for a while after the device is removed
RESULT_SCREENS = frozenset(
    {
        Screen.CLEAN,
        Screen.WARNING,
        Screen.CLEANED,
        Screen.NOT_CLEANED,
        Screen.NOT_VERIFIED,
        Screen.KEY_CHANGED,
        Screen.ERROR,
        Screen.REFUSED,
        Screen.REFUSED_COMPOSITE,
        Screen.SERVICE,
        Screen.TRANSFERRED,
        Screen.TRANSFER_FAILED,
    }
)


class Display(Protocol):
    """All methods are called from the main thread."""

    def start(self) -> None: ...

    def stop(self) -> None: ...

    def message(self, text: str) -> None:
        """Append a line to the message log."""
        ...

    def show(self, screen: Screen, files: Sequence[FileResult] = ()) -> None:
        """Show what the kiosk does, with the files of a result (text displays
        already get it from the messages)."""
        ...

    def show_info(self, lines: Sequence[str]) -> None:
        """Version of the kiosk and of its signatures, shown while waiting."""
        ...

    def show_device(self, device: UsbDevice | None) -> None:
        """Show the inserted device, or clear the device panel."""
        ...

    def show_usage(self, size: int, used: int) -> None: ...

    def progress(self, percent: int) -> None: ...

    def file_scanned(self, result: FileResult, done: int, total: int) -> None:
        """A file was scanned: done files out of total."""
        ...

    def confirm(self, prompt: str) -> None:
        """Wait for the user to acknowledge (key press or touch)."""
        ...
