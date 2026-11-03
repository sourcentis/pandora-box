"""Following a log file another program appends to, across its rotations.

Used by the SIEM export (the log of the kiosk) and by the kiosk (the audit
log of USBGuard). The position of the last line read is saved by the
reader, so that a restart goes on where it stopped.
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO


@dataclass(frozen=True)
class Position:
    """End of the last line read, in the log file of this inode."""

    inode: int
    offset: int


def load_position(path: Path) -> Position | None:
    try:
        data = json.loads(path.read_text())
        return Position(int(data["inode"]), int(data["offset"]))
    except (OSError, ValueError, KeyError, TypeError):
        return None


def save_position(path: Path, position: Position) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps({"inode": position.inode, "offset": position.offset}))
    temporary.replace(path)


def _open(path: Path) -> BinaryIO | None:
    try:
        return path.open("rb")
    except FileNotFoundError:
        return None


def _stderr(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


class LogFollower:
    """The complete lines of a log file, also across its rotations by logrotate.

    warn: called when the file of the saved position is gone.
    """

    def __init__(
        self, path: Path, position: Position | None, warn: Callable[[str], None] = _stderr
    ) -> None:
        self.path = path
        self.file: BinaryIO | None = None
        if position is not None:
            # The file of the saved position: the log file, or the one
            # logrotate moved (delaycompress: not compressed yet)
            for candidate in (path, path.with_name(path.name + ".1")):
                file = _open(candidate)
                if file is None:
                    continue
                stat = os.fstat(file.fileno())
                if stat.st_ino == position.inode:
                    file.seek(position.offset if position.offset <= stat.st_size else 0)
                    self.file = file
                    return
                file.close()
            warn(f"the log file of the last line read is gone: {path} is read from its start")
        self.file = _open(path)

    def close(self) -> None:
        if self.file is not None:
            self.file.close()
            self.file = None

    def position(self) -> Position | None:
        if self.file is None:
            return None
        return Position(os.fstat(self.file.fileno()).st_ino, self.file.tell())

    def read(self, limit: int) -> list[bytes]:
        """Up to limit complete lines, without their line break."""
        if self.file is None:
            self.file = _open(self.path)
            if self.file is None:
                return []
        lines: list[bytes] = []
        while len(lines) < limit:
            start = self.file.tell()
            line = self.file.readline()
            if not line.endswith(b"\n"):
                # The end of the file, or a line still being written
                self.file.seek(start)
                break
            lines.append(line[:-1])
        if not lines and self._replaced(self.file):
            # At the end of a file logrotate moved: go on with the new one
            self.close()
            return self.read(limit)
        return lines

    def _replaced(self, file: BinaryIO) -> bool:
        current = os.fstat(file.fileno())
        try:
            stat = self.path.stat()
        except FileNotFoundError:
            # Moved, the new one is not created yet
            return False
        if stat.st_ino != current.st_ino:
            return True
        if stat.st_size < file.tell():
            # Truncated: from its start again
            file.seek(0)
        return False
