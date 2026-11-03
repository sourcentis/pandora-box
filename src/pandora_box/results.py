"""Results of a device scan."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from pandora_box.engines import EngineResult, FileInfo, Verdict


@dataclass(frozen=True)
class FileResult:
    path: Path
    size: int
    verdict: Verdict
    results: tuple[EngineResult, ...] = ()
    # Skip reason or error message
    detail: str = ""
    duration: float = 0.0
    info: FileInfo | None = None
    rel_path: str = ""
    # The file was not fully scanned (a limit was exceeded)
    incomplete: bool = False
    # Partition of a key with several ones (its kernel name, "sdb2"); rel_path
    # is relative to its root
    volume: str = ""

    @property
    def display_path(self) -> str:
        """The path shown to the user: with its partition on a multi-partition key."""
        return f"{self.volume}/{self.rel_path}" if self.volume else self.rel_path

    @property
    def unscanned(self) -> bool:
        """The file was not fully scanned: it can never be considered clean."""
        return self.incomplete or self.verdict is Verdict.ERROR


@dataclass
class ScanSummary:
    files: list[FileResult] = field(default_factory=list)
    duration: float = 0.0
    # Why the device was not fully scanned (limits, unreadable folders)
    incomplete_reasons: list[str] = field(default_factory=list)
    # Suspicious behaviors of the key during the scan ("removed",
    # "enumerated_again"): its content cannot be trusted, each one is also
    # an incomplete reason
    behaviors: list[str] = field(default_factory=list)

    @property
    def infected(self) -> list[FileResult]:
        return [f for f in self.files if f.verdict is Verdict.MALICIOUS]

    @property
    def suspicious(self) -> list[FileResult]:
        return [f for f in self.files if f.verdict is Verdict.SUSPICIOUS]

    @property
    def unscanned(self) -> list[FileResult]:
        return [f for f in self.files if f.unscanned]

    @property
    def complete(self) -> bool:
        return not self.incomplete_reasons and not self.unscanned

    def count(self, verdict: Verdict) -> int:
        return sum(1 for f in self.files if f.verdict is verdict)
