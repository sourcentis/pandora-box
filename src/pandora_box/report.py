"""JSON scan report: one per scanned device, for audit.

The report is written after the scan, then updated after cleaning with the
actions taken. Its format is described by the JSON Schema
schemas/scan-report-v1.schema.json (SCHEMA_VERSION). File names and device
strings are untrusted: they are escaped (text.escape), and the exact bytes of
each path are kept in base64.
"""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path
from typing import Any

from pandora_box import __version__
from pandora_box.config import Config
from pandora_box.device import UsbDevice
from pandora_box.engines import EngineResult, SignatureInfo
from pandora_box.policy import device_verdict
from pandora_box.results import FileResult, ScanSummary
from pandora_box.text import escape, path_b64
from pandora_box.workers import EngineInfo

SCHEMA_VERSION = 1
SCHEMA_FILE = "scan-report-v1.schema.json"


def load_schema() -> dict[str, Any]:
    text = resources.files("pandora_box").joinpath("schemas", SCHEMA_FILE).read_text("utf-8")
    schema: dict[str, Any] = json.loads(text)
    return schema


@dataclass
class ScanReport:
    """A scan report and the file it is written to."""

    data: dict[str, Any]
    path: Path | None = None

    @property
    def report_id(self) -> str:
        return str(self.data["report_id"])


@dataclass(frozen=True)
class PartitionUsage:
    """A partition of a key with several ones: scanned, or why not."""

    node: str
    fs_type: str
    label: str
    size: int
    used: int
    # Why it was not scanned; "" when it was
    not_scanned: str = ""


@dataclass
class DeviceUsage:
    size: int = 0
    used: int = 0
    # Several partitions: each of them
    partitions: list[PartitionUsage] = field(default_factory=list)


@dataclass
class AirgapAction:
    """The copy of the clean files of the key to a server (airgap)."""

    # "copied", "failed", "refused" (key not verified) or "skipped"
    # (airgap.mode outbound: no copy to the server)
    status: str
    key_id: str = ""
    destination: str = ""
    copied: int = 0
    deleted: int = 0
    unchanged: int = 0
    # Files of the key that are not clean: never copied
    not_copied: list[FileResult] = field(default_factory=list)
    # Clean files that could not be copied, and why
    errors: list[tuple[str, str]] = field(default_factory=list)
    error: str = ""
    # The files of the server copied to the key (airgap.mode outbound or
    # both); None: not attempted
    outbound: OutboundAction | None = None


@dataclass
class OutboundAction:
    """The files waiting on the server for the key, copied to it."""

    # "copied", "nothing" (no new file), "refused" (dangerous files on the
    # key) or "failed"
    status: str
    copied: list[str] = field(default_factory=list)
    unchanged: int = 0
    # Files of the server not copied (dangerous, refused by the key), and why
    rejected: list[tuple[str, str]] = field(default_factory=list)
    error: str = ""


@dataclass
class Actions:
    quarantine_folder: Path | None = None
    quarantined: list[FileResult] = field(default_factory=list)
    removed: list[FileResult] = field(default_factory=list)
    remove_failed: list[FileResult] = field(default_factory=list)
    # None: no cleaning attempted
    cleaned: bool | None = None
    # None: no copy to a server (airgap disabled)
    airgap: AirgapAction | None = None


def build_report(
    config: Config,
    device: UsbDevice | None,
    usage: DeviceUsage,
    engines: list[EngineInfo],
    summary: ScanSummary,
    started: datetime,
    finished: datetime,
    workers: int,
) -> ScanReport:
    """workers: files scanned at the same time (scan.workers once resolved)."""
    files = sorted(summary.files, key=lambda f: (f.volume, f.rel_path))
    by_verdict: dict[str, int] = {}
    for f in files:
        by_verdict[f.verdict.value] = by_verdict.get(f.verdict.value, 0) + 1
    data: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "report_id": str(uuid.uuid4()),
        "kiosk": {"name": config.kiosk.name, "software": "pandora-box", "version": __version__},
        "started": _iso(started),
        "finished": _iso(finished),
        "duration": round(summary.duration, 3),
        "device": _device(device, usage),
        "configuration": _configuration(config, workers),
        "engines": [_engine(e) for e in engines],
        "files": [_file(f) for f in files],
        "verdict": {
            "device": device_verdict(summary).value,
            "complete": summary.complete,
            "incomplete_reasons": list(summary.incomplete_reasons),
            "suspicious_behaviors": list(summary.behaviors),
            "statistics": {
                "files": len(files),
                "bytes": sum(f.size for f in files),
                "clean": by_verdict.get("clean", 0),
                "malicious": by_verdict.get("malicious", 0),
                "suspicious": by_verdict.get("suspicious", 0),
                "error": by_verdict.get("error", 0),
                "skipped": by_verdict.get("skipped", 0),
                "not_fully_scanned": len(summary.unscanned),
            },
        },
        "actions": _actions(Actions()),
    }
    return ScanReport(data)


def set_actions(report: ScanReport, actions: Actions) -> None:
    report.data["actions"] = _actions(actions)


def write_report(report: ScanReport, folder: Path) -> Path:
    """Write (or rewrite) the report atomically, readable by its owner only."""
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    if report.path is None:
        stamp = datetime.fromisoformat(report.data["started"]).strftime("%Y%m%dT%H%M%SZ")
        report.path = folder / f"{stamp}-{report.report_id[:8]}.json"
    tmp = report.path.with_name(f".{report.path.name}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        # ensure_ascii: any character left in a string stays valid JSON text
        json.dump(report.data, f, indent=2, ensure_ascii=True)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    tmp.replace(report.path)
    return report.path


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _device(device: UsbDevice | None, usage: DeviceUsage) -> dict[str, Any]:
    d = device or UsbDevice(node="")
    data: dict[str, Any] = {
        "node": escape(d.node),
        "vendor": escape(d.vendor),
        "model": escape(d.model),
        "serial": escape(d.serial),
        "label": escape(d.label),
        "filesystem": escape(d.fs_type),
        "size": usage.size,
        "used": usage.used,
    }
    if usage.partitions:
        data["partitions"] = [
            {
                "node": escape(p.node),
                "name": escape(Path(p.node).name),
                "filesystem": escape(p.fs_type),
                "label": escape(p.label),
                "size": p.size,
                "used": p.used,
                "scanned": not p.not_scanned,
                "not_scanned": escape(p.not_scanned) if p.not_scanned else None,
            }
            for p in sorted(usage.partitions, key=lambda p: p.node)
        ]
    return data


def _configuration(config: Config, workers: int) -> dict[str, Any]:
    return {
        "fake_scan": config.kiosk.fake_scan,
        "scan": {
            "workers": workers,
            "file_timeout": config.scan.file_timeout,
            "suspicious": config.scan.suspicious,
            "on_error": config.scan.on_error,
        },
        "limits": {
            "max_file_size": config.limits.max_file_size,
            "max_files": config.limits.max_files,
            "max_depth": config.limits.max_depth,
        },
        "policy": {
            "min_malicious_engines": config.policy.min_malicious_engines,
            "skip_content_engines_for_known_files": (
                config.engines.hashlookup.enabled and config.engines.hashlookup.skip_content_engines
            ),
        },
    }


def _engine(engine: EngineInfo) -> dict[str, Any]:
    return {
        "name": engine.name,
        "kind": engine.kind.value,
        "version": engine.version,
        "timeout": engine.timeout,
        "signatures": [_signature(s) for s in engine.signatures],
        "extra": engine.extra,
    }


def _signature(signature: SignatureInfo) -> dict[str, Any]:
    return {
        "name": signature.name,
        "version": signature.version,
        "date": _iso(signature.date) if signature.date else None,
        "path": signature.path,
        "source": signature.source,
    }


def _file(result: FileResult) -> dict[str, Any]:
    info = result.info
    data: dict[str, Any] = {
        "path": escape(result.rel_path),
        "path_b64": path_b64(result.rel_path),
        "size": result.size,
        "sha256": info.sha256 if info else None,
        "sha1": info.sha1 if info else None,
        "md5": info.md5 if info else None,
        "mime": info.mime if info else None,
        # libmagic descriptions may quote the content (document titles...)
        "description": escape(info.description) if info and info.description else None,
        "verdict": result.verdict.value,
        "detail": escape(result.detail),
        "not_fully_scanned": result.unscanned,
        "duration": round(result.duration, 3),
        "engines": [_engine_result(r) for r in result.results],
    }
    if result.volume:
        # Several partitions: the path is relative to the root of this one
        data["partition"] = escape(result.volume)
    return data


def _engine_result(result: EngineResult) -> dict[str, Any]:
    return {
        "engine": result.engine,
        "verdict": result.verdict.value,
        "detections": list(result.detections),
        "error": escape(result.error) if result.error else None,
        "reason": result.reason,
        "facts": dict(result.facts),
        "duration": round(result.duration, 3),
    }


def _actions(actions: Actions) -> dict[str, Any]:
    def paths(results: list[FileResult]) -> list[str]:
        return [escape(r.display_path) for r in results]

    return {
        "quarantine_folder": str(actions.quarantine_folder) if actions.quarantine_folder else None,
        "quarantined": paths(actions.quarantined),
        "removed": paths(actions.removed),
        "remove_failed": paths(actions.remove_failed),
        "cleaned": actions.cleaned,
        "airgap": None if actions.airgap is None else _airgap(actions.airgap),
    }


def _airgap(action: AirgapAction) -> dict[str, Any]:
    return {
        "status": action.status,
        "key_id": action.key_id,
        "destination": escape(action.destination),
        "copied": action.copied,
        "deleted": action.deleted,
        "unchanged": action.unchanged,
        "not_copied": [escape(r.display_path) for r in action.not_copied],
        "errors": [{"path": escape(p), "reason": escape(r)} for p, r in action.errors],
        "error": escape(action.error),
        "outbound": None if action.outbound is None else _outbound(action.outbound),
    }


def _outbound(action: OutboundAction) -> dict[str, Any]:
    return {
        "status": action.status,
        "copied": [escape(p) for p in action.copied],
        "unchanged": action.unchanged,
        "rejected": [{"path": escape(p), "reason": escape(r)} for p, r in action.rejected],
        "error": escape(action.error),
    }
