"""The kiosk: wait for a device, scan it, then remove infected files."""

from __future__ import annotations

import contextlib
import dataclasses
import json
import logging
import os
import stat
import subprocess
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from pandora_box import __version__, airgap, imageupdate, keyfs, keyid, maintenance
from pandora_box.config import Config
from pandora_box.device import (
    ENUMERATED_AGAIN,
    REMOVED,
    DeviceError,
    Mounter,
    SystemMountWatcher,
    UsbDevice,
    UsbIdentity,
)
from pandora_box.engines import Engine, EngineError, EngineKind, Verdict
from pandora_box.engines.registry import NoEngineError, engine_specs, load_engines
from pandora_box.hashing import hash_fd
from pandora_box.imageupdate import UPDATE_FOLDER as IMAGE_FOLDER
from pandora_box.logs import get_logger, log_event
from pandora_box.monitor import Action, DeviceSource
from pandora_box.policy import device_verdict
from pandora_box.quarantine import Quarantine
from pandora_box.remotes import Entry
from pandora_box.report import (
    Actions,
    AirgapAction,
    DeviceUsage,
    OutboundAction,
    PartitionUsage,
    ScanReport,
    build_report,
    set_actions,
    write_report,
)
from pandora_box.sandbox import Sandbox
from pandora_box.scanner import FileResult, Scanner, ScanSummary, describe, pipeline_options
from pandora_box.signatures import find_stale
from pandora_box.sigsets import (
    UPDATE_FOLDER,
    Manifest,
    NotNewerError,
    SignatureSetError,
    current_path,
    current_set,
    install,
    installed_manifest,
    local_public_keys,
    trusted_keys,
    verify_installed,
)
from pandora_box.statemachine import State, StateMachine
from pandora_box.text import escape, human_size
from pandora_box.ui import Display
from pandora_box.ui.base import Screen
from pandora_box.workers import EngineInfo, WorkerPool, auto_workers

logger = get_logger("kiosk")

# Number of infected files listed on screen before asking to clean
_MAX_LISTED = 10
# Time between two checks of the USB device of the key during its scan, in seconds
KEY_CHECK_SECONDS = 1.0
# Suspicious behaviors of a key during its scan (ScanSummary.behaviors)
BEHAVIOR_REASONS = {
    REMOVED: "the key was removed during the scan",
    ENUMERATED_AGAIN: "the key was enumerated again during the scan (another USB device)",
}


__all__ = [
    "Kiosk",
    "NoEngineError",
    "build_engines",
    "build_pool",
    "check_signatures",
    "stale_signatures",
]

# Absolute path: commands are never looked up in PATH
SYSTEMCTL = "/usr/bin/systemctl"
CLAMD_SERVICE = "clamav-daemon.service"


def build_engines(config: Config) -> list[Engine]:
    """Load the enabled engines in this process (configuration check).

    Raise NoEngineError or EngineError on failure.
    """
    return load_engines(engine_specs(config))


def build_pool(config: Config) -> WorkerPool:
    """The scan worker pool (not started).

    Raise NoEngineError without engine, SandboxError when the workers cannot
    be sandboxed.
    """
    specs = engine_specs(config)
    sandbox = build_sandbox(config)
    if sandbox is not None:
        sandbox.check()
    return WorkerPool(
        specs,
        pipeline_options(config),
        config.scan.workers or auto_workers(),
        config.scan.file_timeout,
        sandbox=sandbox,
    )


def signature_files(config: Config) -> list[Path]:
    """The signature files and folders read by the enabled engines.

    clamd reads its own databases (its DatabaseDirectory, in the image the
    clamav folder of the signature set).
    """
    engines = config.engines
    files: list[Path] = []
    if engines.malwarebazaar.enabled:
        files.append(engines.malwarebazaar.database)
    if engines.hashlookup.enabled:
        files.append(engines.hashlookup.bloom)
    if engines.yara.enabled:
        files += [rule_set.path for rule_set in engines.yara.rules]
    return files


def check_signatures(config: Config) -> Manifest | None:
    """Verify the installed signature set and that the engines only read it.

    Raise SignatureSetError when the set is missing, not signed by a trusted
    key, modified, or when an engine file is not part of it. Nothing is
    checked in FAKE_SCAN mode or without signatures.verify.
    """
    if config.kiosk.fake_scan or not config.signatures.verify:
        return None
    folder = config.signatures.folder
    keys = trusted_keys(config.signatures.keys) + local_public_keys(folder)
    manifest = verify_installed(folder, keys)
    current = current_path(folder)
    for path in signature_files(config):
        try:
            rel = path.relative_to(current).as_posix()
        except ValueError:
            raise SignatureSetError(f"{path} is not in the signature set ({current})") from None
        if not any(f.path == rel or f.path.startswith(rel + "/") for f in manifest.files):
            raise SignatureSetError(f"{path} is not in the signature set ({current})")
    return manifest


def restart_clamd() -> None:
    """Restart clamd, which reads its databases at start, if it runs.

    Not running, it is started with the new databases by its socket.
    """
    if not Path("/run/systemd/system").is_dir() or not Path(SYSTEMCTL).exists():
        return
    try:
        subprocess.run(  # noqa: S603  (fixed command, no shell)
            # Never an authentication prompt (polkit) for a user without the right
            [SYSTEMCTL, "--no-ask-password", "try-restart", CLAMD_SERVICE],
            check=True,
            capture_output=True,
            timeout=120,
        )
    except (OSError, subprocess.SubprocessError) as ex:
        log_event(logger, "clamd_restart_failed", logging.ERROR, error=str(ex))


def build_sandbox(config: Config) -> Sandbox | None:
    """The sandbox of the scan workers: the files of the enabled engines only."""
    if not config.scan.sandbox:
        return None
    engines = config.engines
    files = signature_files(config)
    writable: list[Path] = []
    if engines.clamav.enabled:
        files.append(engines.clamav.socket)
    if engines.yara.enabled and engines.yara.cache_dir is not None:
        writable.append(engines.yara.cache_dir)
    # The folder of each file: signature manifests, clamd socket re-created
    read_only = {path if path.is_dir() else path.parent for path in files}
    return Sandbox(config.scan.sandbox_user, tuple(sorted(read_only)), tuple(writable))


def make_mounter(config: Config) -> Mounter:
    device = config.device
    if device.auto_mount:
        return SystemMountWatcher(device.allowed_filesystems, device.auto_mount_wait)
    # Sandboxed workers read the files through their group (YARA-X reopens
    # the descriptor it gets)
    sandbox = build_sandbox(config)
    # The FUSE drivers run in the sandbox of the workers, without their files;
    # without the sandbox (development), the kernel mounts every filesystem
    fuse = None
    if sandbox is not None and device.fuse:
        fuse = Sandbox(config.scan.sandbox_user)
    return Mounter(
        device.mount_point,
        device.allowed_filesystems,
        use_sudo=device.use_sudo,
        timeout=device.command_timeout,
        reader_gid=None if sandbox is None else sandbox.ids()[1],
        fuse=fuse,
    )


def stale_signatures(config: Config, engines: list[EngineInfo]) -> tuple[list[str], list[str]]:
    """Signature databases older than their maximum age, and those without a date.

    Return the warnings shown on the screen (a known date, too old) and the
    databases whose age is unknown (only logged: for instance a ClamAV
    database of custom signatures only, without the official CVD header).
    """
    engine_configs = {
        "malwarebazaar": config.engines.malwarebazaar.max_age_days,
        "hashlookup": config.engines.hashlookup.max_age_days,
        "clamav": config.engines.clamav.max_age_days,
        "yara": config.engines.yara.max_age_days,
    }
    warnings = []
    undated = []
    for engine in engines:
        if engine.name not in engine_configs:
            continue
        max_age = engine_configs[engine.name] or config.signatures.max_age_days
        for stale in find_stale(engine.name, engine.signatures, max_age):
            if stale.age_days == float("inf"):
                undated.append(f"{engine.name}: {stale.signature.name}")
            else:
                warnings.append(
                    f"{engine.name}: signatures {stale.signature.name} are old "
                    f"({stale.age_days:.0f} days)"
                )
    return warnings, undated


class Kiosk:
    def __init__(
        self,
        config: Config,
        display: Display,
        source: DeviceSource,
        pool: WorkerPool,
        mounter: Mounter | None = None,
        signatures_error: str | None = None,
    ) -> None:
        """pool must be started; it is stopped by its owner.

        signatures_error: why the signatures cannot be used (the pool is not
        started). The kiosk then scans nothing: it only accepts a signature
        update device.
        """
        self.config = config
        self.signatures_error = signatures_error
        # The signature set loaded by the engines: an online update installs a
        # new one, loaded when the kiosk is idle
        self.loaded_set = current_set(config.signatures.folder)
        self.loaded_manifest = installed_manifest(config.signatures.folder)
        self.display = display
        self.source = source
        self.scanner = Scanner(pool, config.limits)
        self.mounter = mounter or make_mounter(config)
        # A station (airgap) keeps nothing of the keys: no quarantine, unless
        # it cleans them (airgap.clean)
        keep = config.quarantine.enabled and (not config.airgap.enabled or config.airgap.clean)
        self.quarantine = Quarantine(config.quarantine.folder) if keep else None
        self.device: UsbDevice | None = None
        self.summary: ScanSummary | None = None
        # Files to quarantine and remove, depending on the suspicious policy
        self.to_remove: list[FileResult] = []
        self.report: ScanReport | None = None
        self.actions = Actions()
        # The USB device of the key at the start of its scan, and the time
        # of its last check (None: not on USB, not checked)
        self.usb_identity: UsbIdentity | None = None
        self._key_checked = 0.0
        self.machine = StateMachine(
            {
                State.START: self.on_start,
                State.WAIT: self.on_wait,
                State.INSERTED: self.on_inserted,
                State.SCAN: self.on_scan,
                State.CLEAN: self.on_clean,
                State.ERROR: self.on_error,
            }
        )

    def run(self) -> None:
        try:
            self.machine.run()
        finally:
            self._unmount()
            log_event(logger, "kiosk_stopped")

    # -- states ------------------------------------------------------------

    def on_start(self) -> State:
        installed = installed_manifest(self.config.signatures.folder)
        image_version = imageupdate.running_version()
        log_event(
            logger,
            "kiosk_started",
            version=__version__,
            image_version=image_version,
            ready=self.signatures_error is None,
            signature_set=None if installed is None else installed.serial,
            fake_scan=self.config.kiosk.fake_scan,
            engines={e.name: e.version for e in self.scanner.engines},
            signatures={
                e.name: [
                    [s.name, s.version, s.date.isoformat() if s.date else None]
                    for s in e.signatures
                ]
                for e in self.scanner.engines
            },
        )
        # The version of the image (date and time of its build); the version
        # of the Python package only outside an image (development)
        if image_version is None:
            info = [f"PandoraBox {__version__} (development)"]
        else:
            info = [f"PandoraBox {image_version}{_build_date(image_version)}"]
        if installed is None:
            info.append("Signatures: none installed")
        else:
            created = installed.created.astimezone(UTC)
            info.append(f"Signatures: set {installed.serial} of {created:%Y-%m-%d %H:%M} UTC")
        info.append(f"Engines: {describe_engines(self.scanner.engines)}")
        if self.config.kiosk.fake_scan:
            info.append("FAKE SCAN MODE - for development only, no real detection")
        if self.config.device.auto_mount:
            info.append("AUTO-MOUNT MODE - for development only, devices are not mounted read-only")
        airgap_config = self.config.airgap
        if airgap_config.enabled:
            info.append(
                f"Copy to {airgap_config.protocol}://{airgap_config.host}/{airgap_config.path}"
            )
            if airgap.credential(airgap.TOKEN_KEY_CREDENTIAL) is None:
                log_event(logger, "airgap_unavailable", logging.ERROR, reason="no token key")
                info.append(f"NO KEY TO IDENTIFY THE KEYS ({airgap.TOKEN_KEY_CREDENTIAL})")
        for line in info:
            self.display.message(line)
        self.display.show_info(info)
        self._show_ready()
        return State.WAIT

    def _show_ready(self) -> None:
        # With a device (signature update), the screen of the device stays
        # until it is removed
        if self.device is None:
            self._show_waiting()
        if self.signatures_error is not None:
            log_event(logger, "signatures_unusable", logging.ERROR, error=self.signatures_error)
            self.display.message(f"NO VALID SIGNATURES: {self.signatures_error}")
            self.display.message("This kiosk cannot scan: insert a signature update device.")
            return
        warnings, undated = stale_signatures(self.config, self.scanner.engines)
        for warning in warnings:
            log_event(logger, "signatures_stale", logging.WARNING, warning=warning)
            self.display.message(f"WARNING: {warning}")
        if undated:
            log_event(logger, "signatures_undated", signatures=undated)
        self.display.message("Ready. Insert a USB device.")

    def _show_waiting(self) -> None:
        """The screen of a kiosk without device: ready, or without signatures."""
        self.display.show(Screen.READY if self.signatures_error is None else Screen.UNAVAILABLE)

    def on_wait(self) -> State:
        self._unmount()
        event = self.source.wait_event()
        if event is None:
            return State.STOP
        if event.action is Action.IDLE:
            if imageupdate.RESTART_FLAG.exists():
                return self._restart_after_update()
            self._load_new_set()
            return State.WAIT
        if event.action is Action.REMOVE:
            log_event(logger, "device_removed", node=event.device.node)
            self.device = None
            self.display.show_device(None)
            self._show_waiting()
            self.display.message("Device removed")
            return State.WAIT
        self.device = event.device
        d = event.device
        log_event(
            logger,
            "device_inserted",
            node=d.node,
            fs_type=d.fs_type,
            label=d.label,
            vendor=d.vendor,
            model=d.model,
            serial=d.serial,
            partitions=[[v.node, v.fs_type, v.label] for v in d.partitions],
            unscannable=[list(u) for u in d.unscannable],
        )
        self.display.show_device(d)
        self.display.show(Screen.SCANNING)
        self.display.message("Device inserted")
        return State.INSERTED

    def on_inserted(self) -> State:
        if self.device is None:
            return State.WAIT
        if self.device.multiple:
            # A key with several partitions is scanned, partition after
            # partition: it is never a maintenance or update device
            return self._refuse_scan() or State.SCAN
        try:
            self.mounter.mount(self.device, read_only=True)
        except DeviceError as ex:
            log_event(logger, "mount_failed", logging.ERROR, node=self.device.node, error=str(ex))
            self.display.message(f"Cannot mount device: {ex}")
            return State.ERROR
        root = self.mounter.mount_point
        # A device may hold a maintenance request, a signature set and an
        # image update, each verified on its own: all are handled, the image
        # last as it restarts the kiosk. Such a device is never scanned.
        not_scanned = ""
        if any(
            _has_folder(root, name) and enabled
            for name, enabled in (
                (maintenance.FOLDER, True),
                (UPDATE_FOLDER, self.config.signatures.update_from_devices),
                (IMAGE_FOLDER, self.config.updates.image_from_devices),
            )
        ):
            self.display.show(Screen.SERVICE)
        if _has_folder(root, maintenance.FOLDER):
            self._export_logs(self.device)
            not_scanned = "A maintenance device is not scanned. Remove the device."
        if self.config.signatures.update_from_devices and _has_folder(root, UPDATE_FOLDER):
            self._update_signatures(root / UPDATE_FOLDER)
            not_scanned = "A signature update device is not scanned. Remove the device."
        if self.config.updates.image_from_devices and _has_folder(root, IMAGE_FOLDER):
            version = self._update_image(root / IMAGE_FOLDER)
            self.display.message("An image update device is not scanned. Remove the device.")
            self._release()
            if version is not None:
                log_event(logger, "restarting", image_version=str(version))
                imageupdate.reboot()
                return State.STOP
            return State.WAIT
        if not_scanned:
            self.display.message(not_scanned)
            self._release()
            return State.WAIT
        return self._refuse_scan() or State.SCAN

    def _refuse_scan(self) -> State | None:
        """Without valid signatures, the device is not scanned."""
        if self.signatures_error is None:
            return None
        log_event(logger, "scan_refused", logging.WARNING, reason=self.signatures_error)
        self.display.show(Screen.UNAVAILABLE)
        self.display.message("Cannot scan: no valid signatures. Remove the device.")
        self._release()
        return State.WAIT

    def _export_logs(self, device: UsbDevice) -> None:
        """Write the logs of the kiosk to a maintenance device (signed request)."""
        folder = self.mounter.mount_point / maintenance.FOLDER
        self.display.message("Maintenance device: verifying the request...")
        try:
            maintenance.verify(folder, self.config)
            # Read-write to write the logs: verified again, as mounted now
            self.mounter.unmount()
            self.mounter.mount(device, read_only=False)
            maintenance.verify(folder, self.config)
            self.display.message("Exporting the logs...")
            target, count = maintenance.export(folder, self.config)
        except (maintenance.MaintenanceError, DeviceError, OSError) as ex:
            log_event(logger, "maintenance_refused", logging.WARNING, reason=str(ex))
            self.display.message(f"Maintenance REFUSED: {ex}")
            return
        log_event(logger, "logs_exported", folder=target.name, files=count)
        self.display.message(f"Logs exported to {maintenance.FOLDER}/{target.name}.")

    def _update_image(self, source: Path) -> int | None:
        """Install the image update of the device; return the version to restart on."""
        running = imageupdate.running_version()
        self.display.message("Image update device: verifying the update...")
        try:
            manifest = imageupdate.stage(
                source, trusted_keys(self.config.signatures.keys), running=running
            )
        except NotNewerError as ex:
            log_event(logger, "image_not_newer", reason=str(ex))
            self.display.message(f"System already up to date: {ex}")
            return None
        except (SignatureSetError, OSError) as ex:
            log_event(logger, "image_update_refused", logging.WARNING, reason=str(ex))
            self.display.message(f"Image update REFUSED: {ex}")
            return None
        self.display.message(f"Installing the system version {manifest.serial}...")
        try:
            imageupdate.apply()
        except imageupdate.ImageUpdateError as ex:
            log_event(logger, "image_update_failed", logging.ERROR, error=str(ex))
            self.display.message(f"Image update FAILED: {ex}")
            return None
        log_event(logger, "image_update_installed", version=manifest.serial, previous=running)
        self.display.message(f"System version {manifest.serial} installed: the kiosk restarts.")
        return manifest.serial

    def _update_signatures(self, source: Path) -> None:
        """Install the signature set of the device, then reload the engines."""
        folder = self.config.signatures.folder
        before = installed_manifest(folder)
        self.display.message("Signature update device: verifying the signature set...")
        try:
            manifest = install(source, folder, trusted_keys(self.config.signatures.keys))
        except NotNewerError as ex:
            log_event(logger, "signatures_not_newer", reason=str(ex))
            self.display.message(f"Signatures already up to date: {ex}")
            return
        except (SignatureSetError, OSError) as ex:
            log_event(logger, "signatures_refused", logging.WARNING, reason=str(ex))
            self.display.message(f"Signature update REFUSED: {ex}")
            return
        log_event(
            logger,
            "signatures_installed",
            serial=manifest.serial,
            created=manifest.created.isoformat(),
            files=len(manifest.files),
            previous=None if before is None else before.serial,
        )
        self.display.message(f"Signatures updated: set {manifest.serial}")
        self._reload_engines(before, manifest)

    def _restart_after_update(self) -> State:
        """An image update was installed online: restart, the kiosk being idle."""
        try:
            version = imageupdate.RESTART_FLAG.read_text().strip()
        except OSError:
            version = "?"
        log_event(logger, "restarting", image_version=version)
        self.display.show(Screen.SERVICE)
        self.display.message(f"System version {version} installed: the kiosk restarts.")
        imageupdate.reboot()
        return State.STOP

    def _load_new_set(self) -> None:
        """Load a signature set installed meanwhile (online update)."""
        folder = self.config.signatures.folder
        current = current_set(folder)
        after = installed_manifest(folder)
        if current == self.loaded_set or after is None:
            return
        log_event(
            logger,
            "signatures_changed",
            serial=after.serial,
            previous=None if self.loaded_manifest is None else self.loaded_manifest.serial,
        )
        self.display.message(f"New signatures installed: set {after.serial}")
        self._reload_engines(self.loaded_manifest, after)

    def _reload_engines(self, before: Manifest | None, after: Manifest) -> None:
        self.loaded_set = current_set(self.config.signatures.folder)
        self.loaded_manifest = after
        # In FAKE_SCAN mode, clamd is not used
        clamav = self.config.engines.clamav.enabled and not self.config.kiosk.fake_scan
        if clamav and _changed(before, after, "clamav/"):
            restart_clamd()
        pool = self.scanner.pool
        pool.stop()
        try:
            check_signatures(self.config)
            pool.start()
        except (SignatureSetError, EngineError) as ex:
            pool.stop()
            self.signatures_error = str(ex)
        else:
            self.signatures_error = None
            log_event(logger, "engines_reloaded", engines={e.name: e.version for e in pool.engines})
        self._show_ready()

    def on_scan(self) -> State:
        if self.device is None:
            return State.WAIT
        key = self.device
        volumes = key.volumes
        summary = ScanSummary()
        usage = DeviceUsage()
        started = datetime.now(UTC)
        # Signature versions as they are at the start of the scan
        engines = self.scanner.pool.engine_info()
        # A key that leaves, or comes back as another device, during its scan
        self.usb_identity = self.mounter.usb_identity(key)
        self._key_checked = time.monotonic()
        for node, reason in key.unscannable:
            name = Path(node).name
            log_event(logger, "partition_not_scanned", logging.WARNING, node=node, reason=reason)
            self.display.message(f"Partition {name} NOT scanned: {reason}")
            summary.incomplete_reasons.append(f"partition {name}: {reason}, not scanned")
            usage.partitions.append(PartitionUsage(node, "", "", 0, 0, reason))
        self.display.message("Scanning...")
        self.display.progress(0)
        scanned = 0
        for index, volume in enumerate(volumes):
            if not self._check_key(summary, force=True):
                break
            error = self._scan_volume(volume, index, len(volumes), summary, usage)
            if error is None:
                scanned += 1
                continue
            if key.multiple:
                usage.partitions.append(
                    PartitionUsage(volume.node, volume.fs_type, volume.label, 0, 0, error)
                )
            if not self._check_key(summary, force=True):
                # Not readable as the key left: a verdict all the same
                break
            if not key.multiple:
                return State.ERROR
            summary.incomplete_reasons.append(f"partition {volume.name}: {error}, not scanned")
        self._check_key(summary, force=True)
        if not scanned and not summary.behaviors:
            self.display.message("Cannot read any partition of the device")
            return State.ERROR
        self.summary = summary
        self.display.progress(100)
        s = self.summary
        self.display.message(
            f"Scan done in {s.duration:.1f}s, {len(s.files)} files scanned, "
            f"{len(s.infected)} files infected, {len(s.suspicious)} files suspicious, "
            f"{len(s.unscanned)} files not fully scanned"
        )
        self.to_remove = s.infected
        if self.config.scan.suspicious == "block":
            self.to_remove = s.infected + s.suspicious
        if s.behaviors:
            # The key is gone or another device: nothing to quarantine from it
            self.to_remove = []
        self.report = build_report(
            self.config,
            self.device,
            usage,
            engines,
            s,
            started,
            datetime.now(UTC),
            self.scanner.pool.size,
        )
        # The summary of the scan of a key, for the dashboards of a SIEM
        # (docs/siem.md); its report_id ties the events of the key together
        log_event(
            logger,
            "device_verdict",
            report_id=self.report.report_id,
            verdict=device_verdict(s).value,
            complete=s.complete,
            files=len(s.files),
            infected=len(s.infected),
            suspicious=len(s.suspicious),
            not_scanned=len(s.unscanned),
            duration=round(s.duration, 1),
            used=usage.used,
            detections=detections(s.files),
            suspicious_behaviors=s.behaviors,
        )
        self.actions = Actions()
        self._save_report()
        if self.quarantine is not None:
            try:
                self.actions.quarantine_folder = self.quarantine.store(
                    self.to_remove,
                    self._volume_root,
                    self.report.report_id,
                    self.report.path,
                )
                if self.actions.quarantine_folder is not None:
                    self.actions.quarantined = list(self.to_remove)
            except OSError as ex:
                log_event(logger, "quarantine_failed", logging.ERROR, error=str(ex))
            self._save_report()
        return State.CLEAN

    def _scan_volume(
        self,
        volume: UsbDevice,
        index: int,
        count: int,
        summary: ScanSummary,
        usage: DeviceUsage,
    ) -> str | None:
        """Mount and scan a filesystem of the key; return why it was not scanned.

        Its results are added to summary and usage.
        """
        multiple = self.device is not None and self.device.multiple
        try:
            root = self._mount(volume)
        except DeviceError as ex:
            log_event(logger, "mount_failed", logging.ERROR, node=volume.node, error=str(ex))
            self.display.message(f"Cannot mount device: {ex}")
            return f"cannot mount: {ex}"
        try:
            st = os.statvfs(root)
        except OSError as ex:
            log_event(logger, "statvfs_failed", logging.ERROR, error=str(ex))
            self.display.message(f"Cannot read device: {ex}")
            return f"cannot read: {ex.strerror}"
        size = st.f_frsize * st.f_blocks
        used = max(1, st.f_frsize * (st.f_blocks - st.f_bfree))
        usage.size += size
        usage.used += used
        self.display.show_usage(usage.size, usage.used)
        if multiple:
            usage.partitions.append(
                PartitionUsage(volume.node, volume.fs_type, volume.label, size, used, "")
            )
            label = f", {volume.label}" if volume.label else ""
            self.display.message(f"Partition {volume.name} ({volume.fs_type}{label})")
        log_event(logger, "scan_started", size=size, used=used, node=volume.node)

        def on_progress(result: FileResult, done: int, total: int) -> None:
            self._check_key(summary)
            if multiple:
                result = dataclasses.replace(result, volume=volume.name)
            self.display.message(f"[{done}/{total}] {describe(result)}")
            self.display.file_scanned(result, done, total)
            percent = (index * 100 + done * 100 // max(1, total)) // count
            self.display.progress(min(99, percent))

        part = self.scanner.scan_tree(root, on_progress)
        # A driver that stopped: the files it no longer served are missing
        if (failure := self.mounter.failure) is not None:
            log_event(logger, "filesystem_driver_failed", logging.ERROR, error=failure)
            self.display.message(f"Cannot read device: {failure}")
            part.incomplete_reasons.append(f"filesystem driver: {failure}")
        if multiple:
            part.files = [dataclasses.replace(f, volume=volume.name) for f in part.files]
            part.incomplete_reasons = [
                f"partition {volume.name}: {r}" for r in part.incomplete_reasons
            ]
        summary.files += part.files
        summary.incomplete_reasons += part.incomplete_reasons
        summary.duration += part.duration
        return None

    def _check_key(self, summary: ScanSummary, force: bool = False) -> bool:
        """Whether the key is still the USB device whose scan started.

        A key removed, or enumerated again (it disconnected itself to come
        back, maybe as another device), during its scan is reported as a
        suspicious behavior: its content cannot be trusted, the key is not
        verified. Checked at most every KEY_CHECK_SECONDS, unless force.
        """
        if summary.behaviors:
            return False
        if self.usb_identity is None or self.device is None:
            return True
        now = time.monotonic()
        if not force and now - self._key_checked < KEY_CHECK_SECONDS:
            return True
        self._key_checked = now
        behavior = self.mounter.identity_change(self.device, self.usb_identity)
        if behavior is None:
            return True
        summary.behaviors.append(behavior)
        summary.incomplete_reasons.append(BEHAVIOR_REASONS[behavior])
        log_event(
            logger,
            "device_suspicious_behavior",
            logging.WARNING,
            behavior=behavior,
            node=self.device.node,
            usb_device=self.usb_identity.sysfs,
            busnum=self.usb_identity.busnum,
            devnum=self.usb_identity.devnum,
        )
        self.display.message(f"SUSPICIOUS: {BEHAVIOR_REASONS[behavior]}")
        return False

    def _mount(self, volume: UsbDevice, read_only: bool = True) -> Path:
        """Mount a filesystem of the key, unless it is mounted read-only already."""
        mounted = self.mounter.device == volume and self.mounter.is_mounted()
        if not (read_only and mounted):
            self.mounter.unmount()
            self.mounter.mount(volume, read_only=read_only)
        return self.mounter.mount_point

    def _volume_root(self, result: FileResult) -> Path:
        """Root of the mounted filesystem of a file (quarantine)."""
        try:
            return self._mount(self._volume_of(result))
        except DeviceError as ex:
            raise OSError(str(ex)) from ex

    def _volume_of(self, result: FileResult) -> UsbDevice:
        volumes = () if self.device is None else self.device.volumes
        for volume in volumes:
            if not result.volume or volume.name == result.volume:
                return volume
        raise DeviceError(f"no partition {result.volume}")

    def on_clean(self) -> State:
        if self.summary is None:
            return State.WAIT
        if self.summary.behaviors:
            # Whatever scan.on_error: neither cleaned nor copied to a server
            self._release()
            self.display.show(Screen.NOT_VERIFIED, self.summary.unscanned)
            self.display.message(
                "SUSPICIOUS DEVICE, NOT VERIFIED: do not use it. Remove the device."
            )
            return State.WAIT
        infected = self.to_remove
        if self.config.scan.suspicious == "warn" and self.summary.suspicious:
            suspicious = self.summary.suspicious
            log_event(logger, "suspicious_files", logging.WARNING, count=len(suspicious))
            self._list(
                f"WARNING: {len(suspicious)} suspicious files, use with caution:", suspicious
            )
        not_verified = self._check_complete(self.summary)
        if self.config.airgap.enabled:
            return self._copy_to_server()
        if not infected:
            self._release()
            if not_verified:
                self.display.show(Screen.NOT_VERIFIED, self.summary.unscanned)
                self.display.message("DEVICE NOT VERIFIED: do not use it. Remove the device.")
            else:
                self.display.show(*self._clean_screen())
                self.display.message("No infected file found. You can remove the device.")
            return State.WAIT

        outcome = self._clean(infected)
        if outcome == "error":
            return State.ERROR
        if outcome == "removed":
            self.display.show(Screen.NOT_CLEANED, infected)
            self.display.message("Device removed before cleaning: NOT CLEANED")
            self._release()
            return State.WAIT
        removed = len(self.actions.removed)
        self._save_report()
        self._release()
        # Logged once the device is ejected: in the order things happen
        log_event(
            logger,
            "device_cleaned",
            report_id=self._report_id(),
            removed=removed,
            infected=len(infected),
        )
        if removed == len(infected) and not_verified:
            self.display.show(Screen.NOT_VERIFIED, self.summary.unscanned)
            self.display.message(
                "Device cleaned, but NOT VERIFIED: do not use it. Remove the device."
            )
        elif removed == len(infected):
            screen, kept = self._clean_screen()
            if screen is Screen.WARNING:
                self.display.show(Screen.WARNING, kept)
            else:
                self.display.show(Screen.CLEANED, self.actions.removed)
            self.display.message("Device cleaned! You can remove the device.")
        else:
            self.display.show(Screen.NOT_CLEANED, self.actions.remove_failed)
            self.display.message(f"Device NOT cleaned: {len(infected) - removed} files remain")
        return State.WAIT

    def _clean(self, infected: list[FileResult]) -> str:
        """Show the files to remove, wait for a touch, remove them.

        Return "" once done (self.actions tells which were removed), "removed"
        when the device was removed before, "error" when it cannot be cleaned.
        """
        log_event(logger, "infected_files", count=len(infected))
        self.display.show(Screen.THREATS, infected)
        self._list(f"{len(infected)} infected files detected:", infected)
        # The device is not mounted while the user decides: it can be removed
        try:
            self.mounter.unmount()
        except DeviceError as ex:
            log_event(logger, "unmount_failed", logging.ERROR, error=str(ex))
            self.display.message(f"Cannot unmount device: {ex}")
            return "error"
        self.display.confirm("PRESS A KEY OR TOUCH THE SCREEN TO CLEAN")

        device = self.device
        if device is None or not self.mounter.device_present(device):
            log_event(logger, "device_removed_before_clean", logging.WARNING)
            return "removed"
        self.display.show(Screen.CLEANING)
        for volume in device.volumes:
            files = [r for r in infected if self._volume_of(r) == volume]
            if not files:
                continue
            try:
                # Read-write only to remove the infected files
                self._mount(volume, read_only=False)
            except DeviceError as ex:
                log_event(logger, "mount_rw_failed", logging.ERROR, node=volume.node, error=str(ex))
                self.display.message(f"Cannot clean device: {ex}")
                if not device.multiple:
                    return "error"
                self.actions.remove_failed += files
                continue
            log_event(logger, "device_mounted_rw", node=volume.node)
            for result in files:
                if self._remove(result):
                    self.actions.removed.append(result)
                else:
                    self.actions.remove_failed.append(result)
            self._unmount()
        self.actions.cleaned = len(self.actions.removed) == len(infected)
        return ""

    def on_error(self) -> State:
        self._release()
        self.display.show(Screen.ERROR)
        self.display.message("Error: please remove the device.")
        return State.WAIT

    # -- helpers -----------------------------------------------------------

    # -- copy to a server (airgap) ------------------------------------------

    def _copy_to_server(self) -> State:
        """airgap: the clean files of a verified key go to the server (inbound), the
        files waiting on the server for it come to it (outbound); it is not cleaned.
        """
        summary, device = self.summary, self.device
        if summary is None or device is None:
            return State.WAIT
        mode = self.config.airgap.mode
        inbound, outbound = mode in ("both", "inbound"), mode in ("both", "outbound")
        not_copied = [f for f in summary.files if f.verdict is not Verdict.CLEAN]
        action = AirgapAction("failed" if inbound else "skipped", not_copied=not_copied)
        self.actions.airgap = action
        # Only a key scanned entirely, whatever scan.on_error
        if not summary.complete:
            action.status = "refused"
            if outbound:
                action.outbound = OutboundAction("refused", error="key not verified")
            self._release()
            log_event(
                logger,
                "airgap_refused",
                logging.WARNING,
                report_id=self._report_id(),
                reason="key not verified",
            )
            self.display.show(Screen.NOT_VERIFIED, summary.unscanned)
            self.display.message("DEVICE NOT VERIFIED: nothing copied. Remove the device.")
            return State.WAIT
        self.display.show(Screen.TRANSFERRING)
        config = self.config.airgap
        # The name of the folder of the key on the server: never logged,
        # never shown, never kept (pandora_box.keyid)
        folder = ""
        left: list[FileResult] = []
        error = ""
        try:
            identity = self._key_identity(device)
            folder = identity.folder
            action.key_id = identity.identifier
            if inbound:
                left += self._send_files(folder, device, summary)
            # airgap.clean: the station cleans the key too (scan.suspicious
            # decides for the suspicious files, as on any kiosk)
            dangerous = bool(self.to_remove)
            if dangerous and config.clean:
                outcome = self._clean(self.to_remove)
                if outcome:
                    raise airgap.AirgapError(
                        "key removed before cleaning" if outcome == "removed" else "cannot clean"
                    )
                dangerous = not self.actions.cleaned
                removed = len(self.actions.removed)
                log_event(
                    logger,
                    "device_cleaned",
                    report_id=self._report_id(),
                    removed=removed,
                    infected=len(self.to_remove),
                )
                self.display.show(Screen.TRANSFERRING)
            if outbound:
                try:
                    received, rejected = self._receive(folder, device, summary, dangerous)
                except (airgap.AirgapError, DeviceError, OSError) as ex:
                    error = airgap.hide(str(ex), folder)
                    received, rejected = OutboundAction("failed", error=error), []
                action.outbound = received
                left += rejected
                # The final report, with both directions
                self._send_report(folder)
        except (airgap.AirgapError, keyid.TokenError, DeviceError, OSError) as ex:
            error = error or airgap.hide(str(ex), folder)
            if action.status != "copied" and inbound:
                action.error = error
        finally:
            if folder:
                airgap.remove_staging(config, folder)
        if error:
            log_event(
                logger, "airgap_failed", logging.ERROR, report_id=self._report_id(), error=error
            )
        # Logged before the key is ejected: in the order things happen
        self._release()
        if error:
            self.display.show(Screen.TRANSFER_FAILED)
            self.display.message(f"Copy FAILED: {error}")
            return State.WAIT
        self.display.show(Screen.TRANSFERRED, left)
        if left:
            self._list(f"{len(left)} files not copied:", left)
        self.display.message("You can remove the device.")
        return State.WAIT

    def _send_files(self, folder: str, device: UsbDevice, summary: ScanSummary) -> list[FileResult]:
        """Inbound: copy the clean files of the key to the server; the files not copied."""
        action = self.actions.airgap
        if action is None:
            raise airgap.AirgapError("no copy in progress")
        self.display.message("Copying the clean files to the server...")
        staged = self._stage(folder, device, summary)
        action.errors = list(staged.errors)
        self._stage_report(staged.folder)
        result = airgap.request(
            self.config.airgap, folder, self._report_id(), self._copy_progress()
        )
        action.status = "copied"
        action.destination = result.destination
        action.copied, action.deleted = result.copied, result.deleted
        action.unchanged = result.unchanged
        action.errors += result.errors
        log_event(
            logger,
            "airgap_copied",
            report_id=self._report_id(),
            copied=result.copied,
            deleted=result.deleted,
            unchanged=result.unchanged,
            not_copied=len(action.not_copied),
            errors=len(action.errors),
        )
        self.display.message(
            f"Copied to the server: {result.copied} new or changed files, "
            f"{result.unchanged} unchanged, {result.deleted} deleted from the server"
        )
        failed = {path for path, _ in action.errors}
        return action.not_copied + [f for f in summary.files if self._target(device, f) in failed]

    def _receive(
        self, folder: str, device: UsbDevice, summary: ScanSummary, key_dangerous: bool
    ) -> tuple[OutboundAction, list[FileResult]]:
        """Outbound: scan the files waiting on the server for the key, write the clean ones.

        key_dangerous: the key still holds files the cleaning would remove.
        Return what was done, and the files of the server not copied.
        """
        if key_dangerous:
            log_event(
                logger,
                "airgap_received",
                logging.WARNING,
                report_id=self._report_id(),
                status="refused",
            )
            self.display.message(
                "Files of the server NOT copied: the key holds dangerous files. "
                "Clean it at a kiosk that cleans, then insert it again."
            )
            return OutboundAction("refused", error="dangerous files on the key"), []
        config = self.config.airgap
        first = device.volumes[0]
        root = self._mount(first)
        # The files of the key, to download only what it does not have
        have: dict[str, Entry] = {}
        for result in summary.files:
            if result.volume and result.volume != first.name:
                continue
            with contextlib.suppress(OSError):
                info = (root / result.rel_path).lstat()
                have[result.rel_path] = Entry(info.st_size, int(info.st_mtime))
        downloads = airgap.prepare_outbound(config, folder, have)
        self.display.message("Looking for files on the server for this key...")
        fetched = airgap.request(config, folder, self._report_id(), operation="outbound")
        rejected = list(fetched.errors)
        if not fetched.fetched:
            log_event(
                logger,
                "airgap_received",
                report_id=self._report_id(),
                status="nothing",
                unchanged=fetched.unchanged,
            )
            self.display.message("No new file on the server for this key.")
            return OutboundAction("nothing", unchanged=fetched.unchanged, rejected=rejected), []

        # Scanned like the files of a key: only the clean ones are written
        self.display.message(f"Scanning {fetched.fetched} files of the server...")
        scanned = self.scanner.scan_tree(downloads)
        clean = [
            f
            for f in scanned.files
            if f.verdict is Verdict.CLEAN and not f.unscanned and f.info is not None
        ]
        dangerous = [f for f in scanned.files if f not in clean]
        rejected += [(f.rel_path, f"{f.verdict.value}: {f.detail}") for f in dangerous]
        reserved = {keyid.TOKEN_FILE, f"{keyid.TOKEN_FILE}.tmp"}
        for f in [f for f in clean if f.rel_path.split("/", 1)[0] in reserved]:
            clean.remove(f)
            rejected.append((f.rel_path, "name reserved for the kiosk"))

        # Read-write only to write the files of the server
        root = self._mount(first, read_only=False)
        st = os.statvfs(root)
        layout = keyfs.plan(
            first.fs_type,
            # In the order of their paths: of two names equal but for the case,
            # the same one is kept whatever the order of the scan
            [(f.rel_path, f.size) for f in sorted(clean, key=lambda f: f.rel_path)],
            st.f_bavail * st.f_frsize,
        )
        rejected += layout.rejected
        by_path = {f.rel_path: f for f in clean}
        copied: list[str] = []
        for path, _ in layout.accepted:
            result = by_path[path]
            source = downloads / path
            try:
                sha256 = result.info.sha256 if result.info is not None else ""
                keyfs.write_file(root, path, source, sha256, source.stat().st_mtime)
            except OSError as ex:
                rejected.append((path, ex.strerror or str(ex)))
                continue
            copied.append(path)
        # The FUSE driver writes its last changes before the key is ejected
        self._unmount()
        log_event(
            logger,
            "airgap_received",
            report_id=self._report_id(),
            status="copied",
            copied=len(copied),
            unchanged=fetched.unchanged,
            rejected=len(rejected),
        )
        self.display.message(
            f"Copied to the key from the server: {len(copied)} files, "
            f"{fetched.unchanged} already on it"
        )
        refused = {path for path, _ in rejected}
        left = dangerous + [f for f in clean if f.rel_path in refused]
        status = "copied" if copied else "nothing"
        action = OutboundAction(status, copied, fetched.unchanged, rejected)
        return action, left

    def _send_report(self, folder: str) -> None:
        """Send the report alone to the folder of the key (after the outbound copy)."""
        staged = airgap.staging_folder(self.config.airgap, folder)
        staged.mkdir(mode=0o750, parents=True, exist_ok=True)
        self._stage_report(staged)
        airgap.request(self.config.airgap, folder, self._report_id(), operation="report")

    def _key_identity(self, device: UsbDevice) -> keyid.KeyIdentity:
        """The identity of the key, from its token, else a new one written on it."""
        key = airgap.credential(airgap.TOKEN_KEY_CREDENTIAL)
        if key is None:
            raise airgap.AirgapError(
                f"no key to sign the key identifiers (credential {airgap.TOKEN_KEY_CREDENTIAL})"
            )
        first = device.volumes[0]
        root = self._mount(first)
        try:
            identity = keyid.verify_token(keyid.read_token(root), key)
        except keyid.TokenError as ex:
            if str(ex) != "no token":
                log_event(logger, "key_token_invalid", logging.WARNING, error=str(ex))
        else:
            log_event(logger, "key_identified")
            return identity
        identity, token = keyid.new_token(key)
        # Read-write only to write the token
        root = self._mount(first, read_only=False)
        keyid.write_token(root, token)
        self._unmount()
        log_event(logger, "key_token_written", node=first.node)
        return identity

    def _stage(self, folder: str, device: UsbDevice, summary: ScanSummary) -> airgap.Staged:
        """Copy the clean files of the key into the staging folder of the service."""
        files = [
            f
            for f in summary.files
            if f.verdict is Verdict.CLEAN and f.info is not None and not self._is_token(device, f)
        ]
        needed = sum(f.size for f in files)
        staged = airgap.prepare(self.config.airgap, folder, needed)
        for volume in device.volumes:
            mine = [f for f in files if self._volume_of(f) == volume]
            if not mine:
                continue
            root = self._mount(volume)
            for result in mine:
                # Clean files have their hashes (filtered above)
                sha256 = result.info.sha256 if result.info is not None else ""
                target = self._target(device, result)
                airgap.stage_file(staged, root, result.rel_path, target, sha256)
        self._unmount()
        return staged

    def _stage_report(self, folder: Path) -> None:
        if self.report is None:
            raise airgap.AirgapError("no scan report")
        # Only on the server: a station keeps no report (_save_report)
        set_actions(self.report, self.actions)
        target = folder / airgap.REPORT
        target.write_text(json.dumps(self.report.data, indent=2, ensure_ascii=True) + "\n")

    def _report_id(self) -> str:
        return "" if self.report is None else self.report.report_id

    def _copy_progress(self) -> Callable[[int, int], None]:
        """Progress of the copy, in the messages, at most every tenth."""
        shown = [-1]

        def progress(done: int, total: int) -> None:
            tenth = 10 if total <= 0 else min(10, done * 10 // total)
            if tenth > shown[0]:
                shown[0] = tenth
                self.display.message(f"Copied: {tenth * 10}% of {human_size(total)}")

        return progress

    def _target(self, device: UsbDevice, result: FileResult) -> str:
        """Path of a file in the folder of the key on the server."""
        if not device.multiple:
            return result.rel_path
        index = next((i for i, v in enumerate(device.volumes) if v.name == result.volume), 0)
        return f"partition-{index + 1}/{result.rel_path}"

    def _is_token(self, device: UsbDevice, result: FileResult) -> bool:
        first = device.volumes[0]
        on_first = not result.volume or result.volume == first.name
        return on_first and result.rel_path in (keyid.TOKEN_FILE, f"{keyid.TOKEN_FILE}.tmp")

    def _clean_screen(self) -> tuple[Screen, list[FileResult]]:
        """No infected file is left: a warning for the files kept (warn policies)."""
        files = [] if self.summary is None else self.summary.files
        kept = [
            f
            for f in files
            if f not in self.to_remove and (f.verdict is Verdict.SUSPICIOUS or f.unscanned)
        ]
        return (Screen.WARNING, kept) if kept else (Screen.CLEAN, [])

    def _save_report(self) -> None:
        """Write the scan report; a failure is logged and shown, not fatal.

        A station (airgap) keeps nothing of the keys: its reports only go to
        the server, with the files of the key.
        """
        if self.report is None or self.config.airgap.enabled:
            return
        set_actions(self.report, self.actions)
        try:
            path = write_report(self.report, self.config.report.folder)
        except OSError as ex:
            log_event(logger, "report_failed", logging.ERROR, error=str(ex))
            self.display.message(f"WARNING: cannot write the scan report: {ex.strerror}")
            return
        log_event(logger, "report_written", report_id=self.report.report_id, path=str(path))

    def _check_complete(self, summary: ScanSummary) -> bool:
        """Report files that were not fully scanned.

        Return True when the device must be rejected (scan.on_error = "block").
        Unscanned files are never removed: they are not known to be malicious.
        """
        if summary.complete:
            return False
        unscanned = summary.unscanned
        block = self.config.scan.on_error == "block"
        log_event(
            logger,
            "device_not_verified" if block else "device_incomplete",
            logging.WARNING,
            files=len(unscanned),
            reasons=summary.incomplete_reasons,
        )
        if block:
            title = f"{len(unscanned)} files could not be fully scanned:"
        else:
            title = f"WARNING: {len(unscanned)} files could not be fully scanned, use with caution:"
        self._list(title, unscanned)
        for reason in summary.incomplete_reasons:
            self.display.message(f"Not scanned: {reason}")
        return block

    def _list(self, title: str, results: list[FileResult]) -> None:
        self.display.message(title)
        for result in results[:_MAX_LISTED]:
            self.display.message(result.display_path)
        if len(results) > _MAX_LISTED:
            self.display.message("...")

    def _remove(self, result: FileResult) -> bool:
        """Remove an infected file, if it is still the file that was scanned.

        The device was unmounted while waiting for the user, who may have
        inserted another device: the content must have the scanned SHA-256.
        """
        root = self.mounter.mount_point
        path = root / result.rel_path
        name = escape(result.display_path)
        # Never follow a link out of the device
        if not Path(os.path.realpath(path)).is_relative_to(os.path.realpath(root)):
            log_event(logger, "remove_refused", logging.ERROR, path=name, reason="outside")
            return False
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
            try:
                sha256 = hash_fd(fd).sha256
            finally:
                os.close(fd)
            if result.info is None or sha256 != result.info.sha256:
                log_event(
                    logger, "remove_refused", logging.ERROR, path=name, reason="content changed"
                )
                self.display.message(f"Not removed, changed since the scan: {result.display_path}")
                return False
            path.unlink()
        except OSError as ex:
            log_event(logger, "remove_failed", logging.ERROR, path=name, error=ex.strerror)
            self.display.message(f"Could not remove {result.display_path}: {ex.strerror}")
            return False
        log_event(logger, "file_removed", path=name)
        self.display.message(f"{result.display_path} removed")
        return True

    def _release(self) -> None:
        """Unmount the device, then eject it (device.eject)."""
        self._unmount()
        if self.device is None or not self.config.device.eject:
            return
        try:
            self.mounter.eject(self.device)
        except DeviceError as ex:
            # Unmounted and synced: the device can still be removed safely
            log_event(logger, "eject_failed", logging.WARNING, error=str(ex))

    def _unmount(self) -> None:
        try:
            self.mounter.unmount()
        except DeviceError as ex:
            log_event(logger, "unmount_failed", logging.ERROR, error=str(ex))


def detections(files: list[FileResult]) -> list[str]:
    """The detections of a scan, "engine: name", each once (never the names of the files)."""
    found = {
        f"{r.engine}: {r.detail}"
        for f in files
        for r in f.results
        if r.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS) and r.detail
    }
    return sorted(found)


def describe_engines(engines: list[EngineInfo]) -> str:
    """The enabled engines, with the version of the scanning programs (ClamAV, YARA-X)."""
    if not engines:
        return "none loaded (no valid signatures)"
    names = []
    for engine in engines:
        # The version of a hash engine is the format of its database
        version = engine.version if engine.kind is EngineKind.CONTENT else ""
        names.append(
            f"{engine.name} ({version})" if version and not version.isdigit() else engine.name
        )
    return ", ".join(names)


def _build_date(version: int) -> str:
    """The date of a version made of the time of its build: " of 2026-10-05 14:13 UTC"."""
    try:
        built = datetime.strptime(str(version), "%Y%m%d%H%M%S")
    except ValueError:
        return ""
    return f" of {built:%Y-%m-%d %H:%M} UTC"


def _has_folder(root: Path, name: str) -> bool:
    """The device holds that folder at its root (a folder, not a link)."""
    try:
        return stat.S_ISDIR(os.lstat(root / name).st_mode)
    except OSError:
        return False


def _changed(before: Manifest | None, after: Manifest, prefix: str) -> bool:
    def files(manifest: Manifest | None) -> set[tuple[str, str]]:
        if manifest is None:
            return set()
        return {(f.path, f.sha256) for f in manifest.files if f.path.startswith(prefix)}

    return files(before) != files(after)
