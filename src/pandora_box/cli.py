"""Command line entry point."""

from __future__ import annotations

import argparse
import dataclasses
import os
import signal
import socket
import sys
from pathlib import Path

from pandora_box import __version__
from pandora_box.config import DEFAULT_CONFIG_PATH, INTERFACES, Config, ConfigError, load_config
from pandora_box.engines import EngineError
from pandora_box.kiosk import Kiosk, NoEngineError, build_engines, build_pool, check_signatures
from pandora_box.lock import AlreadyRunningError, InstanceLock
from pandora_box.logs import redact_key_fields, setup_logging
from pandora_box.sandbox import SandboxError
from pandora_box.sigsets import SignatureSetError
from pandora_box.ui import ConsoleDisplay, Display
from pandora_box.ui.framebuffer import FramebufferError
from pandora_box.ui.theme import ThemeError, load_theme
from pandora_box.usbguard import AuditWatcher


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="pandora-box", description="USB decontamination kiosk")
    parser.add_argument(
        "-c",
        "--config",
        type=Path,
        default=Path(os.environ.get("PANDORA_BOX_CONFIG", DEFAULT_CONFIG_PATH)),
        help=f"configuration file (default: {DEFAULT_CONFIG_PATH})",
    )
    parser.add_argument(
        "--check-config", action="store_true", help="validate the configuration and exit"
    )
    parser.add_argument(
        "--fake-scan", action="store_true", help="force FAKE_SCAN mode (development only)"
    )
    parser.add_argument("--interface", choices=INTERFACES, help="override kiosk.interface")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser.parse_args(argv)


def apply_overrides(config: Config, args: argparse.Namespace) -> Config:
    kiosk = config.kiosk
    if args.fake_scan:
        kiosk = dataclasses.replace(kiosk, fake_scan=True)
    if args.interface:
        kiosk = dataclasses.replace(kiosk, interface=args.interface)
    return dataclasses.replace(config, kiosk=kiosk)


def make_display(config: Config) -> Display:
    """The display of the interface; raise ThemeError when its theme is invalid."""
    interface = config.kiosk.interface
    if interface == "framebuffer":
        from pandora_box.ui.framebuffer import FramebufferDisplay

        theme = load_theme(config.display.theme, config.display.language)
        return FramebufferDisplay(config.display, theme)
    if interface == "curses":
        from pandora_box.ui.curses_display import CursesDisplay

        return CursesDisplay()
    return ConsoleDisplay()


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        config = apply_overrides(load_config(args.config), args)
        # Before the engines: a kiosk that cannot show anything is useless
        display = make_display(config)
        pool = build_pool(config)
        if args.check_config:
            check_signatures(config)
            # Load every engine once in this process to check the configuration
            build_engines(config)
    except (ConfigError, NoEngineError, SandboxError) as ex:
        print(f"pandora-box: {ex}", file=sys.stderr)
        return 2
    except ThemeError as ex:
        print(f"pandora-box: theme: {ex}", file=sys.stderr)
        return 2
    except SignatureSetError as ex:
        print(f"pandora-box: signatures: {ex}", file=sys.stderr)
        return 2
    except EngineError as ex:
        _engine_error(ex)
        return 2
    if args.check_config:
        print(f"{args.config}: OK")
        return 0

    lock = InstanceLock("pandora-box")
    try:
        lock.acquire()
    except AlreadyRunningError as ex:
        print(f"pandora-box: {ex}", file=sys.stderr)
        return 1

    try:
        setup_logging(config.kiosk.name, config.logging.level, config.logging.file)
        # A station (airgap) keeps nothing of the keys, its log neither
        redact_key_fields(config.airgap.enabled)
    except OSError as ex:
        print(f"pandora-box: cannot open log file: {ex}", file=sys.stderr)
        lock.release()
        return 1

    # Engines are loaded once, by the scan workers, before the display starts.
    # Without valid signatures, the kiosk only accepts a signature update.
    signatures_error = None
    try:
        check_signatures(config)
        pool.start()
    except (SignatureSetError, EngineError) as ex:
        if not config.signatures.update_from_devices:
            if isinstance(ex, EngineError):
                _engine_error(ex)
            else:
                print(f"pandora-box: signatures: {ex}", file=sys.stderr)
            lock.release()
            return 2
        signatures_error = str(ex)

    from pandora_box.monitor import UdevSource

    # Before curses starts: ncurses handles SIGTERM itself when it has its
    # default action, and exits(1) without the cleanup below
    stop_on_sigterm()
    try:
        display.start()
    except FramebufferError as ex:
        print(f"pandora-box: display: {ex}", file=sys.stderr)
        pool.stop()
        lock.release()
        return 1
    notify_ready()
    source = UdevSource()
    # The USB devices refused by USBGuard, logged with the other events and
    # explained on the screen
    audit = AuditWatcher(notify=source.post) if AuditWatcher.available() else None
    if audit is not None:
        audit.start()
    try:
        Kiosk(config, display, source, pool, signatures_error=signatures_error).run()
    except KeyboardInterrupt:
        pass
    finally:
        if audit is not None:
            audit.stop()
        display.stop()
        pool.stop()
        lock.release()
    return 0


def _stop(signum: int, frame: object) -> None:
    raise KeyboardInterrupt


def stop_on_sigterm() -> None:
    """systemctl stop: stop like Ctrl-C, unmounting the device on the way out."""
    signal.signal(signal.SIGTERM, _stop)


def notify_ready() -> None:
    """Tell systemd that the kiosk is ready (Type=notify, boot assessment)."""
    address = os.environ.get("NOTIFY_SOCKET", "")
    if not address:
        return
    if address.startswith("@"):
        address = "\0" + address[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM | socket.SOCK_CLOEXEC) as sock:
            sock.connect(address)
            sock.sendall(b"READY=1")
    except OSError as ex:
        print(f"pandora-box: cannot notify systemd: {ex}", file=sys.stderr)


def _engine_error(ex: EngineError) -> None:
    print(f"pandora-box: cannot load an enabled engine: {ex}", file=sys.stderr)
    print("pandora-box: fix its configuration or disable it", file=sys.stderr)
