"""Export of the kiosk logs to a SIEM (pandora-box-siem.service).

The kiosk has no network. This service, run as a user the firewall of an
online kiosk lets out, follows the JSON lines log file of the kiosk and sends
every entry to the SIEM: as a syslog message (RFC 5424, the JSON entry as
message) or as the JSON entry alone, over TLS, TCP or UDP.

The log file is the queue: the position of the last entry sent is saved, so
that the entries logged while the SIEM cannot be reached, or while the
service is stopped, are sent later, also after logrotate moved the file.
Syslog has no acknowledgment: the entries sent just before a connection
breaks may be lost (TCP, TLS), and UDP gives no guarantee at all.
"""

from __future__ import annotations

import argparse
import json
import os
import select
import signal
import socket
import ssl
import sys
import threading
from datetime import datetime
from pathlib import Path
from types import FrameType

from pandora_box.config import DEFAULT_CONFIG_PATH, ConfigError, SiemConfig, load_config
from pandora_box.follow import LogFollower, load_position, save_position

STATE_PATH = Path("/var/lib/pandora-box-siem/state.json")
APP_NAME = "pandora-box"
# Entries sent at once, between two saves of the position
BATCH = 100
# Time between two reads of the log file at its end, in seconds
POLL_SECONDS = 1.0
# Wait between two attempts to reach the SIEM, doubled up to the longest, in seconds
MIN_BACKOFF = 1.0
MAX_BACKOFF = 60.0

# Severities of RFC 5424 (section 6.2.1) for the levels of the kiosk logs
SEVERITIES = {"DEBUG": 7, "INFO": 6, "WARNING": 4, "ERROR": 3, "CRITICAL": 2}
_NOTICE = 5


def _say(message: str) -> None:
    # The journal of the service
    print(f"pandora-box-siem: {message}", file=sys.stderr, flush=True)


# -- Messages ------------------------------------------------------------------


def facility_code(name: str) -> int:
    return 1 if name == "user" else 16 + int(name.removeprefix("local"))


def _field(value: object, length: int) -> str:
    """A header field of RFC 5424: printable ASCII without space, or "-"."""
    if not isinstance(value, str) or not value:
        return "-"
    return "".join(c if "!" <= c <= "~" else "_" for c in value[:length])


def _timestamp(value: object) -> str:
    if not isinstance(value, str):
        return "-"
    try:
        moment = datetime.fromisoformat(value)
    except ValueError:
        return "-"
    if moment.tzinfo is None:
        return "-"
    return moment.isoformat(timespec="microseconds")


def syslog_message(line: bytes, facility: str, hostname: str) -> bytes:
    """An RFC 5424 message: the header from the log entry, the entry as message."""
    try:
        entry = json.loads(line)
    except ValueError:
        entry = None
    if not isinstance(entry, dict):
        entry = {}
    severity = SEVERITIES.get(entry.get("level"), _NOTICE)  # type: ignore[arg-type]
    header = " ".join(
        (
            f"<{facility_code(facility) * 8 + severity}>1",
            _timestamp(entry.get("timestamp")),
            _field(entry.get("kiosk") or hostname, 255),
            APP_NAME,
            "-",  # PROCID
            _field(entry.get("event"), 32),  # MSGID
            "-",  # STRUCTURED-DATA
        )
    )
    return header.encode("ascii") + b" " + line


def make_message(line: bytes, config: SiemConfig, hostname: str) -> bytes:
    if config.format == "json":
        return line
    return syslog_message(line, config.facility, hostname)


def frame(message: bytes, config: SiemConfig) -> bytes:
    """A message as sent over a stream (TCP, TLS)."""
    if config.format == "json":
        # One JSON entry per line: a JSON entry has no line break
        return message + b"\n"
    # Octet counting (RFC 5425, RFC 6587)
    return f"{len(message)} ".encode("ascii") + message


# -- Connection ----------------------------------------------------------------


class Sender:
    """Connection to the SIEM, opened again when it breaks."""

    def __init__(self, config: SiemConfig) -> None:
        self.config = config
        self.sock: socket.socket | None = None
        self.context: ssl.SSLContext | None = None
        if config.transport == "tls":
            # Certificate and host name verified, TLS 1.2 at least
            self.context = ssl.create_default_context(
                cafile=str(config.ca) if config.ca is not None else None
            )
            self.context.minimum_version = ssl.TLSVersion.TLSv1_2

    def close(self) -> None:
        if self.sock is not None:
            self.sock.close()
            self.sock = None

    def send(self, messages: list[bytes]) -> None:
        """Send the messages; OSError when the SIEM cannot be reached."""
        if self.sock is not None and self.config.transport != "udp" and _peer_closed(self.sock):
            self.close()
        if self.sock is None:
            self.sock = self._connect()
        try:
            if self.config.transport == "udp":
                for message in messages:
                    self.sock.send(message)
            else:
                self.sock.sendall(b"".join(frame(m, self.config) for m in messages))
        except OSError:
            self.close()
            raise

    def _connect(self) -> socket.socket:
        address = (self.config.host, self.config.server_port)
        if self.config.transport == "udp":
            family, kind, proto, _, target = socket.getaddrinfo(*address, type=socket.SOCK_DGRAM)[0]
            sock = socket.socket(family, kind, proto)
            try:
                sock.connect(target)
            except OSError:
                sock.close()
                raise
            return sock
        sock = socket.create_connection(address, timeout=self.config.timeout)
        if self.context is None:
            return sock
        try:
            return self.context.wrap_socket(sock, server_hostname=self.config.host)
        except OSError:
            sock.close()
            raise


def _peer_closed(sock: socket.socket) -> bool:
    """Whether the SIEM closed (or reset) the connection."""
    readable, _, _ = select.select([sock], [], [], 0)
    if not readable:
        return False
    # The SIEM sends no data, but a TLS 1.3 server sends session tickets
    # after the handshake: only the end of the stream means closed
    timeout = sock.gettimeout()
    sock.setblocking(False)
    try:
        return sock.recv(1) == b""
    except (ssl.SSLWantReadError, BlockingIOError):
        return False
    except OSError:
        return True
    finally:
        sock.settimeout(timeout)


# -- Service -------------------------------------------------------------------


def run(
    config: SiemConfig,
    log_file: Path,
    hostname: str,
    state: Path,
    stop: threading.Event,
    sender: Sender | None = None,
) -> None:
    """Send the entries of the log file until stop is set."""
    follower = LogFollower(
        log_file,
        load_position(state),
        lambda _: _say("the log file of the last entry sent is gone: some entries are not sent"),
    )
    sender = sender or Sender(config)
    pending: list[bytes] = []
    backoff = 0.0
    try:
        while not stop.is_set():
            if not pending:
                pending = [make_message(line, config, hostname) for line in follower.read(BATCH)]
                if not pending:
                    stop.wait(POLL_SECONDS)
                    continue
            try:
                sender.send(pending)
            except OSError as ex:
                if not backoff:
                    _say(f"cannot send to {config.host}:{config.server_port}: {ex}")
                backoff = min(max(MIN_BACKOFF, backoff * 2), MAX_BACKOFF)
                stop.wait(backoff)
                continue
            if backoff:
                _say(f"sending to {config.host}:{config.server_port} again")
                backoff = 0.0
            pending = []
            position = follower.position()
            if position is not None:
                save_position(state, position)
    finally:
        sender.close()
        follower.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pandora-box-siem", description="Send the logs of the kiosk to a SIEM"
    )
    parser.add_argument(
        "-c",
        "--config",
        type=Path,
        default=Path(os.environ.get("PANDORA_BOX_CONFIG", DEFAULT_CONFIG_PATH)),
        help=f"configuration file (default: {DEFAULT_CONFIG_PATH})",
    )
    parser.add_argument(
        "--state",
        type=Path,
        default=STATE_PATH,
        help=f"position of the last entry sent (default: {STATE_PATH})",
    )
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config)
    except ConfigError as ex:
        _say(str(ex))
        return 2
    siem = config.siem
    if not siem.enabled:
        _say("the SIEM export is disabled (siem.enabled)")
        return 0
    log_file = config.logging.file
    if log_file is None:  # refused with the configuration
        return 2
    try:
        sender = Sender(siem)
    except (OSError, ssl.SSLError) as ex:
        _say(f"siem.ca: {ex}")
        return 2

    stop = threading.Event()

    def on_signal(signum: int, frame: FrameType | None) -> None:
        stop.set()

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)
    _say(f"sending {log_file} to {siem.host}:{siem.server_port} ({siem.transport}, {siem.format})")
    run(siem, log_file, config.kiosk.name, args.state, stop, sender)
    return 0
