"""USB devices refused by USBGuard, reported in the kiosk log.

USBGuard blocks every USB device but storage devices and hubs (BadUSB:
keyboards, network adapters, a key that is also a keyboard) and writes its
decisions to its audit log, which only root can read and which the SIEM
export does not send. The kiosk follows that log and logs each refused device
as a usb_device_blocked event: on the maintenance export and in the SIEM
with the other events.

A line of the audit log (src/Daemon/FileAuditBackend.cpp of USBGuard, keys
in alphabetical order, each value between single quotes, not escaped):

    [1730638380.123] (A) uid=0 pid=708 device.rule='block id 046d:c31c
    serial "" name "USB Keyboard" hash "..." parent-hash "..." via-port "1-2"
    with-interface { 03:01:01 03:00:00 } with-connect-type "hotplug"'
    device.system_name='/devices/...' result='SUCCESS' target.new='block'
    target.old='block' type='Policy.Device.Update'

The strings of the device (its name, its serial number) are between double
quotes, with their double quotes, backslashes and unprintable characters
escaped: a device cannot end the value with a single quote of its name.
"""

from __future__ import annotations

import logging
import os
import re
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pandora_box.follow import LogFollower, load_position, save_position
from pandora_box.logs import get_logger, log_event

logger = get_logger("usbguard")

AUDIT_LOG = Path("/var/log/usbguard/usbguard-audit.log")
# Position of the last line read (StateDirectory of pandora-box.service)
STATE_PATH = Path("/var/lib/pandora-box/usbguard-audit.json")
# Time between two reads of the audit log at its end, in seconds
POLL_SECONDS = 1.0
# Lines read at once, between two saves of the position
BATCH = 100

# Decisions of USBGuard that refuse a device
REFUSED = frozenset({"block", "reject"})

# Kinds of the USB interface classes (class:subclass:protocol), for the reader
# of the log: what the device wanted to be
CLASSES = {
    "01": "audio",
    "02": "communications",
    "03": "hid",
    "05": "physical",
    "06": "image",
    "07": "printer",
    "08": "storage",
    "09": "hub",
    "0a": "communications-data",
    "0b": "smart-card",
    "0d": "content-security",
    "0e": "video",
    "0f": "healthcare",
    "10": "audio-video",
    "11": "billboard",
    "12": "usb-c-bridge",
    "dc": "diagnostic",
    "e0": "wireless",
    "ef": "miscellaneous",
    "fe": "application-specific",
    "ff": "vendor-specific",
}
SET_OPERATORS = frozenset({"all-of", "one-of", "none-of", "equals", "equals-ordered", "match-all"})
_HEADER = re.compile(r"\[(\d+(?:\.\d+)?)\]\s+\(A\)\s+")
_KEY = re.compile(r"\s*([A-Za-z][\w.]*)=")


def parse_audit_line(line: str) -> tuple[float | None, dict[str, str]]:
    """The time and the key='value' pairs of a line of the audit log.

    A single quote inside a double-quoted string of a value does not end
    the value.
    """
    moment: float | None = None
    header = _HEADER.match(line)
    position = 0
    if header is not None:
        moment = float(header.group(1))
        position = header.end()
    fields: dict[str, str] = {}
    while True:
        key = _KEY.match(line, position)
        if key is None:
            break
        position = key.end()
        if line.startswith("'", position):
            value, position = _quoted(line, position + 1)
        else:
            # uid=0 pid=708: not quoted
            end = line.find(" ", position)
            end = len(line) if end < 0 else end
            value, position = line[position:end], end
        fields[key.group(1)] = value
    return moment, fields


def _quoted(line: str, start: int) -> tuple[str, int]:
    """The value starting at start up to its closing single quote, and the next position."""
    position = start
    in_string = False
    while position < len(line):
        char = line[position]
        if in_string:
            if char == "\\":
                position += 1
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char == "'":
            return line[start:position], position + 1
        position += 1
    return line[start:], len(line)


_TOKEN = re.compile(r'\s*(?:"((?:[^"\\]|\\.)*)"|([{}])|([^\s{}"]+))')


def _unescape(value: str) -> str:
    """A string of a USBGuard rule: \\" \\\\ and \\xHH (bytes, UTF-8)."""
    raw = bytearray()
    position = 0
    while position < len(value):
        char = value[position]
        if char == "\\" and value.startswith("x", position + 1):
            try:
                raw.append(int(value[position + 2 : position + 4], 16))
                position += 4
                continue
            except ValueError:
                pass
        if char == "\\" and position + 1 < len(value):
            position += 1
            char = value[position]
        raw.extend(char.encode())
        position += 1
    return raw.decode("utf-8", errors="replace")


def parse_rule(rule: str) -> dict[str, Any]:
    """The target and the attributes of a device rule of USBGuard.

    Attributes with several values (with-interface { ... }) are lists.
    """
    tokens: list[tuple[str, str]] = []  # (kind, value): string, brace, word
    for match in _TOKEN.finditer(rule):
        string, brace, word = match.groups()
        if string is not None:
            tokens.append(("string", _unescape(string)))
        elif brace is not None:
            tokens.append(("brace", brace))
        elif word is not None:
            tokens.append(("word", word))
    parsed: dict[str, Any] = {}
    if not tokens or tokens[0][0] != "word":
        return parsed
    parsed["target"] = tokens[0][1]
    index = 1
    while index < len(tokens):
        kind, name = tokens[index]
        index += 1
        if kind != "word" or index >= len(tokens):
            continue
        # Set operators (with-interface equals { ... }): not in device rules
        if tokens[index][0] == "word" and tokens[index][1] in SET_OPERATORS:
            index += 1
        if index < len(tokens) and tokens[index] == ("brace", "{"):
            values = []
            index += 1
            while index < len(tokens) and tokens[index] != ("brace", "}"):
                values.append(tokens[index][1])
                index += 1
            index += 1
            parsed[name] = values
        elif index < len(tokens):
            parsed[name] = tokens[index][1]
            index += 1
    return parsed


def interface_kind(interface: str) -> str:
    """What an interface (class:subclass:protocol) is: keyboard, storage..."""
    parts = interface.lower().split(":")
    usb_class = parts[0]
    if usb_class == "03" and len(parts) == 3:
        # Boot protocol of HID devices; a keyboard of the report protocol
        # only shows as hid
        if parts[2] == "01":
            return "keyboard"
        if parts[2] == "02":
            return "mouse"
    return CLASSES.get(usb_class, "unknown")


def refused_device(line: str) -> dict[str, Any] | None:
    """The fields of the usb_device_blocked event of a line, or None."""
    moment, fields = parse_audit_line(line)
    if fields.get("type") != "Policy.Device.Update" or fields.get("result") != "SUCCESS":
        return None
    target = fields.get("target.new", "")
    if target not in REFUSED:
        return None
    rule = fields.get("device.rule", "")
    attributes = parse_rule(rule)
    interfaces = attributes.get("with-interface", [])
    if isinstance(interfaces, str):
        interfaces = [interfaces]
    kinds = sorted({interface_kind(i) for i in interfaces})
    port = attributes.get("via-port", "")
    event: dict[str, Any] = {
        "target": target,
        "usb_id": attributes.get("id", ""),
        "model": attributes.get("name", ""),
        "serial": attributes.get("serial", ""),
        "port": port if isinstance(port, str) else " ".join(port),
        "interfaces": interfaces,
        "kinds": kinds,
        # A storage device with another function: a key that is also a keyboard
        "composite": "storage" in kinds and len(kinds) > 1,
        "connect_type": attributes.get("with-connect-type", ""),
        "system_name": fields.get("device.system_name", ""),
        "rule": rule,
    }
    if moment is not None:
        event["blocked_at"] = datetime.fromtimestamp(moment, UTC).isoformat()
    return event


class AuditWatcher:
    """Follow the audit log of USBGuard in a thread and log the refused devices."""

    def __init__(self, audit_log: Path = AUDIT_LOG, state: Path = STATE_PATH) -> None:
        self.audit_log = audit_log
        self.state = state
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._save_failed = False

    @staticmethod
    def available(audit_log: Path = AUDIT_LOG) -> bool:
        """Whether USBGuard writes an audit log this process can read (the kiosk image)."""
        return os.access(audit_log.parent, os.R_OK | os.X_OK)

    def start(self) -> None:
        self._thread = threading.Thread(target=self.run, name="usbguard-audit", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def run(self) -> None:
        def warn(message: str) -> None:
            log_event(logger, "usbguard_audit_lost", logging.WARNING, reason=message)

        follower = LogFollower(self.audit_log, load_position(self.state), warn)
        try:
            while not self._stop.is_set():
                try:
                    lines = follower.read(BATCH)
                except OSError as ex:
                    log_event(logger, "usbguard_audit_error", logging.ERROR, error=str(ex))
                    follower.close()
                    self._stop.wait(POLL_SECONDS * 10)
                    continue
                if not lines:
                    self._stop.wait(POLL_SECONDS)
                    continue
                for line in lines:
                    self.handle(line.decode("utf-8", errors="replace"))
                self._save(follower)
        finally:
            follower.close()

    def handle(self, line: str) -> None:
        try:
            event = refused_device(line)
        except (ValueError, OverflowError) as ex:
            log_event(logger, "usbguard_audit_unreadable", logging.WARNING, error=str(ex))
            return
        if event is not None:
            log_event(logger, "usb_device_blocked", logging.WARNING, **event)

    def _save(self, follower: LogFollower) -> None:
        position = follower.position()
        if position is None:
            return
        try:
            save_position(self.state, position)
        except OSError as ex:
            if not self._save_failed:
                # The refused devices are still logged, maybe twice after a restart
                log_event(logger, "usbguard_audit_error", logging.ERROR, error=str(ex))
                self._save_failed = True
