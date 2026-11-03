from __future__ import annotations

import json
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from pandora_box import usbguard
from pandora_box.logs import redact_key_fields, setup_logging
from pandora_box.usbguard import (
    AuditWatcher,
    interface_kind,
    parse_audit_line,
    parse_rule,
    refused_device,
)

# Lines as USBGuard writes them (FileAuditBackend): keys in alphabetical order
KEYBOARD_RULE = (
    'block id 046d:c31c serial "" name "USB Keyboard" hash "AbC=" parent-hash "dEf=" '
    'via-port "1-2" with-interface { 03:01:01 03:00:00 } with-connect-type "hotplug"'
)
KEYBOARD = (
    "[1730638380.123] (A) uid=0 pid=708 "
    f"device.rule='{KEYBOARD_RULE}' device.system_name='/devices/pci0000:00/usb1/1-2' "
    "result='SUCCESS' target.new='block' target.old='block' type='Policy.Device.Update' "
)
INSERT = (
    "[1730638380.120] (A) uid=0 pid=708 "
    f"device.rule='{KEYBOARD_RULE}' device.system_name='/devices/pci0000:00/usb1/1-2' "
    "result='SUCCESS' type='Device.Insert' "
)
STORAGE = (
    '[1730638390.000] (A) uid=0 pid=708 device.rule=\'allow id 0781:5581 serial "4C53" '
    'name "Ultra" hash "x" parent-hash "y" via-port "2-1" with-interface 08:06:50 '
    "with-connect-type \"hotplug\"' device.system_name='/devices/pci0000:00/usb2/2-1' "
    "result='SUCCESS' target.new='allow' target.old='block' type='Policy.Device.Update' "
)


def test_parse_audit_line() -> None:
    moment, fields = parse_audit_line(KEYBOARD)
    assert moment == 1730638380.123
    assert fields == {
        "uid": "0",
        "pid": "708",
        "device.rule": KEYBOARD_RULE,
        "device.system_name": "/devices/pci0000:00/usb1/1-2",
        "result": "SUCCESS",
        "target.new": "block",
        "target.old": "block",
        "type": "Policy.Device.Update",
    }
    assert parse_audit_line("") == (None, {})
    assert parse_audit_line("[1.5] (A) Daemon: Start") == (1.5, {})


def test_a_device_cannot_end_its_value() -> None:
    # A single quote and fake fields in the name of the device (BadUSB)
    rule = (
        "block id 1234:5678 serial \"\" name \"x' target.new='allow' type='Device.Remove\" "
        "with-interface 03:01:01"
    )
    line = (
        f"[1.0] (A) uid=0 pid=1 device.rule='{rule}' result='SUCCESS' "
        "target.new='block' type='Policy.Device.Update' "
    )
    _, fields = parse_audit_line(line)
    assert fields["device.rule"] == rule
    assert fields["target.new"] == "block"
    event = refused_device(line)
    assert event is not None
    assert event["model"] == "x' target.new='allow' type='Device.Remove"


def test_parse_rule() -> None:
    assert parse_rule(KEYBOARD_RULE) == {
        "target": "block",
        "id": "046d:c31c",
        "serial": "",
        "name": "USB Keyboard",
        "hash": "AbC=",
        "parent-hash": "dEf=",
        "via-port": "1-2",
        "with-interface": ["03:01:01", "03:00:00"],
        "with-connect-type": "hotplug",
    }
    # Escaped strings: quote, backslash, bytes of UTF-8
    parsed = parse_rule(r'block name "a\"b\\c \xc3\xa9" with-interface equals { 08:06:50 }')
    assert parsed == {"target": "block", "name": 'a"b\\c é', "with-interface": ["08:06:50"]}
    assert parse_rule("") == {}


def test_interface_kind() -> None:
    assert interface_kind("03:01:01") == "keyboard"
    assert interface_kind("03:01:02") == "mouse"
    assert interface_kind("03:00:00") == "hid"
    assert interface_kind("08:06:50") == "storage"
    assert interface_kind("E0:01:01") == "wireless"
    assert interface_kind("77:00:00") == "unknown"


def test_refused_device() -> None:
    assert refused_device(KEYBOARD) == {
        "target": "block",
        "usb_id": "046d:c31c",
        "model": "USB Keyboard",
        "serial": "",
        "port": "1-2",
        "interfaces": ["03:01:01", "03:00:00"],
        "kinds": ["hid", "keyboard"],
        "composite": False,
        "connect_type": "hotplug",
        "system_name": "/devices/pci0000:00/usb1/1-2",
        "rule": KEYBOARD_RULE,
        "blocked_at": "2024-11-03T12:53:00.123000+00:00",
    }
    # The insertion itself, an allowed device, a daemon message: nothing
    assert refused_device(INSERT) is None
    assert refused_device(STORAGE) is None
    assert refused_device("[1.0] (A) Daemon: Start") is None
    assert refused_device(KEYBOARD.replace("SUCCESS", "FAILURE")) is None
    rejected = refused_device(KEYBOARD.replace("target.new='block'", "target.new='reject'"))
    assert rejected is not None and rejected["target"] == "reject"


def test_composite_key() -> None:
    # A key that is also a keyboard (USB Rubber Ducky)
    line = KEYBOARD.replace("{ 03:01:01 03:00:00 }", "{ 08:06:50 03:01:01 }")
    event = refused_device(line)
    assert event is not None
    assert event["kinds"] == ["keyboard", "storage"]
    assert event["composite"] is True


def _entries(log: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in log.read_text().splitlines()]


def _wait(predicate: object, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while not predicate():  # type: ignore[operator]
        assert time.monotonic() < deadline, "timeout"
        time.sleep(0.01)


@pytest.fixture
def kiosk_log(tmp_path: Path) -> Iterator[Path]:
    log = tmp_path / "pandora-box.log"
    setup_logging("kiosk-1", "INFO", log)
    yield log
    setup_logging("kiosk-1", "INFO", None)


def test_watcher(tmp_path: Path, kiosk_log: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(usbguard, "POLL_SECONDS", 0.01)
    audit = tmp_path / "usbguard-audit.log"
    state = tmp_path / "state.json"
    audit.write_text(INSERT + "\n" + KEYBOARD + "\n" + STORAGE + "\n")
    watcher = AuditWatcher(audit, state)
    watcher.start()
    try:
        _wait(lambda: kiosk_log.exists() and kiosk_log.read_text())
        # A line being written is read once complete
        with audit.open("a") as file:
            file.write(KEYBOARD.replace("1-2", "1-3"))
            file.flush()
            time.sleep(0.05)
            file.write("\n")
        _wait(lambda: len(_entries(kiosk_log)) == 2)
    finally:
        watcher.stop()
    first, second = _entries(kiosk_log)
    assert first["event"] == "usb_device_blocked"
    assert first["level"] == "WARNING"
    assert first["kiosk"] == "kiosk-1"
    assert first["usb_id"] == "046d:c31c"
    assert second["port"] == "1-3"
    assert json.loads(state.read_text())["offset"] == audit.stat().st_size

    # Restarted: the devices already logged are not logged again
    with audit.open("a") as file:
        file.write(KEYBOARD.replace("1-2", "1-4") + "\n")
    watcher = AuditWatcher(audit, state)
    watcher.start()
    try:
        _wait(lambda: len(_entries(kiosk_log)) == 3)
        time.sleep(0.05)
    finally:
        watcher.stop()
    entries = _entries(kiosk_log)
    assert len(entries) == 3
    assert entries[2]["port"] == "1-4"


def test_watcher_without_audit_log(tmp_path: Path, kiosk_log: Path) -> None:
    # USBGuard has not written its log yet
    watcher = AuditWatcher(tmp_path / "missing.log", tmp_path / "state.json")
    watcher.start()
    watcher.stop()
    assert not kiosk_log.exists() or not kiosk_log.read_text()


def test_station_redacts_the_device(kiosk_log: Path, tmp_path: Path) -> None:
    redact_key_fields(True)
    try:
        AuditWatcher(tmp_path / "a.log", tmp_path / "s.json").handle(KEYBOARD)
    finally:
        redact_key_fields(False)
    (entry,) = _entries(kiosk_log)
    assert entry["model"] == entry["serial"] == entry["rule"] == "[redacted]"
    assert entry["usb_id"] == "046d:c31c"
    assert entry["kinds"] == ["hid", "keyboard"]


def test_available(tmp_path: Path) -> None:
    assert AuditWatcher.available(tmp_path / "audit.log")
    assert not AuditWatcher.available(tmp_path / "missing" / "audit.log")
