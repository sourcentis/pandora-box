from __future__ import annotations

import threading
import time

import pytest

from pandora_box.device import UsbDevice
from pandora_box.monitor import (
    IDLE_INTERVAL,
    Action,
    DeviceEvent,
    UdevSource,
    UsbFilesystemFilter,
    describe_key,
)

USB_VFAT = {"ID_FS_USAGE": "filesystem", "ID_BUS": "usb", "ID_FS_TYPE": "vfat"}


def test_filesystems_on_usb_devices_only() -> None:
    events = UsbFilesystemFilter()
    assert events.event("add", "/dev/sda", {**USB_VFAT, "ID_BUS": "ata"}) is None
    assert events.event("add", "/dev/sda", {"ID_BUS": "usb"}) is None
    assert events.event("add", None, USB_VFAT) is None
    assert events.event("change", "/dev/sda", USB_VFAT) is None
    added = events.event("add", "/dev/sda", USB_VFAT)
    assert added is not None
    assert added.action is Action.ADD
    assert added.device.fs_type == "vfat"


def test_removal_of_an_ejected_device() -> None:
    """After an eject, udev drops the filesystem properties of the empty medium."""
    events = UsbFilesystemFilter()
    events.event("add", "/dev/sda", USB_VFAT)
    removed = events.event("remove", "/dev/sda", {"ID_BUS": "usb"})
    assert removed is not None
    assert removed.action is Action.REMOVE
    assert removed.device.node == "/dev/sda"
    # Reported once
    assert events.event("remove", "/dev/sda", {"ID_BUS": "usb"}) is None


def test_removal_of_an_unknown_device_is_ignored() -> None:
    events = UsbFilesystemFilter()
    assert events.event("remove", "/dev/sdb", USB_VFAT) is None


def test_partitions_of_a_key_make_one_insertion() -> None:
    described: list[tuple[str, str]] = []

    def describe(disk: str, node: str, properties: object) -> UsbDevice:
        described.append((disk, node))
        return UsbDevice(
            "/dev/sdb", partitions=(UsbDevice("/dev/sdb1", "vfat"), UsbDevice("/dev/sdb2", "ext4"))
        )

    events = UsbFilesystemFilter(describe)
    added = events.event("add", "/dev/sdb1", USB_VFAT, disk="/dev/sdb")
    assert added is not None
    assert [v.node for v in added.device.volumes] == ["/dev/sdb1", "/dev/sdb2"]
    # The other partition is part of the key
    assert events.event("add", "/dev/sdb2", USB_VFAT, disk="/dev/sdb") is None
    assert described == [("/dev/sdb", "/dev/sdb1")]
    # The first removal of a node of the key reports it, once
    removed = events.event("remove", "/dev/sdb2", {}, disk="/dev/sdb")
    assert removed is not None and removed.action is Action.REMOVE
    assert events.event("remove", "/dev/sdb1", {}, disk="/dev/sdb") is None
    assert events.event("remove", "/dev/sdb", {}) is None
    # Inserted again: a new key
    assert events.event("add", "/dev/sdb1", USB_VFAT, disk="/dev/sdb") is not None


DISK = {"ID_BUS": "usb", "ID_VENDOR": "Acme", "ID_MODEL": "Key", "ID_SERIAL_SHORT": "42"}


def partition(
    fs_type: str = "", usage: str = "", part_type: str = "0xc", label: str = ""
) -> dict[str, str]:
    return {
        **DISK,
        "ID_FS_TYPE": fs_type,
        "ID_FS_USAGE": usage,
        "ID_PART_ENTRY_TYPE": part_type,
        "ID_FS_LABEL": label,
    }


def test_describe_key_with_one_filesystem() -> None:
    # A partition table with one filesystem: that filesystem, as today
    key = describe_key(
        "/dev/sdb",
        DISK,
        [
            ("/dev/sdb1", partition("vfat", "filesystem", label="DATA")),
            ("/dev/sdb2", partition(part_type="0x5")),
        ],
    )
    assert key == UsbDevice("/dev/sdb1", "vfat", "DATA", "Key", "42", "Acme")
    assert not key.multiple
    # No partition table: the filesystem of the disk
    whole = describe_key(
        "/dev/sdb", {**DISK, "ID_FS_USAGE": "filesystem", "ID_FS_TYPE": "exfat"}, []
    )
    assert whole.node == "/dev/sdb" and whole.fs_type == "exfat"


def test_describe_key_with_several_partitions() -> None:
    key = describe_key(
        "/dev/sdb",
        DISK,
        [
            ("/dev/sdb1", partition("vfat", "filesystem", label="EFI")),
            # MBR extended partition, GPT BIOS boot partition: no files
            ("/dev/sdb2", partition(part_type="0x5")),
            ("/dev/sdb3", partition(part_type="21686148-6449-6E6F-744E-656564454649")),
            ("/dev/sdb5", partition("exfat", "filesystem", label="DATA")),
            ("/dev/sdb6", partition("crypto_LUKS", "crypto")),
            ("/dev/sdb7", partition()),
        ],
    )
    assert key.node == "/dev/sdb"
    assert key.multiple
    assert [v.node for v in key.volumes] == ["/dev/sdb1", "/dev/sdb5"]
    assert key.fs_type == "vfat,exfat"
    assert key.label == "EFI / DATA"
    assert (key.vendor, key.model, key.serial) == ("Acme", "Key", "42")
    assert key.unscannable == (
        ("/dev/sdb6", "encrypted (crypto_LUKS)"),
        ("/dev/sdb7", "unknown content (no filesystem)"),
    )
    # One filesystem and an encrypted partition: still a key with partitions
    key = describe_key(
        "/dev/sdb",
        DISK,
        [
            ("/dev/sdb1", partition("vfat", "filesystem")),
            ("/dev/sdb2", partition("BitLocker", "crypto")),
        ],
    )
    assert key.multiple and [v.name for v in key.volumes] == ["sdb1"]


def test_udev_source_returns_posted_events() -> None:
    # A device refused by USBGuard, posted by the thread of the audit log
    # while the kiosk waits: returned without waiting for an IDLE event
    try:
        source = UdevSource()
    except Exception as ex:  # no netlink socket in this sandbox
        pytest.skip(f"no udev: {ex}")
    event = DeviceEvent(Action.REFUSED, UsbDevice("/devices/usb1/1-2"), composite=True)
    timer = threading.Timer(0.2, source.post, (event,))
    timer.start()
    started = time.monotonic()
    try:
        assert source.wait_event() == event
    finally:
        timer.cancel()
    assert time.monotonic() - started < IDLE_INTERVAL
