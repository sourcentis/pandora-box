"""Detection of USB storage devices with udev."""

from __future__ import annotations

import logging
import queue
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol

from pandora_box.device import UsbDevice
from pandora_box.logs import get_logger, log_event

logger = get_logger("monitor")


class Action(StrEnum):
    ADD = "add"
    REMOVE = "remove"
    # No device event for a while: the kiosk may do its background work
    IDLE = "idle"
    # A USB device refused by USBGuard was inserted, then removed
    # (pandora_box.usbguard): device describes it, not a filesystem
    REFUSED = "refused"
    REFUSED_REMOVED = "refused_removed"


# Device of the IDLE events
NO_DEVICE = UsbDevice(node="")
# Seconds without device event before an IDLE event
IDLE_INTERVAL = 5.0
# Longest wait for a udev event before the events posted by other threads
POLL_INTERVAL = 0.5
# Longest wait for udev to identify every partition of an inserted key
SETTLE_TIMEOUT = 10.0

# Partitions that hold no files: MBR extended partitions (containers of the
# logical ones), GPT BIOS boot and Microsoft reserved partitions
NOT_DATA_PARTITIONS = frozenset(
    {
        "0x5",
        "0xf",
        "0x85",
        "21686148-6449-6e6f-744e-656564454649",
        "e3c9e316-0b5c-4db8-817d-f92df00215ae",
    }
)

# Called with the node of the disk of a new key, the node and the udev
# properties of its first filesystem: the description of the whole key
KeyDescriber = Callable[[str, str, Mapping[str, Any]], UsbDevice]


@dataclass(frozen=True)
class DeviceEvent:
    action: Action
    device: UsbDevice
    # REFUSED: a storage device with another function (a key that is also a
    # keyboard)
    composite: bool = False


class DeviceSource(Protocol):
    def wait_event(self) -> DeviceEvent | None:
        """Block until a USB filesystem is added or removed (None: stop).

        Sources may also return IDLE events when nothing happens.
        """
        ...


def describe_key(
    disk: str,
    disk_properties: Mapping[str, Any],
    partitions: Sequence[tuple[str, Mapping[str, Any]]],
) -> UsbDevice:
    """The key of a disk and its partitions (node and udev properties, in order).

    A key with a single filesystem is that filesystem, as a key without
    partition table. Partitions without a filesystem the kiosk can mount
    (encrypted, unknown content) are listed as unscannable: a computer may
    still read them.
    """
    if disk_properties.get("ID_FS_USAGE") == "filesystem" or not partitions:
        return UsbDevice.from_udev(disk_properties, disk)
    volumes = []
    unscannable = []
    for node, properties in partitions:
        usage = str(properties.get("ID_FS_USAGE") or "")
        fs_type = str(properties.get("ID_FS_TYPE") or "")
        if usage == "filesystem":
            volumes.append(UsbDevice.from_udev(properties, node))
        elif str(properties.get("ID_PART_ENTRY_TYPE") or "").lower() in NOT_DATA_PARTITIONS:
            continue
        elif usage == "crypto":
            unscannable.append((node, f"encrypted ({fs_type})"))
        else:
            unscannable.append((node, f"unknown content ({fs_type or 'no filesystem'})"))
    if len(volumes) == 1 and not unscannable:
        return volumes[0]
    key = UsbDevice.from_udev(disk_properties, disk)
    return UsbDevice(
        node=disk,
        fs_type=",".join(v.fs_type for v in volumes),
        label=" / ".join(v.label for v in volumes if v.label),
        model=key.model,
        serial=key.serial,
        vendor=key.vendor,
        partitions=tuple(volumes),
        unscannable=tuple(unscannable),
    )


class UsbFilesystemFilter:
    """Select the udev block events of filesystems on USB devices.

    The partitions of a key make one insertion: the first filesystem of a
    disk reports the whole key (describe), the following ones are part of
    it. A removal is matched by the nodes of a reported insertion, not by
    their properties: once a device is ejected, its medium is empty and udev
    drops its filesystem properties before the device is removed. The first
    removal of a node of the key reports its removal.
    """

    def __init__(self, describe: KeyDescriber | None = None) -> None:
        self._describe = describe
        # Disk of each reported key, and the nodes seen on it
        self._keys: dict[str, set[str]] = {}

    def event(
        self,
        action: str,
        node: str | None,
        properties: Mapping[str, Any],
        disk: str | None = None,
    ) -> DeviceEvent | None:
        """disk: the node of the disk of a partition (None: node is a disk)."""
        if not node:
            return None
        disk = disk or node
        if action == Action.ADD:
            if properties.get("ID_FS_USAGE") != "filesystem" or properties.get("ID_BUS") != "usb":
                return None
            if disk in self._keys:
                self._keys[disk].add(node)
                return None
            self._keys[disk] = {disk, node}
            if self._describe is None:
                device = UsbDevice.from_udev(properties, node)
            else:
                device = self._describe(disk, node, properties)
            self._keys[disk].update(v.node for v in device.volumes)
            return DeviceEvent(Action.ADD, device)
        if action == Action.REMOVE:
            for key, nodes in self._keys.items():
                if node in nodes:
                    del self._keys[key]
                    return DeviceEvent(Action.REMOVE, UsbDevice.from_udev(properties, node))
        return None


class UdevSource:
    """Listen to udev block events for filesystems on USB devices.

    Other threads post their events (the devices refused by USBGuard) with
    post: they are returned in order with the udev ones.
    """

    def __init__(self) -> None:
        import pyudev

        self._context = pyudev.Context()
        self._monitor = pyudev.Monitor.from_netlink(self._context)
        self._monitor.filter_by("block")
        self._filter = UsbFilesystemFilter(self._describe)
        self._posted: queue.SimpleQueue[DeviceEvent] = queue.SimpleQueue()

    def post(self, event: DeviceEvent) -> None:
        """Called from any thread."""
        self._posted.put(event)

    def wait_event(self) -> DeviceEvent | None:
        idle_at = time.monotonic() + IDLE_INTERVAL
        while True:
            try:
                return self._posted.get_nowait()
            except queue.Empty:
                pass
            dev = self._monitor.poll(timeout=POLL_INTERVAL)
            if dev is None:
                if time.monotonic() >= idle_at:
                    return DeviceEvent(Action.IDLE, NO_DEVICE)
                continue
            disk = dev.find_parent("block", "disk") if dev.device_type == "partition" else None
            event = self._filter.event(
                dev.action, dev.device_node, dev, None if disk is None else disk.device_node
            )
            if event is not None:
                return event

    def _describe(self, disk: str, node: str, properties: Mapping[str, Any]) -> UsbDevice:
        import pyudev

        try:
            return self._describe_disk(disk)
        except (pyudev.DeviceNotFoundError, LookupError, OSError, ValueError) as ex:
            # Removed meanwhile, or unknown to udev: the filesystem of the event
            log_event(logger, "key_not_described", logging.WARNING, disk=disk, error=str(ex))
            return UsbDevice.from_udev(properties, node)

    def _describe_disk(self, disk: str) -> UsbDevice:
        import pyudev

        # From sysfs, by its kernel name: the node may be gone already
        disk_device = pyudev.Devices.from_name(self._context, "block", disk.rsplit("/", 1)[-1])
        # udev identifies the partitions one after the other: wait for all
        deadline = time.monotonic() + SETTLE_TIMEOUT
        while True:
            partitions = list(
                self._context.list_devices(subsystem="block", DEVTYPE="partition").match_parent(
                    disk_device
                )
            )
            if all(p.is_initialized for p in partitions) or time.monotonic() > deadline:
                break
            time.sleep(0.2)
        partitions.sort(key=lambda p: int(p.attributes.asstring("partition")))
        return describe_key(
            disk,
            disk_device.properties,
            [(p.device_node, p.properties) for p in partitions if p.device_node],
        )
