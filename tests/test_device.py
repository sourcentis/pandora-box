from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from pandora_box.device import (
    ENUMERATED_AGAIN,
    REMOVED,
    DeviceError,
    Mounter,
    SystemMountWatcher,
    UsbDevice,
    UsbIdentity,
    find_mount,
    identity_change,
    mount_options,
    usb_identity,
)


def test_mount_options_vfat() -> None:
    options = mount_options("vfat", read_only=True, uid=1000, gid=1000)
    assert options[:4] == ["ro", "noexec", "nosuid", "nodev"]
    assert "uid=1000" in options
    assert "utf8" in options


def test_mount_options_ext4() -> None:
    assert mount_options("ext4", read_only=False, uid=0, gid=0) == [
        "rw",
        "noexec",
        "nosuid",
        "nodev",
    ]


def test_from_udev() -> None:
    device = UsbDevice.from_udev(
        {"ID_FS_TYPE": "vfat", "ID_FS_LABEL": "KEY", "ID_MODEL": "Flash", "ID_SERIAL_SHORT": "42"},
        "/dev/sdb1",
    )
    assert device == UsbDevice("/dev/sdb1", "vfat", "KEY", "Flash", "42", "")


def test_rejects_filesystem(tmp_path: Path) -> None:
    mounter = Mounter(tmp_path, ["vfat"])
    with pytest.raises(DeviceError, match="filesystem not allowed: ntfs"):
        mounter.mount(UsbDevice("/dev/sdb1", "ntfs"))


def test_mount_command(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def fake_run(argv: list[str], **kwargs: Any) -> None:
        calls.append(argv)

    monkeypatch.setattr(subprocess, "run", fake_run)
    mounter = Mounter(tmp_path, ["ntfs"], use_sudo=True)
    mounter.mount(UsbDevice("/dev/sdb1", "ntfs"))
    # The block device is read-only first
    assert calls[0] == ["/usr/bin/sudo", "-n", "/usr/sbin/blockdev", "--setro", "/dev/sdb1"]
    argv = calls[1]
    assert argv[:5] == ["/usr/bin/sudo", "-n", "/usr/bin/mount", "-t", "ntfs3"]
    assert argv[5] == "-o"
    assert argv[6].startswith("ro,noexec,nosuid,nodev,")
    assert argv[7:] == ["/dev/sdb1", str(tmp_path)]


def test_mount_read_write(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """To clean, the block device is writable again before the mount."""
    calls: list[list[str]] = []
    monkeypatch.setattr(subprocess, "run", lambda argv, **kwargs: calls.append(argv))
    Mounter(tmp_path, ["vfat"]).mount(UsbDevice("/dev/sdb1", "vfat"), read_only=False)
    assert calls[0] == ["/usr/sbin/blockdev", "--setrw", "/dev/sdb1"]
    assert calls[1][:4] == ["/usr/bin/mount", "-t", "vfat", "-o"]
    assert calls[1][4].startswith("rw,noexec,")


def test_mount_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(argv: list[str], **kwargs: Any) -> None:
        raise subprocess.CalledProcessError(32, argv, stderr="wrong fs type")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(DeviceError, match="wrong fs type"):
        Mounter(tmp_path, ["vfat"]).mount(UsbDevice("/dev/sdb1", "vfat"))


def test_ext4_journal_to_replay(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """An ext4 journal to replay cannot be mounted on a read-only block device."""

    def fake_run(argv: list[str], **kwargs: Any) -> None:
        if argv[0] == "/usr/bin/mount":
            raise subprocess.CalledProcessError(
                32, argv, stderr="mount: /media/k: cannot mount /dev/sdb1 read-only."
            )

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(DeviceError, match="ext4 journal to replay"):
        Mounter(tmp_path, ["ext4"]).mount(UsbDevice("/dev/sdb1", "ext4"))


def test_missing_mount_point(tmp_path: Path) -> None:
    with pytest.raises(DeviceError, match="does not exist"):
        Mounter(tmp_path / "missing", ["vfat"]).mount(UsbDevice("/dev/sdb1", "vfat"))


def mounts_file(tmp_path: Path, node: str, mount_point: Path, options: str = "rw,nosuid") -> Path:
    escaped = str(mount_point).replace(" ", "\\040")
    path = tmp_path / "mounts"
    path.write_text(f"proc /proc proc rw 0 0\n{node} {escaped} vfat {options} 0 0\n")
    return path


def test_find_mount(tmp_path: Path) -> None:
    mounts = mounts_file(tmp_path, "/dev/sdb1", Path("/media/didier/MY KEY"))
    assert find_mount("/dev/sdb1", mounts) == (Path("/media/didier/MY KEY"), ["rw", "nosuid"])
    assert find_mount("/dev/sdc1", mounts) is None
    assert find_mount("/dev/sdb1", tmp_path / "missing") is None


def test_system_mount(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    key = tmp_path / "key"
    key.mkdir()
    mounts = mounts_file(tmp_path, "/dev/sdb1", key)
    calls: list[list[str]] = []

    def udisksctl(argv: list[str], **kwargs: Any) -> None:
        calls.append(argv)
        if argv[1] == "unmount":
            mounts.write_text("")
        else:
            mounts_file(tmp_path, "/dev/sdb1", key)

    monkeypatch.setattr(subprocess, "run", udisksctl)
    watcher = SystemMountWatcher(["vfat"], mounts=mounts)
    device = UsbDevice("/dev/sdb1", "vfat")
    # Mounted by the system at insertion: no command
    watcher.mount(device)
    assert calls == []
    assert watcher.mount_point == key
    assert watcher.is_mounted()
    # Unmounted, then mounted again (read-write) through udisks
    watcher.unmount()
    assert watcher.device is None
    watcher.mount(device, read_only=False)
    watcher.unmount()
    assert calls == [
        ["/usr/bin/udisksctl", "unmount", "--no-user-interaction", "-b", "/dev/sdb1"],
        ["/usr/bin/udisksctl", "mount", "--no-user-interaction", "-b", "/dev/sdb1"],
        ["/usr/bin/udisksctl", "unmount", "--no-user-interaction", "-b", "/dev/sdb1"],
    ]


def test_system_mount_timeout(tmp_path: Path) -> None:
    watcher = SystemMountWatcher(["vfat"], wait=0.2, mounts=tmp_path / "empty", poll=0.05)
    (tmp_path / "empty").write_text("")
    with pytest.raises(DeviceError, match=r"not mounted by the system after 0\.2s"):
        watcher.mount(UsbDevice("/dev/sdb1", "vfat"))


def test_system_mount_checks(tmp_path: Path) -> None:
    mounts = mounts_file(tmp_path, "/dev/sdb1", tmp_path, "ro,nosuid")
    watcher = SystemMountWatcher(["vfat"], mounts=mounts)
    with pytest.raises(DeviceError, match="filesystem not allowed: ntfs"):
        watcher.mount(UsbDevice("/dev/sdb1", "ntfs"))
    watcher.mount(UsbDevice("/dev/sdb1", "vfat"))
    with pytest.raises(DeviceError, match="read-only by the system"):
        watcher.mount(UsbDevice("/dev/sdb1", "vfat"), read_only=False)


def test_eject(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr(subprocess, "run", lambda argv, **kwargs: calls.append(argv))
    node = tmp_path / "sdb1"
    node.touch()
    Mounter(tmp_path, ["vfat"], use_sudo=True).eject(UsbDevice(str(node), "vfat"))
    assert calls == [["/usr/bin/sudo", "-n", "/usr/bin/eject", str(node)]]
    # A removed device is not ejected
    Mounter(tmp_path, ["vfat"]).eject(UsbDevice(str(tmp_path / "gone"), "vfat"))
    assert len(calls) == 1


def test_system_eject(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr(subprocess, "run", lambda argv, **kwargs: calls.append(argv))
    node = tmp_path / "sdb1"
    node.touch()
    SystemMountWatcher(["vfat"], mounts=tmp_path / "mounts").eject(UsbDevice(str(node), "vfat"))
    assert calls == [["/usr/bin/udisksctl", "power-off", "--no-user-interaction", "-b", str(node)]]


def _sysfs(tmp_path: Path, devnum: int = 7, node: str = "sdb") -> Path:
    """A sysfs tree: a key on port 1-2 of bus 1, its disk and its partition."""
    sys = tmp_path / "sys"
    port = sys / "devices" / "pci0000:00" / "0000:00:14.0" / "usb1" / "1-2"
    disk = port / "1-2:1.0" / "host6" / "target6:0:0" / "6:0:0:0" / "block" / node
    (disk / f"{node}1").mkdir(parents=True, exist_ok=True)
    for folder, number in ((port.parent, 1), (port, devnum)):
        (folder / "busnum").write_text("1\n")
        (folder / "devnum").write_text(f"{number}\n")
    (sys / "class" / "block").mkdir(parents=True, exist_ok=True)
    for name, target in ((node, disk), (f"{node}1", disk / f"{node}1")):
        link = sys / "class" / "block" / name
        if link.is_symlink():
            link.unlink()
        link.symlink_to(target)
    return sys


def test_usb_identity(tmp_path: Path) -> None:
    sys = _sysfs(tmp_path)
    port = "devices/pci0000:00/0000:00:14.0/usb1/1-2"
    # The USB device of the key, from its disk or its partition: not its interface
    assert usb_identity("/dev/sdb", sys) == UsbIdentity(port, 1, 7)
    assert usb_identity("/dev/sdb1", sys) == UsbIdentity(port, 1, 7)
    assert usb_identity("/dev/sdc", sys) is None


def test_usb_identity_not_on_usb(tmp_path: Path) -> None:
    sys = tmp_path / "sys"
    disk = sys / "devices" / "pci0000:00" / "nvme" / "block" / "nvme0n1"
    disk.mkdir(parents=True)
    (sys / "class" / "block").mkdir(parents=True)
    (sys / "class" / "block" / "nvme0n1").symlink_to(disk)
    assert usb_identity("/dev/nvme0n1", sys) is None


def test_identity_change(tmp_path: Path) -> None:
    sys = _sysfs(tmp_path)
    before = usb_identity("/dev/sdb1", sys)
    assert before is not None
    assert identity_change(before, "/dev/sdb1", sys) is None
    # Enumerated again on the same port: a new device number
    _sysfs(tmp_path, devnum=8)
    assert identity_change(before, "/dev/sdb1", sys) == ENUMERATED_AGAIN


def test_identity_change_new_node(tmp_path: Path) -> None:
    sys = _sysfs(tmp_path)
    before = usb_identity("/dev/sdb1", sys)
    assert before is not None
    # Back as sdc: its node sdb1 is gone, another device is on its port
    shutil.rmtree(sys / "devices")
    (sys / "class" / "block" / "sdb1").unlink()
    _sysfs(tmp_path, devnum=9, node="sdc")
    assert identity_change(before, "/dev/sdb1", sys) == ENUMERATED_AGAIN


def test_identity_change_removed(tmp_path: Path) -> None:
    sys = _sysfs(tmp_path)
    before = usb_identity("/dev/sdb1", sys)
    assert before is not None
    shutil.rmtree(sys / "devices" / "pci0000:00" / "0000:00:14.0" / "usb1" / "1-2")
    assert identity_change(before, "/dev/sdb1", sys) == REMOVED
