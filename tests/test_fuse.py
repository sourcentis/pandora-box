from __future__ import annotations

import pwd
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, cast

import pytest

from pandora_box import device as device_module
from pandora_box import fuse
from pandora_box.device import DeviceError, Mounter, UsbDevice
from pandora_box.fuse import (
    FuseDriver,
    FuseError,
    connection_id,
    driver_command,
    sandbox_options,
    start_driver,
)
from pandora_box.sandbox import Sandbox


@pytest.fixture
def scan_user(monkeypatch: pytest.MonkeyPatch) -> None:
    def getpwnam(name: str) -> pwd.struct_passwd:
        return pwd.struct_passwd((name, "x", 990, 990, "", "/", "/usr/sbin/nologin"))

    monkeypatch.setattr(pwd, "getpwnam", getpwnam)


def test_driver_commands() -> None:
    assert driver_command("ext4", "/dev/sdb1", 5, True, 990) == [
        "/usr/bin/fuse2fs",
        "-f",
        "-o",
        "ro",
        "/dev/sdb1",
        "/dev/fd/5",
    ]
    assert driver_command("ext4", "/dev/sdb1", 5, False, 990)[2:] == ["/dev/sdb1", "/dev/fd/5"]
    assert driver_command("exfat", "/dev/sdb1", 5, True, 990) == [
        "/usr/sbin/mount.exfat-fuse",
        "-o",
        "ro,uid=0,gid=990,fmask=0137,dmask=0027",
        "/dev/sdb1",
        "/dev/fd/5",
    ]
    # ntfs-3g gets the connection from the preloaded library, not as mount point
    assert driver_command("ntfs", "/dev/sdb1", 5, False, 0) == [
        "/usr/bin/env",
        "LD_PRELOAD=/usr/lib/pandora-box/fuse-premounted.so",
        "PANDORA_BOX_FUSE_FD=5",
        "/usr/bin/ntfs-3g",
        "-o",
        "no_detach,uid=0,gid=0,fmask=0137,dmask=0027",
        "/dev/sdb1",
        "/mnt",
    ]
    with pytest.raises(ValueError, match="vfat"):
        driver_command("vfat", "/dev/sdb1", 5, True, 0)


def test_start_driver(scan_user: None, monkeypatch: pytest.MonkeyPatch) -> None:
    started: dict[str, Any] = {}

    def popen(argv: list[str], **kwargs: Any) -> Any:
        started.update(argv=argv, **kwargs)
        return type("Process", (), {"pid": 42})()

    monkeypatch.setattr(subprocess, "Popen", popen)
    real_stat = Path.stat

    def stat(path: Path, **kwargs: Any) -> Any:
        if str(path) == "/dev/sdb1":
            return type("Stat", (), {"st_gid": 6})()
        return real_stat(path, **kwargs)

    monkeypatch.setattr(Path, "stat", stat)
    monkeypatch.setattr(fuse, "FuseDriver", lambda process, name, *args: name)
    name: Any = start_driver(
        Sandbox("pandora-box-scan"), "ntfs", "/dev/sdb1", 7, Path("/media/k"), True, 990, 60
    )
    assert name == "ntfs-3g"
    argv = started["argv"]
    assert started["pass_fds"] == (7,)
    text = " ".join(argv)
    # The block device is the only device; the user gets its group only
    assert "--dev-bind /dev/sdb1 /dev/sdb1" in text
    assert "--groups=6" in argv
    assert "--clear-groups" not in argv
    # The library is preloaded into ntfs-3g only, not into bubblewrap
    setpriv = argv.index("setpriv")
    assert "LD_PRELOAD" not in " ".join(argv[:setpriv])
    assert argv[argv.index("--no-new-privs") + 2 :][:4] == [
        sys.executable,
        "-m",
        "pandora_box.fuse",
        "/usr/bin/env",
    ]


def test_sandbox_options() -> None:
    options = sandbox_options("/dev/sdc")
    assert options[:3] == ["--dev-bind", "/dev/sdc", "/dev/sdc"]
    assert "/etc/passwd" in options
    assert options[-4:] == ["--perms", "0777", "--dir", "/mnt"]


def test_connection_id(tmp_path: Path) -> None:
    mountinfo = tmp_path / "mountinfo"
    mountinfo.write_text(
        "24 1 254:2 / / ro,relatime - erofs /dev/dm-0 ro\n"
        "40 24 0:52 / /media/pandora\\040box rw,nosuid - fuse.ntfs /dev/sdb1 rw,user_id=0\n"
    )
    assert connection_id(Path("/media/pandora box"), mountinfo) == "52"
    assert connection_id(Path("/"), mountinfo) == str((254 << 20) | 2)
    assert connection_id(Path("/media/other"), mountinfo) is None
    assert connection_id(Path("/"), tmp_path / "missing") is None


def process(code: str) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        [sys.executable, "-c", code], stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )


def driver(
    tmp_path: Path,
    code: str,
    waiting: str = "0",
    timeout: float = 5.0,
    mount_point: Path | None = None,
) -> FuseDriver:
    (tmp_path / "conn" / "52").mkdir(parents=True, exist_ok=True)
    (tmp_path / "conn" / "52" / "waiting").write_text(waiting)
    (tmp_path / "block" / "sdb1").mkdir(parents=True, exist_ok=True)
    (tmp_path / "block" / "sdb1" / "stat").write_text("10 0 80 0 0 0 0 0 0 0 0\n")
    mount_point = mount_point or tmp_path
    mountinfo = tmp_path / "mountinfo"
    mountinfo.write_text(f"40 24 0:52 / {mount_point} rw - fuse.ext4 /dev/sdb1 rw\n")
    return FuseDriver(
        process(code),
        "fuse2fs",
        "/dev/sdb1",
        mount_point,
        timeout,
        connections=tmp_path / "conn",
        block_devices=tmp_path / "block",
        mountinfo=mountinfo,
        poll=0.05,
    )


def test_driver_ready_and_stopped(tmp_path: Path) -> None:
    d = driver(tmp_path, "import time; time.sleep(0.5)")
    d.wait_ready()
    d.stop()
    assert d.failure is None


def test_driver_failed_to_start(tmp_path: Path) -> None:
    code = "print('Journal needs recovery; running e2fsck is required.'); raise SystemExit(3)"
    d = driver(tmp_path, code, mount_point=tmp_path / "missing")
    with pytest.raises(FuseError, match="fuse2fs: Journal needs recovery") as raised:
        d.wait_ready()
    assert "Journal needs recovery" in raised.value.output


def test_driver_crash_is_reported(tmp_path: Path) -> None:
    d = driver(tmp_path, "import time; time.sleep(0.2); raise SystemExit(-11 % 256)")
    deadline = time.monotonic() + 5
    while d.failure is None and time.monotonic() < deadline:
        time.sleep(0.05)
    assert d.failure == "fuse2fs stopped (exit status 245)"


def test_stuck_driver_is_killed(tmp_path: Path) -> None:
    """Requests waiting, the device idle: the driver no longer answers."""
    d = driver(tmp_path, "import time; time.sleep(30)", waiting="1", timeout=0.3)
    deadline = time.monotonic() + 5
    while d.process.poll() is None and time.monotonic() < deadline:
        time.sleep(0.05)
    assert d.process.returncode is not None
    assert d.failure == "fuse2fs not answering for 0.3s"


def test_busy_driver_is_not_killed(tmp_path: Path) -> None:
    """Requests waiting while the device reads: a slow device, not a stuck driver."""
    # The I/O counters move 20 times per timeout: a CI runner busy enough to
    # delay this thread for a whole second is not a realistic case
    unmounted = tmp_path / "unmounted"
    code = f"import os, time\nwhile not os.path.exists({str(unmounted)!r}): time.sleep(0.05)"
    d = driver(tmp_path, code, waiting="1", timeout=1.0)
    stat = tmp_path / "block" / "sdb1" / "stat"
    sectors = 0
    deadline = time.monotonic() + 2 * d.timeout
    while time.monotonic() < deadline:
        sectors += 1
        stat.write_text(f"10 0 {sectors} 0 0 0 0 0 0 0 0\n")
        time.sleep(0.05)
    assert d.process.poll() is None
    unmounted.touch()
    d.stop()
    assert d.failure is None


def test_reap_waits_for_background_processes() -> None:
    """exfat-fuse goes to the background: the sandbox must stay."""
    result = subprocess.run(
        [sys.executable, "-m", "pandora_box.fuse", "/bin/sh", "-c", "(sleep 0.3; echo served) &"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0
    assert result.stdout == "served\n"
    status = subprocess.run([sys.executable, "-m", "pandora_box.fuse", "/bin/sh", "-c", "exit 3"])
    assert status.returncode == 3


class FakeDriver:
    name = "ntfs-3g"
    failure: str | None = None

    def __init__(self, error: FuseError | None = None) -> None:
        self.error = error
        self.stopped = False

    def wait_ready(self) -> None:
        if self.error is not None:
            raise self.error

    def unmounting(self) -> None:
        pass

    def stop(self) -> None:
        self.stopped = True


def fuse_mounter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, driver: FakeDriver
) -> tuple[Mounter, list[list[str]]]:
    calls: list[list[str]] = []
    (tmp_path / "fuse").write_text("")
    monkeypatch.setattr(device_module, "FUSE_DEVICE", str(tmp_path / "fuse"))
    monkeypatch.setattr(subprocess, "run", lambda argv, **kwargs: calls.append(argv))
    monkeypatch.setattr(
        device_module,
        "mount_connection",
        lambda fd, fs_type, node, path, ro: calls.append(["mount", fs_type, node, str(path), ro]),
    )
    monkeypatch.setattr(
        device_module, "unmount_connection", lambda path: calls.append(["umount", str(path)])
    )
    monkeypatch.setattr(device_module, "start_driver", lambda *args: driver)
    media = tmp_path / "media"
    media.mkdir()
    sandbox = Sandbox("pandora-box-scan")
    return Mounter(media, ["ntfs", "ext4", "vfat"], fuse=sandbox, reader_gid=990), calls


def test_fuse_mount(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeDriver()
    mounter, calls = fuse_mounter(tmp_path, monkeypatch, fake)
    mounter.mount(UsbDevice("/dev/sdb1", "ntfs"))
    assert calls[0] == ["/usr/sbin/blockdev", "--setro", "/dev/sdb1"]
    # The kiosk mounts the connection
    assert calls[1] == ["mount", "ntfs", "/dev/sdb1", str(mounter.mount_point), True]
    assert mounter.driver is cast(Any, fake)
    fake.failure = "ntfs-3g stopped (exit status 139)"
    assert mounter.failure == fake.failure

    monkeypatch.setattr(device_module, "find_mount_point", lambda path: ["ro"])
    mounter.unmount()
    assert calls[-1] == ["umount", str(mounter.mount_point)]
    assert fake.stopped
    assert mounter.driver is None


def test_vfat_stays_in_the_kernel(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    mounter, calls = fuse_mounter(tmp_path, monkeypatch, FakeDriver())
    mounter.mount(UsbDevice("/dev/sdb1", "vfat"))
    assert calls[1][:3] == ["/usr/bin/mount", "-t", "vfat"]
    assert mounter.driver is None


def test_fuse_journal_to_replay(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    error = FuseError(
        "fuse2fs: Journal needs recovery; running `e2fsck -E journal_only' is required.",
        "Mounting read-only.\nJournal needs recovery; running `e2fsck -E journal_only' is"
        " required.\n",
    )
    mounter, calls = fuse_mounter(tmp_path, monkeypatch, FakeDriver(error))
    with pytest.raises(DeviceError, match="ext4 journal to replay"):
        mounter.mount(UsbDevice("/dev/sdb1", "ext4"))
    # The connection is unmounted
    assert calls[-1] == ["umount", str(mounter.mount_point)]
    assert mounter.driver is None
    assert mounter.device is None


def test_fuse_driver_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    error = FuseError("ntfs-3g: Failed to read NTFS boot sector", "")
    mounter, calls = fuse_mounter(tmp_path, monkeypatch, FakeDriver(error))
    with pytest.raises(DeviceError, match="ntfs-3g: Failed to read NTFS boot sector"):
        mounter.mount(UsbDevice("/dev/sdb1", "ntfs"))
    assert calls[-1][0] == "umount"


def test_mount_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[object, ...]] = []
    monkeypatch.setattr(fuse, "_libc", lambda *args: calls.append(args))
    fuse.mount_connection(7, "exfat", "/dev/sdb1", Path("/media/k"), True)
    fuse.mount_connection(7, "exfat", "/dev/sdb1", Path("/media/k"), False)
    fuse.unmount_connection(Path("/media/k"))
    data = b"fd=7,rootmode=40000,user_id=0,group_id=0,allow_other"
    # ro, nosuid, nodev, noexec; read-write to clean
    assert calls == [
        ("mount", b"/dev/sdb1", b"/media/k", b"fuse.exfat", 15, data),
        ("mount", b"/dev/sdb1", b"/media/k", b"fuse.exfat", 14, data),
        ("umount2", b"/media/k", 0),
    ]


def test_mount_error(tmp_path: Path) -> None:
    with pytest.raises(FuseError, match=r"^umount2: (Operation not permitted|Invalid argument)$"):
        fuse.unmount_connection(tmp_path)
