"""End-to-end test of a PandoraBox image in a QEMU/KVM virtual machine.

Boots the test image (image/build.sh --profile test) with Secure Boot and the
image signing certificate enrolled, checks its integrity protections, then
plays the whole user workflow with an emulated USB key holding the corpus of
corpus.py: insertion, scan by the real engines, cleaning confirmed with a key
press on the kiosk screen, quarantine, report, eject and removal; then the
cleaned key is inserted again and must be reported clean. Two more boots
check that a modified root filesystem cannot be read and that firmware
trusting another key refuses the image. Run it with image/vm.sh test.
"""

from __future__ import annotations

import argparse
import contextlib
import functools
import hashlib
import json
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Iterator
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import corpus
import keys
from machine import SIGNING_CERTIFICATE, Machine, MachineError, make_key, read_key

# The kiosk code builds and signs the signature sets of the update test
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from pandora_box import sigsets

UPDATE_KEY = Path("image/update.key")
# Signed image updates to the versions 2 to 4 (image/build-test.sh)
IMAGE_UPDATES = Path("image/mkosi.output/updates")


def image_versions() -> list[str]:
    """Versions of the test image and of its updates 2, 3 and 4 (timestamps)."""
    return (IMAGE_UPDATES / "versions").read_text().split()


# Published for the online update test: http://10.0.2.2:8080/ in the machine
PUBLISH_PORT = 8080
SOURCES = "sources"
# The abuse.ch Auth-Key of the test profile (/etc/credstore)
AUTH_KEY = "vm-test-auth-key"
# SIEM of the test profile: syslog over TCP to 10.0.2.2:5514 in the machine
SIEM_PORT = 5514
# Copy of the verified keys to the SFTP server of the test (sftp_server.py):
# 10.0.2.2:2222 in the machine, keys made by image/build-test.sh
AIRGAP_KEYS = Path("image/vm/airgap")
AIRGAP_PORT = 2222
AIRGAP_CONFIG = "/etc/pandora-box/airgap-test.toml"

LOG = "/var/log/pandora-box/pandora-box.log"
# Discoverable Partitions Specification: root partition of x86-64
ROOT_TYPE = "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709"
SECURE_BOOT_VARIABLE = "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
REPORTS = "/var/lib/pandora-box/reports"
# Keys pressed after a reset: the firmware and the boot loader start in it
BOOT_KEYS_DURATION = 15.0


class TestFailure(Exception):
    pass


def check(condition: bool, message: str) -> None:
    if not condition:
        raise TestFailure(message)


def step(message: str) -> None:
    print(f"--- {message}", flush=True)


def events(vm: Machine) -> list[dict[str, Any]]:
    output = vm.shell.run(f"cat {LOG} 2>/dev/null || true")
    return [json.loads(line) for line in output.splitlines() if line.startswith("{")]


def wait_event(
    vm: Machine,
    name: str,
    occurrence: int = 1,
    timeout: float = 120.0,
    action: Callable[[], None] | None = None,
) -> dict[str, Any]:
    """Wait for the nth kiosk log event of that name; run action while waiting."""
    deadline = time.monotonic() + timeout
    while True:
        found = [e for e in events(vm) if e.get("event") == name]
        if len(found) >= occurrence:
            return found[occurrence - 1]
        if time.monotonic() > deadline:
            raise TestFailure(f"kiosk event {name} (#{occurrence}) not logged")
        if action is not None:
            action()
        time.sleep(1.0)


def wait_screen(vm: Machine, text: str, timeout: float = 30.0) -> str:
    """Wait until the kiosk screen shows the text; return its texts."""
    deadline = time.monotonic() + timeout
    while True:
        screen = vm.shell.run("kiosk-screen")
        if text in screen:
            return screen
        if time.monotonic() > deadline:
            raise TestFailure(f"not on the kiosk screen: {text}\n{screen}")
        time.sleep(0.5)


def wait_screen_name(vm: Machine, name: str, timeout: float = 30.0) -> None:
    """Wait until the kiosk shows that screen (a station logs no texts of its screen)."""
    deadline = time.monotonic() + timeout
    while True:
        shown = [e.get("screen") for e in events(vm) if e.get("event") == "display_screen"]
        if shown and shown[-1] == name:
            return
        if time.monotonic() > deadline:
            raise TestFailure(f"screen {name} not shown (last: {shown[-1:]})")
        time.sleep(0.5)


# Color of the header of the built-in theme
HEADER_COLOR = (0x8B, 0x00, 0x19)


def screen_pixels(vm: Machine) -> tuple[int, int, bytes]:
    """Width, height and RGB pixels of the screen of the machine (QMP screendump)."""
    path = vm.workdir / "screen.ppm"
    vm.monitor.execute("screendump", filename=str(path))
    data = path.read_bytes()
    # Binary PPM: "P6", width, height, maximum value, each followed by one
    # whitespace, then the pixels (which may start with whitespace bytes)
    fields = []
    start = 0
    for _ in range(4):
        end = start
        while data[end : end + 1].isspace():
            end += 1
        stop = end
        while not data[stop : stop + 1].isspace():
            stop += 1
        fields.append(data[end:stop])
        start = stop + 1
    magic, width, height, maximum = fields
    check(magic == b"P6" and maximum == b"255", "unexpected screendump format")
    return int(width), int(height), data[start:]


def check_drawn(vm: Machine) -> None:
    """The waiting screen is drawn on the screen, not only logged: its header."""
    deadline = time.monotonic() + 30
    while True:
        width, height, pixels = screen_pixels(vm)
        # Middle of the left of the header, away from the title
        offset = (20 * width + 10) * 3
        color = tuple(pixels[offset : offset + 3])
        if color == HEADER_COLOR:
            break
        check(time.monotonic() < deadline, f"header not drawn on the screen: {color}")
        time.sleep(1.0)
    check((width, height) == (1024, 600), f"screen size: {width}x{height}")
    print(f"waiting screen drawn on the {width}x{height} screen")


def last_report(vm: Machine) -> dict[str, Any]:
    path = vm.shell.run(f"ls -t {REPORTS}/*.json | head -n 1").strip()
    report: dict[str, Any] = json.loads(vm.shell.run(f"cat {path}"))
    return report


def check_boot(vm: Machine, timeout: float) -> None:
    step("boot")
    vm.shell.login(timeout)
    started = wait_event(vm, "kiosk_started", timeout=timeout)
    check(not started["fake_scan"], "the kiosk runs in FAKE_SCAN mode")
    check(started["ready"], "the kiosk cannot scan")
    check(started["signature_set"] == 1, f"signature set: {started['signature_set']}")
    engines = sorted(started["engines"])
    check(
        engines == ["clamav", "hashlookup", "heuristics", "malwarebazaar", "yara"],
        f"unexpected engines: {engines}",
    )
    failed = vm.shell.run("systemctl --failed --no-legend --plain").strip()
    check(not failed, f"failed units:\n{failed}")
    screen = wait_screen(vm, "Please insert a USB key")
    # The test set is new; its ClamAV database has no date (custom
    # signatures only): logged, not shown
    check("WARNING" not in screen, f"warning on the kiosk screen:\n{screen}")
    # The versions of the kiosk, of the system and of the signatures
    system = image_versions()[0]
    built = f"{system[:4]}-{system[4:6]}-{system[6:8]} {system[8:10]}:{system[10:12]} UTC"
    check(f"PandoraBox {system} of {built}" in screen, f"no image version on the screen:\n{screen}")
    check("Signatures: set 1 of " in screen, f"no signature set on the screen:\n{screen}")
    check_drawn(vm)
    check(count_events(vm, "signatures_undated") == 1, "undated ClamAV database not logged")
    print(f"kiosk started with engines {', '.join(engines)}, signature set 1 verified")


def check_integrity(vm: Machine) -> None:
    step("check Secure Boot and dm-verity")
    # The variable holds 4 attribute bytes, then 1 when Secure Boot is enabled
    secure_boot = vm.shell.run(f"od -An -t u1 {SECURE_BOOT_VARIABLE}").split()
    check(secure_boot[-1:] == ["1"], f"Secure Boot is not enabled: {secure_boot}")
    lockdown = vm.shell.run("cat /sys/kernel/security/lockdown").strip()
    check("[none]" not in lockdown, f"kernel lockdown: {lockdown}")
    source = vm.shell.run("findmnt -n -o SOURCE /").strip()
    uuid = vm.shell.run("cat /sys/dev/block/$(mountpoint -d /)/dm/uuid 2>/dev/null || true").strip()
    check(uuid.startswith("CRYPT-VERITY-"), f"root filesystem is not dm-verity: {source} {uuid}")
    check(
        vm.shell.run(f"sha256sum < {corpus.VERITY_CANARY_PATH}").split()[0]
        == hashlib.sha256(corpus.VERITY_CANARY).hexdigest(),
        "cannot read the dm-verity canary",
    )
    print(f"Secure Boot enabled, kernel lockdown {lockdown}, root on dm-verity ({source})")


def root_partition(image: Path) -> tuple[int, int]:
    """Offset and size in bytes of the root partition of a disk image."""
    table = json.loads(
        subprocess.run(
            ["sfdisk", "--json", str(image)], check=True, capture_output=True, text=True
        ).stdout
    )["partitiontable"]
    sector = table.get("sectorsize", 512)
    for partition in table["partitions"]:
        if partition["type"].upper() == ROOT_TYPE:
            return partition["start"] * sector, partition["size"] * sector
    raise TestFailure(f"{image}: no root partition")


def find_canary(image: Path) -> int:
    """Offset in the disk image of the first block of the dm-verity canary file."""
    start, size = root_partition(image)
    chunk = 16 * 1024 * 1024
    overlap = len(corpus.VERITY_CANARY_MARKER)
    with image.open("rb") as disk:
        position = start
        while position < start + size:
            disk.seek(position)
            data = disk.read(chunk + overlap)
            index = data.find(corpus.VERITY_CANARY_MARKER)
            if index >= 0:
                return position + index
            position += chunk
    raise TestFailure(f"{image}: dm-verity canary not found in the root partition")


def check_modified_root(image: Path, workdir: Path, timeout: float) -> None:
    step("modified root filesystem: the modified block cannot be read")
    offset = find_canary(image)

    def modify(disk: Path) -> None:
        # Overwrite the canary on the disk of the machine (the image is unchanged)
        subprocess.run(
            ["qemu-io", "-f", "qcow2", "-c", f"write -P 0x41 {offset} 16", str(disk)],
            check=True,
            capture_output=True,
        )

    with Machine(image, workdir, SIGNING_CERTIFICATE, modify) as vm:
        vm.shell.login(timeout)
        check(
            not vm.shell.succeeds(f"cat {corpus.VERITY_CANARY_PATH}"),
            "the modified canary could be read",
        )
        errors = vm.shell.run("dmesg | grep -i 'verity' | grep -i 'corrupt' || true").strip()
        check(bool(errors), "no dm-verity corruption in the kernel log")
        print(errors.splitlines()[0])


def check_foreign_key(image: Path, workdir: Path, timeout: float) -> None:
    step("firmware trusting another key: the image does not boot")
    workdir.mkdir(parents=True, exist_ok=True)
    certificate = workdir / "foreign.crt"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-subj", "/CN=Foreign key", "-keyout", str(workdir / "foreign.key"),
         "-out", str(certificate)],
        check=True, capture_output=True,
    )  # fmt: skip
    serial = workdir / "serial.log"
    with Machine(image, workdir, certificate) as vm:
        deadline = time.monotonic() + timeout
        while "Access Denied" not in serial.read_text(errors="replace"):
            check(time.monotonic() < deadline, "the firmware did not report Access Denied")
            time.sleep(0.5)
        # Nothing else may start: no shell on the virtio console
        try:
            vm.shell.login(10.0)
        except MachineError:
            pass
        else:
            raise TestFailure("the image booted with firmware trusting another key")
    print("the firmware refused the bootloader: Access Denied")


def check_filesystems(vm: Machine) -> None:
    step("check the filesystems")
    fs_type, options = vm.shell.run("findmnt -n -o FSTYPE,OPTIONS /").split()
    check(fs_type == "erofs" and "ro" in options.split(","), f"root: {fs_type} {options}")
    for path in ("/etc/pandora-box/test", "/usr/test", "/media/test"):
        check(not vm.shell.succeeds(f"touch {path}"), f"{path} is writable")
    fs_type, options = vm.shell.run("findmnt -n -o FSTYPE,OPTIONS /var").split()
    check(fs_type == "ext4" and "rw" in options.split(","), f"/var: {fs_type} {options}")
    # The data partition (1 GB in the image) and its filesystem grew to fill
    # the disk (8 GB, after the two system slots)
    size = int(vm.shell.run("findmnt -n -b -o SIZE /var"))
    check(size > 4 * 1024**3, f"/var was not grown: {size} bytes")
    print(f"root: read-only erofs, /var: ext4, {size / 1024**3:.1f} GiB")


def usb_devices(vm: Machine) -> dict[str, str]:
    """Product name -> authorized flag ("0" or "1") of the USB devices."""
    output = vm.shell.run(
        "for d in /sys/bus/usb/devices/*; do [ -f $d/product ] && "
        'echo "$(cat $d/authorized) $(cat $d/product)"; done; true'
    )
    return {line[2:]: line[0] for line in output.splitlines() if line[1:2] == " "}


def check_airgap(vm: Machine, workdir: Path) -> None:
    """The clean files of a verified key copied to an SFTP server, kept in sync."""
    step("copy of the verified keys to a server (airgap)")
    from sftp_server import SftpServer

    root = workdir / "airgap-server"
    server = SftpServer(root, AIRGAP_PORT, AIRGAP_KEYS / "host", AIRGAP_KEYS / "client.pub")
    # The kiosk and the service read the configuration of the copy, only
    # for this test (runtime drop-ins: the root filesystem is read-only)
    for unit, command in (
        ("pandora-box", f"/usr/bin/pandora-box --config {AIRGAP_CONFIG}"),
        ("pandora-box-airgap", f"/usr/bin/pandora-box-airgap {AIRGAP_CONFIG}"),
    ):
        folder = f"/run/systemd/system/{unit}.service.d"
        vm.shell.run(
            f"mkdir -p {folder} && printf '[Service]\\nExecStart=\\nExecStart={command}\\n'"
            f" > {folder}/50-airgap-test.conf"
        )
    try:
        started = count_events(vm, "kiosk_started")
        vm.shell.run("systemctl daemon-reload && systemctl restart pandora-box-airgap", timeout=60)
        vm.shell.run("systemctl restart pandora-box", timeout=300)
        wait_next_event(vm, "kiosk_started", started, timeout=300)
        wait_screen_name(vm, "ready")
        user = vm.shell.run("ps -o user:32= -p $(systemctl show -P MainPID pandora-box-airgap)")
        check(user.split() == ["pandora-box-airgap"], f"service user: {user}")

        reports_before = vm.shell.run(f"ls {REPORTS} | wc -l").strip()
        image = workdir / "airgap.img"
        make_key(image)
        log = KioskLog(vm)
        vm.insert_key(image)
        log.wait("airgap_copied", timeout=180)
        wait_screen_name(vm, "transferred")
        # The folder of the key is named after the secret of its token: the
        # kiosk neither logs nor keeps it
        folders = sorted((root / "keys").iterdir())
        check(len(folders) == 1, f"folders on the server: {folders}")
        key_folder = folders[0]
        identifier = key_folder.name
        clean = sorted(path for path, (_, engine) in corpus.KEY.items() if not engine)
        on_server = sorted(
            p.relative_to(key_folder).as_posix()
            for p in key_folder.rglob("*")
            if p.is_file() and not p.relative_to(key_folder).as_posix().startswith(".pandora-box")
        )
        check(on_server == clean, f"files on the server: {on_server}")
        for path in clean:
            check((key_folder / path).read_bytes() == corpus.KEY[path][0], f"{path}: content")
        reports = list((key_folder / ".pandora-box").glob("*.json"))
        check(len(reports) == 1, f"reports on the server: {reports}")
        log.wait("device_ejected")
        vm.remove_key()
        log.wait("device_removed")
        # The key is not cleaned: it only got its identifier
        files = read_key(image)
        infected = sorted(path for path, (_, engine) in corpus.KEY.items() if engine)
        check(all(path in files for path in infected), f"key cleaned: {files}")
        check(".pandora-box" in files, f"no identifier on the key: {files}")
        print(f"{len(clean)} clean files copied, {len(infected)} not copied")

        # The station keeps nothing of the key: no report, no quarantine, a
        # log without its file names, label or key_folder, staged in memory
        reports_after = vm.shell.run(f"ls {REPORTS} | wc -l").strip()
        check(reports_after == reports_before, f"reports kept: {reports_before} -> {reports_after}")
        logged = vm.shell.run(f"tail -n +{log.line - 20} {LOG}")
        for secret in (identifier, "readme.txt", "eicar.com", "USBKEY"):
            check(secret not in logged, f"{secret} in the log of the station")
        staging = vm.shell.run("findmnt -n -o FSTYPE /var/lib/pandora-box-airgap/staging").strip()
        check(staging == "tmpfs", f"staging folder on {staging}")
        print("no report kept, no file name, label or folder in the log, staging in memory")

        # A file removed from the key is removed from the server
        subprocess.run(["mdel", "-i", str(image), "::readme.txt"], check=True)
        vm.insert_key(image)
        copied = log.wait("airgap_copied", timeout=180)
        folders = sorted((root / "keys").iterdir())
        check(folders == [key_folder], f"another folder for the same key: {folders}")
        check(copied["deleted"] == 1 and copied["copied"] == 0, f"synchronization: {copied}")
        check(not (key_folder / "readme.txt").exists(), "readme.txt left on the server")
        check(len(list((key_folder / ".pandora-box").glob("*.json"))) == 2, "second report missing")
        log.wait("device_ejected")
        vm.remove_key()
        log.wait("device_removed")
        print("inserted again: same identifier, the removed file deleted from the server")

        # Outbound: an infected key gets nothing from the server; a clean one
        # gets the clean files waiting for it, not the malicious ones
        for report in (key_folder / ".pandora-box").glob("*.json"):
            outbound = json.loads(report.read_text())["actions"]["airgap"]["outbound"]
            check(outbound["status"] == "refused", f"infected key, outbound: {outbound}")
        content = workdir / "airgap-clean"
        content.mkdir()
        (content / "readme.txt").write_bytes(corpus.KEY["readme.txt"][0])
        clean_image = workdir / "airgap-clean.img"
        make_key(clean_image, content)
        vm.insert_key(clean_image)
        received = log.wait("airgap_received", timeout=180)
        check(received["status"] == "nothing", f"nothing waiting yet: {received}")
        log.wait("device_ejected")
        vm.remove_key()
        log.wait("device_removed")
        clean_folder = next(f for f in (root / "keys").iterdir() if f != key_folder)
        waiting = clean_folder / ".pandora-box" / "outbound"
        (waiting / "docs").mkdir(parents=True)
        (waiting / "docs" / "answer.txt").write_bytes(b"answer from the protected network\n")
        (waiting / "virus.com").write_bytes(corpus.KEY["docs/eicar.com"][0])
        vm.insert_key(clean_image)
        received = log.wait("airgap_received", timeout=180)
        check(received["status"] == "copied" and received["copied"] == 1, f"outbound: {received}")
        log.wait("device_ejected")
        vm.remove_key()
        log.wait("device_removed")
        files = read_key(clean_image)
        check("docs/answer.txt" in files, f"file of the server not on the key: {files}")
        check("virus.com" not in files, f"malicious file of the server on the key: {files}")
        print("infected key refused; clean key: the clean file of the server written on it")

        # The service reads the staging folder, not the reports of the kiosk
        airgap_user = "setpriv --reuid=pandora-box-airgap --regid=pandora-box-airgap --init-groups"
        check(
            not vm.shell.succeeds(f"{airgap_user} ls /var/lib/pandora-box"),
            "the copy service user reads the reports",
        )
        check(
            vm.shell.run("ls -A /var/lib/pandora-box-airgap/staging").strip() == "",
            "staging folder not emptied",
        )
        print("service user without access to the reports, staging folder emptied")
    finally:
        server.close()
        started = count_events(vm, "kiosk_started")
        vm.shell.run(
            "rm -r /run/systemd/system/pandora-box.service.d"
            " /run/systemd/system/pandora-box-airgap.service.d && systemctl daemon-reload"
        )
        vm.shell.run("systemctl restart pandora-box-airgap pandora-box", timeout=300)
        wait_next_event(vm, "kiosk_started", started, timeout=300)


def check_usb_policy(vm: Machine) -> None:
    step("USB devices other than storage are blocked")
    authorized_default = vm.shell.run("cat /sys/module/usbcore/parameters/authorized_default")
    check(authorized_default.strip() == "0", f"usbcore.authorized_default: {authorized_default}")
    check(vm.shell.succeeds("systemctl is-active usbguard"), "usbguard is not running")
    for module in (
        "usbnet", "cdc_ether", "rndis_host", "btusb", "cfg80211", "usbserial",
        "dccp", "sctp", "rds", "tipc", "firewire_core",
    ):  # fmt: skip
        check(not vm.shell.succeeds(f"modinfo {module}"), f"kernel module {module} is present")
    check(vm.shell.succeeds("modinfo usb-storage"), "kernel module usb-storage is missing")
    # The rule of the touchscreen of the reference hardware is loaded
    rules = vm.shell.run("usbguard list-rules")
    check('id 0eef:0005 serial "220211"' in rules, f"no touchscreen rule:\n{rules}")
    interfaces = vm.shell.run("ls /sys/class/net").split()

    for driver, product in (("usb-kbd", "Keyboard"), ("usb-net", "Network")):
        vm.add_usb_device(driver, driver)
        deadline = time.monotonic() + 30
        while True:
            found = {name: flag for name, flag in usb_devices(vm).items() if product in name}
            if found:
                break
            check(time.monotonic() < deadline, f"{driver} not seen by the kernel")
            time.sleep(0.5)
        time.sleep(2)  # leave time for USBGuard to apply its policy
        found = {name: flag for name, flag in usb_devices(vm).items() if product in name}
        check(set(found.values()) == {"0"}, f"{driver} was authorized: {found}")
        name = next(iter(found))
        print(f"{driver} ({name}): blocked")
        vm.remove_usb_device(driver)

    inputs = vm.shell.run("grep -i 'qemu.*keyboard' /proc/bus/input/devices || true").strip()
    check(not inputs, f"input device created for the keyboard: {inputs}")
    after = vm.shell.run("ls /sys/class/net").split()
    check(after == interfaces, f"network interfaces: {interfaces}, then {after}")
    audit = vm.shell.run(
        "grep -c 'result=.SUCCESS.*target.new=.block' /var/log/usbguard/usbguard-audit.log || true"
    ).strip()
    print(f"no input device, no new network interface, {audit} devices blocked by USBGuard")
    # The kiosk reports the refused devices in its log (and so to the SIEM)
    deadline = time.monotonic() + 30
    while True:
        blocked = [e for e in events(vm) if e["event"] == "usb_device_blocked"]
        kinds = {kind for e in blocked for kind in e.get("kinds", ())}
        if {"keyboard", "communications"} <= kinds:
            break
        check(time.monotonic() < deadline, f"refused devices not in the kiosk log: {blocked}")
        time.sleep(0.5)
    print(f"{len(blocked)} usb_device_blocked events in the kiosk log: {sorted(kinds)}")


SYSCTL = {
    "kernel.dmesg_restrict": "1",
    "kernel.kptr_restrict": "2",
    "kernel.yama.ptrace_scope": "3",
    "kernel.kexec_load_disabled": "1",
    "kernel.unprivileged_bpf_disabled": "1",
    "kernel.unprivileged_userns_clone": "0",
    "kernel.io_uring_disabled": "2",
    "kernel.sysrq": "0",
    "fs.suid_dumpable": "0",
}
KERNEL_OPTIONS = ("init_on_free=1", "slab_nomerge", "vsyscall=none", "lockdown=confidentiality")


def check_sandbox(vm: Machine) -> None:
    step("scan workers are sandboxed")
    # The Python processes of the workers (their bubblewrap parents run as root)
    pids = vm.shell.run(
        "for p in $(pgrep -f pandora_box.worker); do "
        '[ "$(stat -c %U /proc/$p)" = pandora-box-scan ] && echo $p; done; true'
    ).split()
    # One engine per worker: scan.workers ("auto": as many as the CPUs and the
    # memory allow) for ClamAV and for YARA, one for each hash engine
    started = wait_event(vm, "workers_started")
    check(
        len(pids) == started["workers"] >= 4,
        f"{len(pids)} sandboxed workers, {started['workers']} started",
    )
    init_net = vm.shell.run("readlink /proc/1/ns/net").strip()
    for pid in pids:
        status = dict(
            line.split(":\t", 1)
            for line in vm.shell.run(f"cat /proc/{pid}/status").splitlines()
            if ":\t" in line
        )
        check(status["NoNewPrivs"].strip() == "1", f"worker {pid}: no_new_privs not set")
        check(status["Seccomp"].strip() == "2", f"worker {pid}: no system call filter")
        check(int(status["CapEff"], 16) == 0, f"worker {pid}: capabilities {status['CapEff']}")
        check(int(status["CapBnd"], 16) == 0, f"worker {pid}: bounding set {status['CapBnd']}")
        check(
            vm.shell.run(f"readlink /proc/{pid}/ns/net").strip() != init_net,
            f"worker {pid}: in the network namespace of the system",
        )
        for path in ("media", "var/lib/pandora-box", "var/log", "etc/pandora-box", "home"):
            check(
                not vm.shell.succeeds(f"test -e /proc/{pid}/root/{path}"),
                f"worker {pid} sees /{path}",
            )
    print(f"{len(pids)} workers: user pandora-box-scan, no capabilities, no_new_privs, seccomp,")
    print("no network, no device, no kiosk data in their file system")


def check_hardening(vm: Machine) -> None:
    step("system hardening")
    values = dict(
        line.split(" = ", 1) for line in vm.shell.run(f"sysctl {' '.join(SYSCTL)}").splitlines()
    )
    check(values == SYSCTL, f"sysctl: {values}")
    options = vm.shell.run("cat /proc/cmdline").split()
    missing = [o for o in KERNEL_OPTIONS if o not in options]
    check(not missing, f"kernel options missing: {missing}")
    lockdown = vm.shell.run("cat /sys/kernel/security/lockdown").strip()
    check("[confidentiality]" in lockdown, f"kernel lockdown: {lockdown}")
    # Image updates restart the kiosk when it is idle, never systemd-sysupdate;
    # no system or configuration extension merged from /var
    for unit in ("systemd-sysupdate.timer", "systemd-sysupdate-reboot.timer",
                 "systemd-sysext.service", "systemd-confext.service",
                 "systemd-pcrlock-make-policy.service"):  # fmt: skip
        state = vm.shell.run(f"systemctl is-enabled {unit} || true").strip()
        check(state != "enabled", f"{unit} is enabled")
    # No login prompt on the screens of the kiosk (the test image has a
    # serial console only)
    gettys = vm.shell.run("ps -o tty= -C agetty || true").split()
    check(not [t for t in gettys if t.startswith("tty") and t[3:].isdigit()], f"gettys: {gettys}")
    masked = vm.shell.run("systemctl show -P LoadState ctrl-alt-del.target").strip()
    check(masked == "masked", f"ctrl-alt-del.target: {masked}")
    policies = vm.shell.run("nft list ruleset").count("policy drop;")
    check(policies == 3, f"firewall: {policies} chains dropping by default, 3 expected")
    clamd = vm.shell.run(
        "systemctl show -P PrivateNetwork -P MemoryDenyWriteExecute clamav-daemon"
    ).split()
    check(clamd == ["yes", "yes"], f"clamd sandbox: {clamd}")
    check(vm.shell.run("ps -o user= -C clamd").strip() == "clamav", "clamd does not run as clamav")
    # Overview of all the units: "NAME EXPOSURE PREDICATE HAPPY"
    exposure = vm.shell.run(
        "systemd-analyze security --no-pager"
        " | grep -E '^(pandora-box|pandora-box-siem|clamav-daemon|usbguard)\\.service' || true"
    )
    print("sysctl, kernel options, lockdown, firewall, no login console: OK")
    units = [" ".join(line.split()[:2]) for line in exposure.splitlines()]
    # A oneshot service is not in the overview once it has run
    update = (
        vm.shell.run("systemd-analyze security --no-pager pandora-box-update.service | tail -n 1")
        .split(": ")[-1]
        .split()
    )
    units.append(f"pandora-box-update.service {update[0] if update else '?'}")
    print("systemd exposure (0 to 10):", ", ".join(units))


def check_audit(vm: Machine) -> None:
    step("audit log")
    status = vm.shell.run("auditctl -s")
    check("enabled 2" in status, f"audit rules not locked: {status}")
    rules = len(vm.shell.run("auditctl -l").splitlines())
    check(rules > 10, f"{rules} audit rules")
    # Events of the scenario so far: key mounts, programs, signature sets, modules
    found = {}
    for key in ("mount", "exec", "signatures", "modules"):
        events = vm.shell.run(f"ausearch -k {key} -i 2>/dev/null | grep -c '^type=SYSCALL' || true")
        found[key] = int(events.strip() or 0)
        check(found[key] > 0, f"no audit event {key}")
    print(f"auditd: {rules} rules, locked; events: {found}")


def run_lynis(vm: Machine) -> None:
    step("lynis assessment (information)")
    output = vm.shell.run(
        "lynis audit system --quick --no-colors --report-file /tmp/lynis.dat 2>&1"
        " | grep 'Hardening index'; grep '^warning\\[\\]=' /tmp/lynis.dat;"
        " echo suggestions: $(grep -c '^suggestion' /tmp/lynis.dat);"
        " grep '^suggestion' /tmp/lynis.dat | cut -d'|' -f1,2 || true",
        timeout=900,
    )
    for line in output.splitlines():
        print(line.strip().replace("warning[]=", "warning: "))


def count_reports(vm: Machine) -> int:
    return int(vm.shell.run(f"ls {REPORTS} | wc -l"))


def check_reboot(vm: Machine, timeout: float, signature_set: int) -> None:
    step("reboot: the data is kept, the system is unchanged, no boot menu")
    reports = count_reports(vm)
    before = count_events(vm, "kiosk_started")
    serial = vm.workdir / "serial.log"
    offset = serial.stat().st_size
    vm.shell.send("systemctl reboot")
    vm.monitor.wait_event("RESET", timeout=timeout)
    # A key held while the firmware and the boot loader start: the boot
    # loader menu must not open (it would wait there)
    deadline = time.monotonic() + BOOT_KEYS_DURATION
    while time.monotonic() < deadline:
        vm.press_key("spc")
        time.sleep(0.2)
    vm.shell.reset()
    vm.shell.login(timeout)
    with serial.open("rb") as log:
        log.seek(offset)
        console = log.read()
    check(b"Debian GNU/Linux 13 (trixie) (" not in console, "the boot loader menu opened")
    started = wait_next_event(vm, "kiosk_started", before, timeout=timeout)
    check(started["ready"], "the kiosk cannot scan after a reboot")
    check(started["signature_set"] == signature_set, f"signature set after a reboot: {started}")
    check(count_reports(vm) == reports, "scan reports lost after a reboot")
    check(not vm.shell.succeeds("test -e /usr/test"), "the root filesystem changed")
    failed = vm.shell.run("systemctl --failed --no-legend --plain").strip()
    check(not failed, f"failed units:\n{failed}")
    loader = vm.shell.run("cat $(bootctl --print-esp-path)/loader/loader.conf")
    check("timeout menu-disabled" in loader, f"boot loader configuration:\n{loader}")
    print(f"{reports} scan reports kept, signature set {signature_set} verified at start")
    print("keys pressed at boot: the boot loader menu stays closed")


def count_events(vm: Machine, name: str) -> int:
    return sum(1 for e in events(vm) if e.get("event") == name)


def wait_next_event(vm: Machine, name: str, before: int, **kwargs: Any) -> dict[str, Any]:
    return wait_event(vm, name, occurrence=before + 1, **kwargs)


def signature_set(
    workdir: Path,
    name: str,
    serial: int,
    signing_key: Path,
    malwarebazaar: tuple[bytes, ...] = (),
) -> Path:
    """A key image holding a signature set, and the folder of the set."""
    content = workdir / name
    folder = content / sigsets.UPDATE_FOLDER
    corpus.write_signatures(folder, malwarebazaar)
    sigsets.build(folder, serial)
    sigsets.sign(folder, signing_key)
    return content


def insert_update(vm: Machine, workdir: Path, content: Path, event: str) -> dict[str, Any]:
    """Insert a signature update key; return the kiosk event about the set."""
    image = workdir / f"{content.name}.img"
    make_key(image, content)
    before = {name: count_events(vm, name) for name in (event, "device_ejected")}
    vm.insert_key(image)
    result = wait_next_event(vm, event, before[event])
    wait_next_event(vm, "device_ejected", before["device_ejected"])
    vm.remove_key()
    return result


def check_signature_update(vm: Machine, workdir: Path) -> None:
    step("signature update keys")
    # A newer set, signed with the update key: it detects a new sample
    content = signature_set(workdir, "update-2", 2, UPDATE_KEY, (corpus.NEW_SAMPLE,))
    installed = insert_update(vm, workdir, content, "signatures_installed")
    check(installed["serial"] == 2, f"installed set: {installed}")
    wait_screen(vm, "Signatures updated: set 2")
    wait_event(vm, "engines_reloaded")
    print("set 2 installed, engines reloaded")

    # The new sample is detected
    sample = workdir / "new-sample"
    sample.mkdir()
    (sample / "new-sample.bin").write_bytes(corpus.NEW_SAMPLE)
    make_key(workdir / "new-sample.img", sample)
    before = count_events(vm, "device_cleaned")
    vm.insert_key(workdir / "new-sample.img")
    wait_next_event(vm, "device_cleaned", before, action=vm.press_key, timeout=60)
    report = last_report(vm)
    entry = next(f for f in report["files"] if f["path"] == "new-sample.bin")
    detected_by = [e["engine"] for e in entry["engines"] if e["detections"]]
    check(detected_by == ["malwarebazaar"], f"new sample detected by {detected_by}")
    vm.remove_key()
    print("the sample added by set 2 is detected")

    # Refused: modified after signing, signed by another key, older
    # (a file that differs from the installed set: an unchanged one is not
    # read from the key, the installed copy is used)
    content = signature_set(workdir, "update-3", 3, UPDATE_KEY, (corpus.NEW_SAMPLE, b"x"))
    database = content / sigsets.UPDATE_FOLDER / corpus.MALWAREBAZAAR_DB
    database.write_bytes(database.read_bytes()[:-1] + b"\0")
    refused = insert_update(vm, workdir, content, "signatures_refused")
    check("does not match the manifest" in refused["reason"], f"modified set: {refused}")
    foreign = workdir / "foreign.key"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(foreign)], check=True
    )
    content = signature_set(workdir, "update-4", 4, foreign)
    refused = insert_update(vm, workdir, content, "signatures_refused")
    check("invalid signature" in refused["reason"], f"foreign set: {refused}")
    content = signature_set(workdir, "update-old", 1, UPDATE_KEY)
    old = insert_update(vm, workdir, content, "signatures_not_newer")
    check("not newer than the installed 2" in old["reason"], f"older set: {old}")
    current = vm.shell.run("readlink /var/lib/pandora-box-signatures/current").strip()
    check(current == "sets/2", f"installed set: {current}")
    print("refused: modified set, set signed by another key, older set")


class Publisher:
    """HTTP server publishing files for the machine; it records the requests.

    The MalwareBazaar export needs the abuse.ch Auth-Key of the test profile.
    """

    def __init__(self, root: Path) -> None:
        self.root = root
        self.requests: list[str] = []
        publisher = self

        class Handler(SimpleHTTPRequestHandler):
            def do_GET(self) -> None:
                publisher.requests.append(self.path)
                if "malwarebazaar" in self.path and self.headers["Auth-Key"] != AUTH_KEY:
                    self.send_error(401, "Auth-Key")
                    return
                super().do_GET()

            def log_message(self, *args: object) -> None:
                pass

        root.mkdir(parents=True, exist_ok=True)
        self.httpd = ThreadingHTTPServer(
            ("127.0.0.1", PUBLISH_PORT), functools.partial(Handler, directory=str(root))
        )
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


def publish_sources(folder: Path, malwarebazaar: tuple[bytes, ...]) -> None:
    """The files of the sources of the test profile (updates.mirrors)."""
    import io
    import zipfile

    from pandora_box.bloom import write_filter

    folder.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(folder / "yara-forge-rules-core.zip", "w") as z:
        z.writestr("packages/core/yara-rules-core.yar", corpus.YARA_RULE)
    export = "".join(f"{hashlib.sha256(s).hexdigest()}\n" for s in malwarebazaar)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as z:
        z.writestr("full_sha256.txt", f"# MalwareBazaar export (VM test)\n{export}")
    (folder / "malwarebazaar-full-sha256.zip").write_bytes(buffer.getvalue())
    known = hashlib.sha1(corpus.KNOWN_FILE).hexdigest().upper().encode()
    write_filter(folder / "hashlookup-full.bloom", [known])


def check_online_update(vm: Machine, workdir: Path) -> int:
    """Signatures downloaded from their sources; return the serial of the set."""
    step("online signature update, from the sources")
    publisher = Publisher(workdir / "www")
    try:
        samples = (corpus.MALWAREBAZAAR_SAMPLE, corpus.NEW_SAMPLE, b"published online")
        publish_sources(publisher.root / SOURCES, samples)
        before = count_events(vm, "engines_reloaded")
        output = vm.shell.run("systemctl start pandora-box-update.service", timeout=600)
        changed = wait_event(vm, "signatures_changed")
        serial = int(changed["serial"])
        wait_next_event(vm, "engines_reloaded", before)
        # The same service also asks for an image update (updates.image_url)
        files = sorted(p.rsplit("/", 1)[-1] for p in publisher.requests if "/sources/" in p)
        expected = ["hashlookup-full.bloom", "malwarebazaar-full-sha256.zip",
                    "yara-forge-rules-core.zip"]  # fmt: skip
        check(files == expected, f"downloaded: {files}")
        current = vm.shell.run("readlink /var/lib/pandora-box-signatures/current").strip()
        check(current == f"sets/{serial}", f"installed set: {current}, {output}")
        # Signed with the key of the kiosk; ClamAV kept from the installed set
        check(
            vm.shell.succeeds("test -f /var/lib/pandora-box-signatures/local-key/local.pem"),
            "no key of the kiosk",
        )
        mode = vm.shell.run("stat -c %a /var/lib/pandora-box-signatures/local-key/local.key")
        check(mode.strip() == "600", f"key of the kiosk: mode {mode}")
        check(
            vm.shell.succeeds(
                f"test -f /var/lib/pandora-box-signatures/current/{corpus.CLAMAV_DB}"
            ),
            "ClamAV database not kept",
        )
        print(f"set {serial} built from the sources, signed by the kiosk, loaded when idle")

        # Unchanged sources (HTTP 304, Last-Modified): no new set
        publisher.requests.clear()
        vm.shell.run("systemctl start pandora-box-update.service", timeout=600)
        check(count_events(vm, "signatures_changed") == 1, "a new set for unchanged sources")
        check(
            vm.shell.run("readlink /var/lib/pandora-box-signatures/current").strip()
            == f"sets/{serial}",
            "the set changed",
        )
        print("unchanged sources: no new set")

        # Only the update service may go out
        connect = (
            "python3 -c 'import socket; socket.create_connection"
            f'(("10.0.2.2", {PUBLISH_PORT}), timeout=5)\''
        )
        check(not vm.shell.succeeds(connect), "the kiosk (root) can open a connection")
        check(
            vm.shell.succeeds(f"setpriv --reuid=pandora-box-update --init-groups {connect}"),
            "the update service user cannot open a connection",
        )
        print("firewall: only the update service user can open a connection")
        # Time: systemd-timesyncd, the only one allowed to send NTP requests
        timesyncd = vm.shell.run("systemctl is-active systemd-timesyncd").strip()
        check(timesyncd == "active", f"systemd-timesyncd: {timesyncd}")
        ntp = (
            "python3 -c 'import socket; socket.socket(socket.AF_INET, socket.SOCK_DGRAM)"
            '.sendto(b"x", ("10.0.2.2", 123))\''
        )
        check(not vm.shell.succeeds(ntp), "the kiosk (root) can send an NTP request")
        check(
            vm.shell.succeeds(f"setpriv --reuid=systemd-timesync --init-groups {ntp}"),
            "systemd-timesyncd cannot send an NTP request",
        )
        print("time: systemd-timesyncd active, alone allowed to send NTP requests")
        # Only the update service reads the credential
        check(
            not vm.shell.succeeds(
                "setpriv --reuid=pandora-box-update --init-groups "
                "cat /etc/credstore/pandora-box.abusech-auth-key"
            ),
            "the update user reads /etc/credstore",
        )
    finally:
        publisher.stop()
    return serial


class SiemReceiver:
    """Syslog receiver (TCP, octet counting) for the log export of the machine."""

    def __init__(self) -> None:
        self.listener = socket.create_server(("127.0.0.1", SIEM_PORT))
        self.data = b""
        self.lock = threading.Lock()
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            threading.Thread(target=self._receive, args=(conn,), daemon=True).start()

    def _receive(self, conn: socket.socket) -> None:
        with conn:
            while chunk := conn.recv(65536):
                with self.lock:
                    self.data += chunk

    def messages(self) -> list[bytes]:
        with self.lock:
            data = self.data
        messages = []
        while data:
            length, _, rest = data.partition(b" ")
            if not length.isdigit() or len(rest) < int(length):
                break
            messages.append(rest[: int(length)])
            data = rest[int(length) :]
        return messages

    def close(self) -> None:
        self.listener.close()


def check_siem(vm: Machine) -> None:
    """The log entries of the kiosk sent to the SIEM of the test profile."""
    step("log export to a SIEM")
    receiver = SiemReceiver()
    try:
        # At once, without waiting for the next attempt of the service
        vm.shell.run("systemctl restart pandora-box-siem.service")
        logged = len(events(vm))
        deadline = time.monotonic() + 60
        while len(receiver.messages()) < logged and time.monotonic() < deadline:
            time.sleep(1.0)
        messages = receiver.messages()
        check(len(messages) >= logged, f"{len(messages)} entries sent of {logged}")
        # HOSTNAME, APP-NAME and PROCID of RFC 5424
        headers = {m.split(b" ", 6)[2:5] == [b"vm-test", b"pandora-box", b"-"] for m in messages}
        check(headers == {True}, f"syslog header: {messages[0][:80]!r}")
        sent = [json.loads(m.split(b" - ", 2)[2])["event"] for m in messages]
        check("device_verdict" in sent, f"events sent: {sorted(set(sent))}")
        # A new entry is sent as it is logged
        marker = '{"level": "INFO", "kiosk": "vm-test", "event": "vm_siem_marker"}'
        vm.shell.run(f"echo '{marker}' >> {LOG}")
        deadline = time.monotonic() + 30
        while not receiver.messages()[-1].endswith(marker.encode()):
            check(time.monotonic() < deadline, "new entry not sent")
            time.sleep(0.5)
        print(f"{len(receiver.messages())} log entries sent over syslog (RFC 5424, TCP)")

        user = vm.shell.run("ps -o user:32= -p $(systemctl show -P MainPID pandora-box-siem)")
        check(user.split() == ["pandora-box-siem"], f"service user: {user}")
        check(
            vm.shell.succeeds("test -s /var/lib/pandora-box-siem/state.json"),
            "position of the last entry not saved",
        )
        # It reads the logs, not the reports or the quarantine
        siem_user = "setpriv --reuid=pandora-box-siem --regid=pandora-box-siem --init-groups"
        check(vm.shell.succeeds(f"{siem_user} head -c1 {LOG}"), "cannot read the log file")
        check(
            not vm.shell.succeeds(f"{siem_user} ls /var/lib/pandora-box"),
            "the SIEM export user reads the reports",
        )
        print("service user reads the log file only")
    finally:
        receiver.close()


def image_state(vm: Machine) -> tuple[str, list[str], list[str]]:
    """Running image version, labels of the root partitions, UKIs in the ESP."""
    version = vm.shell.run(". /etc/os-release; echo $IMAGE_VERSION").strip()
    # The partitions under the dm-verity device of the root filesystem
    labels = vm.shell.run(
        "cat /sys/dev/block/$(mountpoint -d /)/slaves/*/uevent | sed -n 's/^PARTNAME=//p'"
    ).split()
    ukis = sorted(vm.shell.run("ls /boot/EFI/Linux").split())
    return version, labels, ukis


def insert_image_update(vm: Machine, workdir: Path, update: Path, timeout: float) -> None:
    """Insert a key holding an image update; wait until the machine restarts."""
    content = workdir / f"image-{update.name}"
    shutil.copytree(update, content / "pandora-box-image")
    image = workdir / f"image-{update.name}.img"
    make_key(image, content, 1024 * 1024 * 1024)
    before = count_events(vm, "image_update_installed")
    vm.insert_key(image)
    # The kiosk installs the update, then restarts the machine
    vm.monitor.wait_event("RESET", timeout=900)
    vm.remove_key()
    vm.shell.reset()
    vm.shell.login(timeout)
    installed = wait_next_event(vm, "image_update_installed", before)
    expected = sigsets.parse_manifest((update / sigsets.MANIFEST).read_bytes(), "image").serial
    check(installed["version"] == expected, f"image update: {installed}")


def corrupted_update(workdir: Path, step: int, version: int) -> Path:
    """The image update of that step, with its root filesystem modified."""
    update = workdir / str(step)
    shutil.copytree(IMAGE_UPDATES / str(step), update)
    [packed] = (update / "files").glob("*.root.raw.xz")
    raw = packed.with_suffix("")
    subprocess.run(["xz", "-q", "-d", str(packed)], check=True)
    with raw.open("r+b") as root:
        root.seek(1024)  # the EROFS superblock: read when it is mounted
        root.write(b"\xff" * 128)
    subprocess.run(["xz", "-q", "-T0", "-2", str(raw)], check=True)
    sigsets.build(update, version, content=sigsets.CONTENT_IMAGE)
    sigsets.sign(update, UPDATE_KEY)
    return update


def check_image_update(vm: Machine, workdir: Path, timeout: float) -> None:
    step("A/B image update")
    v1, v2, v3, v4 = image_versions()
    version, labels, ukis = image_state(vm)
    check(version == v1 and f"pandora-box_{v1}" in labels, f"running: {version}, {labels}")
    reports = count_reports(vm)

    # Update 2: written to the free slot, booted, then kept (boot assessment)
    insert_image_update(vm, workdir, IMAGE_UPDATES / "2", timeout)
    version, labels, ukis = wait_kept(vm, v2)
    check(version == v2 and f"pandora-box_{v2}" in labels, f"after update: {version}, {labels}")
    # The longest label (36 characters) of a timestamp version
    signature = f"/dev/disk/by-partlabel/pandora-box_{v2}_veritysig"
    check(vm.shell.succeeds(f"test -e {signature}"), f"no partition {signature}")
    check(count_reports(vm) == reports, "scan reports lost by the image update")
    print(f"version {v2} installed in the free slot, booted and kept: {', '.join(ukis)}")

    # Update 3, online: the update service downloads and installs it, then
    # the idle kiosk restarts
    restarts = count_events(vm, "restarting")
    publisher = Publisher(workdir / "www-image")
    try:
        shutil.copytree(IMAGE_UPDATES / "3", publisher.root / "pandora-box-image")
        vm.shell.send("systemctl start pandora-box-update.service")
        vm.monitor.wait_event("RESET", timeout=900)
    finally:
        publisher.stop()
    downloaded = [p for p in publisher.requests if "/pandora-box-image/files/" in p]
    check(len(downloaded) == 4, f"files downloaded: {downloaded}")
    vm.shell.reset()
    vm.shell.login(timeout)
    restarted = wait_next_event(vm, "restarting", restarts)
    check(restarted["image_version"] == v3, f"restart: {restarted}")
    version, labels, ukis = wait_kept(vm, v3)
    check(version == v3 and f"pandora-box_{v3}" in labels, f"after online update: {version}")
    print(f"version {v3} downloaded, installed, the idle kiosk restarted, kept: {', '.join(ukis)}")

    # Update 4 does not boot (its root filesystem is modified): after 3
    # tries, systemd-boot goes back to version 3
    insert_image_update(vm, workdir, corrupted_update(workdir, 4, int(v4)), timeout)
    version, labels, ukis = image_state(vm)
    check(version == v3 and f"pandora-box_{v3}" in labels, f"after a bad update: {version}")
    check(f"pandora-box_{v4}+0-3.efi" in ukis, f"version {v4} not marked bad: {ukis}")
    print(f"version {v4} failed 3 boots, back to version {v3}: {', '.join(ukis)}")


def wait_kept(vm: Machine, version: str) -> tuple[str, list[str], list[str]]:
    """Wait until the running version is marked good (its UKI loses its counter)."""
    deadline = time.monotonic() + 120
    while True:
        state = image_state(vm)
        if f"pandora-box_{version}.efi" in state[2]:
            return state
        check(time.monotonic() < deadline, f"version {version} not marked good: {state}")
        time.sleep(2)


def plug_touchscreen(vm: Machine) -> None:
    """The touch tablet of the machine, allowed by the rule of the test profile."""
    step("touchscreen: allowed by its USBGuard rule")
    vm.add_usb_device("usb-tablet", "touch")
    deadline = time.monotonic() + 30
    while True:
        found = {n: flag for n, flag in usb_devices(vm).items() if "Tablet" in n}
        if found and set(found.values()) == {"1"}:
            break
        check(time.monotonic() < deadline, f"touch tablet not authorized: {found}")
        time.sleep(0.5)
    print(f"{next(iter(found))}: allowed")


def check_infected_key(vm: Machine, key: Path) -> None:
    step("insert the infected key")
    vm.insert_key(key)
    infected = wait_event(vm, "infected_files")
    expected = {path for path, (_, engine) in corpus.KEY.items() if engine}
    check(infected["count"] == len(expected), f"infected files: {infected['count']}")

    step("confirm the cleaning with a touch on the kiosk screen")
    # The infected files are listed before they are removed
    time.sleep(1.0)
    screen = wait_screen(vm, "Touch the screen to clean the key")
    for path in expected:
        check(path in screen, f"{path} not listed on the kiosk screen\n{screen}")
    # A touch before the kiosk waits for it may be discarded: touch again
    # until the cleaning is done (the other keys are confirmed with the keyboard)
    cleaned = wait_event(vm, "device_cleaned", action=vm.touch, timeout=60)
    check(cleaned["removed"] == len(expected), f"removed files: {cleaned['removed']}")
    wait_event(vm, "device_ejected")
    wait_screen(vm, "USB key cleaned")

    step("check the report and the quarantine")
    report = last_report(vm)
    check(report["verdict"]["device"] == "malicious", f"device verdict: {report['verdict']}")
    check(report["verdict"]["complete"], "the device was not fully scanned")
    files = {f["path"]: f for f in report["files"]}
    check(sorted(files) == sorted(corpus.KEY), f"scanned files: {sorted(files)}")
    for path, (_, engine) in corpus.KEY.items():
        entry = files[path]
        detected_by = sorted(e["engine"] for e in entry["engines"] if e["detections"])
        if engine:
            check(entry["verdict"] == "malicious", f"{path}: verdict {entry['verdict']}")
            check(detected_by == [engine], f"{path}: detected by {detected_by}")
        else:
            check(entry["verdict"] == "clean", f"{path}: verdict {entry['verdict']}")
            check(not detected_by, f"{path}: detected by {detected_by}")
        print(f"{path}: {entry['verdict']} {' '.join(detected_by)}")

    stored = wait_event(vm, "quarantine_stored")
    manifest = json.loads(vm.shell.run(f"cat {stored['folder']}/manifest.json"))
    quarantined = {f["original_path"]: f["sha256"] for f in manifest["files"]}
    check(
        quarantined
        == {
            path: hashlib.sha256(content).hexdigest()
            for path, (content, engine) in corpus.KEY.items()
            if engine
        },
        f"quarantine: {quarantined}",
    )

    step("remove the key and check its content")
    vm.remove_key()
    wait_event(vm, "device_removed")
    remaining = read_key(key)
    clean = sorted(path for path, (_, engine) in corpus.KEY.items() if not engine)
    check(remaining == clean, f"files left on the key: {remaining}")
    print(f"files left on the key: {', '.join(remaining)}")


class KioskLog:
    """Follow the kiosk log in order, from the line where it is created.

    Each event waited for must come after the previous one: an event of an
    earlier insertion is never taken for the expected one.
    """

    def __init__(self, vm: Machine) -> None:
        self.vm = vm
        self.line = int(vm.shell.run(f"cat {LOG} 2>/dev/null | wc -l"))

    def wait(
        self, name: str, timeout: float = 120.0, action: Callable[[], None] | None = None
    ) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while True:
            output = self.vm.shell.run(f"tail -n +{self.line + 1} {LOG}")
            for index, line in enumerate(output.splitlines()):
                if line.startswith("{") and json.loads(line).get("event") == name:
                    self.line += index + 1
                    event: dict[str, Any] = json.loads(line)
                    return event
            if time.monotonic() > deadline:
                raise TestFailure(f"kiosk event {name} not logged after line {self.line}")
            if action is not None:
                action()
            time.sleep(1.0)


# Driver of each filesystem: vfat in the kernel, the others in user space, in
# the sandbox of the scan workers (pandora_box.fuse)
DRIVERS = {"vfat": "kernel", "exfat": "mount.exfat-fuse", "ntfs": "ntfs-3g", "ext4": "fuse2fs"}


def scan_and_clean(vm: Machine, name: str, image: Path) -> None:
    """Insert a key holding the corpus: clean it, then it is reported clean."""
    log = KioskLog(vm)
    vm.insert_key(image)
    inserted = log.wait("device_inserted")
    mounted = log.wait("device_mounted")
    driver = DRIVERS[inserted["fs_type"]]
    check(mounted["driver"] == driver, f"{name}: driver {mounted['driver']}, not {driver}")
    infected = log.wait("infected_files")
    expected = sorted(path for path, (_, engine) in corpus.KEY.items() if engine)
    check(infected["count"] == len(expected), f"{name}: infected files: {infected['count']}")
    # The kiosk ejects the key, then logs the cleaning
    log.wait("device_ejected", action=vm.press_key, timeout=60)
    cleaned = log.wait("device_cleaned")
    check(cleaned["removed"] == len(expected), f"{name}: removed files: {cleaned['removed']}")
    vm.remove_key()
    log.wait("device_removed")

    vm.insert_key(image)
    log.wait("device_inserted")
    verdict = log.wait("device_verdict")
    check(verdict["verdict"] == "clean", f"{name}: verdict after cleaning: {verdict}")
    files = sorted(f["path"] for f in last_report(vm)["files"])
    clean = sorted(path for path, (_, engine) in corpus.KEY.items() if not engine)
    check(files == clean, f"{name}: files after cleaning: {files}")
    log.wait("device_ejected")
    vm.remove_key()
    log.wait("device_removed")
    print(
        f"{name}: {inserted['fs_type']} on {inserted['node']} ({driver} driver), "
        f"{len(expected)} infected files removed, then reported clean"
    )


def check_filesystem_keys(vm: Machine, workdir: Path) -> None:
    step("keys of the other filesystems: exfat, NTFS, ext4, partitioned")
    images = {}
    for name, build in keys.CORPUS_KEYS.items():
        images[name] = workdir / f"{name}.img"
        build(images[name])
    # exfat and NTFS are filled in the machine, the kiosk stopped
    started = count_events(vm, "kiosk_started")
    log = KioskLog(vm)
    vm.shell.run("systemctl stop pandora-box", timeout=120)
    # Stopped cleanly: the kiosk ran its cleanup (unmount), exit status 0
    log.wait("kiosk_stopped", timeout=10)
    result = vm.shell.run("systemctl show -P Result pandora-box").strip()
    check(result == "success", f"kiosk stop: {result}")
    for fs_type in keys.FILLED_IN_MACHINE:
        keys.fill_in_machine(vm, images[fs_type], fs_type)
    vm.shell.run("systemctl start pandora-box", timeout=300)
    wait_next_event(vm, "kiosk_started", started, timeout=300)
    wait_screen(vm, "Please insert a USB key")
    for name, image in images.items():
        scan_and_clean(vm, name, image)


def check_partitioned_keys(vm: Machine, workdir: Path) -> None:
    """Keys with several partitions: one insertion, one verdict for the key."""
    step("keys with several partitions")
    image = workdir / "two-partitions.img"
    keys.two_partitions_key(image)
    before = count_events(vm, "device_inserted")
    log = KioskLog(vm)
    vm.insert_key(image)
    inserted = log.wait("device_inserted")
    filesystems = [fs for _, fs, _ in inserted["partitions"]]
    check(filesystems == ["vfat", "ext4"], f"partitions of the key: {inserted}")
    infected = log.wait("infected_files")
    expected = sorted(path for path, (_, engine) in corpus.KEY.items() if engine)
    check(infected["count"] == len(expected), f"infected files: {infected['count']}")
    log.wait("device_ejected", action=vm.press_key, timeout=60)
    cleaned = log.wait("device_cleaned")
    check(cleaned["removed"] == len(expected), f"removed files: {cleaned['removed']}")
    vm.remove_key()
    log.wait("device_removed")
    # One insertion for the key, not one per partition
    inserted_count = count_events(vm, "device_inserted") - before
    check(inserted_count == 1, f"{inserted_count} insertions for one key")

    vm.insert_key(image)
    verdict = log.wait("device_verdict")
    check(verdict["verdict"] == "clean", f"verdict after cleaning: {verdict}")
    report = last_report(vm)
    partitions = [(p["filesystem"], p["scanned"]) for p in report["device"]["partitions"]]
    check(partitions == [("vfat", True), ("ext4", True)], f"report partitions: {partitions}")
    # Files of each partition, by partition number
    files = sorted((f["partition"][-1], f["path"]) for f in report["files"])
    clean = [("1", path) for path, (_, engine) in sorted(corpus.KEY.items()) if not engine]
    second = ("2", keys.SECOND_PARTITION_FILE[0])
    check(files == sorted([*clean, second]), f"files after cleaning: {files}")
    log.wait("device_ejected")
    vm.remove_key()
    log.wait("device_removed")
    print(f"vfat and ext4 partitions: {len(expected)} infected files removed, then clean")

    # A partition without filesystem may hold anything: the key is not verified
    image = workdir / "unknown-partition.img"
    keys.unknown_partition_key(image)
    vm.insert_key(image)
    verdict = log.wait("device_verdict")
    check(verdict["verdict"] == "not_verified", f"partition without filesystem: {verdict}")
    wait_screen(vm, "USB key NOT verified")
    reasons = last_report(vm)["verdict"]["incomplete_reasons"]
    check(len(reasons) == 1 and "unknown content" in reasons[0], f"reasons: {reasons}")
    vm.remove_key()
    log.wait("device_removed")
    print(f"partition without filesystem: not verified ({reasons[0]})")


def check_refused_keys(vm: Machine, workdir: Path) -> None:
    step("unsupported and corrupted filesystems")
    image = workdir / "unsupported.img"
    keys.unsupported_key(image)
    log = KioskLog(vm)
    vm.insert_key(image)
    failed = log.wait("mount_failed")
    check("filesystem not allowed: erofs" in failed["error"], f"unsupported: {failed}")
    wait_screen(vm, "An error occurred")
    vm.remove_key()
    log.wait("device_removed")
    print(f"unsupported: refused, {failed['error'].splitlines()[0]}")

    # Mounted, but files or folders cannot be read: the key is not verified.
    # fuse2fs mounts the ext4 key without its group descriptors, the folders
    # of the key cannot be read.
    for name, build, unreadable in (
        ("corrupted-vfat", keys.corrupted_vfat_key, keys.UNREADABLE),
        ("corrupted-ext4", keys.corrupted_ext4_key, "cannot read the device"),
    ):
        image = workdir / f"{name}.img"
        build(image)
        log = KioskLog(vm)
        vm.insert_key(image)
        verdict = log.wait("device_verdict")
        check(
            verdict["verdict"] == "not_verified" and not verdict["complete"],
            f"{name}: verdict {verdict}",
        )
        wait_screen(vm, "USB key NOT verified")
        report = last_report(vm)
        check(unreadable in json.dumps(report), f"{name}: {unreadable} not reported")
        vm.remove_key()
        log.wait("device_removed")
        print(f"{name}: not verified, {unreadable}")


def check_maintenance(vm: Machine, workdir: Path) -> None:
    step("maintenance device: the kiosk exports its logs")
    from pandora_box import maintenance

    content = workdir / "maintenance"
    maintenance.request(content / maintenance.FOLDER, UPDATE_KEY)
    image = workdir / "maintenance.img"
    make_key(image, content)
    log = KioskLog(vm)
    vm.insert_key(image)
    exported = log.wait("logs_exported")
    log.wait("device_ejected")
    vm.remove_key()
    log.wait("device_removed")
    files = read_key(image)
    folder = f"{maintenance.FOLDER}/{exported['folder']}"
    for name in ("journal.txt", "kernel.txt", "pandora-box.log", "usb-devices.txt",
                 "hardware.txt", "signatures.txt", "services.txt"):  # fmt: skip
        check(f"{folder}/{name}" in files, f"{name} not exported: {files}")
    check(not any("credstore" in f or f.endswith(".key") for f in files), f"secrets: {files}")
    print(f"{exported['files']} files exported to {folder}")


def check_structure_key(vm: Machine, workdir: Path) -> None:
    step("encrypted archive, PDF with JavaScript")
    content = workdir / "structure"
    content.mkdir()
    (content / "secret.zip").write_bytes(corpus.encrypted_zip())
    (content / "active.pdf").write_bytes(corpus.ACTIVE_PDF)
    (content / "readme.txt").write_bytes(b"a clean file\n")
    image = workdir / "structure.img"
    make_key(image, content)
    log = KioskLog(vm)
    vm.insert_key(image)
    # The suspicious PDF is removed (scan.suspicious = "block"), the archive is
    # not: it could not be scanned
    log.wait("device_ejected", action=vm.press_key, timeout=90)
    cleaned = log.wait("device_cleaned")
    check(cleaned["removed"] == 1, f"removed: {cleaned}")
    files = {f["path"]: f for f in last_report(vm)["files"]}
    archive = files["secret.zip"]
    check(archive["verdict"] == "error", f"secret.zip: {archive['verdict']}")
    clamav = next(e for e in archive["engines"] if e["engine"] == "clamav")
    check(clamav["detections"] == ["Heuristics.Encrypted.Zip"], f"secret.zip: {clamav}")
    pdf = next(e for e in files["active.pdf"]["engines"] if e["engine"] == "heuristics")
    check(pdf["detections"] == ["Heuristics.PDF.JavaScript"], f"active.pdf: {pdf}")
    check(files["active.pdf"]["verdict"] == "suspicious", f"active.pdf: {files['active.pdf']}")
    wait_screen(vm, "USB key NOT verified")
    vm.remove_key()
    log.wait("device_removed")
    left = read_key(image)
    check(left == ["readme.txt", "secret.zip"], f"files left on the key: {left}")
    print("secret.zip: not fully scanned (encrypted), kept; active.pdf: suspicious, removed")


def check_clean_key(vm: Machine, key: Path) -> None:
    step("insert the cleaned key again")
    vm.insert_key(key)
    verdict = wait_event(vm, "device_verdict", occurrence=2)
    check(verdict["verdict"] == "clean", f"device verdict: {verdict}")
    wait_event(vm, "device_ejected", occurrence=2)
    vm.remove_key()
    wait_event(vm, "device_removed", occurrence=2)
    check(read_key(key) == sorted(p for p, (_, e) in corpus.KEY.items() if not e), "key changed")
    print("the cleaned key is reported clean")


@contextlib.contextmanager
def saved_log(vm: Machine, workdir: Path) -> Iterator[None]:
    """On a failure, copy the kiosk log of the machine into the work folder."""
    try:
        yield
    except (TestFailure, MachineError, TimeoutError):
        with contextlib.suppress(MachineError, TimeoutError, OSError):
            (workdir / "kiosk.log").write_text(vm.shell.run(f"cat {LOG}", timeout=30))
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--image", type=Path, default=Path("image/mkosi.output/pandora-box-test.raw")
    )
    parser.add_argument("--boot-timeout", type=float, default=300.0)
    parser.add_argument("--workdir", type=Path, help="keep the logs and key image in this folder")
    args = parser.parse_args(argv)
    if not args.image.exists():
        print(f"{args.image}: no such image, run image/build.sh --profile test", file=sys.stderr)
        return 2

    updates = [IMAGE_UPDATES / str(step) for step in (2, 3, 4)] + [IMAGE_UPDATES / "versions"]
    for path in (SIGNING_CERTIFICATE, UPDATE_KEY, *updates):
        if not path.exists():
            print(f"{path}: missing, run image/build-test.sh", file=sys.stderr)
            return 2

    image = args.image.resolve()
    with tempfile.TemporaryDirectory() as tmp:
        workdir = (args.workdir or Path(tmp)).resolve()
        workdir.mkdir(parents=True, exist_ok=True)
        key = workdir / "usbkey.img"
        make_key(key)
        current = workdir
        try:
            with Machine(image, workdir, SIGNING_CERTIFICATE) as vm, saved_log(vm, workdir):
                check_boot(vm, args.boot_timeout)
                check_sandbox(vm)
                check_integrity(vm)
                check_filesystems(vm)
                plug_touchscreen(vm)
                check_infected_key(vm, key)
                check_clean_key(vm, key)
                check_maintenance(vm, workdir)
                check_filesystem_keys(vm, workdir)
                check_partitioned_keys(vm, workdir)
                check_refused_keys(vm, workdir)
                check_structure_key(vm, workdir)
                check_signature_update(vm, workdir)
                online_set = check_online_update(vm, workdir)
                check_siem(vm)
                check_airgap(vm, workdir)
                check_usb_policy(vm)
                check_hardening(vm)
                check_audit(vm)
                run_lynis(vm)
                check_reboot(vm, args.boot_timeout, online_set)
                check_image_update(vm, workdir, args.boot_timeout)
            current = workdir / "modified-root"
            check_modified_root(image, current, args.boot_timeout)
            current = workdir / "foreign-key"
            check_foreign_key(image, current, 60.0)
        except (TestFailure, MachineError, TimeoutError) as ex:
            print(f"FAILED: {ex}", file=sys.stderr)
            serial = current / "serial.log"
            if serial.exists():
                tail = serial.read_text(errors="replace").splitlines()[-40:]
                print("--- serial console (last lines)", *tail, sep="\n", file=sys.stderr)
            return 1
    print("PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
