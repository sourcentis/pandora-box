# Testing with QEMU

The image is tested in a QEMU/KVM virtual machine, without the reference
hardware: UEFI firmware (OVMF) with Secure Boot, an empty USB 3 controller,
and USB keys inserted and removed while the kiosk runs, which triggers the
same udev events as a real device. QEMU runs in the build container: only
Docker is needed, and `/dev/kvm` for speed.

## In short

```sh
image/build-test.sh   # the test image and three image updates
image/vm.sh test      # automated test, about 7 minutes with KVM
image/vm.sh run       # interactive machine, kiosk screen on VNC localhost:0
```

> [!NOTE]
> Hostile samples should only ever be copied into key images, never onto the
> development desktop.

## Test profile

`--profile test` builds `pandora-box-test.raw`, for the virtual machine tests
only, **never for a kiosk**. It includes the profile
[`online`](build.md#profile-online), and adds:

- a test-only signature set, generated from `image/vm/corpus.py`, signed
  with the development update key and installed (serial 1): a ClamAV
  database that detects the EICAR test file, a MalwareBazaar database, a
  Hashlookup filter and a YARA rule, each detecting one file of the test key;
- the matching configuration, with every engine enabled, and online updates
  from `http://10.0.2.2:8080/` (the build container, seen from the QEMU user
  network);
- a root shell without password on the virtio console (`hvc0`), and kernel
  messages on the serial port;
- `kiosk-screen`, which prints the texts of the kiosk screen in that shell (the
  graphical interface logs them, `display_screen` events at the DEBUG level);
- a USBGuard rule for the touch tablet of the virtual machine (QEMU
  `usb-tablet`, `/etc/usbguard/rules.d/50-vm-test.conf`): the test confirms a
  cleaning with a touch. The keyboard of the virtual machines is not a USB
  device.

`image/build-test.sh` builds the test image (version 1) and three signed
image updates to newer versions (`image/mkosi.output/updates/`), for the A/B
update test.

## Automated test

```sh
image/build-test.sh
image/vm.sh test
```

The test boots the test image in QEMU (KVM when `/dev/kvm` is writable,
otherwise much slower emulation), with UEFI firmware (OVMF) where the image
signing certificate is enrolled (Secure Boot enabled), and an empty USB 3
controller. It plays the whole user workflow, through QMP and the shell on
the virtio console:

1. the kiosk starts with its five engines and the signature set 1, verified,
   and no systemd unit fails;
2. the scan workers (one engine each) run in their sandbox (user,
   capabilities, `no_new_privs`, seccomp, network namespace, no device or
   kiosk data in their file system); Secure Boot is enabled, the kernel is
   locked down and the root filesystem is on dm-verity;
3. the root filesystem is read-only EROFS, and `/var` was grown to fill the
   8 GB disk of the machine;
4. an emulated USB key (a vfat disk image holding the corpus) is inserted,
   which triggers the same udev events as a real device;
5. each file gets the expected verdict from the expected engine;
6. the cleaning is confirmed with a touch on the kiosk screen; the
   infected files are quarantined (checked against their SHA-256) and
   removed from the key, which is ejected;
7. the key is removed: only the clean files are left on it;
8. the cleaned key is inserted again and reported clean;
9. keys of the other filesystems go through the same scan and cleaning, then
   are reported clean: exfat, NTFS, ext4 (its files private to their owner,
   as on the key of a Linux user), each read by its FUSE driver, and a key
   with an MBR partition table and a vfat partition; a key on EROFS (a
   filesystem the kernel mounts, but not allowed) is refused; a vfat key
   with a cut cluster chain and an ext4 key whose group descriptors are
   overwritten are mounted, but a file or the folders cannot be read: the key
   is reported not verified (`image/vm/keys.py`; exfat and NTFS have no tool
   writing files without mounting them: they are formatted in the container,
   then filled by the FUSE drivers of the machine, the kiosk stopped); a key
   of 4000 files removed during its scan is a suspicious behavior
   (`device_suspicious_behavior`, `removed`): not verified, the `key_changed`
   screen shown, the behavior in its report;
10. a signature update key with a newer set (serial 2) is installed, the
    engines are reloaded and the new sample it detects is found; a modified
    set, a set signed with another key and an older set are refused; a newer
    set published on an HTTP server by the test is downloaded by the update
    service (only its changed file), installed and loaded by the idle kiosk,
    and only the update service user can open a network connection
    (systemd-timesyncd alone sends NTP requests); the
    log entries of the kiosk are sent to a syslog receiver of the test
    (`[siem]`), by the SIEM export user, who cannot read the reports; with
    the copy to a server enabled (`[airgap]`, an SFTP server of the test),
    the clean files of a key are copied by the copy service user, the key
    keeps its malicious files and gets its identifier, then a file removed
    from the key is deleted from the server; an
    emulated USB keyboard and network adapter are blocked by USBGuard (no
    input device, no network interface), each explained on the screen until
    it is removed; a USB key that is also a keyboard, emulated in the machine
    as a USB gadget (`dummy_hcd`, `libcomposite`: a mass storage and a
    keyboard function), is blocked as a whole, neither mounted nor scanned,
    shown on the `refused_composite` screen and logged as
    `usb_device_blocked` with `composite`; the excluded drivers are not in
    the image; the kernel settings, the firewall and the service sandboxes are
    in place;
11. after a reboot, the scan reports are still there, the root filesystem is
    unchanged and the signature set 5 is verified at start; a key pressed
    while the firmware and the boot loader start does not open the boot
    loader menu;
12. an image update key to version 2 is inserted: the kiosk installs it in
    the free slot and restarts, version 2 boots from slot B and is kept (its
    UKI loses its boot counter), with the same data; version 3, published on
    an HTTP server by the test, is downloaded and installed by the update
    service, then the idle kiosk restarts on it and it is kept; finally a
    version 4 whose root filesystem is modified is installed from a key: it
    fails 3 boots (dm-verity, the initrd restarts) and systemd-boot goes back
    to version 3.

Two more machines boot the same image:

- with a block of the root filesystem modified on the disk (a canary file of
  the test image): it cannot be read and the kernel reports the corruption;
- with firmware trusting another key: the firmware refuses systemd-boot
  ("Access Denied") and nothing starts.

The test also runs `lynis` (hardening index 73, no warnings) and prints the
exposure of the services measured by `systemd-analyze security`.

The built image is never modified: the machine writes to a new disk overlay
(`system.qcow2`) at every start. It takes about 7 minutes with KVM.
`image/vm.sh test --workdir DIR` keeps the serial console logs, the QEMU logs
and the key images in `DIR`, and the kiosk log (`kiosk.log`) when the test
fails.

## Interactive machine

```sh
image/vm.sh run                                      # test image
image/vm.sh run image/mkosi.output/pandora-box.raw   # production image
```

The kiosk screen is shown over VNC, display `:0` (port 5900), for example
with `gvncviewer localhost:0` (most viewers read `host:N` as a display
number, port 5900 + N); `kiosk-screen` also prints it in the shell of the
test image. The terminal shows this shell (virtio console), not the kiosk,
and, after `Ctrl-A C`, the QEMU monitor; `Ctrl-A X` stops the machine.

A production image has no signature set: it shows `NO VALID SIGNATURES`
until a signature update device is inserted, as a new kiosk
([Initial installation](install.md#first-signature-set)).

### Test keys

A test key is created in `image/vm/work/usbkey.img`; insert and remove it from
the QEMU monitor:

```
(qemu) drive_add 0 if=none,id=key,format=raw,file=/src/image/vm/work/usbkey.img
(qemu) device_add usb-storage,bus=xhci.0,drive=key,id=usbkey,removable=on
(qemu) device_del usbkey
```

Paths are seen from the container, where the repository is mounted on `/src`.
Any disk image can be used as a key.

### Real USB keys

A USB key plugged into this computer can be passed through to the machine.
List the USB storage devices of this computer, with their port (`BUS-PORT`)
and identifier (`VENDOR:PRODUCT`):

```sh
image/vm.sh usb
```
```
1-4  abcd:1234  General UDisk
    sda     3,8G
    └─sda1  3,7G vfat   /media/didier/6B20-F9DE
```

Then start the machine with `--usb`, followed by a port, which passes through
any key plugged into that port, like the USB port of a kiosk, or by an
identifier, which passes through that model of key on any port:

```sh
image/vm.sh run --usb 1-4
```

QEMU attaches the key to the machine as soon as it is plugged in (or at once
if it is already there) and takes it from this computer: its kernel driver is
detached. Before starting the machine, unmount the key
(`udisksctl unmount -b /dev/sda1`) and disable the automatic mounting of USB
devices of the desktop, so that this computer never mounts a key meant for
the kiosk. `--usb` can be given several times. On GNOME:

```sh
gsettings set org.gnome.desktop.media-handling automount false
gsettings set org.gnome.desktop.media-handling automount-open false
# after the tests: the same commands with "true"
```

QEMU then runs as root in the container, with access to the USB devices of
this computer and its network (to receive the udev events of the keys
plugged in later); the kiosk screen is on `localhost:5900` as before.
