# Image internals

How the kiosk image is made and protected. To build it, test it, install it
and maintain it, see [Building the image](build.md),
[Testing with QEMU](vm.md), [Initial installation](install.md) and
[System updates](update.md).

The image is built with [mkosi](https://github.com/systemd/mkosi) from Debian
13 (trixie) packages.

## Partitions

The disk image has two system slots (A/B updates) and a data partition:

| Partition | Filesystem | Content |
|---|---|---|
| ESP | vfat, 512 MB | systemd-boot and the UKIs (`pandora-box_<version>.efi`), all signed |
| root, slot A (`pandora-box_<version>`) | EROFS, read-only, 1 GB | the whole system but `/var` (about 400 MB used) |
| root-verity, slot A | 64 MB | dm-verity hash tree of the root filesystem |
| root-verity-sig, slot A | 16 KB | signature of the root hash |
| root, root-verity, root-verity-sig, slot B (`_empty`) | same sizes | the next version (A/B updates) |
| data (`pandora-box-data`) | ext4, 1 GB in the image | `/var`: scan reports, quarantine, logs, signed signature sets (clamd reads its databases there) |

The version of the image is the date and time of its build, UTC, like the
serial of a signature set: `20261005143700` (`image/build.sh` sets it,
`--image-version=N` overrides it). It is in `/etc/os-release`
(`IMAGE_VERSION`), in the labels of its partitions (`pandora-box_<version>`,
`_verity`, `_veritysig`: 36 characters at most) and in the name of its UKI.

The root filesystem is read-only by design (EROFS cannot be written at all):
the system and its configuration only change with a new image. Everything
the kiosk writes is in `/var`. The data partition is the last one: at every
boot, `systemd-repart` grows it to fill the disk
(`/usr/lib/repart.d/20-var.conf`), then `systemd-growfs` grows its
filesystem (`x-systemd.growfs` in `/etc/fstab`), so the image can be written
to a disk of any size. As `/etc` is read-only, the machine ID is generated
again at every boot (a new journal folder per boot, within the journald
size limits).

The image contains:

- the kernel, systemd and udev, Python 3 and clamd (`clamav-daemon`), with no
  network service: `systemd-networkd`, `systemd-resolved`, freshclam and the
  ClamAV on-access scanner are disabled (`10-pandora-box.preset`);
- pandora-box in `/usr/lib/pandora-box` (`/usr/bin/pandora-box`), its
  configuration in `/etc/pandora-box/pandora-box.toml` and its service, which
  draws the graphical touch interface on the first console (framebuffer, see
  [Screen](#screen));
- no `login` program and no root password: no interactive session is
  possible.

## Signing, Secure Boot and dm-verity

The boot chain is verified from the firmware to every block of the system:

1. with Secure Boot, the firmware only starts systemd-boot if it is signed
   with a key of its `db`, and systemd-boot only starts a signed UKI;
2. the UKI holds the kernel, the initrd and the kernel command line, which
   contains the dm-verity root hash (`roothash=`): changing it breaks the
   signature;
3. the root filesystem is opened with dm-verity: every block read is checked
   against the hash tree, whose root is that hash. A modified block cannot
   be read (I/O error, "data block ... is corrupted" in the kernel log);
4. with Secure Boot, the Debian kernel enables its lockdown mode
   (`integrity`): even root cannot modify the running kernel.

`/var` is not protected by dm-verity: it holds the data of the kiosk, never
programs or configuration.

The image is signed with `image/mkosi.key` and `image/mkosi.crt` (systemd-boot,
UKI, root hash). When they do not exist, `image/build.sh` generates a
**development** key pair, valid 10 years, that never leaves the developer's
computer (ignored by git). A kiosk must only trust the release keys of the
project, which are not defined yet: they will be kept out of the repository,
and mkosi can sign with a key in a hardware token
(`--secure-boot-key-source=provider:pkcs11`).

The image also trusts the signature sets signed with `image/update.key`: its
public key `image/update.pem` is installed in `/usr/share/pandora-box/keys/`
(under dm-verity). `image/build.sh` generates a development pair when they
do not exist; the test profile signs its signature set with it. See
[Signatures](signatures.md).

On a kiosk, the certificate is enrolled in the firmware in place of the
Microsoft keys (PK, KEK and db), so that it starts nothing else. The ESP
contains the keys in the format expected by the firmware
(`loader/keys/auto/`): with the firmware in Secure Boot setup mode (keys
cleared in the firmware setup), systemd-boot enrolls them at the first boot
(`secure-boot-enroll force`). Enrolling only the project certificate also
refuses the option ROMs signed by Microsoft: a computer whose display or
disk controller needs one (a graphics card, for instance) would not start
it. The virtual machines enroll the certificate with `virt-fw-vars` instead
(`image/vm/machine.py`).

systemd-boot has no menu (`/efi/loader/loader.conf`, `timeout
menu-disabled`): it starts the default entry, the newest version not marked
bad, and does not read the keyboard. A keyboard plugged into the kiosk
cannot select another version, edit the kernel command line (refused with
Secure Boot anyway), power off the machine or reboot into the firmware
setup. The ESP is not part of the image updates: this file stays as
installed.

## Screen

The kiosk draws its graphical interface into the framebuffer of the graphics
driver (`/dev/fb0`), without a display server or a browser, and puts the
first console (`tty1`) in graphics mode so that the kernel does not draw text
over it: see [interface.md](interface.md). The screen of the reference
hardware is a Waveshare 7-inch HDMI LCD (1024x600). The firmware of the
ThinkCentre starts in 1024x768, and the Intel driver keeps that mode: the
bottom of the interface would be off the screen. The kernel command line
therefore sets the mode of the screen, `video=1024x600M@60` (CVT timings, as
Waveshare documents them); with another screen, change it in
`image/mkosi.conf`. The Intel driver still keeps the framebuffer of the
firmware, large enough for that mode: the kiosk only draws its visible part,
the size of `video=`, and follows a change of the framebuffer size. It logs
the size and the pixel format it draws for (`display_started`).

The curses interface (`kiosk.interface = "curses"`, administrator mode) draws
text on the console instead: it shrinks the console to the screen of
`video=` (8x16 font: 37 lines, 128 columns) the same way, and logs the size
it draws for (`display_started`, `display_resized`).

## USB devices

A kiosk must only use USB storage devices: a key that is also a keyboard
(BadUSB) could type commands, a network adapter could open a network.

- **USBGuard** (`/etc/usbguard/rules.conf`) allows hubs and the devices
  whose interfaces are all mass storage; it blocks every other device,
  including a key that has a storage interface and another one. Blocked
  devices are listed in `/var/log/usbguard/usbguard-audit.log`, and the
  kiosk reports each one in its own log as a `usb_device_blocked` event,
  also sent to the SIEM ([Refused USB devices](logs.md#refused-usb-devices)).
- **No device is authorized before USBGuard has started**: the kernel
  command line sets `usbcore.authorized_default=0`. If USBGuard does not
  start, no USB device is usable.
- **Drivers removed from the image** (`KernelModulesExclude=` in
  `image/mkosi.conf`): USB network adapters, wireless, Bluetooth, USB serial
  adapters and modems, plus the staging drivers and batman-adv, which would
  bring the wireless modules back as dependencies. Such devices have no
  driver even if they were authorized.
- **USB HID is kept for the touchscreen** of the reference hardware, a
  Waveshare 7-inch HDMI LCD (C), allowed by its own rule:

  ```
  allow id 0eef:0005 serial "220211" name "WS170120" with-interface 03:00:00 via-port "1-8"
  ```

  its USB touch controller (eGalax) with its single generic HID interface (a
  keyboard has `03:01:01`), on the internal port of the enclosure, this unit
  only. A device that copies its identifiers on another port, or that adds a
  keyboard interface, is blocked; so is every keyboard and mouse. Another
  unit or port: adapt the rule to the line the audit log shows when it is
  blocked. The kernel (`mousedev`) turns a touch into a left click on
  `/dev/input/mice`, which the kiosk reads to confirm a cleaning.

  The test image allows the touch tablet of the virtual machine (QEMU
  `usb-tablet`, same interface) in its own rule
  (`/etc/usbguard/rules.d/50-vm-test.conf`): the test confirms a cleaning
  with a touch. The keyboard of the virtual machines is not a USB device.

### Mouse instead of a touchscreen

With a screen that is not a touchscreen, a mouse confirms a cleaning: the
kernel merges all mice in `/dev/input/mice`, and a left click is read as a
touch. Nothing changes in the kiosk, but USBGuard blocks every mouse: allow
yours by its own rule in `image/mkosi.extra/etc/usbguard/rules.conf`, then
rebuild the image and write it again. The root file system is read-only and
checked by dm-verity: a rule changed on the kiosk itself is not possible.

1. Plug the mouse into the kiosk and take its line from
   `/var/log/usbguard/usbguard-audit.log`, or from `usb-devices.txt` of a
   [maintenance export](logs.md#maintenance-device): its `id`, `name`,
   `serial` (when it has one) and port.
2. Add a rule that allows this mouse, with only a mouse interface
   (`03:01:02`), on the port where it is plugged, for example:

    ```
    allow id 046d:c077 name "USB Optical Mouse" with-interface equals { 03:01:02 } via-port "1-5"
    ```

    Add `serial "..."` when the mouse has a serial number: the rule then
    allows this unit only.

Choose a simple wired mouse. Many wireless mice (receivers shared with a
keyboard) and gaming mice also have a keyboard interface (`03:01:01`):
`equals` keeps them blocked, so that a keyboard cannot pass for a mouse.
Keep the mouse on the port of the rule. Edit the file with LF line endings:
the build refuses a file with CRLF line endings.

## System hardening

After the ANSSI configuration recommendations for GNU/Linux systems:

- **Kernel settings** (`/usr/lib/sysctl.d/90-pandora-box.conf`): kernel
  logs and addresses hidden, no ptrace, no kexec, no unprivileged eBPF, user
  namespaces or userfaultfd, io_uring disabled, no SysRq, no core dumps,
  protected links and FIFOs, no IP forwarding or redirects.
- **Kernel command line**: memory initialized on allocation and free, no
  slab merging, randomized page allocator and kernel stack, no legacy
  vsyscall, no debugfs, lockdown in `confidentiality` mode (Secure Boot only
  enables `integrity`: even root cannot read kernel memory), IOMMU in strict
  mode and no DMA before the kernel starts (DMA attacks through ports).
- **Firewall** (`/etc/nftables.conf`): every packet is dropped, in and out,
  except on the loopback interface.
- **No login**: no login console on the screens (`getty@` and `getty-static`
  disabled), no `login` program, no root password, Ctrl-Alt-Del masked.
- **clamd sandbox** (`clamav-daemon.service.d/50-pandora-box.conf`): no
  network, read-only system, no device, system call filter,
  `MemoryDenyWriteExecute` (the Debian clamd interprets bytecode signatures,
  without JIT); it runs as the `clamav` user.
- **Kiosk service** (`packaging/systemd/pandora-box.service`): read-only
  system, system call filter, limited capabilities. It keeps `AF_NETLINK`
  (udev events), the capabilities needed to start the worker sandbox
  (namespaces, change of user, loopback interface of the workers) and
  cannot have `MemoryDenyWriteExecute` or `RestrictSUIDSGID`: the first one
  would also apply to the YARA-X workers, which compile rules to native
  code, the second one refuses a system call bubblewrap needs.
- **Kernel modules removed**: network protocols the kiosk never uses (DCCP,
  SCTP, RDS, TIPC) and FireWire, another way to reach the memory of the
  kiosk, besides the USB network, Bluetooth and Wi-Fi drivers, and the NTFS
  and exFAT drivers (read in user space, see
  [Filesystem drivers](#filesystem-drivers)). The protocols, FireWire, NTFS
  and exFAT are also listed in `/etc/modprobe.d/pandora-box.conf`, where the
  auditing tools look for them.
- **Audit log** (`/etc/audit/audit.rules`, auditd): loading of kernel modules,
  mounts (except those of systemd and bubblewrap), every program started,
  ptrace, changes of the clock, of the signature sets and of the staged image
  updates. The rules are locked (`-e 2`): changing them needs a reboot. They
  are loaded by `auditctl -R` (`augenrules` writes into `/etc`, read-only).
  The log is in `/var/log/audit/audit.log`, for instance
  `ausearch -k signatures -i`.

The test profile includes `lynis`, run by the automated test: hardening index
73, no warnings. Its remaining suggestions do not apply to a kiosk without
login (password policy, banners, package tools, fail2ban) or come later
(remote logging, phase 5).

## Scan worker sandbox

The scan workers parse hostile files with several engines (libmagic, YARA-X,
the clamd client...): they are assumed compromisable (`scan.sandbox`,
`src/pandora_box/sandbox.py`).

- **One engine per worker**: a compromised engine (a crafted file
  exploiting YARA-X or libmagic) cannot forge the result of another engine.
  The kiosk hashes each file itself, asks the worker of each hash engine
  (MalwareBazaar, Hashlookup) with the hashes only, then passes the file to
  a worker of each content engine (ClamAV, YARA-X), and combines their
  results itself; a worker only reports the result of its own engine.
  Content engines have `scan.workers` workers each, hash engines one.
  `scan.workers = "auto"` (the default) scans one file per CPU at the same
  time, as many as the memory allows (1.5 GB for clamd and the system, then
  256 MB each, for the YARA rules mostly): 6 on the ThinkCentre M720q (6
  cores, 8 GB), 1 or 2 on a computer with 2 GB.
- **No access to the device**: the kiosk opens each file safely (no link
  followed, the file of the inventory) and passes the open descriptor to the
  workers of the content engines, which never open a file of the device;
  the workers of the hash engines never get the file.
- **bubblewrap**: new PID, IPC, UTS, cgroup and network namespaces (no
  network interface but loopback); a file system holding only `/usr`, a few
  files of `/etc`, the signature folders of the enabled engines
  (read-only), the YARA-X cache and the clamd socket folder: no device
  mount point, no reports, quarantine, logs or configuration.
- **Dedicated user** `pandora-box-scan` (`packaging/sysusers/`), switched to
  by `setpriv`: no capability, no supplementary group, `no_new_privs`.
- **System call filter** (`src/pandora_box/seccomp.py`), installed once
  the engines are loaded: no program execution, debugging, mounts,
  namespaces, eBPF, kernel modules, io_uring, network sockets...
- **Untrusted answers**: workers answer in JSON (never pickle), limited in
  size and validated (`src/pandora_box/protocol.py`); the path and size of
  the file always come from the kiosk. A malformed answer kills the worker
  and the file is reported as an error.

bubblewrap runs as root (the kiosk service), so unprivileged user namespaces
stay disabled.

The virtual machine test checks these settings and prints the exposure of
the services measured by `systemd-analyze security` (0 to 10, lower is
better): about 1.6 for clamd, 3.8 for the kiosk (which starts the worker
sandbox), 2.8 for USBGuard.

## Filesystem drivers

A kernel filesystem driver parses the structures written on the key: a flaw
of this driver, on a crafted key, runs code in the kernel, before any
sandbox (the NTFS, exFAT and ext4 drivers of Linux get regular fuzzing
findings). NTFS, exFAT and ext4 are therefore read by a FUSE driver, in the
sandbox of the scan workers (`device.fuse`, `src/pandora_box/fuse.py`):

| Filesystem | Driver |
|---|---|
| vfat | kernel (its simplest and oldest driver) |
| exFAT | `exfat-fuse` |
| NTFS | `ntfs-3g` |
| ext4 | `fuse2fs` |

- **No privilege**: the kiosk opens `/dev/fuse` and mounts the connection
  itself (`noexec,nosuid,nodev`, read-only to scan); the driver only serves
  it. libfuse 3 drivers take the mounted connection as mount point
  `/dev/fd/N`; ntfs-3g carries its own FUSE library, which mounts by itself:
  a library preloaded into ntfs-3g only (`packaging/fuse/premounted.c`)
  hands it the connection. `fusermount3` is not setuid.
- **Sandbox**: the bubblewrap sandbox of the workers, as the
  `pandora-box-scan` user with the group of the block device, without
  capabilities. The block device is its only device; it sees `/usr`, the
  user names and nothing of the kiosk.
- **Watchdog**: a driver that crashed makes every access fail; a driver
  whose requests stay unanswered while the key reads nothing is killed after
  `device.command_timeout`. Either way the key is reported not verified.
  Once the key is unmounted, the kiosk waits for the driver to exit: it
  writes its last changes (cleaning).
- **Kernel drivers removed**: the image has no NTFS and exFAT kernel
  modules; ext4 stays for the data partition.

A compromised driver no longer takes over the kiosk, but it can still hide
files from the scan. fuse2fs refuses an ext4 key whose journal needs a
replay, like the kernel.

## Unified kernel image

The UKI (about 40 MB) holds the kernel, the initrd of the image
(`image/mkosi.images/initrd/`, without the udev hardware database, charset
conversions, Perl, documentation and networkd) and an initrd of kernel
modules. That one only holds what mounts the root filesystem
(`KernelModulesInitrdInclude=` in `image/mkosi.conf`): disk controllers
(NVMe, SATA, Intel VMD, eMMC, virtio), dm-verity, EROFS and CRC32C, which
EROFS loads by name. The other modules are loaded from the root filesystem.
A computer whose disk controller is not in this list cannot find its root
filesystem: add its module there.
