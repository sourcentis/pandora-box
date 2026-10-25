# PandoraBox Roadmap

This roadmap follows the development of **PandoraBox** phase by phase: goals, tasks done and to do, decisions. For an overview of the project, see the [README](README.md); for the documentation, see the [documentation site](https://sourcentis.github.io/pandora-box/).

## Vision

Provide a **free, auditable and hardened** USB decontamination kiosk, a credible alternative to commercial solutions, suited to sensitive environments (healthcare, industry, public administration).

## Guiding principles

- **Minimal, hardened image**: the system contains only what is needed to scan.
- **Defense in depth**: the USB device is hostile, and analyzers are assumed to be compromisable.
- **Offline by default**: no network connection is required to scan; updates go through a signed channel.
- **Plugin engines**: every detection engine implements a common interface.
- **Traceability**: every scan produces a structured, timestamped report.
- **Language**: Python 3.11+ for the orchestrator (reuse of PandoraBox v1 code, analysis ecosystem).

## Priorities

The open tasks of the phases below, by priority.

**1. First public release**

1. Create the release keys and publish their fingerprints (phase 2)
2. Write the deployment guide (phase 6)
3. Physical hardening and assembly guide (phase 2)

**2. Hardening and user features**

1. Update server: one image per kiosk identifier, checked at boot and every hour (phase 5)
2. Scan receipt for the user (phase 5)

**3. Later**

1. Fuzzing, then external security audit (phase 6)
2. Mapping to NIS2 and ISO 27001 (phase 6)
3. Executables with `capa`, content disarm and reconstruction with Dangerzone (phase 4)
4. Software TPM, once measured boot is used (phase 2)
5. Maintenance console or SSH, to reconsider (phase 2)

---

## Phase 0 — Foundations

Goal: restart from a clean base while reusing what works in PandoraBox v1.

### Code reused from PandoraBox v1

| Component | Decision |
|---|---|
| State machine (START, WAIT, SCAN, CLEAN, STOP) | Kept, refactored into a dedicated module |
| USB detection with `pyudev` | Kept |
| Device mounting / unmounting | Kept, hardened (mount options, read-only) |
| Quarantine of infected files | Kept |
| Curses interface (administrator mode) | Kept as a text display of the kiosk, without administrator functions |
| Logging, logrotate, systemd service | Kept, moved to structured JSON |
| USB auto-mount mode | Kept for development only (`device.auto_mount`): never on the kiosk, which mounts devices read-only itself |
| Image slideshow display (`fim`) | Removed, replaced by the graphical kiosk interface in phase 3, which reuses its images |
| Single-instance lock | Kept |
| `pypandora` calls | Removed, replaced by the engine pipeline |
| Comodo engine | Removed (no longer maintained on Linux) |

### Tasks

- [x] Project name: **PandoraBox** (repository `pandora-box`, Python module `pandora_box`)
- [x] New repository, GPL-3.0 license, `CONTRIBUTING.md`, `SECURITY.md`
- [x] Python package structure (`pyproject.toml`), type hints, `ruff`, `mypy`
- [x] TOML configuration (replaces the `.ini`), validated at startup
- [x] Keep `FAKE_SCAN` mode for development
- [x] Continuous integration: lint, unit tests, package build
- [x] End-to-end tests in a container with a simulated USB disk image (loop device)

### Current status

The PandoraBox v1 code has been ported to the `pandora_box` package (`src/pandora_box/`):

| Module | Role |
|---|---|
| `cli.py` | Command line entry point (`pandora-box`) |
| `config.py` | TOML configuration, validated at startup |
| `statemachine.py`, `kiosk.py` | State machine and kiosk workflow |
| `monitor.py` | USB detection with udev |
| `device.py` | Hardened mounting (`ro,noexec,nosuid,nodev` on a read-only block device, read-write only to clean) |
| `fuse.py` | NTFS, exFAT and ext4 read by FUSE drivers in the sandbox, with a watchdog |
| `inventory.py` | Device inventory: never follows links, never leaves the device, limits |
| `scanner.py`, `workers.py`, `worker.py` | Scan in supervised worker processes, timeouts and watchdog |
| `sigsets.py`, `publish.py` | Signed signature sets: verification, installation, publication from the sources, `pandora-box-signatures` command |
| `sandbox.py`, `seccomp.py`, `protocol.py` | Worker sandbox (bubblewrap, dedicated user, system call filter), validated JSON messages from the workers |
| `pipeline.py`, `hashing.py`, `filetype.py` | Per file: hashes (SHA-256, SHA-1, MD5), libmagic type, engines |
| `engines/` | Engine interface, MalwareBazaar, Hashlookup, ClamAV, YARA-X and fake engine |
| `hashdb.py`, `bloom.py`, `clamd.py` | MalwareBazaar database, DCSO Bloom filter reader, clamd client |
| `policy.py` | Verdict aggregation per file and per device |
| `report.py`, `schemas/` | JSON scan report and its JSON Schema |
| `signatures.py` | Signature provenance and freshness, verification hook (phase 2) |
| `quarantine.py` | Copy of infected files with a manifest referencing the report |
| `ui/` | Graphical kiosk interface (framebuffer, themes), curses (administrator) and console interfaces |
| `logs.py`, `lock.py` | JSON logs, single-instance lock |

Deployment files are in `packaging/`: example configuration, systemd service, tmpfiles and logrotate.

The detection engines, their data files and the verdict policy are described in [docs/engines.md](docs/engines.md). Every engine is enabled by default: the kiosk refuses to start when an enabled engine cannot load its signatures, or when no content engine (ClamAV or YARA-X) is enabled.

Development setup, configuration and tests: see the [development guide](https://sourcentis.github.io/pandora-box/development/).

## Phase 1 — Scanning engine (MVP)

Goal: replace Pandora with an equivalent or better local pipeline.

- [x] Common plugin interface: `scan(file) -> Verdict` (clean, suspicious, malicious, error, skipped)
- [x] Device inventory and hash computation (SHA-256, SHA-1, MD5)
- [x] **Hashlookup (CIRCL)** as an offline Bloom filter of known files
- [x] **MalwareBazaar**: offline list of malicious hashes
- [x] **ClamAV** through `clamd` (Unix socket) + third-party signatures
- [x] **YARA-X** + YARA Forge and signature-base rules
- [x] Real file type identification (`libmagic`)
- [x] Parallel scan in supervised worker processes, timeout per file and per engine
- [x] Verdict aggregation with a configurable policy
- [x] Limits: maximum file size, number of files, directory depth
- [x] Keys with several partitions
- [x] JSON scan report with a JSON Schema
- [x] Test set of samples and known false positives (`tests/corpus/`)

See [docs/engines.md](docs/engines.md) for the engines and the verdict policy.

## Phase 2 — Minimal hardened image

Goal: ship a ready-to-flash system image with the smallest possible attack surface.

### Current status

A first image is built with mkosi from Debian 13 packages and boots in a QEMU/KVM virtual machine, where an automated test plays the whole workflow with an emulated USB key and the real engines. The root filesystem is read-only (EROFS) and protected by dm-verity, the data (`/var`) is on its own partition, grown to fill the disk at boot, and the bootloader and unified kernel image are signed for Secure Boot. Only USB storage devices are allowed (USBGuard), and the image has no driver for USB network, wireless or Bluetooth devices. The system is hardened (kernel settings and lockdown, firewall, no login console, clamd sandbox) and the scan workers run in a sandbox (bubblewrap, dedicated user, system call filter). The kiosk only uses a signed signature set, verified at each start; without one, it scans nothing and waits for a signature update device. With the image profile `online`, the kiosk downloads the signatures from their sources itself (ClamAV, YARA Forge, MalwareBazaar, Hashlookup), with the credentials of the image, and signs the set with its own key. See [docs/image.md](docs/image.md):

```sh
image/build-test.sh   # build the test images (Docker only)
image/vm.sh test      # end-to-end test in a virtual machine
```

### Build

- [x] Image based on Debian 13 (trixie), built with `mkosi`
- [x] Single target: x86_64
- [x] Signed image and published checksums ([docs/release.md](docs/release.md))
- [x] Reproducible builds and an SBOM for every release

### Reference hardware

- **Computer**: refurbished Lenovo ThinkCentre (x86_64)
- **Memory**: 2 GB minimum, the size of the test virtual machine (clamd alone uses about 1 GB with the full ClamAV databases)
- **Display**: Waveshare 7-inch HDMI LCD (C), capacitive touchscreen, 1024x600 (USB touch controller `0eef:0005`)
- **Enclosure**: 3D-printed

Validated hardware and its settings: [docs/hardware.md](docs/hardware.md); BIOS configuration: [docs/install.md](docs/install.md).

Tasks:

- [x] List of validated ThinkCentre models
- [x] Touchscreen model selection and driver support
- [x] Enclosure design published under an open hardware license ([3D/](3D/))
- [x] BIOS configuration guide
- [x] Assembly guide
- [ ] ~~Physical hardening of the enclosure~~ *(not retained)*

### System integrity

- [x] Read-only root filesystem, variable data on a separate partition
- [x] `dm-verity` on the system partition
- [x] Unified Kernel Image (UKI) and Secure Boot
- [x] Atomic A/B updates with automatic rollback
- [x] Online image updates
- [x] Smaller UKI

### Hardening

- [x] No interactive account and no SSH
- [x] Maintenance device that brings back the logs
- [x] Hardened kernel settings
- [x] `nftables` firewall: deny all by default
- [x] **USBGuard**: only mass-storage devices allowed
- [x] No USB network, wireless, Bluetooth, serial or modem drivers
- [x] USBGuard rule for the touchscreen of the reference hardware
- [x] No boot loader menu
- [x] Devices mounted read-only on a read-only block device, no automount
- [x] Four supported filesystems: vfat, exFAT, NTFS, ext4
- [x] NTFS, exFAT and ext4 mounted through FUSE in a sandbox
- [x] Hardened systemd services
- [x] Each scan worker runs in a sandbox
- [x] One worker per engine
- [x] Audit log (`auditd`) for sensitive operations
- [x] Assessment with `lynis` and the ANSSI recommendations
- [ ] ~~Maintenance console or SSH, if the logs are not enough~~ *(not retained)*

### Signature updates

See [docs/signatures.md](docs/signatures.md).

- [x] Signed signature sets
- [x] Signature set verified at each start
- [x] Offline updates from a signed USB device, for air-gapped kiosks
- [x] Publication of signature sets from the sources
- [x] Online updates through a dedicated channel
- [x] Online updates from the sources themselves
- [x] Time synchronization of online kiosks
- [ ] Create the release keys and publish their fingerprints
- [ ] Define the publication schedule

### Testing in a virtual machine

The container end-to-end tests (`tests/e2e/run.sh`) cover the scan workflow, but not the image itself: boot, Secure Boot, dm-verity, kernel settings, udev, USBGuard, systemd services. The whole chain is tested locally in a QEMU/KVM virtual machine, without the reference hardware: the image boots with UEFI firmware (OVMF) and an empty USB 3 controller, and emulated USB keys (disk images) are inserted and removed while the kiosk runs, which triggers the same udev events as a real device. Hostile samples are only ever copied into key images, never onto the development desktop. See [docs/vm.md](docs/vm.md) for the automated test and the interactive virtual machine.

Tasks:

- [x] Test image profile
- [x] Automated end-to-end test in the virtual machine
- [x] Read-only root filesystem, data partition grown to fill the disk, data kept after a reboot
- [x] Secure Boot and dm-verity tested in the virtual machine
- [x] Test keys for every supported filesystem and the refused cases
- [x] Emulated keyboard and network adapter blocked by USBGuard
- [x] No outgoing network outside the update channel
- [x] A/B update and rollback tested in the virtual machine
- [x] Run in continuous integration
- [ ] Software TPM (`swtpm`), once measured boot is used

## Phase 3 — Kiosk interface

### Current status

The kiosk draws a graphical interface on its touch screen: waiting for a key, scan progress (files scanned, threats found, latest files and their verdict), the dangerous files listed before they are removed, a touch anywhere on the screen to clean, then the result. It is drawn with Pillow straight into the framebuffer, without a display server or a browser. An administrator customizes it with a theme built into the image: logo, colors, texts and images. See [docs/interface.md](docs/interface.md).

- [x] Graphical interface drawn into the framebuffer
- [x] User flow: insertion, progress, dangerous files, cleaning, verdict
- [x] Touch-first interface for any screen size
- [x] Theme customization by the administrator
- [x] Internationalization: French and English
- [x] German and Dutch texts built in
- [x] Accessibility: contrast and font size
- [ ] ~~Protected administrator mode~~ *(not retained)*

## Phase 4 — Advanced analysis

- [x] PDF analysis: active content is suspicious
- [x] Archives unpacked and scanned within limits
- [x] Encrypted archives and documents flagged as unscannable
- [x] Detection of programs disguised as documents
- [ ] Executables analyzed with `capa`, optional
- [ ] Content disarm and reconstruction (CDR) with Dangerzone
- [ ] ~~Selective copy of clean files to a second device~~ *(not retained)*
- [ ] ~~Reformatting option for the cleaning~~ *(not retained)*
- [ ] ~~Office documents with `oletools`~~ *(not retained)*

## Phase 5 — Fleet management and traceability

- [x] Log export to a SIEM ([docs/siem.md](docs/siem.md))
- [x] Signed identifier of each key for the file transfer stations
- [x] Inbound file transfer station: copy the clean files of a key to a server ([docs/airgap.md](docs/airgap.md))
- [x] Outbound file transfer station: copy the clean files waiting on a server to a key
- [x] Statistics dashboard (devices scanned, detections): in the SIEM ([docs/siem.md](docs/siem.md#dashboards))
- [ ] Centralized distribution of signed updates: the update server, below
- [ ] ~~Printed or exported scan receipt for the user~~ *(not retained)*
- [ ] ~~Optional central server: kiosk inventory, reports, signature status~~ *(not retained)*

### Update server

An organization of about a hundred kiosks publishes their updates on its own server. Each image has a unique identifier (uid), and the server holds one image per uid, ready to install, and the signature set shared by every kiosk. A kiosk checks for a newer image of its uid, and for newer signatures, at boot and then every hour; it downloads either or both. Most of the chain exists: the online image update (`updates.image_url`: signed manifest, newer version only, download as an unprivileged user, installation without network, restart when idle, A/B with rollback) and the published signature set (`updates.url`). What is missing:

- [ ] Image uid: 128 random bits, chosen by the fleet inventory, kept in the image (read-only), named in every log entry and in the maintenance export
- [ ] Fleet inventory (uid, kiosk name, profile, configuration and theme of each image), and build of every image of the fleet with one PIN of the YubiKey, from a common base build: only the configuration differs
- [ ] Tree of the update server, built by the fleet tool: `<uid>/` (image update of that uid) and `signatures/` (shared set); a static HTTPS server, no code on the server
- [ ] The signed manifest of an image update names its uid: a kiosk refuses the image of another uid, even validly signed and newer
- [ ] `updates.server` in the configuration: the kiosk derives the folder of its image and of the signatures from it and from its uid
- [ ] Check at boot (once the network and the time are there) and every hour, with a random delay; only the manifests are downloaded when nothing changed
- [ ] A version that failed to boot (rollback) is not installed again: the kiosk waits for a newer one
- [ ] Interrupted downloads resumed (HTTP range): an image update is about 215 MB
- [ ] A signature key separate from the update key, which the kiosk only trusts for signature sets: the publication host signs the sets unattended, the update key stays offline for the image updates and maintenance requests
- [ ] Gradual rollout: an image is published to a few pilot uids first, then to the others
- [ ] Events and SIEM dashboard of the fleet: uid, image version and signature serial of each kiosk, updates found, installed, refused or rolled back
- [ ] Test in the virtual machine: an update server in a container, two uids, a refused image of another uid, a rollback not installed again
- [ ] Guide: deploying the update server and adding a kiosk to the fleet

## Phase 6 — Assurance and compliance

- [x] Detection regression test corpus
- [x] Threat model ([docs/threat-model.md](docs/threat-model.md))
- [ ] Write the deployment guide
- [ ] Fuzzing of the entry points
- [ ] External security audit of the image
- [ ] Mapping to NIS2 and ISO 27001 requirements (control 7.10 "Storage media")

---

## Out of scope (for now)

- Workstation agent blocking devices that have not been scanned
- Dynamic analysis (execution sandbox)
- Encrypted devices (BitLocker, VeraCrypt)
- Smartphones and MTP devices
- `.deb` package installable on an existing system: PandoraBox is only distributed as a complete hardened image

## Decisions

### Scan

- Policy for a "suspicious" verdict: configurable with `scan.suspicious`, `block` (default, suspicious files removed like malicious ones) or `warn` (kept, with a warning).
- Policy for files that could not be fully scanned (engine error or timeout, limits): configurable with `scan.on_error`. `block` (default) reports the device as not verified; unscanned files are listed but never removed, since they are not known to be malicious.
- A Hashlookup hit means "known file", not "benign file": content engines also scan known files by default (the CIRCL filter lists the EICAR test file, tools and malware; `engines.hashlookup.skip_content_engines` skips them, opt-in), a malicious hash always wins, and the decision is recorded in the scan report.
- YARA Forge already includes signature-base: only YARA Forge `core` is configured by default, signature-base is opt-in.
- A key with several partitions is scanned filesystem by filesystem, with one verdict, report and confirmation for the key; an encrypted or unknown partition makes the key not verified.
- Archives are unpacked and scanned by ClamAV within its limits; beyond them (decompression bombs) the file is not fully scanned. Encrypted archives and documents are unscannable (ClamAV `AlertEncrypted`).
- PDF: JavaScript and Launch actions are suspicious; automatic actions, embedded files and forms are reported (`engines.heuristics`, like `pdfid`). A program disguised as a document (extension and real type mismatch, double extension) is detected.
- Office documents: `oletools` is not added, as documents with macros are already suspicious (ClamAV `AlertOLE2Macros`).

### Build and releases

- Single target x86_64: ARM64 is not targeted, the Raspberry Pi proved too slow.
- The release keys are kept in two YubiKeys 5: the Secure Boot key (RSA 2048, slot 9c) and the update key (Ed25519, slot 82), used through PKCS#11 by the build ([docs/release.md](docs/release.md)).
- `image/release.sh` builds a tag only, signs the image with the release keys, and publishes the compressed disk image, the signed image update, the SBOM (CycloneDX) and the checksums signed with the update key as a draft GitHub release. Only the image without profile is published: the profile `online` holds the credentials of an organization.
- A release is reproducible: its inputs come from the tag (Debian packages and build tools from snapshot.debian.org at the time of the tag, that time as `SOURCE_DATE_EPOCH` and image version, a seed derived from the commit), and `image/reproduce.sh` builds it again and compares everything but the signatures, which hold the time they were made.
- The unified kernel image only holds the kernel modules needed to mount the root filesystem: 40 MB instead of 130 MB.

### Hardware

- Validated computer: ThinkCentre M720q Tiny (10T7, Core i5-9400T, Intel UHD 630). Touchscreen: Waveshare 7-inch HDMI LCD (C), its mode on the kernel command line, its touch controller (`0eef:0005`, serial, HID interface only, internal port) allowed by USBGuard.
- Physical hardening: only the scanning USB ports reachable from the outside, the other ports and the BIOS access protected.
- Enclosure under the CERN-OHL-S v2: STL of the 7-inch and 10-inch models, OpenSCAD source of the 7-inch model; the source of the 10-inch model remains to be added.

### Hardening

- No `login` program, no root password, no login console, Ctrl-Alt-Del masked. The maintenance device (a request signed with the update key, valid 7 days) brings back the logs without login or network; a maintenance console or SSH goes against the absence of any login, and is only reconsidered if the logs are not enough.
- No administrator mode on the kiosk itself (screen of status, logs and actions, behind a PIN or a signed key): the maintenance device already brings the logs back, the updates come on signed keys, and the actions (restart, switch off) need nothing more than the power; a PIN would add a shared secret, observable and only changed with a new image, to a system that has none.
- Kernel: `lockdown=confidentiality`, memory initialization, IOMMU, unused modules removed. USBGuard authorizes no device before it starts (`usbcore.authorized_default=0`); USB HID is kept for the touchscreen, keyboards and mice are blocked; systemd-boot does not read the keyboard.
- systemd services: `ProtectSystem`, `NoNewPrivileges`, seccomp filters, `PrivateNetwork` and `MemoryDenyWriteExecute` for clamd, exposure measured by `systemd-analyze security` in the virtual machine test.
- Scan workers: one per engine, each in a `bubblewrap` sandbox without network, under a dedicated user without capabilities, with a system call filter. The kiosk opens the files and passes their descriptors, hashes the files itself (hash engines never get the file), only accepts validated JSON from the workers and combines the results.

### Devices and mounting

- Devices are mounted `ro,noexec,nosuid,nodev` by the kiosk, without automount (no udisks); only vfat, exFAT, NTFS and ext4 are mounted. The block device is read-only while it is scanned (`blockdev --setro`): the kernel writes nothing to it.
- An ext4 key whose journal needs a replay (removed without being ejected) is not verified and never mounted: read-only, the kiosk would see other files than a computer that replays the journal; read-write, the kernel would replay a journal given by the device. The kiosk asks to eject it properly from a computer, then to insert it again.
- A kernel filesystem driver parses the structures given by the device: a flaw (ext4, ntfs3 and exfat get regular fuzzing findings on crafted images) runs code in the kernel, before any sandbox. NTFS, exFAT and ext4 are therefore read by FUSE drivers (ntfs-3g, exfat-fuse, fuse2fs, Debian packages) in the sandbox of the scan workers, with the block device as their only device (`device.fuse`); the image has no ntfs3 and exfat kernel modules. vfat stays in the kernel, its simplest and oldest driver: fusefat is experimental, lklfuse is not packaged in Debian. A compromised FUSE driver no longer takes over the kiosk, but can still hide files from the scan; a disposable micro-VM would also cover vfat, at a much higher cost.
- The kiosk mounts the FUSE connection itself (`mount -t fuse.TYPE -o fd=N`), the driver only serves it, as the sandbox user: libfuse 3 drivers take it as mount point `/dev/fd/N`; ntfs-3g carries its own FUSE library, which mounts by itself, so a library preloaded into it (`packaging/fuse/premounted.c`) hands it the connection. No setuid `fusermount3`.
- A crashed driver makes every access fail; a driver whose requests stay unanswered while the device is idle is killed by a watchdog after `device.command_timeout`. Either way the key is not verified. Once the device is unmounted, the kiosk waits for the driver to exit: it writes its last changes (cleaning).
- fuse2fs refuses an ext4 key whose journal needs a replay, like the kernel; it mounts an ext4 key with corrupted group descriptors, whose folders then cannot be read: the key is not verified instead of refused.

### Signatures

- Signature sets are signed with Ed25519 and verified with `openssl`: no rollback, atomic installation, previous set kept; the installed set is verified at each start, and the engines (and clamd) only read it.
- `pandora-box-signatures publish` downloads the sources (ClamAV, YARA Forge, MalwareBazaar, Hashlookup) with a cache, checks the set with the kiosk engines, then signs it (container `publish/`).
- Online (image profile `online`): the update service is the only user allowed out by the firewall (HTTP(S), proxy), only the changed files are downloaded, the new set is loaded when the kiosk is idle. Built from the sources, the set is signed with a key generated on the kiosk; the abuse.ch Auth-Key is a systemd credential of the image (`image/credentials.toml`, outside git).
- Online kiosks synchronize their clock with systemd-timesyncd (NTP servers of the organization or from DHCP); only timesyncd may send NTP requests.

### File transfer stations

- The stations only handle a verified key: a key the kiosk could scan entirely. A key not verified is refused, without copy in either direction and without identifier written on it.
- Inbound station (`[airgap]`): from a verified key, only the clean files are copied, never the malicious or suspicious ones, to a server configured on the kiosk, by rsync over SSH (rsync on the server) or SFTP. SMB is not supported for now: the Python client would not survive a rewrite in Rust, which has no mature SMB 3 client yet; a Windows server is reached by its own OpenSSH server over SFTP, with `windows_names` reporting the names NTFS refuses or confuses (case ignored), and a fallback when `posix-rename` is missing; checked against Windows Server 2025 in QEMU (`tests/windows/`), whose OpenSSH only lets the `OpenSSH Users` group in and only opens port 22 to the Private network profile. One directory per key, named after its identifier, kept as a mirror of the clean files of its last verified scan: new and changed files (size, modification time) are copied, files no longer on the key, or no longer clean, are deleted from the server; the scan reports are kept in its `.pandora-box/` folder, one per scan, named after the `report_id`. A per-scan snapshot was dropped: every insertion would copy the whole key again. The key is not cleaned unless `airgap.clean` is set; otherwise the token is the only file written on it, with the files of the server (outbound).
- The kiosk has no network: it stages the clean files (checked against the scanned SHA-256) for the service `pandora-box-airgap`, its own user let out by the firewall, which reads nothing else of the kiosk and gets the SSH key as a systemd credential; the kiosk asks it over a Unix socket and deletes the staged files afterwards. The host key of an SSH server must be listed in `airgap.known_hosts`, never trusted on first use.
- A stolen station leads to no key: the folder of a key on the server is named after a 256-bit secret of its token (SHA-256), computed when the key is inserted and never logged or kept; the account of the kiosks cannot list the folders of the keys (Unix mode 0300, NTFS rights without listing, rrsync in a readable folder holding them). A station keeps no scan report (they go to the server), has no quarantine (unless it cleans, with `quarantine.enabled`), logs no names, hashes, labels or serial numbers of the keys, and stages in memory (tmpfs). Still on it: the USB descriptors in the system journal and the USBGuard audit log, and the credentials of the image (disk not encrypted).
- Outbound station (`airgap.mode`, `both` by default: both directions at the same insertion): a key holding a file the cleaning would remove (a malicious file, or a suspicious file with `scan.suspicious = "block"`) gets nothing until it is cleaned, then inserted again. A station does not clean by default; with `airgap.clean` it cleans the key as any kiosk (a touch on the screen, `scan.suspicious` for the suspicious files, `quarantine.enabled` for a copy of the removed files, the only data of the keys it then keeps), after the copy to the server, and a key cleaned entirely gets the files of the server at the same insertion. The protected network puts the files for a key in `<folder>/.pandora-box/outbound/` on the server (protected from the inbound mirror), found by the identifier of the key in its reports. The kiosk sends the files of the key (path, size, modification time); the service downloads into the staging folder (memory) those the key does not have or has in another version, and leaves them on the server. They are scanned like the files of a key, then the clean ones are written at the root of its first filesystem, replacing a file of the same name, checked against the scanned SHA-256 (the service could change them after the scan), after a check of its free space; the limits of each filesystem are handled (4 GiB files on vfat, forbidden characters, name length, case-insensitive names), a file that cannot be written is reported, never renamed, and `.pandora-box` stays reserved for the token. The key stays in the kiosk from the scan to the end of the copy.
- Identifier: the USB serial number is missing or shared on some keys, so at the first insertion of a verified key the kiosk writes a token in a hidden file `.pandora-box` at its root (on the first supported partition): a random UUID and a random 256-bit secret, signed with a key of the kiosks of the organization (Ed25519, systemd credential of the image). The file is read as hostile data (size limit, strict format); a malformed or unsigned token is logged and replaced with a new one (new identifier, empty outbound directory). The signature prevents forging an identifier, not copying the file to another key.
- An ext4 key with a journal to replay is not reformatted to receive files: its identifier could not be read, and it would lose its outbound files.

### Fleet updates

- One image per uid, not one image for the fleet with a configuration per kiosk: the configuration stays in the read-only root filesystem, covered by dm-verity and Secure Boot, and each kiosk can have its own (name, network, SIEM, file transfer server, theme). A uid can also be given to several identical kiosks.
- The update server is a static HTTPS server that holds no key: the kiosks only download signed files, so a compromised server can delay updates, not install anything. The uid in the signed manifest stops it from giving a kiosk the image of another one.
- The uid is long and random: the folder of an image cannot be guessed, as an image of the profile `online` holds credentials (abuse.ch Auth-Key). Client certificates on the server are possible, not required.
- The kiosks pull, the server pushes nothing and knows nothing of them: with a hundred kiosks checking every hour, a few kilobytes of manifests per check; the state of the fleet is in the SIEM, as the statistics, not on a server of PandoraBox.
- Signature sets are signed automatically, many times a day, by the publication host (`publish/`), which copies them to the update server: with a key of their own, trusted only for signature sets, the update key and the Secure Boot key stay offline in the YubiKeys. Whoever steals the signature key can weaken the detection (a set with fewer signatures, still newer and loaded by the engines), not change the system nor get the logs.

### Logs and statistics

- The statistics of a fleet (keys scanned, verdicts, detections, cleanings, signature sets) are dashboards of the SIEM that receives the logs, not a server of PandoraBox: one documentation for every SIEM (Splunk, Elastic, Graylog, Wazuh, Loki), built on `device_verdict`, the summary of the scan of a key (counts, duration, detection names, never a file name), tied to the other events of the key by its `report_id`.

### Interface

- The interface is drawn with Pillow into the framebuffer, without display server, browser or local web server: the earlier plan (FastAPI and htmx in `cage` with Chromium) would have added a browser and a socket to the image. Cleaning is confirmed by a touch anywhere on the screen, without buttons.
- Accessibility: a theme is refused when a text does not reach the WCAG 2.1 AA contrast with its background (4.5:1, 3:1 for large bold texts and the progress bar); `text_scale` enlarges every text up to 1.5 times, and the tests check that no text leaves the screen or overlaps another one, on every screen, language, screen size and text size. A user setting on the kiosk itself is not added: the screen has no buttons.
- An administrator customizes it with a theme folder built into the image (logo, colors, texts of every screen, images, fonts), checked at build time; `pandora-box-theme preview` shows the screens without a kiosk. English, French, German and Dutch are built in (`display.language`), a theme can add a language or change their texts; the screens fit the longer texts (a title wraps, the animation of the waiting screen shrinks, the banner of the threats screen takes two lines).

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md). To report a vulnerability, follow [SECURITY.md](SECURITY.md).

## License

PandoraBox is free software, licensed under the [GNU General Public License v3.0](LICENSE).
