# Threat model

What PandoraBox protects, against whom, how, and what it does not cover. It
describes the kiosk image built from this repository, on the validated
hardware, installed as in [Initial installation](install.md).

## In short

A kiosk takes USB keys of unknown origin, scans their files with several
engines and removes the dangerous ones before the keys are used on a
workstation. It assumes that **every key is hostile**: not only its files,
but also its filesystem and the USB device itself. Everything that reads the
key is confined, the system cannot be changed without the release keys, and
the kiosk tells the user when it could not check a key entirely.

PandoraBox reduces the risk; it does not remove it. A file that no engine
detects is reported clean, and a key whose firmware is malicious can show
other files to the workstation. Keep the protections of the workstations.

## Assets

| Asset | Why it matters |
|---|---|
| The verdict shown to the user | A key reported clean is used on a workstation: a wrong "clean" is the main failure |
| The integrity of the kiosk system | A compromised kiosk could report every key clean, or infect the keys it scans |
| The signature sets | Old or forged signatures detect nothing |
| The release keys (Secure Boot, update) | Whoever holds them decides what a kiosk boots and trusts |
| Scan reports, logs and quarantine | Names and hashes of the files of the users, copies of malware |
| The workstations and the network behind the kiosk | What the kiosk is there to protect |

## Attackers

| Attacker | Means | Goal |
|---|---|---|
| **A user, unknowingly** | A key infected elsewhere | None: the most common case, and the reason for the kiosk |
| **A crafted key** | Malicious files, crafted filesystem, partition table or USB descriptors, a device that is not a storage device (BadUSB) | Pass malware off as clean; take over the kiosk |
| **A passer-by** | Physical access to the kiosk for minutes: the scanning ports, the screen, the enclosure | Change the system, read the reports and the quarantine |
| **The network** | An online kiosk talks to update servers, NTP and a SIEM | Forge signatures, delay updates, read the logs |
| **The supply chain** | Debian packages, signature sources (ClamAV, YARA Forge, abuse.ch, CIRCL), the build machine | Plant a backdoor in an image or a signature set |

The administrators who build the images and hold the release keys are
trusted.

## Trust boundaries

```
 USB key (hostile)
   │  USB descriptors ─────────► USBGuard: only mass storage, touchscreen by its rule
   │  partition table, vfat ───► kernel of the kiosk
   │  NTFS, exFAT, ext4 ───────► FUSE driver, sandboxed (pandora-box-scan, no capability)
   ▼
 kiosk process (root, hardened systemd service)
   │  lists, opens and hashes the files; never interprets their content
   │  passes each file as a descriptor, gets validated JSON back
   ▼
 scan workers, one per engine, sandboxed (bubblewrap, no network, seccomp)
   libmagic, YARA-X, heuristics, clamd client  ─►  clamd (own sandbox, no network)

 Signature sets, image updates, maintenance requests (hostile until verified)
   └─► Ed25519 signature checked against the keys of the read-only root filesystem
 Boot: firmware ─► systemd-boot ─► kernel image, signed (Secure Boot) ─► root on dm-verity
```

## Threats and mitigations

### A crafted key against the kiosk

| Threat | Mitigations |
|---|---|
| A USB device that is a keyboard, a network adapter or a serial port (BadUSB) | USBGuard authorizes no device before it starts, then only mass storage; keyboards and mice are blocked; no USB network, Bluetooth, Wi-Fi or serial drivers ([USB devices](image.md#usb-devices)); each refused device is logged and sent to the SIEM (`usb_device_blocked`) |
| A crafted filesystem exploiting a kernel driver | NTFS, exFAT and ext4 are read by FUSE drivers in the sandbox, the kernel has no driver for NTFS and exFAT; only vfat stays in the kernel ([Filesystem drivers](image.md#filesystem-drivers)) |
| A file exploiting a parser (libmagic, YARA-X, ClamAV) | Each engine in its own worker, sandboxed: no network, no device, no data of the kiosk, dedicated user, system call filter; clamd in its own sandbox; a worker only reports its own engine, the kiosk combines the results ([Scan worker sandbox](image.md#scan-worker-sandbox)) |
| Links, special files, deep trees, huge keys, decompression bombs | The inventory never follows a link nor leaves the device; limits on file size, file count and depth; beyond them the key is not verified |
| Writing to the key during the scan, an ext4 journal replay | The key is mounted read-only on a read-only block device; an ext4 key whose journal needs a replay is refused |
| A worker or driver that crashes or hangs | Timeouts and watchdogs; the files concerned are not fully scanned and the key is reported **not verified**, never clean |
| A key that disconnects itself during its scan, to come back with another content or as another device | The USB device of the key is checked during the scan: a key removed or enumerated again is a suspicious behavior, logged and sent to the SIEM (`device_suspicious_behavior`); the key is **not verified**, neither cleaned nor copied to a server |
| A key swapped between the scan and the cleaning | A file is only removed if its SHA-256 is still the scanned one |

### Malware passed off as clean

| Threat | Mitigations |
|---|---|
| Malware unknown to one engine | Five engines: ClamAV, YARA-X (YARA Forge), MalwareBazaar, Hashlookup, heuristics; a malicious verdict from any engine wins |
| A known file used as a disguise | A Hashlookup hit means "known", not "benign": content engines still scan it by default |
| Encrypted archives and documents, files beyond the limits | Not scannable: reported, and the key is not verified (`scan.on_error = "block"`) |
| Documents with macros or active content, programs disguised as documents | Reported suspicious, removed like malicious files by default (`scan.suspicious = "block"`) |
| Old signatures | Freshness warnings on the screen; signature sets are updated offline or online |

### The system of the kiosk

| Threat | Mitigations |
|---|---|
| Changing the system on the disk | Read-only EROFS root filesystem checked by dm-verity, its root hash in the kernel image signed for Secure Boot; the firmware only trusts the certificate of the image; a modified block cannot be read |
| Booting something else | BIOS supervisor password, Secure Boot in custom mode, no boot loader menu, no keyboard read at boot ([Initial installation](install.md)) |
| Logging in | No login program, no root password, no console, Ctrl-Alt-Del masked; logs leave through a maintenance request signed with the update key |
| Installing an older or forged version | Image updates and signature sets are signed with the update key and must be newer than the installed ones; A/B slots with automatic return to the previous version |
| Kernel attacks from a compromised process | Lockdown `confidentiality`, no unprivileged user namespaces, eBPF or userfaultfd, unused kernel modules removed, IOMMU |

### The network (online kiosks)

| Threat | Mitigations |
|---|---|
| Forged or replayed signatures from a malicious server | Sets built on the kiosk from the sources are checked by the engines, then signed with a key generated on the kiosk; published sets must carry a trusted signature and a newer serial; ClamAV databases are also signed by Cisco Talos |
| Other traffic from a compromised process | Firewall: everything dropped except DHCP, DNS, NTP, the update service and the SIEM export, each allowed by its system user; the kiosk and the workers have no network |
| Reading the exported logs | Syslog over TLS by default, with the certificate authorities of the SIEM |
| A fake server receiving the copied keys, or reading them on the way (airgap) | The host key of the SSH server must be listed in the image, never trusted on first use; the copy service has its own user and reads nothing of the kiosk but the clean files staged for it |

### Supply chain and releases

| Threat | Mitigations |
|---|---|
| A tampered release | Release keys on two YubiKeys; checksums signed with the update key; reproducible builds: anyone can rebuild a release from its tag and compare it ([Releases](release.md)) |
| A tampered package | Debian packages from snapshot.debian.org, pinned at the time of the tag; Python packages pinned by hash; a software bill of materials (CycloneDX) per release |

## What PandoraBox does not cover

- **Undetected malware.** A new or targeted file that no engine knows is
  reported clean. The kiosk is one layer: keep the protections of the
  workstations.
- **A key with malicious firmware.** A USB key can show some content to the
  kiosk and other content to the workstation, or change once the kiosk has
  ejected it. No scan can rule that out: only trusted keys do.
- **The USB and storage stack of the kernel.** The kernel still parses the
  USB descriptors, the partition table and vfat. A kernel flaw there is
  outside every sandbox.
- **A compromised FUSE driver or engine** cannot take over the kiosk, but it
  can hide files or report a wrong verdict for its own engine.
- **The kiosk process itself** runs as root: it lists the files and hashes
  them, and draws their names on the screen (FreeType); a flaw there is not
  sandboxed.
- **Physical access beyond the scanning ports.** Opening the enclosure gives
  access to the disk: `/var` is not encrypted (no TPM), so the reports, the
  logs and the quarantine can be read. A station that copies to a server
  keeps none of them, nor the folders of the keys on the server: see
  [A stolen kiosk](airgap.md#a-stolen-kiosk). Lost BIOS password, disconnected
  intrusion switch or reachable internal ports defeat the boot protections.
- **The release keys.** Whoever holds the YubiKeys and their PIN can build
  an image that the kiosks boot and trust.
- **The clock of an offline kiosk.** The freshness warnings rely on the clock
  of the computer.
- **Denial of service.** A key can make a scan long or fail; the limits and
  timeouts keep the kiosk available, the key is not verified.
- **Encrypted devices, smartphones and MTP devices** are not supported.

## Assumptions

- The kiosk runs an image built from this repository, with release keys
  kept as described in [Releases](release.md).
- It is installed as in [Initial installation](install.md): BIOS password,
  Secure Boot with the certificate of the image only, enclosure that only
  exposes the scanning ports.
- Its signatures are updated regularly.
- Users bring the cleaned keys to workstations that keep their own
  protections.

To report a vulnerability, follow the [security policy](https://github.com/sourcentis/pandora-box/blob/main/SECURITY.md).
