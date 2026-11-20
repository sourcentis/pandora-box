# Introduction

![Pandora-Box](images/pandora-box.png){ width="300" .no-border }

**PandoraBox** is an open source USB decontamination kiosk, a "sheep-dip
station": a user inserts a USB key, the kiosk scans every file with several
detection engines, shows the dangerous files it found, and removes them when
the user touches the screen. It is a complete rewrite of the first version of
PandoraBox, without dependency on Pandora (CIRCL).


## Objective

USB keys remain a common way into information systems that are otherwise
well protected: shared between organizations, used on unmanaged computers,
plugged into isolated networks. A decontamination kiosk checks them before
they are used on a workstation.

PandoraBox aims to be a **free, auditable and hardened** alternative to
commercial kiosks, for sensitive environments: healthcare, industry, public
administration. It runs on a refurbished small computer with a touch screen,
and works without network.

## How it works

- **Several engines**: known malicious hashes (MalwareBazaar), known files
  (CIRCL Hashlookup), ClamAV, YARA-X rules (YARA Forge) and structure
  heuristics (programs disguised as documents, PDF with JavaScript). See
  [Detection engines](engines.md).
- **Fail closed**: a file that could not be fully scanned (encrypted archive,
  limit exceeded, engine error) is never reported as clean. Every partition
  of a key is scanned; a partition that cannot be (encrypted, unknown
  filesystem) makes the key not verified.
- **Nothing is removed without the user**: the dangerous files are listed on
  the screen, copied to the quarantine of the kiosk, then removed from the key
  only after a touch of the screen.
- **Traceability**: every scan produces a structured JSON report.

## Guiding principles

- **Minimal, hardened image**: the system contains only what is needed to
  scan. Read-only root filesystem with dm-verity, Secure Boot, USBGuard, no
  account and no login. See [Image internals](image.md).
- **Defense in depth**: the USB key is hostile, and the analyzers are assumed
  to be compromisable. Each engine runs in its own sandbox, without network.
- **Offline by default**: no network is needed to scan; signatures and system
  updates come on signed USB keys, or through a dedicated online channel. See
  [Signatures](signatures.md).
- **Customizable**: the organization sets its logo, colors and texts of the
  interface. See [Interface](interface.md).

## Documentation

### Install a kiosk

To plan a deployment in an organization (keys, places, network, operation),
start with the [Deployment guide](deployment.md).

| Step | Page |
|---|---|
| 1. Choose the hardware | [Hardware](hardware.md): validated computer and screen, enclosure |
| 2. Build the image | [Building the image](build.md): configuration, keys, profile `online` |
| 3. Test it in a virtual machine | [Testing with QEMU](vm.md): automated test, interactive machine, real USB keys |
| 4. Install the kiosk | [Initial installation](install.md): BIOS, writing the disk, Secure Boot, first signature set |

### Maintain a kiosk

| Task | Page |
|---|---|
| Update the signatures | [Signatures](signatures.md): signature update devices, publication, online updates |
| Update the system | [System updates](update.md): A/B image updates, from a USB key or online |
| Read the logs | [Logs](logs.md): maintenance device; [Log export to a SIEM](siem.md) |

### Reference

| Page | Content |
|---|---|
| [Interface](interface.md) | Screens of the kiosk, theme of the organization |
| [Configuration](configuration.md) | Every setting of `pandora-box.toml` |
| [Detection engines](engines.md) | Engines, verdict policy, scan report |
| [Image internals](image.md) | Partitions, boot chain, USB devices, hardening, sandbox |
| [Threat model](threat-model.md) | What the kiosk protects, against whom, and what it does not cover |
| [Development](development.md) | Run the kiosk from the sources, tests |

The progress of the project is followed in the
[roadmap](https://github.com/sourcentis/pandora-box/blob/main/ROADMAP.md).
PandoraBox is free software, licensed under the
[GNU General Public License v3.0](https://github.com/sourcentis/pandora-box/blob/main/LICENSE).
