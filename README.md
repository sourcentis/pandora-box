# Pandora-Box

[<img src="docs/images/pandora-box.png" width="200">](docs/images/pandora-box.png)

[![CI](https://img.shields.io/github/actions/workflow/status/sourcentis/pandora-box/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/sourcentis/pandora-box/actions/workflows/ci.yml)
![License](https://img.shields.io/github/license/sourcentis/pandora-box.svg?style=flat-square)
![Python](https://img.shields.io/badge/python-3.11%2B-blue?style=flat-square)
![Contributors](https://img.shields.io/github/contributors/sourcentis/pandora-box.svg?style=flat-square)
![Stars](https://img.shields.io/github/stars/sourcentis/pandora-box?style=flat-square)

**English** | [Français](README.fr.md)

### Introduction

USB keys remain a common way into information systems that are otherwise well protected: shared between organizations, plugged into unmanaged computers, carried into isolated networks. A decontamination kiosk, or "sheep-dip station", checks them before they reach a workstation.

**PandoraBox** is an open source USB decontamination kiosk. A user inserts a USB key, the kiosk scans every file with several detection engines, shows on its touch screen the dangerous files it found, and removes them when the user touches the screen. It runs on a refurbished small computer, works without network, and is distributed as a complete hardened system image.

PandoraBox aims to be a **free, auditable and hardened** alternative to commercial kiosks, for sensitive environments such as healthcare, industry and public administration. It is a complete rewrite of the first version of PandoraBox, without dependency on Pandora (CIRCL).

📚 [Explore the Documentation](https://sourcentis.github.io/pandora-box/) |
🗺️ [Read the Roadmap](ROADMAP.md) |
🔍 [View the Sources](src/pandora_box/)

## 🌟 **Key Features**

- 🔍 **Several detection engines:** known malicious hashes ([MalwareBazaar](https://bazaar.abuse.ch/)), known files ([CIRCL Hashlookup](https://www.circl.lu/services/hashlookup/)), [ClamAV](https://www.clamav.net/), [YARA-X](https://virustotal.github.io/yara-x/) with the [YARA Forge](https://yarahq.github.io/) rules, and heuristics for programs disguised as documents and PDF with JavaScript.
- 🚫 **Fail closed:** a file that could not be fully scanned (encrypted archive, limit exceeded, engine error) is never reported as clean.
- 👆 **Touch interface, no buttons:** progress of the scan, dangerous files listed before their removal, a touch anywhere on the screen to clean the key.
- 🎨 **Customizable:** the organization sets its logo, colors, texts and language of the interface.
- 🗄️ **Quarantine and reports:** dangerous files are copied to the kiosk before their removal, and every scan produces a JSON report.
- 🛡️ **Hardened image:** read-only root filesystem protected by dm-verity, Secure Boot, USBGuard against BadUSB devices, no account and no login, each engine in a sandbox without network.
- ✍️ **Signed updates:** signature sets and system updates are signed, installed from a USB key on offline kiosks, or downloaded through a dedicated channel; A/B system updates with automatic rollback.
- 🧰 **Maintenance without login:** a signed USB key brings back the logs of the kiosk.

## 🖼️ **Screenshots**

### ⏳ **Waiting for a key, scan in progress**

[<img src="docs/images/interface-ready.png" width="400">](docs/images/interface-ready.png) [<img src="docs/images/interface-scanning.png" width="400">](docs/images/interface-scanning.png)

### ☣️ **Threats found, key cleaned**

[<img src="docs/images/interface-threats.png" width="400">](docs/images/interface-threats.png) [<img src="docs/images/interface-cleaned.png" width="400">](docs/images/interface-cleaned.png)

## 🛠️ **Technologies Used**

- **Kiosk:** Python 3.11+, with [Pillow](https://python-pillow.org/) to draw the interface straight into the framebuffer (no display server, no browser)
- **Engines:** ClamAV (clamd), YARA-X, MalwareBazaar and Hashlookup databases, libmagic
- **System:** Debian 13 image built with [mkosi](https://github.com/systemd/mkosi), systemd-boot, Secure Boot, dm-verity, systemd-sysupdate, USBGuard, bubblewrap, nftables
- **Tests:** pytest, and an end-to-end test of the whole image in a QEMU/KVM virtual machine

## 💻 **Hardware**

- **Computer:** refurbished Lenovo ThinkCentre Tiny (validated: M720q, Core i5-9400T; also tested: HP ProDesk 400 G5 SFF), 2 GB of memory minimum
- **Screen:** Waveshare 7-inch HDMI LCD (C), capacitive touch screen, 1024x600
- **Enclosure:** 3D-printed, in the [3D](3D/) folder (CERN-OHL-S v2)

See the [hardware guide](https://sourcentis.github.io/pandora-box/hardware/), and the [installation guide](https://sourcentis.github.io/pandora-box/install/) for the BIOS settings.

## 📦 **Installation**

PandoraBox is distributed as a complete system image, built with Docker only:

```bash
git clone https://github.com/sourcentis/pandora-box.git
cd pandora-box
image/build.sh                                  # build the image
image/build-test.sh && image/vm.sh test         # optional: test it in a virtual machine
```

Then write `image/mkosi.output/pandora-box.raw` to the disk of the kiosk, enroll the Secure Boot key and install a signature set from a USB key. Every step is described in the documentation: [building the image](https://sourcentis.github.io/pandora-box/build/), [testing with QEMU](https://sourcentis.github.io/pandora-box/vm/), [initial installation](https://sourcentis.github.io/pandora-box/install/), and the maintenance: [signatures](https://sourcentis.github.io/pandora-box/signatures/), [system updates](https://sourcentis.github.io/pandora-box/update/), [logs](https://sourcentis.github.io/pandora-box/logs/).

To deploy kiosks in an organization (keys, places, network, operation), see the [deployment guide](https://sourcentis.github.io/pandora-box/deployment/).

To work on the code, see the [development guide](https://sourcentis.github.io/pandora-box/development/).

## 📜 **Roadmap**

The project is developed in phases: scanning engine, hardened image, kiosk interface, advanced analysis, fleet management, assurance and compliance. Follow its progress in the [Roadmap](ROADMAP.md).

## 🤝 **Contributing**

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md). To report a vulnerability, follow [SECURITY.md](SECURITY.md).

## 📄 **License**

PandoraBox is free software, licensed under the [GNU General Public License v3.0](LICENSE). The enclosure in [3D](3D/) is licensed under the CERN-OHL-S v2.
