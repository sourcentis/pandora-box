# Development

This page explains how to work on PandoraBox on a development computer: run the kiosk outside the image, with or without real engines, and run the tests. To build the kiosk image and test it in a virtual machine, see [Building the image](build.md) and [Testing with QEMU](vm.md).

The code is in the `pandora_box` package (`src/pandora_box/`):

| Module | Role |
|---|---|
| `cli.py` | Command line entry point (`pandora-box`) |
| `config.py` | TOML configuration, validated at startup |
| `statemachine.py`, `kiosk.py` | State machine and kiosk workflow |
| `monitor.py` | USB detection with udev |
| `usbguard.py` | USB devices refused by USBGuard, read from its audit log: logged, and explained on the screen |
| `device.py` | Hardened mounting (`ro,noexec,nosuid,nodev` on a read-only block device, read-write only to clean) |
| `fuse.py` | NTFS, exFAT and ext4 read by FUSE drivers in the sandbox, with a watchdog |
| `inventory.py` | Device inventory: never follows links, never leaves the device, limits |
| `results.py` | Results of a scan: file results and device summary |
| `scanner.py`, `workers.py`, `worker.py` | Scan in supervised worker processes, timeouts and watchdog |
| `sigsets.py`, `publish.py` | Signed signature sets: verification, installation, publication from the sources, `pandora-box-signatures` command |
| `sandbox.py`, `seccomp.py`, `protocol.py` | Worker sandbox (bubblewrap, dedicated user, system call filter), validated JSON messages from the workers |
| `pipeline.py`, `hashing.py`, `filetype.py` | Per file: hashes (SHA-256, SHA-1, MD5), libmagic type, engines |
| `engines/` | Engine interface, MalwareBazaar, Hashlookup, ClamAV, YARA-X and fake engine |
| `hashdb.py`, `bloom.py`, `clamd.py` | MalwareBazaar database, DCSO Bloom filter reader, clamd client |
| `policy.py` | Verdict aggregation per file and per device |
| `report.py`, `schemas/` | JSON scan report and its JSON Schema |
| `signatures.py` | Signature provenance and freshness |
| `quarantine.py` | Copy of infected files with a manifest referencing the report |
| `imageupdate.py`, `maintenance.py` | A/B image updates, maintenance devices (log export) |
| `online.py` | Online signature updates (`pandora-box-update.service`) |
| `siem.py`, `follow.py` | Log export to a SIEM (`pandora-box-siem.service`); following a log file across its rotations, also used for the audit log of USBGuard |
| `airgap.py`, `remotes.py`, `keyid.py`, `keyfs.py` | Copy to a server (stations): workflow and `pandora-box-airgap` service, mirror over rsync or SFTP, signed identifier written on the keys, limits of the filesystems of the keys |
| `ui/` | Graphical kiosk interface (framebuffer, themes), curses (administrator) and console interfaces |
| `logs.py`, `lock.py` | JSON logs, single-instance lock |
| `text.py` | Untrusted strings (file names, device labels) made printable and escaped |

Deployment files are in `packaging/`: configuration, systemd services, tmpfiles, sysusers and logrotate.

## Prerequisites

- Linux with udev (USB detection and mounting require root privileges)
- **Python 3.11 or later**
- libmagic (`sudo apt install libmagic1`)
- for real scans: `clamav-daemon` (see [docs/engines.md](engines.md#clamav))

Recent distributions (Debian 12 and later, Ubuntu 23.04 and later) forbid `pip install` into the system Python ([PEP 668](https://peps.python.org/pep-0668/), `externally-managed-environment` error). Always work inside a virtual environment, and never use `--break-system-packages`.

## Create the virtual environment

If your system Python is 3.11 or later (Debian 12 and 13, Ubuntu 24.04):

```sh
sudo apt install python3-venv python3-full
git clone https://github.com/sourcentis/pandora-box.git
cd pandora-box
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e ".[dev]"
```

If your system Python is older (Ubuntu 22.04 ships Python 3.10), use [uv](https://docs.astral.sh/uv/), which downloads a suitable Python without touching the system:

```sh
curl -LsSf https://astral.sh/uv/install.sh | sh
git clone https://github.com/sourcentis/pandora-box.git
cd pandora-box
uv venv --python 3.11
source .venv/bin/activate
uv pip install -e ".[dev]"
```

## Configure and run

```sh
cp packaging/pandora-box.toml pandora-box.toml
# YARA rules, MalwareBazaar (needs ABUSECH_AUTH_KEY), Hashlookup: an unsigned set
pandora-box-signatures publish dev-signatures --sources yara-forge,malwarebazaar,hashlookup
# copy the printed [engines.*] and [signatures] settings into pandora-box.toml,
# set the quarantine, report and log folders, then check the configuration
pandora-box --config pandora-box.toml --check-config
sudo .venv/bin/pandora-box --config pandora-box.toml --interface console
```

`sudo` resets `PATH`, so the kiosk is started with the full path of the executable installed in the virtual environment (`.venv/bin/pandora-box`).

Mounting a device requires root: adding your user to a group (such as `disk`) is not enough. On a desktop that mounts USB devices itself (udisks automount), set `auto_mount = true` in `[device]` instead: the kiosk then uses the system mount, and unmounts and mounts the device again with `udisksctl`, so it runs without `sudo`. This is for development only: the system mount is usually read-write and not hardened.

The device is unmounted while the kiosk asks the user to confirm the cleaning, so that it can be removed safely. To clean, it is mounted again read-write; a file is only removed if its SHA-256 is still the one that was scanned (another device may have been inserted in the meantime). When the scan and the cleaning are over, the device is ejected (`device.eject`, with `eject`, or `udisksctl power-off` in auto-mount mode).

The scan workers run in a sandbox by default (`scan.sandbox`): it needs root, `bwrap` (Debian package `bubblewrap`), `setpriv` and a `pandora-box-scan` user (`sudo systemd-sysusers packaging/sysusers/pandora-box.conf`). For development without them, set `sandbox = false` in `[scan]`.

NTFS, exFAT and ext4 are read by FUSE drivers in this sandbox (`device.fuse`, see [Image internals](image.md#filesystem-drivers)): Debian packages `ntfs-3g`, `exfat-fuse` and `fuse2fs`, and the library preloaded into ntfs-3g, to build once:

```sh
sudo mkdir -p /usr/lib/pandora-box
sudo cc -O2 -shared -fPIC -o /usr/lib/pandora-box/fuse-premounted.so packaging/fuse/premounted.c -ldl
```

Without the sandbox (`sandbox = false`), or with `fuse = false` in `[device]`, the kernel drivers mount them.

The kiosk only uses a signed signature set (`signatures.verify`, see [docs/signatures.md](signatures.md)): development signatures are not signed, set `verify = false` in `[signatures]` to use them.

To work on the workflow without signatures, set `fake_scan = true` in `[kiosk]` (or use `--fake-scan`): only the [EICAR test file](https://www.eicar.org/download-anti-malware-testfile/) is reported as malicious, so the whole workflow (scan, quarantine, cleaning) can be tested without real engines.

## Lint and tests

With the virtual environment activated:

```sh
ruff check .
mypy src
pytest
```

Integration tests run against real engines when they are available: a clamd socket (`PANDORA_BOX_CLAMD_SOCKET`, default `/run/clamav/clamd.ctl`), real rules (`PANDORA_BOX_YARA_RULES`, paths separated by `:`) or a full configuration for the detection corpus (`PANDORA_BOX_CORPUS_CONFIG`). End-to-end tests with loop devices and a real clamd run in a container: `tests/e2e/run.sh`.

## Interface without a kiosk

The screens of the graphical interface can be drawn into PNG files, with made-up files, to work on them or on a theme without a framebuffer (see [Interface](interface.md)):

```sh
pandora-box-theme preview /tmp/preview --language fr
```

## Documentation

This documentation is built with [MkDocs](https://www.mkdocs.org/) and the [Material](https://squidfunk.github.io/mkdocs-material/) theme, from the `docs/` folder and `mkdocs.yml`. It is published on GitHub Pages by the `docs` workflow when `docs/` changes on the `main` branch. To see it while writing:

```sh
pip install -r requirements-docs.txt
mkdocs serve        # http://127.0.0.1:8000, reloaded on every change
mkdocs build --strict
```

The documentation is in English and French (`mkdocs-static-i18n` plugin): each English page `page.md` has its translation `page.fr.md`, published under `/fr/`. A page without a translation is shown in English. The headings of a French page keep the anchor of the English page (`## Profil online { #profile-online }`), so that links to a section work in both languages.

With MkDocs installed by pipx, add the extensions of `requirements-docs.txt`
to its environment instead (the GitHub alerts, `> [!WARNING]`, need
`markdown-callouts`):

```sh
pipx install mkdocs
pipx inject mkdocs mkdocs-material markdown-callouts mkdocs-static-i18n
```
