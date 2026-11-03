# Logs

A kiosk has no login and accepts no connection: its logs are brought back
with a signed **maintenance device**, or sent as they are logged to a SIEM
by an online kiosk.

## In short

```sh
image/maintenance-key.sh /media/$USER/KEY            # any kiosk
image/maintenance-key.sh /media/$USER/KEY kiosk-1    # only kiosk.name = kiosk-1
```

Insert the key into the kiosk: it writes its logs to
`pandora-box-maintenance/<kiosk>-<date>/` and ejects the key.

For a continuous export, see [Log export to a SIEM](siem.md).

## What the kiosk logs

| Log | Path on the kiosk | Content |
|---|---|---|
| Kiosk | `/var/log/pandora-box/pandora-box.log` | JSON lines: devices inserted and removed, USB devices refused by USBGuard, scans and their verdicts, infected files, quarantine and cleaning, signature and image updates, maintenance devices, errors |
| Scan reports | `/var/lib/pandora-box/reports/` | One JSON report per scanned device (see [Scan report](engines.md#scan-report)) |
| Quarantine | `/var/lib/pandora-box/quarantine/` | Copies of the infected files removed from the keys |
| Journal | `journalctl` | System, services and kernel; one folder per boot, within the journald size limits |
| USBGuard | `/var/log/usbguard/usbguard-audit.log` | Devices allowed and blocked |
| Audit | `/var/log/audit/audit.log` | Kernel modules loaded, mounts, programs started, ptrace, changes of the clock, of the signature sets and of the staged image updates |

Every entry of the kiosk log holds `timestamp`, `level`, `kiosk`
(`kiosk.name`) and `event`, then the fields of the event. The level is set
by `logging.level` (`INFO` by default). logrotate moves the log file every
month and keeps 12 months, compressed.

Everything is on the data partition (`/var`), kept across reboots and image
updates.

## Maintenance device

A maintenance device brings the logs of a kiosk back without taking its disk
out. On the computer that holds the update key, with a USB key mounted:

```sh
image/maintenance-key.sh /media/$USER/KEY            # any kiosk
image/maintenance-key.sh /media/$USER/KEY kiosk-1    # only kiosk.name = kiosk-1
```

writes `pandora-box-maintenance/` on the key: a request signed with the
update key, valid 7 days. Inserted into the kiosk, even one without
signatures, the key is not scanned: the kiosk verifies the request, writes
its logs to `pandora-box-maintenance/<kiosk>-<date>/` and ejects the key
(`src/pandora_box/maintenance.py`).

| File | Content |
|---|---|
| `pandora-box.log` | Log of the kiosk |
| `journal.txt`, `journal-previous-boot.txt` | Journal of the boot and of the previous one |
| `kernel.txt` | Kernel messages |
| `boots.txt`, `boot-entries.txt` | Boots, installed versions of the image ([System updates](update.md)) |
| `services.txt`, `failed-services.txt` | systemd units, failed units |
| `usbguard-audit.log`, `usb-devices.txt`, `usb-rules.txt` | USB devices allowed and blocked, rules |
| `disks.txt` | Disks and partitions |
| `hardware.txt`, `cpuinfo.txt`, `meminfo.txt`, `input-devices.txt` | Hardware and screens, input devices |
| `os-release.txt`, `cmdline.txt` | Version of the image, kernel command line |
| `signatures.txt` | Installed signature set |

Nothing changes on the kiosk, and the export holds no key, credential or
scan report. A request signed by another key, too old, for another kiosk
or modified is refused (`maintenance_refused` in the log).

One key can hold a maintenance request, a signature set
(`pandora-box-signatures/`) and an image update (`pandora-box-image/`):
the kiosk handles them in that order in one insertion, each verified on its
own; the export shows the kiosk before the updates, and the image update
comes last as it restarts the kiosk.

## Useful events

| Event | Meaning |
|---|---|
| `device_verdict` | Summary of the scan of a device: verdict, counts, duration, detections, `report_id` (see [Dashboards](siem.md#dashboards)) |
| `infected_files` | Dangerous files found on a device |
| `signatures_installed`, `signatures_refused`, `signatures_not_newer` | Result of a signature update device |
| `signatures_changed` | New signature set loaded after an online update |
| `maintenance_refused` | Maintenance request refused |
| `usb_device_blocked` | USB device refused by USBGuard (see [Refused USB devices](#refused-usb-devices)) |
| `airgap_copied`, `airgap_failed`, `airgap_refused` | Copy of a key to a server (see [Copy to a server](airgap.md)) |
| `display_started`, `display_resized` | Size of the screen the interface draws for |

## Refused USB devices

USBGuard blocks every USB device that is not only storage: a keyboard, a
mouse, a network adapter, a key that is also a keyboard (BadUSB, see
[USB devices](image.md#usb-devices)). Its audit log is readable only by
root and is not sent to the SIEM: the kiosk follows it
(`src/pandora_box/usbguard.py`) and logs each refused device in its own log,
with the other events, as `usb_device_blocked` (level `WARNING`):

| Field | Content |
|---|---|
| `target` | Decision of USBGuard: `block` (or `reject`) |
| `usb_id` | Vendor and product identifiers, `vendor:product` |
| `model`, `serial` | Name and serial number the device gives |
| `port` | USB port, e.g. `1-2` |
| `interfaces` | Interfaces of the device, `class:subclass:protocol` |
| `kinds` | What these interfaces are: `storage`, `keyboard`, `mouse`, `hid`, `communications` (network, modem), `wireless` (Bluetooth), `vendor-specific`... |
| `composite` | `true` for a storage device with another function: a key that is also a keyboard |
| `connect_type` | `hotplug` when inserted, else present at boot or internal |
| `system_name` | Path of the device in sysfs |
| `rule` | Device rule of USBGuard, to adapt into an `allow` rule (touchscreen, mouse) |
| `blocked_at` | Time of the decision of USBGuard |

Devices blocked before the kiosk starts (at boot) are reported once it has
started; the position of the last line read is saved
(`/var/lib/pandora-box/usbguard-audit.json`), so a restart of the kiosk
reports no device twice. On a [station](airgap.md#a-stolen-kiosk),
`model`, `serial` and `rule` are left out.

A device the operator meant to use (a mouse) appears here too; a key
refused as a whole (`composite`), or a keyboard or a network adapter on a
kiosk that has none, deserves a look.

## Export to a SIEM

An online kiosk can send every entry of its log to a SIEM (Wazuh, Elastic,
Graylog, Splunk, or any syslog server), over syslog or JSON, TLS, TCP or
UDP: see [Log export to a SIEM](siem.md).
