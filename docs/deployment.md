# Deployment guide

This page is for an organization that deploys PandoraBox kiosks: the
decisions to take first, the keys and the people who hold them, where the
kiosks go, the network they need, the rollout, then the daily operation.
The technical steps are described in the other pages; this one says which to
follow, in which order, and why.

## In short

1. [Decide](#decisions): whose keys, offline or online, kiosk or file
   transfer station, how many kiosks.
2. [Prepare the keys](#keys-and-roles) and name the people who hold them.
3. [Choose the hardware](#hardware) and [the places](#placement) of the
   kiosks.
4. [Open the network flows](#network) of the online kiosks.
5. [Build the image](#building-the-images) of the organization and
   [test it](#pilot) on a pilot kiosk.
6. [Install the kiosks](#installing-the-kiosks), then
   [tell the users](#users).
7. [Operate](#operation): signatures, image updates, logs, detections.

## Decisions

### Whose keys

A kiosk trusts two keys, fixed at its installation
([Releases](release.md#release-keys)): the **Secure Boot key** decides what it
boots, the **update key** which signature sets, image updates and
maintenance requests it accepts.

| Option | Suits | Consequences |
|---|---|---|
| **Release image of the project** | Evaluation, a kiosk on the reference hardware | Ready to write and verifiable ([Verifying a release](release.md#verifying-a-release)). No customization: built-in theme, default configuration, no profile `online`. Its USBGuard rule allows one touch controller, by its serial number and port: another screen unit is blocked. Every signature set and maintenance request must be signed by the update key of the project |
| **Image of the organization** | Every production deployment | The organization builds its image ([Building the image](build.md)) with its own keys, and chooses its configuration, theme, touchscreen rule, profile and credentials. It keeps its keys and publishes its own signature sets |

In practice, a production deployment builds its own image: it needs its own
touchscreen rule, the name of each kiosk, often its theme and the profile
`online`, and an update key it holds itself, to sign its signature sets and
maintenance requests. The rest of this page assumes it.

A kiosk installed with some keys only accepts the updates signed with them.
Changing keys means writing a new image to its disk
([Initial installation](install.md)).

### Offline or online

| | Offline (no profile) | Online (`--profile online`) |
|---|---|---|
| Network | None: the image has no network configuration | Wired network, DHCP, outgoing flows only ([Network](#network)) |
| Signatures | A signature update device, inserted by an operator | Downloaded by the kiosk every 6 hours, from the sources or from a set published by the organization |
| Image updates | A USB key | A USB key, or a published update (`updates.image_url`) |
| Logs | A maintenance device | Sent to a SIEM as they are logged; maintenance device too |
| Clock | Hardware clock, never corrected | NTP |
| Credentials in the image | None | abuse.ch Auth-Key, and the SSH key of a file transfer station: the image must not leave the organization |

An offline kiosk has the smallest attack surface, but its signatures are
only as fresh as the last visit of an operator, and its logs only reach the
organization when someone brings them back. The kiosk warns on its screen
when its signatures are older than 7 days
([Signature freshness](engines.md#signature-freshness)): plan a visit at
least every week, or choose the profile `online`.

### Kiosk or file transfer station

A kiosk scans the key and removes the dangerous files. A **file transfer
station** also copies the clean files of the verified keys to a server of the
organization, and writes on the keys the files that the protected network
left for them ([Copy to a server](airgap.md)). It needs the profile
`online`, a server reachable over SSH, and its credentials in the image.

Choose a station when the files must enter or leave an isolated network:
the users then never plug their keys into a workstation of that network.

### How many kiosks

Each kiosk names itself in its logs and its SIEM messages with `kiosk.name`
([Configuration](configuration.md)). It is part of the configuration, hence
of the image: without it, every kiosk is called `pandora-box`, the host name
of the image. To tell the kiosks apart in the SIEM and in the maintenance
exports, build one image per kiosk, with the same keys and only its name
changing. Keep the list of the kiosks: name, place, profile, image version.

## Keys and roles

| Role | Holds | Does |
|---|---|---|
| **Key holders** (two people) | The Secure Boot key and the update key, on two YubiKeys, and their PIN ([Release keys](release.md#release-keys)) | Sign the images, the image updates, the signature sets and the maintenance requests |
| **Builder** | The build computer, with Docker and the sources | Builds the images and the image updates |
| **Operators** | The BIOS supervisor password, the USB keys of maintenance | Install the kiosks, bring the signature sets, image updates and maintenance devices, check the kiosks |
| **Security team** | The SIEM, the maintenance exports | Follows the detections, the refused devices, the kiosks whose signatures are old |

- Create the keys once, on an offline computer, in **two** YubiKeys
  ([Creating the keys](release.md#creating-the-keys)); keep the second one in
  a safe, apart from the first. A lost Secure Boot key means that every
  kiosk must be installed again by hand; a lost update key, that they get
  no more signature sets nor image updates.
- The development keys that `image/build.sh` generates
  (`image/mkosi.key`, `image/update.key`) are files on the build computer:
  never use them for a production kiosk.
- The BIOS supervisor password protects Secure Boot and the boot order of
  every kiosk: keep it with the keys, not on the kiosk.
- The abuse.ch Auth-Key and the SSH key of a station are in the image of an
  online kiosk: treat the image files and the disks of the kiosks as
  confidential.

## Hardware

Use the validated hardware: a Lenovo ThinkCentre M720q Tiny and a Waveshare
7-inch touchscreen, in the 3D-printed enclosure
([Hardware](hardware.md), [Assembly](assembly.md)). Another computer or
screen needs its own settings: the mode of the screen, the rule of its
touchscreen, the disk controller in the initrd. Test it in a pilot first.

Plan for each kiosk:

- 2 GB of memory at least (clamd alone uses about 1 GB); with `scan.workers
  = "auto"`, each file scanned in parallel takes 256 MB more, so 4 GB to scan
  six files at a time ([Configuration](configuration.md#reference));
- a disk of 32 GB or more: the two system slots (about 2.7 GB), the
  signature sets (about 1.2 GB each, the previous one kept, and the staging
  of an online kiosk), the reports, the logs and the quarantine;
- the USBGuard rule of **each** touchscreen: it is tied to the serial number
  and the port of its touch controller. Read it in `usb-devices.txt` of a
  maintenance export, or in the `usb_device_blocked` event of the kiosk,
  then build the image of that kiosk with it
  ([USB devices](image.md#usb-devices));
- a spare kiosk, installed and with signatures, to swap a failed one.

## Placement

- A place **visible** to staff, at the entrance of the protected area: a
  reception desk, a security post, the entrance of a lab. Not a closed room
  where nobody sees who uses the kiosk.
- Only the scanning port reachable: the enclosure hides the other ports
  and the power button. Disable the unused USB ports in the BIOS when it
  allows it ([Initial installation](install.md#devices-and-advanced-settings)).
- A power outlet; the kiosk starts again by itself after a power failure
  (BIOS setting *After Power Loss*).
- For an online kiosk, a wired network outlet in a dedicated network segment
  (VLAN), without access to the internal networks.
- The user procedure displayed next to the kiosk: see [Users](#users).

## Network

An offline kiosk needs nothing. An online kiosk only opens outgoing
connections: its firewall drops every incoming connection, and only lets
out the services below, each by its own system user
([Profile online](build.md#profile-online)). Allow the same flows, and only
them, from the network segment of the kiosks:

| Flow | Destination | Protocol, port | When |
|---|---|---|---|
| DHCP | DHCP server of the segment | UDP 67 | always |
| DNS | DNS servers given by DHCP | UDP and TCP 53 | always |
| NTP | NTP servers of the image, else of DHCP, else the Debian pool ([Time](build.md#time)) | UDP 123 | always |
| ClamAV signatures | `database.clamav.net` | HTTPS, TCP 443 | `updates.sources` |
| YARA Forge | `github.com` and the GitHub download hosts it redirects to | HTTPS, TCP 443 | `updates.sources` |
| MalwareBazaar | `mb-api.abuse.ch` | HTTPS, TCP 443 | `updates.sources` |
| Hashlookup | `cra.circl.lu` | HTTPS, TCP 443 | `updates.sources` |
| Published signature set, image updates | the web server of the organization | HTTPS, TCP 443 | `updates.url`, `updates.image_url` |
| Proxy | the proxy of the organization | its port | `updates.proxy`, in place of the four sources above |
| SIEM | the SIEM | TLS, TCP 6514 by default (TCP or UDP 514) | `[siem]` ([SIEM](siem.md)) |
| File transfer station | the SSH server | TCP 22 | `[airgap]` ([Copy to a server](airgap.md)) |

Two ways to feed the signatures of a fleet:

- **From the sources**: every kiosk downloads the sources itself (among
  them the Hashlookup filter, about 1 GB each month), and needs the abuse.ch
  Auth-Key in its image.
- **From a published set**: a publication computer of the organization runs
  `publish/publish.sh` every day and puts the signed set on an internal web
  server ([A published set instead](signatures.md#a-published-set-instead)).
  The kiosks only reach that server, need no credential, and only download
  the files that changed. Prefer it beyond a few kiosks, or when the
  kiosks may not reach the Internet.

## Building the images

On the build computer, for each kiosk (see [Building the image](build.md)):

1. Set the configuration in `packaging/pandora-box.toml`: `kiosk.name`,
   `display.language`, `[updates]`, `[siem]`, `[airgap]`. Check it with
   `pandora-box --check-config`.
2. Put the theme of the organization in `image/theme/`
   ([Interface](interface.md#customization)), the certificate authorities of
   the SIEM in `image/siem-ca.pem`, the credentials in
   `image/credentials.toml`, the touchscreen rule in
   `image/mkosi.extra/etc/usbguard/rules.conf`.
3. Build with the keys of the organization, with or without
   `--profile online`.
4. Keep the configuration of each kiosk outside the image (a private
   repository, for instance): the next image of that kiosk is built from it.

The image version is the time of the build: every image update must be
newer than the installed one ([System updates](update.md)).

## Pilot

Before the fleet, run the image in a virtual machine
([Testing with QEMU](vm.md)), then install a pilot kiosk and keep it a few
weeks in a real place:

- the touchscreen confirms a cleaning;
- the EICAR test file is reported and removed;
- keys of every filesystem used in the organization (vfat, exFAT, NTFS,
  ext4) are scanned; an encrypted key or a phone is refused, as expected;
- a signature update device, an image update and a maintenance device are
  accepted;
- for an online kiosk: the signatures are updated by themselves, the SIEM
  receives the events, the clock is right;
- for a station: the clean files reach the server, the outbound files reach
  the key;
- the scan time of the usual keys of the users is acceptable
  ([Hardware](hardware.md#validated-hardware)).

## Installing the kiosks

For each kiosk ([Initial installation](install.md)):

1. Configure the BIOS: supervisor password, Secure Boot in setup mode, boot
   from the internal disk only, VT-d on, power on after a power failure.
2. Write the image of the kiosk to its disk.
3. At the first boot, check that Secure Boot is in **User** mode.
4. Insert a first signature set: until then, the kiosk shows
   `NO VALID SIGNATURES` and scans nothing.
5. Check it with the EICAR test file and a maintenance device:
   `failed-services.txt` is empty, `signatures.txt` shows the set.
6. Write its name, place, image version and the date in the list of the
   kiosks.

## Users

Tell the users what the kiosk does, and what it does not:

- **When**: every key that comes from outside, or was used outside, is
  scanned before it is plugged into a workstation of the organization.
- **How**: insert the key, wait for the result, touch the screen to remove
  the dangerous files, remove the key. The posters of
  [`docs/poster/`](https://github.com/sourcentis/pandora-box/tree/main/docs/poster)
  show these steps, to print and display next to the kiosk.
- **The result**: a key **not verified** must not be used: a file could not
  be scanned (encrypted archive, file too big, error). The user brings it
  to the security team, or does without it.
- **The limits**: a clean result means that no engine detected anything, not
  that the key is safe ([Threat model](threat-model.md)). Workstations keep
  their own protections.
- **Who to call**: the contact of the security team, in the theme of the
  kiosk ([Texts](interface.md#texts)) or on the poster.

## Operation

### Recurring tasks

| Task | Frequency | How |
|---|---|---|
| Signature set | every day (online), at least every week (offline) | [Signatures](signatures.md): automatic online; a signature update device otherwise |
| Image update | every month, and for each security update of Debian that concerns the kiosk | rebuild with the same keys and configuration, then [System updates](update.md) |
| Logs | continuously (SIEM), or at each visit (maintenance device) | [Logs](logs.md), [SIEM](siem.md) |
| Check of the kiosk | at each visit | the screen shows no signature warning; the enclosure is closed and intact; no device other than the kiosk is plugged in |
| Quarantine and reports | every year | see [Data on the kiosk](#data-on-the-kiosk) |
| YubiKeys | every year | both YubiKeys still sign (a test signature); the PINs are known by the key holders |

### What to watch

In the SIEM, or in the maintenance exports ([Useful events](logs.md#useful-events),
[Dashboards](siem.md#dashboards)):

| Event | Action |
|---|---|
| `infected_files`, `device_verdict` malicious | Find out where the key comes from, and the workstations it was plugged into before the kiosk |
| `usb_device_blocked` with `composite` | A key that is also a keyboard: keep the key, it is an attack tool |
| `usb_device_blocked`, other devices | Someone plugged in a keyboard, a network adapter or a phone: check the kiosk |
| `device_suspicious_behavior` | A key that disconnected itself during its scan: keep it for analysis |
| `signatures_refused`, `maintenance_refused` | A device signed by another key, too old or modified: who brought it? |
| No `signatures_changed` for several days (online) | The kiosk no longer reaches its sources: network, proxy, Auth-Key |
| No event at all from a kiosk | Turned off, unplugged, or failing to boot: go and see |

### Detections

When a kiosk reports a malicious file:

1. The file is copied to the quarantine of the kiosk, then removed from the
   key after a touch of the screen. Its SHA-256 and the engines that
   detected it are in the scan report and in the `infected_files` event.
2. Ask the user where the key comes from, and on which computers it was
   used: they may be infected.
3. A copy of the file is in the quarantine of the kiosk
   (`/var/lib/pandora-box/quarantine/`), on its disk only: the maintenance
   export does not bring it back. To analyze it, take the disk out, in a
   lab.

### Failures

| Symptom | Cause, action |
|---|---|
| `NO VALID SIGNATURES` | No set installed, or the installed set fails its verification: insert a signature update device |
| Signature warning on the screen | The signatures are older than 7 days: insert a set, or check the network of an online kiosk |
| The touchscreen does not confirm | USBGuard blocks it: another unit or another port than the rule of the image ([USB devices](image.md#usb-devices)) |
| The kiosk restarts on the previous version | The new image failed to boot 3 times: `boots.txt` of a maintenance export ([If the new version fails](update.md#if-the-new-version-fails)) |
| The kiosk does not start | Take the spare kiosk; check the BIOS settings and the disk of the failed one |

## Data on the kiosk

The data partition (`/var`) of a kiosk holds the scan reports (names and
hashes of the files of the users), the logs and the quarantine (copies of
malware). It is **not encrypted**: whoever takes the disk can read it
([Threat model](threat-model.md#what-pandorabox-does-not-cover)).

- Decide how long the reports and the quarantine are kept, and record the
  kiosk in the register of processing of the organization when the reports
  name people's files. The logs are rotated every month and kept 12 months
  ([Logs](logs.md#what-the-kiosk-logs)).
- A file transfer station keeps neither reports nor quarantine on its disk
  ([A stolen kiosk](airgap.md#a-stolen-kiosk)).
- A kiosk is a place where malware is kept: do not let it leave the
  organization without wiping its disk.

## Decommissioning

1. Bring back the logs with a maintenance device, if they are still needed.
2. Wipe the disk (`blkdiscard`, or a full overwrite of a hard disk): it
   holds the quarantine, the reports, and the credentials of an online
   kiosk.
3. In the BIOS: Security → Secure Boot → **Restore Factory Keys**, and
   remove the supervisor password, before giving the computer to another use.
4. For an online kiosk or a station: revoke its credentials (abuse.ch
   Auth-Key, SSH key on the server) when they are not shared by the other
   kiosks, and close its network flows.
5. Remove it from the list of the kiosks.
