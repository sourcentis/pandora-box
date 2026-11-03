# Releases

A release of PandoraBox is a ready-to-write image published on
[GitHub](https://github.com/sourcentis/pandora-box/releases), signed with the
release keys of the project. A kiosk installed from it only starts images
signed with the same Secure Boot key, and only installs the signature sets,
image updates and maintenance requests signed with the same update key.

An organization that wants its own keys builds its image itself
([Building the image](build.md)): its kiosks then trust its keys, not those of
the project.

## Release keys

| Key | Algorithm | YubiKey slot | Signs | Public part |
|---|---|---|---|---|
| Secure Boot key | RSA 2048 | 9c | systemd-boot, the unified kernel image, the dm-verity root hash; enrolled in the firmware of the kiosk | `image/release/secure-boot.crt` |
| Update key | Ed25519 | 82 | signature sets, image updates, maintenance requests, checksums of a release | `image/release/update.pem` |

The private keys never leave a **YubiKey 5** (PIV application, firmware 5.7
or newer for Ed25519). The build container uses them through `ykcs11` and the
OpenSSL PKCS#11 provider (`image/pkcs11.sh`). It reaches the YubiKey through
the PC/SC daemon of the build computer when one runs and answers it
(`/run/pcscd`), else it starts its own, with the USB devices. The client of
the container (pcsc-lite 2, Debian 13) does not talk to an older daemon
(Debian 12): stop that one while signing, as it holds the YubiKey
(`sudo systemctl stop pcscd.socket pcscd`); the scripts say so.

Two YubiKeys of the **5 series** are needed (5 NFC, 5C NFC, 5 Nano…). The
firmware of a YubiKey cannot be updated: check that it is 5.7 or newer before
buying. The *Security Key by Yubico* models only have FIDO, not PIV: they
cannot hold the keys. `ykman info` (package `yubikey-manager`, on the build
computer) gives the model, the firmware and the applications enabled over
USB; `ykman config usb --enable PIV` enables PIV when it is turned off.

The public parts are committed in `image/release/`. Their fingerprints are
also published here, so that a release can be checked against a source other
than itself:

```sh
openssl x509 -in image/release/secure-boot.crt -noout -fingerprint -sha256
openssl pkey -pubin -in image/release/update.pem -outform DER | sha256sum
```

| Key | SHA-256 fingerprint |
|---|---|
| Secure Boot key (`secure-boot.crt`, certificate) | `B0:A3:3D:3E:50:41:67:26:CB:BF:6B:D4:B7:97:7F:2A:0C:D0:C4:C4:F8:2B:C2:75:2A:A5:20:06:AB:84:2C:83` |
| Update key (`update.pem`, public key in DER) | `06d2d2f5e183f7f9bd1ae118df37e8e789aca6153768718cf07d1d3e37c73fb8` |

Created on 2026-11-03; the Secure Boot certificate is valid until
2036-10-31 (the firmware of a kiosk does not check it).

### Creating the keys

Once, on an offline computer. The keys are created in memory, imported into
**two** YubiKeys, the second one kept in a safe, then erased. A lost Secure
Boot key means that the kiosks can only be installed again, by hand; a lost
update key, that they get no more signature sets.

In the build container, with the files in memory only. The container uses
its own PC/SC daemon: stop the one of the computer first, if it runs one
(`sudo systemctl stop pcscd.socket pcscd`, `sudo systemctl start pcscd.socket`
afterwards).

```sh
docker run --rm -it --device-cgroup-rule='c 189:* rmw' -v /dev/bus/usb:/dev/bus/usb \
    -v /run/udev:/run/udev:ro \
    -v "$PWD/image/release:/release" --tmpfs /keys:mode=0700 pandora-box-builder bash
pcscd --disable-polkit   # no polkit in the container: it would refuse every client
opensc-tool -l      # lists the reader of the YubiKey: Yubico YubiKey ... CCID
cd /keys
openssl req -new -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=PandoraBox release Secure Boot key/" \
    -keyout secure-boot.key -out secure-boot.crt
openssl genpkey -algorithm ed25519 -out update.key
openssl req -new -x509 -key update.key -days 3650 -subj "/CN=PandoraBox release update key/" -out update.crt
openssl pkey -in update.key -pubout -out update.pem
```

The container sees the USB devices plugged in after it started (`/dev/bus/usb`
of the computer, every USB device allowed): the YubiKeys can be swapped
without leaving it, which would erase the private keys. Its PC/SC daemon does
not see a YubiKey plugged in after it started: restart it after each swap.
`-r Yubico` chooses the YubiKey when the computer has another smart card
reader.

Then for each YubiKey (`-k` asks for its management key; change the default
PIN, PUK and management key of a new YubiKey first):

```sh
pkill pcscd; pcscd --disable-polkit; sleep 2; opensc-tool -l   # after plugging it in
yubico-piv-tool -r Yubico -k -a import-key -s 9c -i secure-boot.key --pin-policy=once --touch-policy=never
yubico-piv-tool -r Yubico -k -a import-certificate -s 9c -i secure-boot.crt
yubico-piv-tool -r Yubico -k -a import-key -s 82 -i update.key --pin-policy=once --touch-policy=never
yubico-piv-tool -r Yubico -k -a import-certificate -s 82 -i update.crt
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/libykcs11.so --login --list-objects
```

`ykcs11` only shows the key of a slot that holds a certificate. The PIN policy
`once` lets one build sign every part of the image with a single PIN; the
touch policy `never`, without touching the YubiKey at each signature.

Finally, publish the public keys and leave the container, which erases the
private keys:

```sh
cp secure-boot.crt update.pem /release/
exit
git add image/release/secure-boot.crt image/release/update.pem
```

With other slots or another token, give the PKCS#11 URIs of the keys and the
module: `PANDORA_BOX_SECURE_BOOT_KEY`, `PANDORA_BOX_UPDATE_KEY` and
`PANDORA_BOX_PKCS11_MODULE` (see `image/pkcs11.sh`).

## Making a release

The version of a release is its date, in UTC: the tag `vYYYY.MM.DD`,
created the day of the release; `vYYYY.MM.DD.2`, `.3`… for another release
the same day, and a suffix (`vYYYY.MM.DD-rc1`) for a test that is not
published. `image/release.sh` refuses any other tag, and a tag whose date is
not the day it was created. The image version shown by the kiosk is the time
of the tag, to the second (`YYYYMMDDHHMMSS`).

On the build computer, with the YubiKey plugged in and
[gh](https://cli.github.com/) logged in to GitHub:

```sh
git tag -a v2026.11.03 -m "PandoraBox 2026.11.03"
git push origin v2026.11.03
image/release.sh v2026.11.03
```

`image/release.sh` asks for the PIN of the YubiKey once, then:

1. extracts the files of the tag only (`git archive`) to `release/v2026.11.03/src/`:
   no local theme, credentials or development keys get into the image;
2. checks the PIN before the build: signs a test message with both keys of
   the YubiKey and verifies it with the public keys of the tag; a wrong PIN
   (one try used), a key that cannot sign or another key stops it at once,
   with the PIN tries left;
3. builds the image without profile, signed with the Secure Boot key
   (`image/build.sh --release`), trusting `image/release/update.pem`, with
   the inputs of a [reproducible build](#reproducing-a-release);
4. checks the signature of the unified kernel image, builds the signed image
   update, compresses the disk image, writes the software bill of materials,
   signs the checksums with the update key, and checks every signature with
   the public keys of the tag;
5. creates a **draft** release of the tag on GitHub with the files of
   `release/v2026.11.03/assets/`.

| File | Content |
|---|---|
| `pandora-box-v2026.11.03.raw.xz` | disk image, to write to the disk of the kiosk |
| `pandora-box-image-v2026.11.03.tar` | signed image update: `pandora-box-image/`, to extract at the root of a USB key ([System updates](update.md)) |
| `pandora-box-v2026.11.03.cdx.json` | software bill of materials (SBOM, CycloneDX 1.5): the Debian and Python packages of the image, with their versions |
| `secure-boot.crt`, `update.pem` | public release keys |
| `SHA256SUMS`, `SHA256SUMS.sig` | checksums, signed with the update key |

Check the draft on GitHub, then publish it. `--no-publish` stops before
GitHub. The image of a release has no profile: the profile `online` holds the
credentials and settings of an organization, and is not published.

### Testing without a YubiKey

`image/softhsm-keys.sh` creates a SoftHSM token, a folder, with test keys in
the slots and labels of the YubiKey:

```sh
image/softhsm-keys.sh /tmp/token
cp /tmp/token/secure-boot.crt /tmp/token/update.pem image/release/   # in a test clone only
git commit -m "Test keys" image/release/
tag=v$(date -u +%Y.%m.%d)-test
git tag -a "$tag" -m "Test release"
echo 123456 | PANDORA_BOX_SOFTHSM=/tmp/token image/release.sh "$tag" --no-publish
```

## Reproducing a release

The image of a release only depends on its tag: anyone can build it again
and check that it is made of the published source code and Debian packages.
`image/reproducible.sh` derives every input of the build from the tag:

| Input | Value |
|---|---|
| Debian packages, and the tools of the build container | [snapshot.debian.org](https://snapshot.debian.org/) at the time of the tag |
| Time of the files (`SOURCE_DATE_EPOCH`), image version | the time of the tag |
| Partition UUIDs, dm-verity salt | a seed derived from the commit |
| Python packages | pinned with their hashes (`image/requirements.txt`) |

To check a release, download its files and build its tag again:

```sh
gh release download v2026.11.03 -D /tmp/v2026.11.03
image/reproduce.sh v2026.11.03 /tmp/v2026.11.03
```

`image/reproduce.sh` checks the files with their signed checksums, builds the
tag with the same inputs, trusting the same update key, but signed with
development keys, then compares:

| Part | Expected |
|---|---|
| root filesystem, dm-verity hash tree | identical |
| unified kernel image | every section identical, the kernel without its Secure Boot signatures (Debian's and the image's) |
| software bill of materials | identical |

The signatures cannot be compared: they need the release keys, and hold the
time they were made. They are checked with the public keys instead
([Verifying a release](#verifying-a-release)). mkosi 25.3 is patched in the
build container (`image/patch-mkosi.py`) so that the microcode of the kernel
image is reproducible.

## Verifying a release

Download the files of the release, then check the signature of the checksums
with the update key of the project, and the files with the checksums:

```sh
openssl pkeyutl -verify -pubin -inkey update.pem -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig
sha256sum -c SHA256SUMS
openssl pkey -pubin -in update.pem -outform DER | sha256sum
```

The last fingerprint must be the one given [above](#release-keys): the
`update.pem` of a release alone proves nothing, as anyone publishing a fake
release would give their own. Then write the image
([Initial installation](install.md#writing-the-image)):

```sh
xz -dc pandora-box-v2026.11.03.raw.xz | sudo dd of=/dev/sdX bs=4M conv=fsync status=progress
```

At its first boot, the kiosk enrolls `secure-boot.crt` in its firmware. A
kiosk installed with development keys does not accept the updates of a
release: write the release image to its disk again.
