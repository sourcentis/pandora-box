# Image build and test environment: mkosi, QEMU/KVM and OVMF from Debian 13
# (trixie), so that the developer only needs Docker. Used by image/build.sh
# and image/vm.sh. The PKCS#11 tools sign a release with the keys of a
# YubiKey (image/release.sh); SoftHSM and OpenSC test it without one.
FROM debian:trixie-slim

# Debian packages of snapshot.debian.org at that time, YYYYMMDDTHHMMSSZ: the
# tools of a reproducible build (image/build.sh --snapshot)
ARG SNAPSHOT=
RUN if [ -n "$SNAPSHOT" ]; then \
        for archive in "debian trixie trixie-updates" "debian-security trixie-security"; do \
            set -- $archive; name=$1; shift; \
            printf '%s\n' "Types: deb" \
                "URIs: http://snapshot.debian.org/archive/$name/$SNAPSHOT/" \
                "Suites: $*" "Components: main" \
                "Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg" \
                "Check-Valid-Until: no" ""; \
        done >/etc/apt/sources.list.d/debian.sources; \
    fi \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        mkosi systemd-container systemd-ukify systemd-boot-efi systemd-repart \
        apt debian-archive-keyring dpkg-dev \
        dosfstools e2fsprogs erofs-utils exfatprogs ntfs-3g mtools cpio zstd \
        python3 python3-venv python3-pip git ca-certificates \
        qemu-system-x86 qemu-utils ovmf swtpm swtpm-tools \
        openssl sbsigntool python3-virt-firmware \
        python3-paramiko openssh-client \
        pkcs11-provider p11-kit p11-kit-modules ykcs11 yubico-piv-tool pcscd libccid \
        softhsm2 opensc \
    # ykcs11 2.7.1 of Debian 13 cannot sign with the Ed25519 update key: it
    # does not list CKM_EDDSA (yubico-piv-tool 2.7.2), so the OpenSSL PKCS#11
    # provider finds no mechanism. Version 2.7.3 of Debian forky, from
    # snapshot.debian.org, checked by its SHA-256 (it only needs Debian 13).
    && base=https://snapshot.debian.org/archive/debian/20260909T142347Z/pool/main/y/yubico-piv-tool \
    && for deb in \
        "libykpiv2 b5fb16770a65c5dcf829a7513193280145247ebfc8cee0dbd305f9b35e510d06" \
        "ykcs11 5454dccc3af9c54b866a3ee5ff7498a3a62f326a3f9aaca9a7bc2b1bf0481d85" \
        "yubico-piv-tool 4a4c358b29382a2058dcbde1e572e49f0f45f65fdada5c56723129de006eda94"; do \
        set -- $deb; \
        /usr/lib/apt/apt-helper download-file "$base/${1}_2.7.3-2_amd64.deb" "/tmp/$1.deb" "SHA256:$2" \
            || exit 1; \
    done \
    && dpkg -i /tmp/libykpiv2.deb /tmp/ykcs11.deb /tmp/yubico-piv-tool.deb \
    && rm /tmp/*.deb \
    && rm -rf /var/lib/apt/lists/* \
    # p11-kit loads the PKCS#11 module of the token only (image/pkcs11.sh)
    && rm -f /usr/share/p11-kit/modules/*.module

# Reproducible microcode initrd (image/patch-mkosi.py)
COPY patch-mkosi.py /tmp/
RUN python3 /tmp/patch-mkosi.py && rm /tmp/patch-mkosi.py
