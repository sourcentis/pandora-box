# Release keys in a PKCS#11 token (docs/release.md), sourced by
# image/build.sh --release and image/release.sh.
#   pkcs11_docker_options  on the build computer: options of docker run
#   pkcs11_read_pin        on the build computer: PIN of the token
#   pkcs11_setup           in the build container: PIN, key URIs, OpenSSL
#   pkcs11_check_keys      in the build container, after pkcs11_setup: both
#                          keys sign, and match the public keys of the tree
#
# The keys are in a YubiKey 5 (PIV), used through ykcs11 and the OpenSSL
# PKCS#11 provider: the Secure Boot key in slot 9c, the update key in slot 82.
# Environment, all optional:
#   PANDORA_BOX_SECURE_BOOT_KEY  PKCS#11 URI of the Secure Boot key
#   PANDORA_BOX_UPDATE_KEY       PKCS#11 URI of the update key
#   PANDORA_BOX_PKCS11_MODULE    another PKCS#11 module than ykcs11
#   PANDORA_BOX_SOFTHSM          folder of a SoftHSM token, to test without a
#                                YubiKey (image/softhsm-keys.sh)

# Host side (POSIX sh). The PIN is read from the standard input of the
# container (docker run -i), never passed in its environment or arguments.
pkcs11_docker_options() {
    options="-i --tmpfs /run/pandora-box:mode=0700"
    options="$options -e PANDORA_BOX_SECURE_BOOT_KEY -e PANDORA_BOX_UPDATE_KEY"
    options="$options -e PANDORA_BOX_PKCS11_MODULE"
    # The YubiKey is reached through the PC/SC daemon of the build computer
    # when it runs one that answers the container (it holds the reader); else
    # the container starts its own, with the USB devices
    if [ -S /run/pcscd/pcscd.comm ]; then
        options="$options -v /run/pcscd:/run/pcscd-host"
    fi
    if [ -d /dev/bus/usb ]; then
        options="$options --device /dev/bus/usb"
    fi
    if [ -d /run/udev ]; then
        options="$options -v /run/udev:/run/udev:ro"
    fi
    if [ -n "${PANDORA_BOX_SOFTHSM:-}" ]; then
        options="$options -v $(realpath "$PANDORA_BOX_SOFTHSM"):/run/softhsm"
        options="$options -e SOFTHSM2_CONF=/run/softhsm/softhsm2.conf"
    fi
    echo "$options"
}

# Ask for the PIN of the token on the terminal, then write it on the standard
# output (piped to docker run -i)
pkcs11_read_pin() {
    if [ -t 0 ]; then
        printf 'PIN of the release token: ' >&2
        stty -echo
        IFS= read -r pin || true
        stty echo
        printf '\n' >&2
    else
        IFS= read -r pin || true
    fi
    printf '%s\n' "$pin"
}

# Container side (bash). mkosi runs its signing tools in a sandbox that only
# shares /usr and /run with the container, and only gives its Environment= to
# the tools of the image, not to those of the initrd, which share its keys: so
# the OpenSSL PKCS#11 provider finds the module through p11-kit, from
# /usr/share/p11-kit/modules, and the PIN from the key URI (pin-source, a file
# in /run). The PC/SC socket is in /run too.
pkcs11_setup() {
    local pin module=/usr/share/p11-kit/modules/pandora-box.module openssl_module=
    IFS= read -r pin || true
    if [ -z "$pin" ]; then
        echo "error: no PIN for the release token" >&2
        return 1
    fi
    (umask 077 && printf '%s' "$pin" >/run/pandora-box/pin)
    : "${PANDORA_BOX_SECURE_BOOT_KEY:=pkcs11:object=Private%20key%20for%20Digital%20Signature;type=private}"
    : "${PANDORA_BOX_UPDATE_KEY:=pkcs11:object=Private%20key%20for%20Retired%20Key%201;type=private}"
    PANDORA_BOX_SECURE_BOOT_KEY=$(_pkcs11_with_pin "$PANDORA_BOX_SECURE_BOOT_KEY")
    PANDORA_BOX_UPDATE_KEY=$(_pkcs11_with_pin "$PANDORA_BOX_UPDATE_KEY")
    export PANDORA_BOX_SECURE_BOOT_KEY PANDORA_BOX_UPDATE_KEY
    # The only module of p11-kit: a module that fails to start (ykcs11
    # without a reader) makes every token unusable
    if [ -n "${SOFTHSM2_CONF:-}" ]; then
        # SoftHSM reads its configuration from SOFTHSM2_CONF or /etc, which
        # the sandbox does not have: a p11-kit server in the container gives
        # its token through a socket in /run
        p11-kit server --provider /usr/lib/softhsm/libsofthsm2.so \
            --name /run/pandora-box/softhsm.sock "pkcs11:" >/dev/null
        echo "remote: unix:path=/run/pandora-box/softhsm.sock" >"$module"
        # The openssl command of the container loads SoftHSM itself: the
        # p11-kit server does not pass Ed25519 signatures. no-deinit: SoftHSM
        # crashes at the exit of the process otherwise.
        openssl_module="pkcs11-module-path = /usr/lib/softhsm/libsofthsm2.so
pkcs11-module-quirks = no-deinit no-operation-state"
    else
        echo "module: ${PANDORA_BOX_PKCS11_MODULE:-/usr/lib/x86_64-linux-gnu/libykcs11.so}" \
            >"$module"
        _pcsc_start || return 1
    fi
    # The openssl command of the container loads the provider too
    cat >/etc/ssl/openssl.cnf <<EOF
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
pkcs11 = pkcs11_sect

[default_sect]
activate = 1

[pkcs11_sect]
module = /usr/lib/x86_64-linux-gnu/ossl-modules/pkcs11.so
$openssl_module
activate = 1
EOF
}

# Sign a short message with each key of the token and verify the signature
# with the public key of the tree (image/release/), before a long build: the
# PIN is right, both keys sign (the Ed25519 update key too), and they are the
# keys of the release. A wrong PIN stops at the first key: one try is used.
pkcs11_check_keys() {
    local dir errors="" rc=0
    dir=$(mktemp -d)
    printf 'PandoraBox release keys check\n' >"$dir/message"
    if ! errors=$(openssl pkeyutl -sign -inkey "$PANDORA_BOX_SECURE_BOOT_KEY" -rawin \
        -digest sha256 -in "$dir/message" -out "$dir/secure-boot.sig" 2>&1); then
        echo "error: the token refused to sign with the Secure Boot key: wrong PIN?" >&2
        rc=1
    elif ! OPENSSL_CONF=/dev/null openssl pkeyutl -verify -certin \
        -inkey image/release/secure-boot.crt -rawin -digest sha256 \
        -in "$dir/message" -sigfile "$dir/secure-boot.sig" >/dev/null 2>&1; then
        echo "error: the Secure Boot key of the token is not the one of image/release/secure-boot.crt" >&2
        rc=1
    elif ! errors=$(openssl pkeyutl -sign -inkey "$PANDORA_BOX_UPDATE_KEY" -rawin \
        -in "$dir/message" -out "$dir/update.sig" 2>&1); then
        echo "error: the token refused to sign with the update key" >&2
        rc=1
    elif ! OPENSSL_CONF=/dev/null openssl pkeyutl -verify -pubin \
        -inkey image/release/update.pem -rawin \
        -in "$dir/message" -sigfile "$dir/update.sig" >/dev/null 2>&1; then
        echo "error: the update key of the token is not the one of image/release/update.pem" >&2
        rc=1
    fi
    rm -rf "$dir"
    if [ "$rc" -ne 0 ]; then
        if [ -n "$errors" ]; then
            printf '%s\n' "$errors" | tail -n 3 >&2
        fi
        # Tries left on a YubiKey (read without the PIN)
        if [ -z "${SOFTHSM2_CONF:-}" ] && [ -z "${PANDORA_BOX_PKCS11_MODULE:-}" ]; then
            yubico-piv-tool -r Yubico -a status 2>/dev/null | grep -i 'PIN tries' >&2 || true
        fi
    fi
    return "$rc"
}

# A PKCS#11 URI with the PIN file of the token, unless it gives a PIN
_pkcs11_with_pin() {
    case "$1" in
    *pin-source=* | *pin-value=*) printf '%s' "$1" ;;
    *\?*) printf '%s&pin-source=file:/run/pandora-box/pin' "$1" ;;
    *) printf '%s?pin-source=file:/run/pandora-box/pin' "$1" ;;
    esac
}

# The PC/SC daemon of the build computer when it answers and has the reader of
# the token, else one of the container. The client library of the container
# (Debian 13, pcsc-lite 2) does not talk to a daemon older than pcsc-lite 2
# (Debian 12): the daemon of the build computer is then stopped, as it holds
# the reader. The tools of mkosi find the socket at its usual place, in /run.
_pcsc_start() {
    local host=/run/pcscd-host/pcscd.comm readers
    mkdir -p /run/pcscd
    if [ -S "$host" ] && readers=$(_pcsc_readers "$host") && _pcsc_has_token "$readers"; then
        ln -sf "$host" /run/pcscd/pcscd.comm
        return 0
    fi
    # No polkit in the container: pcscd would refuse every client
    pcscd --disable-polkit
    # The daemon finds the readers after it starts
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        if readers=$(_pcsc_readers /run/pcscd/pcscd.comm) && _pcsc_has_token "$readers"; then
            return 0
        fi
        sleep 0.5
    done
    echo "error: no reader of the release token" >&2
    if [ -S "$host" ] && ! _pcsc_readers "$host" >/dev/null; then
        echo "The PC/SC daemon of this computer holds it, but is too old for the container" >&2
        echo "(pcsc-lite < 2): stop it while signing (sudo systemctl stop pcscd.socket pcscd)." >&2
    elif [ -z "${PANDORA_BOX_PKCS11_MODULE:-}" ]; then
        echo "Plug in the YubiKey: a YubiKey 5 with PIV over USB (ykman info), not a Security Key." >&2
    fi
    return 1
}

# Names of the readers of a PC/SC daemon (its socket), one per line; fails if
# it does not answer
_pcsc_readers() {
    PCSCLITE_CSOCK_NAME=$1 python3 - <<'EOF'
import ctypes
import sys

pcsc = ctypes.CDLL("libpcsclite.so.1")
pcsc.SCardEstablishContext.restype = pcsc.SCardListReaders.restype = ctypes.c_long
context = ctypes.c_long()
if pcsc.SCardEstablishContext(2, None, None, ctypes.byref(context)):  # SCARD_SCOPE_SYSTEM
    sys.exit(1)
size = ctypes.c_ulong()
rv = pcsc.SCardListReaders(context, None, None, ctypes.byref(size)) & 0xFFFFFFFF
if rv == 0x8010002E:  # SCARD_E_NO_READERS_AVAILABLE
    sys.exit(0)
names = ctypes.create_string_buffer(size.value)
if rv or pcsc.SCardListReaders(context, None, names, ctypes.byref(size)):
    sys.exit(1)
print("\n".join(n.decode(errors="replace") for n in names.raw.split(b"\0") if n))
EOF
}

# A reader of the token among these: a YubiKey for ykcs11, any reader for
# another module
_pcsc_has_token() {
    if [ -n "${PANDORA_BOX_PKCS11_MODULE:-}" ]; then
        [ -n "$1" ]
    else
        case "$1" in
        *[Yy]ubico*) return 0 ;;
        *) return 1 ;;
        esac
    fi
}
