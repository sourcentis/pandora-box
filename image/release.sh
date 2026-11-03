#!/bin/sh
# Build a release of PandoraBox and publish it as a draft GitHub release
# (docs/release.md):
#   image/release.sh TAG [--no-publish]
# TAG: a tag of the repository, pushed to GitHub. The image is built from the
# files of the tag only (git archive: no local theme, credential or key), with
# the inputs of image/reproducible.sh (anyone can build it again and compare,
# image/reproduce.sh), and signed with the keys of the release token
# (image/pkcs11.sh), whose PIN is asked once. release/TAG/assets/ then holds:
#   pandora-box-TAG.raw.xz        disk image, to write to the kiosk
#   pandora-box-image-TAG.tar     signed image update (pandora-box-image/)
#   pandora-box-TAG.cdx.json      software bill of materials (CycloneDX)
#   secure-boot.crt, update.pem   public release keys
#   SHA256SUMS, SHA256SUMS.sig    checksums, signed with the update key
# A draft release of the tag is created with them (gh), to check and publish
# on GitHub; --no-publish stops before.
set -eu

usage() {
    sed -n '2,19p' "$0" >&2
    exit 2
}

tag=""
publish=yes
for arg do
    case "$arg" in
    --no-publish) publish="" ;;
    -*) usage ;;
    *) [ -z "$tag" ] && tag=$arg || usage ;;
    esac
done
[ -n "$tag" ] || usage

cd "$(dirname "$0")/.."
if ! git rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
    echo "error: no tag $tag" >&2
    exit 1
fi
if [ -n "$publish" ] && ! git ls-remote --exit-code --tags origin "refs/tags/$tag" >/dev/null; then
    echo "error: the tag $tag is not on GitHub (git push origin $tag)" >&2
    exit 1
fi
out=release/$tag
if [ -e "$out" ]; then
    echo "error: $out exists: remove it to build the release again" >&2
    exit 1
fi
mkdir -p "$out/src" "$out/assets"
git archive "$tag" | tar -x -C "$out/src"
for key in secure-boot.crt update.pem; do
    if [ ! -f "$out/src/image/release/$key" ]; then
        echo "error: no image/release/$key in the tag $tag (docs/release.md)" >&2
        exit 1
    fi
done

. "$out/src/image/pkcs11.sh"
. "$out/src/image/reproducible.sh"
reproducible_options "$tag"

echo "Release $tag of PandoraBox: the image is built from the tag and signed with" >&2
echo "the release keys of the YubiKey (Secure Boot key, slot 9c; update key, slot 82)." >&2
echo "Plug in the YubiKey: its PIN is asked once, checked by signing a test message" >&2
echo "with both keys, then used for the whole build. Three wrong PINs block the PIV" >&2
echo "application of the YubiKey (its PUK unblocks it)." >&2
pin=$(pkcs11_read_pin)
# Before the build: the PIN is right, and both keys of the token are those of
# the tag, with the signing tools of the tag (its build container, which
# image/build.sh then finds in the cache)
echo "Checking the PIN..." >&2
docker build -q -t pandora-box-builder --build-arg SNAPSHOT="$snapshot" "$out/src/image" >/dev/null
# shellcheck disable=SC2046  # pkcs11_docker_options: several words
if ! printf '%s\n' "$pin" | docker run --rm $(pkcs11_docker_options) \
    -v "$PWD/$out/src:/src:ro" -w /src pandora-box-builder bash -c '
        set -euo pipefail
        . image/pkcs11.sh
        pkcs11_setup
        pkcs11_check_keys'; then
    echo "error: the release keys cannot sign: nothing was built" >&2
    rm -rf "$out"
    exit 1
fi
echo "PIN accepted: both release keys sign and are those of the tag. Building the release..." >&2
# shellcheck disable=SC2086  # options: several words
printf '%s\n' "$pin" | "$out/src/image/build.sh" --release $options

# Image update, compressed disk image and checksums, signed with the update
# key; every signature is verified with the public keys of the tag
# shellcheck disable=SC2046  # pkcs11_docker_options: several words
printf '%s\n' "$pin" | docker run --rm $(pkcs11_docker_options) \
    -v "$PWD/$out:/release" -w /release/src \
    -e PYTHONPATH=/release/src/src -e PYTHONDONTWRITEBYTECODE=1 \
    -e TAG="$tag" -e COMMIT="$commit" -e EPOCH="$epoch" -e HOST_IDS="$(id -u):$(id -g)" \
    pandora-box-builder bash -c '
        set -euo pipefail
        . image/pkcs11.sh
        pkcs11_setup
        output=image/mkosi.output
        assets=/release/assets
        sbverify --cert image/release/secure-boot.crt "$output/pandora-box.efi" >/dev/null
        python3 -m pandora_box.imageupdate package "$output/pandora-box.raw" \
            /release/update/pandora-box-image --key "$PANDORA_BOX_UPDATE_KEY"
        update=/release/update/pandora-box-image
        OPENSSL_CONF=/dev/null openssl pkeyutl -verify -pubin -inkey image/release/update.pem \
            -rawin -in "$update/manifest.json" -sigfile "$update/manifest.json.sig" >/dev/null
        tar -C /release/update -cf "$assets/pandora-box-image-$TAG.tar" pandora-box-image
        xz -T0 -c "$output/pandora-box.raw" >"$assets/pandora-box-$TAG.raw.xz"
        python3 image/sbom.py "$output/pandora-box.manifest" "$assets/pandora-box-$TAG.cdx.json" \
            --commit "$COMMIT" --epoch "$EPOCH" >/dev/null
        cp image/release/secure-boot.crt image/release/update.pem "$assets/"
        cd "$assets"
        sha256sum "pandora-box-$TAG.raw.xz" "pandora-box-image-$TAG.tar" \
            "pandora-box-$TAG.cdx.json" secure-boot.crt update.pem >SHA256SUMS
        openssl pkeyutl -sign -inkey "$PANDORA_BOX_UPDATE_KEY" -rawin \
            -in SHA256SUMS -out SHA256SUMS.sig
        OPENSSL_CONF=/dev/null openssl pkeyutl -verify -pubin -inkey update.pem \
            -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig >/dev/null
        chown -R "$HOST_IDS" /release'

# A file of a GitHub release must be smaller than 2 GiB
for asset in "$out"/assets/*; do
    if [ "$(stat -c %s "$asset")" -ge 2147483648 ]; then
        echo "error: $asset is bigger than 2 GiB, the limit of GitHub" >&2
        exit 1
    fi
done

cat >"$out/notes.md" <<EOF
PandoraBox $tag, image version $version (commit $commit).

| File | Content |
|---|---|
| \`pandora-box-$tag.raw.xz\` | disk image, to write to the disk of the kiosk ([Initial installation](https://sourcentis.github.io/pandora-box/install/)) |
| \`pandora-box-image-$tag.tar\` | signed image update, to extract at the root of a USB key ([System updates](https://sourcentis.github.io/pandora-box/update/)) |
| \`pandora-box-$tag.cdx.json\` | software bill of materials (CycloneDX): Debian and Python packages of the image |
| \`secure-boot.crt\`, \`update.pem\` | public release keys |
| \`SHA256SUMS\`, \`SHA256SUMS.sig\` | checksums, signed with the update key |

Verify the files before using them ([Releases](https://sourcentis.github.io/pandora-box/release/#verifying-a-release)):

\`\`\`sh
openssl pkeyutl -verify -pubin -inkey update.pem -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig
sha256sum -c SHA256SUMS
\`\`\`

The key \`update.pem\` must be the one of the repository and of the documentation, not only the one of this release.

The build is reproducible: Debian packages of snapshot.debian.org at $snapshot, \`SOURCE_DATE_EPOCH=$epoch\`. Build it again from the tag and compare it with these files: \`image/reproduce.sh $tag DIR\` ([Reproducing a release](https://sourcentis.github.io/pandora-box/release/#reproducing-a-release)).
EOF
echo "release $tag (image version $version): $out/assets"
ls -l "$out/assets"
if [ -z "$publish" ]; then
    exit 0
fi
gh release create "$tag" --draft --verify-tag --title "PandoraBox $tag" \
    --notes-file "$out/notes.md" "$out"/assets/*
echo "draft release $tag created on GitHub: check it, then publish it"
