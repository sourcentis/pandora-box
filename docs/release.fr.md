# Versions publiées

Une version publiée de PandoraBox est une image prête à écrire, publiée sur
[GitHub](https://github.com/sourcentis/pandora-box/releases), signée avec les
clés de publication du projet. Une borne installée à partir d'elle ne démarre
que des images signées avec la même clé Secure Boot, et n'installe que les
jeux de signatures, mises à jour de l'image et demandes de maintenance signés
avec la même clé de mise à jour.

Une organisation qui veut ses propres clés construit son image elle-même
([Construction de l'image](build.md)) : ses bornes font alors confiance à ses
clés, pas à celles du projet.

## Clés de publication { #release-keys }

| Clé | Algorithme | Emplacement YubiKey | Signe | Partie publique |
|---|---|---|---|---|
| Clé Secure Boot | RSA 2048 | 9c | systemd-boot, l'image noyau unifiée, le hash racine dm-verity ; inscrite dans le firmware de la borne | `image/release/secure-boot.crt` |
| Clé de mise à jour | Ed25519 | 82 | jeux de signatures, mises à jour de l'image, demandes de maintenance, sommes de contrôle d'une version | `image/release/update.pem` |

Les clés privées ne quittent jamais une **YubiKey 5** (application PIV,
firmware 5.7 ou plus récent pour Ed25519). Le conteneur de construction les
utilise par `ykcs11` et le fournisseur PKCS#11 d'OpenSSL
(`image/pkcs11.sh`). Il atteint la YubiKey par le démon PC/SC de
l'ordinateur de construction quand il en fait tourner un qui lui répond
(`/run/pcscd`), sinon il démarre le sien, avec les périphériques USB. Le
client du conteneur (pcsc-lite 2, Debian 13) ne parle pas à un démon plus
ancien (Debian 12) : arrêtez celui-ci pendant la signature, car il retient la
YubiKey (`sudo systemctl stop pcscd.socket pcscd`) ; les scripts le disent.

Il faut deux YubiKeys de la **série 5** (5 NFC, 5C NFC, 5 Nano…). Le
firmware d'une YubiKey ne se met pas à jour : vérifiez qu'il est en 5.7 ou
plus récent avant l'achat. Les modèles *Security Key by Yubico* n'ont que
FIDO, pas PIV : ils ne peuvent pas porter les clés. `ykman info` (paquet
`yubikey-manager`, sur l'ordinateur de construction) donne le modèle, le
firmware et les applications actives en USB ; `ykman config usb --enable PIV`
active PIV quand il est désactivé.

Les parties publiques sont dans le dépôt, dans `image/release/`. Leurs
empreintes sont aussi publiées ici, pour vérifier une version avec une autre
source qu'elle-même :

```sh
openssl x509 -in image/release/secure-boot.crt -noout -fingerprint -sha256
openssl pkey -pubin -in image/release/update.pem -outform DER | sha256sum
```

| Clé | Empreinte SHA-256 |
|---|---|
| Clé Secure Boot (`secure-boot.crt`, certificat) | `B0:A3:3D:3E:50:41:67:26:CB:BF:6B:D4:B7:97:7F:2A:0C:D0:C4:C4:F8:2B:C2:75:2A:A5:20:06:AB:84:2C:83` |
| Clé de mise à jour (`update.pem`, clé publique en DER) | `06d2d2f5e183f7f9bd1ae118df37e8e789aca6153768718cf07d1d3e37c73fb8` |

Créées le 2026-11-03 ; le certificat Secure Boot est valide jusqu'au
2036-10-31 (le micrologiciel d'une borne ne le vérifie pas).

### Créer les clés { #creating-the-keys }

Une seule fois, sur un ordinateur hors ligne. Les clés sont créées en
mémoire, importées dans **deux** YubiKeys, la seconde gardée dans un coffre,
puis effacées. Une clé Secure Boot perdue signifie que les bornes ne peuvent
plus qu'être réinstallées, à la main ; une clé de mise à jour perdue, qu'elles
ne reçoivent plus de jeux de signatures.

Dans le conteneur de construction, avec les fichiers en mémoire seulement.
Le conteneur utilise son propre démon PC/SC : arrêtez d'abord celui de
l'ordinateur, s'il en fait tourner un (`sudo systemctl stop pcscd.socket
pcscd`, puis `sudo systemctl start pcscd.socket` à la fin).

```sh
docker run --rm -it --device-cgroup-rule='c 189:* rmw' -v /dev/bus/usb:/dev/bus/usb \
    -v /run/udev:/run/udev:ro \
    -v "$PWD/image/release:/release" --tmpfs /keys:mode=0700 pandora-box-builder bash
pcscd --disable-polkit   # pas de polkit dans le conteneur : il refuserait tout client
opensc-tool -l      # liste le lecteur de la YubiKey : Yubico YubiKey ... CCID
cd /keys
openssl req -new -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=PandoraBox release Secure Boot key/" \
    -keyout secure-boot.key -out secure-boot.crt
openssl genpkey -algorithm ed25519 -out update.key
openssl req -new -x509 -key update.key -days 3650 -subj "/CN=PandoraBox release update key/" -out update.crt
openssl pkey -in update.key -pubout -out update.pem
```

Le conteneur voit les périphériques USB branchés après son démarrage
(`/dev/bus/usb` de l'ordinateur, tous les périphériques USB autorisés) : les
YubiKeys peuvent être échangées sans en sortir, ce qui effacerait les clés
privées. Son démon PC/SC ne voit pas une YubiKey branchée après son
démarrage : relancez-le après chaque échange. `-r Yubico` choisit la YubiKey
quand l'ordinateur a un autre lecteur de cartes à puce.

Puis pour chaque YubiKey (`-k` demande sa clé de gestion ; changez d'abord
le PIN, le PUK et la clé de gestion par défaut d'une YubiKey neuve) :

```shcccccdh
pkill pcscd; pcscd --disable-polkit; sleep 2; opensc-tool -l   # une fois branchée
yubico-piv-tool -r Yubico -k -a import-key -s 9c -i secure-boot.key --pin-policy=once --touch-policy=never
yubico-piv-tool -r Yubico -k -a import-certificate -s 9c -i secure-boot.crt
yubico-piv-tool -r Yubico -k -a import-key -s 82 -i update.key --pin-policy=once --touch-policy=never
yubico-piv-tool -r Yubico -k -a import-certificate -s 82 -i update.crt
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/libykcs11.so --login --list-objects
```

`ykcs11` ne montre que la clé d'un emplacement qui contient un certificat. La
politique de PIN `once` permet à une construction de signer toutes les
parties de l'image avec un seul PIN ; la politique de toucher `never`, sans
toucher la YubiKey à chaque signature.

Enfin, publiez les clés publiques et quittez le conteneur, ce qui efface les
clés privées :

```sh
cp secure-boot.crt update.pem /release/
exit
git add image/release/secure-boot.crt image/release/update.pem
```

Avec d'autres emplacements ou un autre jeton, donnez les URI PKCS#11 des clés
et le module : `PANDORA_BOX_SECURE_BOOT_KEY`, `PANDORA_BOX_UPDATE_KEY` et
`PANDORA_BOX_PKCS11_MODULE` (voir `image/pkcs11.sh`).

## Publier une version { #making-a-release }

Le numéro d'une version est sa date, en UTC : le tag `vAAAA.MM.JJ`, créé le
jour de la publication ; `vAAAA.MM.JJ.2`, `.3`… pour une autre version le
même jour, et un suffixe (`vAAAA.MM.JJ-rc1`) pour un essai qui n'est pas
publié. `image/release.sh` refuse tout autre tag, ainsi qu'un tag dont la
date n'est pas le jour de sa création. La version de l'image affichée par la
borne est l'heure du tag, à la seconde (`AAAAMMJJHHMMSS`).

Sur l'ordinateur de construction, avec la YubiKey branchée et
[gh](https://cli.github.com/) connecté à GitHub :

```sh
git tag -a v2026.11.03 -m "PandoraBox 2026.11.03"
git push origin v2026.11.03
image/release.sh v2026.11.03
```

`image/release.sh` demande une fois le PIN de la YubiKey, puis :

1. extrait les seuls fichiers du tag (`git archive`) dans
   `release/v2026.11.03/src/` : aucun thème local, identifiant ou clé de
   développement n'entre dans l'image ;
2. vérifie le PIN avant la construction : signe un message de test avec les
   deux clés de la YubiKey et le vérifie avec les clés publiques du tag ; un
   mauvais PIN (un essai consommé), une clé qui ne signe pas ou une autre clé
   l'arrête aussitôt, avec les essais de PIN restants ;
3. construit l'image sans profil, signée avec la clé Secure Boot
   (`image/build.sh --release`), qui fait confiance à
   `image/release/update.pem`, avec les entrées d'une
   [construction reproductible](#reproducing-a-release) ;
4. vérifie la signature de l'image noyau unifiée, construit la mise à jour
   signée de l'image, compresse l'image disque, écrit la nomenclature
   logicielle, signe les sommes de contrôle avec la clé de mise à jour, et
   vérifie chaque signature avec les clés publiques du tag ;
5. crée un **brouillon** de version du tag sur GitHub avec les fichiers de
   `release/v2026.11.03/assets/`.

| Fichier | Contenu |
|---|---|
| `pandora-box-v2026.11.03.raw.xz` | image disque, à écrire sur le disque de la borne |
| `pandora-box-image-v2026.11.03.tar` | mise à jour signée de l'image : `pandora-box-image/`, à extraire à la racine d'une clé USB ([Mises à jour du système](update.md)) |
| `pandora-box-v2026.11.03.cdx.json` | nomenclature logicielle (SBOM, CycloneDX 1.5) : les paquets Debian et Python de l'image, avec leurs versions |
| `secure-boot.crt`, `update.pem` | clés publiques de publication |
| `SHA256SUMS`, `SHA256SUMS.sig` | sommes de contrôle, signées avec la clé de mise à jour |

Vérifiez le brouillon sur GitHub, puis publiez-le. `--no-publish` s'arrête
avant GitHub. L'image d'une version n'a pas de profil : le profil `online`
contient les identifiants et réglages d'une organisation, et n'est pas
publié.

### Tester sans YubiKey { #testing-without-a-yubikey }

`image/softhsm-keys.sh` crée un jeton SoftHSM, un dossier, avec des clés de
test dans les emplacements et sous les noms de la YubiKey :

```sh
image/softhsm-keys.sh /tmp/token
cp /tmp/token/secure-boot.crt /tmp/token/update.pem image/release/   # dans un clone de test seulement
git commit -m "Test keys" image/release/
tag=v$(date -u +%Y.%m.%d)-test
git tag -a "$tag" -m "Test release"
echo 123456 | PANDORA_BOX_SOFTHSM=/tmp/token image/release.sh "$tag" --no-publish
```

## Reproduire une version { #reproducing-a-release }

L'image d'une version ne dépend que de son tag : chacun peut la construire à
nouveau et vérifier qu'elle est faite du code source et des paquets Debian
publiés. `image/reproducible.sh` déduit du tag chaque entrée de la
construction :

| Entrée | Valeur |
|---|---|
| Paquets Debian, et outils du conteneur de construction | [snapshot.debian.org](https://snapshot.debian.org/) à la date du tag |
| Date des fichiers (`SOURCE_DATE_EPOCH`), version de l'image | la date du tag |
| UUID des partitions, sel dm-verity | une graine déduite du commit |
| Paquets Python | figés avec leurs empreintes (`image/requirements.txt`) |

Pour vérifier une version, téléchargez ses fichiers et construisez à nouveau
son tag :

```sh
gh release download v2026.11.03 -D /tmp/v2026.11.03
image/reproduce.sh v2026.11.03 /tmp/v2026.11.03
```

`image/reproduce.sh` vérifie les fichiers avec leurs sommes de contrôle
signées, construit le tag avec les mêmes entrées, en faisant confiance à la
même clé de mise à jour, mais signé avec des clés de développement, puis
compare :

| Partie | Attendu |
|---|---|
| système de fichiers racine, arbre de hachage dm-verity | identiques |
| image noyau unifiée | chaque section identique, le noyau sans ses signatures Secure Boot (celle de Debian et celle de l'image) |
| nomenclature logicielle | identique |

Les signatures ne peuvent pas être comparées : elles demandent les clés de
publication, et contiennent la date à laquelle elles ont été faites. Elles
sont vérifiées avec les clés publiques
([Vérifier une version](#verifying-a-release)). mkosi 25.3 est corrigé dans le
conteneur de construction (`image/patch-mkosi.py`) pour que le microcode de
l'image noyau soit reproductible.

## Vérifier une version { #verifying-a-release }

Téléchargez les fichiers de la version, puis vérifiez la signature des
sommes de contrôle avec la clé de mise à jour du projet, et les fichiers avec
les sommes de contrôle :

```sh
openssl pkeyutl -verify -pubin -inkey update.pem -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig
sha256sum -c SHA256SUMS
openssl pkey -pubin -in update.pem -outform DER | sha256sum
```

La dernière empreinte doit être celle donnée [plus haut](#release-keys) : le
`update.pem` d'une version ne prouve rien à lui seul, car quiconque
publierait une fausse version donnerait le sien. Écrivez ensuite l'image
([Installation initiale](install.md#writing-the-image)) :

```sh
xz -dc pandora-box-v2026.11.03.raw.xz | sudo dd of=/dev/sdX bs=4M conv=fsync status=progress
```

À son premier démarrage, la borne inscrit `secure-boot.crt` dans son
firmware. Une borne installée avec des clés de développement n'accepte pas
les mises à jour d'une version publiée : écrivez à nouveau l'image de la
version sur son disque.
