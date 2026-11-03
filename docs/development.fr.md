# Développement

Cette page explique comment travailler sur PandoraBox sur un ordinateur de développement : lancer la borne hors de l'image, avec ou sans vrais moteurs, et lancer les tests. Pour construire l'image de la borne et la tester dans une machine virtuelle, voir [Construction de l'image](build.md) et [Test avec QEMU](vm.md).

Le code est dans le paquet `pandora_box` (`src/pandora_box/`) :

| Module | Rôle |
|---|---|
| `cli.py` | Point d'entrée en ligne de commande (`pandora-box`) |
| `config.py` | Configuration TOML, validée au démarrage |
| `statemachine.py`, `kiosk.py` | Machine à états et déroulement de la borne |
| `monitor.py` | Détection USB avec udev |
| `usbguard.py` | Périphériques USB refusés par USBGuard, lus dans son journal d'audit : consignés et expliqués à l'écran |
| `device.py` | Montage durci (`ro,noexec,nosuid,nodev` sur un périphérique bloc en lecture seule, lecture-écriture seulement pour nettoyer) |
| `fuse.py` | NTFS, exFAT et ext4 lus par des pilotes FUSE dans le bac à sable, avec un chien de garde |
| `inventory.py` | Inventaire de la clé : ne suit jamais les liens, ne quitte jamais la clé, limites |
| `results.py` | Résultats d'une analyse : résultat de chaque fichier et synthèse de la clé |
| `scanner.py`, `workers.py`, `worker.py` | Analyse dans des processus surveillés, délais et chien de garde |
| `sigsets.py`, `publish.py` | Jeux de signatures signés : vérification, installation, publication depuis les sources, commande `pandora-box-signatures` |
| `sandbox.py`, `seccomp.py`, `protocol.py` | Bac à sable des processus d'analyse (bubblewrap, utilisateur dédié, filtre d'appels système), messages JSON validés venant des processus |
| `pipeline.py`, `hashing.py`, `filetype.py` | Par fichier : empreintes (SHA-256, SHA-1, MD5), type libmagic, moteurs |
| `engines/` | Interface des moteurs, MalwareBazaar, Hashlookup, ClamAV, YARA-X et faux moteur |
| `hashdb.py`, `bloom.py`, `clamd.py` | Base MalwareBazaar, lecteur de filtre de Bloom DCSO, client clamd |
| `policy.py` | Combinaison des verdicts par fichier et par clé |
| `report.py`, `schemas/` | Rapport d'analyse JSON et son schéma JSON |
| `signatures.py` | Provenance et fraîcheur des signatures |
| `quarantine.py` | Copie des fichiers infectés avec un manifeste qui renvoie au rapport |
| `imageupdate.py`, `maintenance.py` | Mises à jour A/B de l'image, clés de maintenance (export des journaux) |
| `online.py` | Mises à jour des signatures en ligne (`pandora-box-update.service`) |
| `siem.py`, `follow.py` | Export des journaux vers un SIEM (`pandora-box-siem.service`) ; suivi d'un fichier journal à travers ses rotations, utilisé aussi pour le journal d'audit d'USBGuard |
| `airgap.py`, `remotes.py`, `keyid.py`, `keyfs.py` | Copie vers un serveur (bornes de transfert) : déroulement et service `pandora-box-airgap`, miroir par rsync ou SFTP, identifiant signé écrit sur les clés, limites des systèmes de fichiers des clés |
| `ui/` | Interface graphique de la borne (framebuffer, thèmes), interfaces curses (administrateur) et console |
| `logs.py`, `lock.py` | Journaux JSON, verrou d'instance unique |
| `text.py` | Chaînes non fiables (noms de fichiers, libellés des clés) rendues affichables et échappées |

Les fichiers de déploiement sont dans `packaging/` : configuration, services systemd, tmpfiles, sysusers et logrotate.

## Prérequis { #prerequisites }

- Linux avec udev (la détection USB et le montage nécessitent les droits root)
- **Python 3.11 ou plus récent**
- libmagic (`sudo apt install libmagic1`)
- pour de vraies analyses : `clamav-daemon` (voir [Moteurs de détection](engines.md#clamav))

Les distributions récentes (Debian 12 et suivantes, Ubuntu 23.04 et suivantes) interdisent `pip install` dans le Python du système ([PEP 668](https://peps.python.org/pep-0668/), erreur `externally-managed-environment`). Travaillez toujours dans un environnement virtuel, et n'utilisez jamais `--break-system-packages`.

## Créer l'environnement virtuel { #create-the-virtual-environment }

Si le Python de votre système est en version 3.11 ou plus (Debian 12 et 13, Ubuntu 24.04) :

```sh
sudo apt install python3-venv python3-full
git clone https://github.com/sourcentis/pandora-box.git
cd pandora-box
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e ".[dev]"
```

Si le Python de votre système est plus ancien (Ubuntu 22.04 fournit Python 3.10), utilisez [uv](https://docs.astral.sh/uv/), qui télécharge un Python adapté sans toucher au système :

```sh
curl -LsSf https://astral.sh/uv/install.sh | sh
git clone https://github.com/sourcentis/pandora-box.git
cd pandora-box
uv venv --python 3.11
source .venv/bin/activate
uv pip install -e ".[dev]"
```

## Configurer et lancer { #configure-and-run }

```sh
cp packaging/pandora-box.toml pandora-box.toml
# règles YARA, MalwareBazaar (nécessite ABUSECH_AUTH_KEY), Hashlookup : un jeu non signé
pandora-box-signatures publish dev-signatures --sources yara-forge,malwarebazaar,hashlookup
# copiez les réglages [engines.*] et [signatures] affichés dans pandora-box.toml,
# réglez les dossiers de quarantaine, de rapports et de journaux, puis vérifiez la configuration
pandora-box --config pandora-box.toml --check-config
sudo .venv/bin/pandora-box --config pandora-box.toml --interface console
```

`sudo` réinitialise `PATH` : la borne est donc lancée avec le chemin complet de l'exécutable installé dans l'environnement virtuel (`.venv/bin/pandora-box`).

Monter un périphérique nécessite root : ajouter votre utilisateur à un groupe (comme `disk`) ne suffit pas. Sur un bureau qui monte lui-même les périphériques USB (montage automatique d'udisks), réglez plutôt `auto_mount = true` dans `[device]` : la borne utilise alors le montage du système, puis démonte et remonte la clé avec `udisksctl`, et fonctionne donc sans `sudo`. C'est réservé au développement : le montage du système est en général en lecture-écriture et n'est pas durci.

La clé est démontée pendant que la borne demande à l'utilisateur de confirmer le nettoyage, pour qu'elle puisse être retirée sans risque. Pour nettoyer, elle est remontée en lecture-écriture ; un fichier n'est supprimé que si son SHA-256 est toujours celui qui a été analysé (une autre clé a pu être insérée entre-temps). Une fois l'analyse et le nettoyage terminés, la clé est éjectée (`device.eject`, avec `eject`, ou `udisksctl power-off` en mode de montage automatique).

Les processus d'analyse tournent dans un bac à sable par défaut (`scan.sandbox`) : il nécessite root, `bwrap` (paquet Debian `bubblewrap`), `setpriv` et un utilisateur `pandora-box-scan` (`sudo systemd-sysusers packaging/sysusers/pandora-box.conf`). Pour développer sans eux, réglez `sandbox = false` dans `[scan]`.

NTFS, exFAT et ext4 sont lus par des pilotes FUSE dans ce bac à sable (`device.fuse`, voir [Fonctionnement de l'image](image.md#filesystem-drivers)) : paquets Debian `ntfs-3g`, `exfat-fuse` et `fuse2fs`, et la bibliothèque préchargée dans ntfs-3g, à compiler une fois :

```sh
sudo mkdir -p /usr/lib/pandora-box
sudo cc -O2 -shared -fPIC -o /usr/lib/pandora-box/fuse-premounted.so packaging/fuse/premounted.c -ldl
```

Sans le bac à sable (`sandbox = false`), ou avec `fuse = false` dans `[device]`, ce sont les pilotes du noyau qui les montent.

La borne n'utilise qu'un jeu de signatures signé (`signatures.verify`, voir [Signatures](signatures.md)) : les signatures de développement ne sont pas signées, réglez `verify = false` dans `[signatures]` pour les utiliser.

Pour travailler sur le déroulement sans signatures, réglez `fake_scan = true` dans `[kiosk]` (ou utilisez `--fake-scan`) : seul le [fichier de test EICAR](https://www.eicar.org/download-anti-malware-testfile/) est déclaré malveillant, si bien que tout le déroulement (analyse, quarantaine, nettoyage) peut être testé sans vrais moteurs.

## Analyse statique et tests { #lint-and-tests }

Avec l'environnement virtuel activé :

```sh
ruff check .
mypy src
pytest
```

Les tests d'intégration utilisent de vrais moteurs quand ils sont disponibles : un socket clamd (`PANDORA_BOX_CLAMD_SOCKET`, par défaut `/run/clamav/clamd.ctl`), de vraies règles (`PANDORA_BOX_YARA_RULES`, chemins séparés par `:`) ou une configuration complète pour le corpus de détection (`PANDORA_BOX_CORPUS_CONFIG`). Les tests de bout en bout avec des périphériques loop et un vrai clamd tournent dans un conteneur : `tests/e2e/run.sh`.

## Interface sans borne { #interface-without-a-kiosk }

Les écrans de l'interface graphique peuvent être dessinés dans des fichiers PNG, avec des fichiers fictifs, pour travailler dessus ou sur un thème sans framebuffer (voir [Interface](interface.md)) :

```sh
pandora-box-theme preview /tmp/preview --language fr
```

## Documentation { #documentation }

Cette documentation est construite avec [MkDocs](https://www.mkdocs.org/) et le thème [Material](https://squidfunk.github.io/mkdocs-material/), à partir du dossier `docs/` et de `mkdocs.yml`. Elle est publiée sur GitHub Pages par le workflow `docs` quand `docs/` change sur la branche `main`. Pour la voir pendant la rédaction :

```sh
pip install -r requirements-docs.txt
mkdocs serve        # http://127.0.0.1:8000, rechargée à chaque modification
mkdocs build --strict
```

La documentation est en anglais et en français (plugin `mkdocs-static-i18n`) : chaque page anglaise `page.md` a sa traduction `page.fr.md`, publiée sous `/fr/`. Une page sans traduction s'affiche en anglais. Les titres d'une page française reprennent l'ancre de la page anglaise (`## Profil online { #profile-online }`), pour que les liens vers une section fonctionnent dans les deux langues.

Avec MkDocs installé par pipx, ajoutez plutôt les extensions de `requirements-docs.txt` à son environnement (les alertes GitHub, `> [!WARNING]`, nécessitent `markdown-callouts`) :

```sh
pipx install mkdocs
pipx inject mkdocs mkdocs-material markdown-callouts mkdocs-static-i18n
```
