# Journaux

Une borne n'a pas de session et n'accepte aucune connexion : ses journaux
sont récupérés avec une **clé de maintenance** signée, ou envoyés au fil de
l'eau à un SIEM par une borne en ligne.

## En bref { #in-short }

```sh
image/maintenance-key.sh /media/$USER/KEY            # toute borne
image/maintenance-key.sh /media/$USER/KEY kiosk-1    # seulement kiosk.name = kiosk-1
```

Insérez la clé dans la borne : elle écrit ses journaux dans
`pandora-box-maintenance/<borne>-<date>/` et éjecte la clé.

Pour un export continu, voir [Export vers un SIEM](siem.md).

## Ce que la borne journalise { #what-the-kiosk-logs }

| Journal | Chemin sur la borne | Contenu |
|---|---|---|
| Borne | `/var/log/pandora-box/pandora-box.log` | Lignes JSON : clés insérées et retirées, périphériques USB refusés par USBGuard, analyses et leurs verdicts, fichiers infectés, quarantaine et nettoyage, mises à jour des signatures et de l'image, clés de maintenance, erreurs |
| Rapports d'analyse | `/var/lib/pandora-box/reports/` | Un rapport JSON par clé analysée (voir [Rapport d'analyse](engines.md#scan-report)) |
| Quarantaine | `/var/lib/pandora-box/quarantine/` | Copies des fichiers infectés supprimés des clés |
| Journal système | `journalctl` | Système, services et noyau ; un dossier par démarrage, dans les limites de taille de journald |
| USBGuard | `/var/log/usbguard/usbguard-audit.log` | Périphériques autorisés et bloqués |
| Audit | `/var/log/audit/audit.log` | Modules du noyau chargés, montages, programmes lancés, ptrace, changements de l'horloge, des jeux de signatures et des mises à jour de l'image en attente |

Chaque entrée du journal de la borne contient `timestamp`, `level`, `kiosk`
(`kiosk.name`) et `event`, puis les champs de l'événement. Le niveau est
réglé par `logging.level` (`INFO` par défaut). logrotate déplace le fichier
de journal chaque mois et garde 12 mois, compressés.

Tout se trouve sur la partition de données (`/var`), conservée lors des
redémarrages et des mises à jour de l'image.

## Clé de maintenance { #maintenance-device }

Une clé de maintenance récupère les journaux d'une borne sans sortir son
disque. Sur l'ordinateur qui détient la clé de mise à jour, avec une clé USB
montée :

```sh
image/maintenance-key.sh /media/$USER/KEY            # toute borne
image/maintenance-key.sh /media/$USER/KEY kiosk-1    # seulement kiosk.name = kiosk-1
```

écrit `pandora-box-maintenance/` sur la clé : une demande signée avec la clé
de mise à jour, valable 7 jours. Insérée dans la borne, même une borne sans
signatures, la clé n'est pas analysée : la borne vérifie la demande, écrit
ses journaux dans `pandora-box-maintenance/<borne>-<date>/` et éjecte la clé
(`src/pandora_box/maintenance.py`).

| Fichier | Contenu |
|---|---|
| `pandora-box.log` | Journal de la borne |
| `journal.txt`, `journal-previous-boot.txt` | Journal système du démarrage en cours et du précédent |
| `kernel.txt` | Messages du noyau |
| `boots.txt`, `boot-entries.txt` | Démarrages, versions de l'image installées ([Mises à jour du système](update.md)) |
| `services.txt`, `failed-services.txt` | Unités systemd, unités en échec |
| `usbguard-audit.log`, `usb-devices.txt`, `usb-rules.txt` | Périphériques USB autorisés et bloqués, règles |
| `disks.txt` | Disques et partitions |
| `hardware.txt`, `cpuinfo.txt`, `meminfo.txt`, `input-devices.txt` | Matériel et écrans, périphériques d'entrée |
| `os-release.txt`, `cmdline.txt` | Version de l'image, ligne de commande du noyau |
| `signatures.txt` | Jeu de signatures installé |

Rien ne change sur la borne, et l'export ne contient ni clé, ni identifiant,
ni rapport d'analyse. Une demande signée par une autre clé, trop ancienne,
destinée à une autre borne ou modifiée est refusée (`maintenance_refused`
dans le journal).

Une même clé peut contenir une demande de maintenance, un jeu de signatures
(`pandora-box-signatures/`) et une mise à jour de l'image
(`pandora-box-image/`) : la borne les traite dans cet ordre en une seule
insertion, chacun vérifié séparément ; l'export montre la borne avant les
mises à jour, et la mise à jour de l'image vient en dernier, puisqu'elle
redémarre la borne.

## Événements utiles { #useful-events }

| Événement | Signification |
|---|---|
| `device_verdict` | Synthèse de l'analyse d'une clé : verdict, compteurs, durée, détections, `report_id` (voir [Tableaux de bord](siem.md#dashboards)) |
| `infected_files` | Fichiers dangereux trouvés sur une clé |
| `signatures_installed`, `signatures_refused`, `signatures_not_newer` | Résultat d'une clé de mise à jour des signatures |
| `signatures_changed` | Nouveau jeu de signatures chargé après une mise à jour en ligne |
| `maintenance_refused` | Demande de maintenance refusée |
| `usb_device_blocked` | Périphérique USB refusé par USBGuard (voir [Périphériques USB refusés](#refused-usb-devices)) |
| `airgap_copied`, `airgap_failed`, `airgap_refused` | Copie d'une clé vers un serveur (voir [Copie vers un serveur](airgap.md)) |
| `display_started`, `display_resized` | Taille de l'écran pour laquelle l'interface dessine |

## Périphériques USB refusés { #refused-usb-devices }

USBGuard bloque tout périphérique USB qui n'est pas seulement du stockage :
un clavier, une souris, un adaptateur réseau, une clé qui est aussi un
clavier (BadUSB, voir [Périphériques USB](image.md#usb-devices)). Son
journal d'audit n'est lisible que par root et n'est pas envoyé au SIEM : la
borne le suit (`src/pandora_box/usbguard.py`) et consigne chaque
périphérique refusé dans son propre journal, avec les autres événements,
sous la forme `usb_device_blocked` (niveau `WARNING`) :

| Champ | Contenu |
|---|---|
| `target` | Décision d'USBGuard : `block` (ou `reject`) |
| `usb_id` | Identifiants du fabricant et du produit, `fabricant:produit` |
| `model`, `serial` | Nom et numéro de série donnés par le périphérique |
| `port` | Port USB, par exemple `1-2` |
| `interfaces` | Interfaces du périphérique, `classe:sous-classe:protocole` |
| `kinds` | Nature de ces interfaces : `storage`, `keyboard`, `mouse`, `hid`, `communications` (réseau, modem), `wireless` (Bluetooth), `vendor-specific`... |
| `composite` | `true` pour un périphérique de stockage qui a une autre fonction : une clé qui est aussi un clavier |
| `connect_type` | `hotplug` s'il a été branché, sinon présent au démarrage ou interne |
| `system_name` | Chemin du périphérique dans sysfs |
| `rule` | Règle de périphérique d'USBGuard, à adapter en règle `allow` (écran tactile, souris) |
| `blocked_at` | Heure de la décision d'USBGuard |

Les périphériques bloqués avant le démarrage de la borne (au démarrage du
système) sont signalés une fois qu'elle a démarré ; la position de la
dernière ligne lue est enregistrée
(`/var/lib/pandora-box/usbguard-audit.json`), si bien qu'un redémarrage de
la borne ne signale aucun périphérique deux fois. Sur une
[borne de transfert](airgap.md#a-stolen-kiosk), `model`, `serial` et `rule`
sont omis.

Un périphérique que l'opérateur voulait utiliser (une souris) apparaît
aussi ; une clé refusée en entier (`composite`), ou un clavier ou un
adaptateur réseau sur une borne qui n'en a pas, mérite un examen.

## Export vers un SIEM { #export-to-a-siem }

Une borne en ligne peut envoyer chaque entrée de son journal à un SIEM
(Wazuh, Elastic, Graylog, Splunk, ou tout serveur syslog), en syslog ou en
JSON, sur TLS, TCP ou UDP : voir [Export vers un SIEM](siem.md).
