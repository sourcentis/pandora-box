# Guide de déploiement

Cette page s'adresse à une organisation qui déploie des bornes PandoraBox :
les décisions à prendre d'abord, les clés et les personnes qui les
détiennent, l'emplacement des bornes, le réseau dont elles ont besoin, la
mise en service, puis l'exploitation courante. Les étapes techniques sont
décrites dans les autres pages ; celle-ci dit lesquelles suivre, dans quel
ordre, et pourquoi.

## En bref { #in-short }

1. [Décidez](#decisions) : quelles clés, hors ligne ou en ligne, borne ou
   borne de transfert de fichiers, combien de bornes.
2. [Préparez les clés](#keys-and-roles) et désignez les personnes qui les
   détiennent.
3. [Choisissez le matériel](#hardware) et [l'emplacement](#placement) des
   bornes.
4. [Ouvrez les flux réseau](#network) des bornes en ligne.
5. [Construisez l'image](#building-the-images) de l'organisation et
   [testez-la](#pilot) sur une borne pilote.
6. [Installez les bornes](#installing-the-kiosks), puis
   [informez les utilisateurs](#users).
7. [Exploitez-les](#operation) : signatures, mises à jour de l'image,
   journaux, détections.

## Décisions { #decisions }

### Quelles clés { #whose-keys }

Une borne fait confiance à deux clés, fixées à son installation
([Versions publiées](release.md#release-keys)) : la **clé Secure Boot**
décide de ce qu'elle démarre, la **clé de mise à jour** des jeux de
signatures, mises à jour de l'image et demandes de maintenance qu'elle
accepte.

| Option | Convient à | Conséquences |
|---|---|---|
| **Image publiée par le projet** | Une évaluation, une borne sur le matériel de référence | Prête à écrire et vérifiable ([Vérifier une version](release.md#verifying-a-release)). Aucune personnalisation : thème intégré, configuration par défaut, pas de profil `online`. Sa règle USBGuard autorise un seul contrôleur tactile, par son numéro de série et son port : un autre exemplaire de l'écran est bloqué. Chaque jeu de signatures et chaque demande de maintenance doit être signé par la clé de mise à jour du projet |
| **Image de l'organisation** | Tout déploiement en production | L'organisation construit son image ([Construction de l'image](build.md)) avec ses propres clés, et choisit sa configuration, son thème, la règle de son écran tactile, son profil et ses secrets. Elle garde ses clés et publie ses propres jeux de signatures |

En pratique, un déploiement en production construit sa propre image : il
lui faut sa propre règle d'écran tactile, le nom de chaque borne, souvent
son thème et le profil `online`, et une clé de mise à jour qu'il détient
lui-même, pour signer ses jeux de signatures et ses demandes de
maintenance. La suite de cette page le suppose.

Une borne installée avec certaines clés n'accepte que les mises à jour
signées avec elles. Changer de clés impose d'écrire une nouvelle image sur
son disque ([Installation initiale](install.md)).

### Hors ligne ou en ligne { #offline-or-online }

| | Hors ligne (sans profil) | En ligne (`--profile online`) |
|---|---|---|
| Réseau | Aucun : l'image n'a aucune configuration réseau | Réseau filaire, DHCP, flux sortants uniquement ([Réseau](#network)) |
| Signatures | Une clé de mise à jour des signatures, insérée par un exploitant | Téléchargées par la borne toutes les 6 heures, depuis les sources ou depuis un jeu publié par l'organisation |
| Mises à jour de l'image | Une clé USB | Une clé USB, ou une mise à jour publiée (`updates.image_url`) |
| Journaux | Une clé de maintenance | Envoyés à un SIEM au fil de l'eau ; clé de maintenance aussi |
| Horloge | Horloge matérielle, jamais corrigée | NTP |
| Secrets dans l'image | Aucun | Auth-Key abuse.ch, et la clé SSH d'une borne de transfert : l'image ne doit pas sortir de l'organisation |

Une borne hors ligne a la plus petite surface d'attaque, mais ses
signatures ne sont pas plus fraîches que le dernier passage d'un
exploitant, et ses journaux n'arrivent à l'organisation que quand quelqu'un
les rapporte. La borne prévient à l'écran quand ses signatures ont plus de
7 jours ([Fraîcheur des signatures](engines.md#signature-freshness)) :
prévoyez un passage au moins chaque semaine, ou choisissez le profil
`online`.

### Borne ou borne de transfert { #kiosk-or-file-transfer-station }

Une borne analyse la clé et supprime les fichiers dangereux. Une **borne
de transfert de fichiers** copie en plus les fichiers sains des clés
vérifiées sur un serveur de l'organisation, et écrit sur les clés les
fichiers que le réseau protégé leur a laissés
([Copie vers un serveur](airgap.md)). Elle demande le profil `online`, un
serveur joignable en SSH, et ses secrets dans l'image.

Choisissez une borne de transfert quand les fichiers doivent entrer dans
un réseau isolé ou en sortir : les utilisateurs ne branchent alors jamais
leurs clés sur un poste de ce réseau.

### Combien de bornes { #how-many-kiosks }

Chaque borne se nomme dans ses journaux et ses messages SIEM avec
`kiosk.name` ([Configuration](configuration.md)). Ce réglage fait partie de
la configuration, donc de l'image : sans lui, toutes les bornes s'appellent
`pandora-box`, le nom d'hôte de l'image. Pour distinguer les bornes dans le
SIEM et dans les exports de maintenance, construisez une image par borne,
avec les mêmes clés, seul son nom changeant. Tenez la liste des bornes :
nom, emplacement, profil, version de l'image.

## Clés et rôles { #keys-and-roles }

| Rôle | Détient | Fait |
|---|---|---|
| **Détenteurs des clés** (deux personnes) | La clé Secure Boot et la clé de mise à jour, sur deux YubiKey, et leur PIN ([Clés de publication](release.md#release-keys)) | Signent les images, les mises à jour de l'image, les jeux de signatures et les demandes de maintenance |
| **Constructeur** | L'ordinateur de construction, avec Docker et les sources | Construit les images et les mises à jour de l'image |
| **Exploitants** | Le mot de passe superviseur du BIOS, les clés USB de maintenance | Installent les bornes, apportent les jeux de signatures, les mises à jour de l'image et les clés de maintenance, vérifient les bornes |
| **Équipe sécurité** | Le SIEM, les exports de maintenance | Suit les détections, les périphériques refusés, les bornes dont les signatures sont anciennes |

- Créez les clés une seule fois, sur un ordinateur hors ligne, dans
  **deux** YubiKey ([Créer les clés](release.md#creating-the-keys)) ;
  gardez la seconde dans un coffre, à part de la première. Une clé Secure
  Boot perdue impose de réinstaller chaque borne à la main ; une clé de
  mise à jour perdue, qu'elles ne reçoivent plus ni jeux de signatures ni
  mises à jour de l'image.
- Les clés de développement que génère `image/build.sh`
  (`image/mkosi.key`, `image/update.key`) sont des fichiers sur
  l'ordinateur de construction : ne les utilisez jamais pour une borne en
  production.
- Le mot de passe superviseur du BIOS protège Secure Boot et l'ordre de
  démarrage de chaque borne : gardez-le avec les clés, pas sur la borne.
- L'Auth-Key abuse.ch et la clé SSH d'une borne de transfert sont dans
  l'image d'une borne en ligne : traitez les fichiers d'image et les
  disques des bornes comme confidentiels.

## Matériel { #hardware }

Utilisez le matériel validé : un Lenovo ThinkCentre M720q Tiny et un écran
tactile Waveshare 7 pouces, dans le boîtier imprimé en 3D
([Matériel](hardware.md), [Assemblage](assembly.md)). Un autre ordinateur ou
un autre écran demande ses propres réglages : le mode de l'écran, la règle
de son écran tactile, le contrôleur de disque dans l'initrd. Testez-le
d'abord sur une borne pilote.

Prévoyez pour chaque borne :

- 2 Go de mémoire au moins (clamd seul en utilise environ 1 Go) ; avec
  `scan.workers = "auto"`, chaque fichier analysé en parallèle prend
  256 Mo de plus, soit 4 Go pour analyser six fichiers à la fois
  ([Configuration](configuration.md#reference)) ;
- un disque de 32 Go ou plus : les deux emplacements système (environ
  2,7 Go), les jeux de signatures (environ 1,2 Go chacun, le précédent est
  gardé, plus la préparation d'une borne en ligne), les rapports, les
  journaux et la quarantaine ;
- la règle USBGuard de **chaque** écran tactile : elle est liée au numéro de
  série et au port de son contrôleur tactile. Lisez-la dans
  `usb-devices.txt` d'un export de maintenance, ou dans l'événement
  `usb_device_blocked` de la borne, puis construisez l'image de cette borne
  avec elle ([Périphériques USB](image.md#usb-devices)) ;
- une borne de secours, installée et pourvue de signatures, pour remplacer
  une borne en panne.

## Emplacement { #placement }

- Un endroit **visible** du personnel, à l'entrée de la zone protégée : un
  accueil, un poste de sécurité, l'entrée d'un laboratoire. Pas une pièce
  fermée où personne ne voit qui utilise la borne.
- Seul le port d'analyse accessible : le boîtier cache les autres ports et
  le bouton d'alimentation. Désactivez les ports USB inutilisés dans le
  BIOS quand il le permet
  ([Installation initiale](install.md#devices-and-advanced-settings)).
- Une prise de courant ; la borne redémarre seule après une coupure de
  courant (réglage *After Power Loss* du BIOS).
- Pour une borne en ligne, une prise réseau filaire dans un segment réseau
  dédié (VLAN), sans accès aux réseaux internes.
- La procédure des utilisateurs affichée à côté de la borne : voir
  [Utilisateurs](#users).

## Réseau { #network }

Une borne hors ligne n'a besoin de rien. Une borne en ligne n'ouvre que des
connexions sortantes : son pare-feu rejette toute connexion entrante, et ne
laisse sortir que les services ci-dessous, chacun par son propre
utilisateur système ([Profil online](build.md#profile-online)). Autorisez
les mêmes flux, et seulement eux, depuis le segment réseau des bornes :

| Flux | Destination | Protocole, port | Quand |
|---|---|---|---|
| DHCP | Serveur DHCP du segment | UDP 67 | toujours |
| DNS | Serveurs DNS donnés par DHCP | UDP et TCP 53 | toujours |
| NTP | Serveurs NTP de l'image, sinon du DHCP, sinon le pool Debian ([Heure](build.md#time)) | UDP 123 | toujours |
| Signatures ClamAV | `database.clamav.net` | HTTPS, TCP 443 | `updates.sources` |
| YARA Forge | `github.com` et les serveurs de téléchargement GitHub vers lesquels il redirige | HTTPS, TCP 443 | `updates.sources` |
| MalwareBazaar | `mb-api.abuse.ch` | HTTPS, TCP 443 | `updates.sources` |
| Hashlookup | `cra.circl.lu` | HTTPS, TCP 443 | `updates.sources` |
| Jeu de signatures publié, mises à jour de l'image | le serveur web de l'organisation | HTTPS, TCP 443 | `updates.url`, `updates.image_url` |
| Proxy | le proxy de l'organisation | son port | `updates.proxy`, à la place des quatre sources ci-dessus |
| SIEM | le SIEM | TLS, TCP 6514 par défaut (TCP ou UDP 514) | `[siem]` ([SIEM](siem.md)) |
| Borne de transfert | le serveur SSH | TCP 22 | `[airgap]` ([Copie vers un serveur](airgap.md)) |

Deux façons d'alimenter en signatures un parc de bornes :

- **Depuis les sources** : chaque borne télécharge elle-même les sources
  (dont le filtre Hashlookup, environ 1 Go chaque mois), et a besoin de
  l'Auth-Key abuse.ch dans son image.
- **Depuis un jeu publié** : un ordinateur de publication de l'organisation
  lance `publish/publish.sh` chaque jour et dépose le jeu signé sur un
  serveur web interne
  ([Un jeu publié à la place](signatures.md#a-published-set-instead)). Les
  bornes ne joignent que ce serveur, n'ont besoin d'aucun secret, et ne
  téléchargent que les fichiers qui ont changé. Préférez-le au-delà de
  quelques bornes, ou quand les bornes ne doivent pas joindre Internet.

## Construire les images { #building-the-images }

Sur l'ordinateur de construction, pour chaque borne (voir
[Construction de l'image](build.md)) :

1. Réglez la configuration dans `packaging/pandora-box.toml` :
   `kiosk.name`, `display.language`, `[updates]`, `[siem]`, `[airgap]`.
   Vérifiez-la avec `pandora-box --check-config`.
2. Placez le thème de l'organisation dans `image/theme/`
   ([Interface](interface.md#customization)), les autorités de
   certification du SIEM dans `image/siem-ca.pem`, les secrets dans
   `image/credentials.toml`, la règle de l'écran tactile dans
   `image/mkosi.extra/etc/usbguard/rules.conf`.
3. Construisez avec les clés de l'organisation, avec ou sans
   `--profile online`.
4. Gardez la configuration de chaque borne hors de l'image (un dépôt privé,
   par exemple) : la prochaine image de cette borne se construit à partir
   d'elle.

La version de l'image est l'heure de sa construction : chaque mise à jour
de l'image doit être plus récente que celle installée
([Mises à jour du système](update.md)).

## Borne pilote { #pilot }

Avant le parc, faites tourner l'image dans une machine virtuelle
([Test avec QEMU](vm.md)), puis installez une borne pilote et gardez-la
quelques semaines dans un vrai emplacement :

- l'écran tactile confirme un nettoyage ;
- le fichier de test EICAR est signalé et supprimé ;
- des clés de chaque système de fichiers utilisé dans l'organisation (vfat,
  exFAT, NTFS, ext4) sont analysées ; une clé chiffrée ou un téléphone est
  refusé, comme prévu ;
- une clé de mise à jour des signatures, une mise à jour de l'image et une
  clé de maintenance sont acceptées ;
- pour une borne en ligne : les signatures se mettent à jour d'elles-mêmes,
  le SIEM reçoit les événements, l'horloge est juste ;
- pour une borne de transfert : les fichiers sains arrivent sur le serveur,
  les fichiers sortants arrivent sur la clé ;
- la durée d'analyse des clés habituelles des utilisateurs est acceptable
  ([Matériel](hardware.md#validated-hardware)).

## Installer les bornes { #installing-the-kiosks }

Pour chaque borne ([Installation initiale](install.md)) :

1. Configurez le BIOS : mot de passe superviseur, Secure Boot en mode
   configuration, démarrage sur le disque interne uniquement, VT-d activé,
   redémarrage après une coupure de courant.
2. Écrivez l'image de la borne sur son disque.
3. Au premier démarrage, vérifiez que Secure Boot est en mode **User**.
4. Insérez un premier jeu de signatures : jusque-là, la borne affiche
   `NO VALID SIGNATURES` et n'analyse rien.
5. Vérifiez-la avec le fichier de test EICAR et une clé de maintenance :
   `failed-services.txt` est vide, `signatures.txt` montre le jeu.
6. Notez son nom, son emplacement, la version de l'image et la date dans la
   liste des bornes.

## Utilisateurs { #users }

Dites aux utilisateurs ce que fait la borne, et ce qu'elle ne fait pas :

- **Quand** : toute clé qui vient de l'extérieur, ou qui a servi à
  l'extérieur, est analysée avant d'être branchée sur un poste de
  l'organisation.
- **Comment** : insérer la clé, attendre le résultat, toucher l'écran pour
  supprimer les fichiers dangereux, retirer la clé. Les affiches de
  [`docs/poster/`](https://github.com/sourcentis/pandora-box/tree/main/docs/poster)
  montrent ces étapes, à imprimer et afficher à côté de la borne.
- **Le résultat** : une clé **non vérifiée** ne doit pas être utilisée : un
  fichier n'a pas pu être analysé (archive chiffrée, fichier trop gros,
  erreur). L'utilisateur l'apporte à l'équipe sécurité, ou s'en passe.
- **Les limites** : un résultat sain signifie qu'aucun moteur n'a rien
  détecté, pas que la clé est sûre ([Modèle de menace](threat-model.md)).
  Les postes de travail gardent leurs propres protections.
- **Qui appeler** : le contact de l'équipe sécurité, dans le thème de la
  borne ([Textes](interface.md#texts)) ou sur l'affiche.

## Exploitation { #operation }

### Tâches récurrentes { #recurring-tasks }

| Tâche | Fréquence | Comment |
|---|---|---|
| Jeu de signatures | chaque jour (en ligne), au moins chaque semaine (hors ligne) | [Signatures](signatures.md) : automatique en ligne ; une clé de mise à jour des signatures sinon |
| Mise à jour de l'image | chaque mois, et pour chaque mise à jour de sécurité Debian qui concerne la borne | reconstruire avec les mêmes clés et la même configuration, puis [Mises à jour du système](update.md) |
| Journaux | en continu (SIEM), ou à chaque passage (clé de maintenance) | [Journaux](logs.md), [SIEM](siem.md) |
| Vérification de la borne | à chaque passage | l'écran n'affiche aucun avertissement de signatures ; le boîtier est fermé et intact ; aucun autre appareil que la borne n'est branché |
| Quarantaine et rapports | chaque année | voir [Données sur la borne](#data-on-the-kiosk) |
| YubiKey | chaque année | les deux YubiKey signent encore (une signature de test) ; les détenteurs des clés connaissent les PIN |

### Ce qu'il faut surveiller { #what-to-watch }

Dans le SIEM, ou dans les exports de maintenance
([Événements utiles](logs.md#useful-events),
[Tableaux de bord](siem.md#dashboards)) :

| Événement | Action |
|---|---|
| `infected_files`, `device_verdict` malveillant | Chercher d'où vient la clé, et sur quels postes elle a été branchée avant la borne |
| `usb_device_blocked` avec `composite` | Une clé qui est aussi un clavier : gardez la clé, c'est un outil d'attaque |
| `usb_device_blocked`, autres périphériques | Quelqu'un a branché un clavier, un adaptateur réseau ou un téléphone : vérifiez la borne |
| `device_suspicious_behavior` | Une clé qui s'est déconnectée d'elle-même pendant son analyse : gardez-la pour analyse |
| `signatures_refused`, `maintenance_refused` | Une clé signée par une autre clé, trop ancienne ou modifiée : qui l'a apportée ? |
| Aucun `signatures_changed` depuis plusieurs jours (en ligne) | La borne ne joint plus ses sources : réseau, proxy, Auth-Key |
| Aucun événement d'une borne | Éteinte, débranchée, ou elle ne démarre plus : allez voir |

### Détections { #detections }

Quand une borne signale un fichier malveillant :

1. Le fichier est copié dans la quarantaine de la borne, puis supprimé de la
   clé après un appui sur l'écran. Son SHA-256 et les moteurs qui l'ont
   détecté sont dans le rapport d'analyse et dans l'événement
   `infected_files`.
2. Demandez à l'utilisateur d'où vient la clé, et sur quels ordinateurs
   elle a servi : ils peuvent être infectés.
3. Une copie du fichier est dans la quarantaine de la borne
   (`/var/lib/pandora-box/quarantine/`), sur son disque uniquement : l'export
   de maintenance ne la rapporte pas. Pour l'analyser, sortez le disque, en
   laboratoire.

### Pannes { #failures }

| Symptôme | Cause, action |
|---|---|
| `NO VALID SIGNATURES` | Aucun jeu installé, ou le jeu installé échoue à sa vérification : insérez une clé de mise à jour des signatures |
| Avertissement de signatures à l'écran | Les signatures ont plus de 7 jours : insérez un jeu, ou vérifiez le réseau d'une borne en ligne |
| L'écran tactile ne confirme pas | USBGuard le bloque : un autre exemplaire ou un autre port que la règle de l'image ([Périphériques USB](image.md#usb-devices)) |
| La borne redémarre sur la version précédente | La nouvelle image a échoué 3 fois à démarrer : `boots.txt` d'un export de maintenance ([Si la nouvelle version échoue](update.md#if-the-new-version-fails)) |
| La borne ne démarre pas | Prenez la borne de secours ; vérifiez les réglages du BIOS et le disque de la borne en panne |

## Données sur la borne { #data-on-the-kiosk }

La partition de données (`/var`) d'une borne contient les rapports
d'analyse (noms et empreintes des fichiers des utilisateurs), les journaux
et la quarantaine (copies de logiciels malveillants). Elle n'est **pas
chiffrée** : qui prend le disque peut la lire
([Modèle de menace](threat-model.md#what-pandorabox-does-not-cover)).

- Décidez combien de temps les rapports et la quarantaine sont gardés, et
  inscrivez la borne au registre des traitements de l'organisation quand
  les rapports nomment les fichiers de personnes. Les journaux changent de
  fichier chaque mois et sont gardés 12 mois
  ([Journaux](logs.md#what-the-kiosk-logs)).
- Une borne de transfert ne garde ni rapports ni quarantaine sur son disque
  ([Une borne volée](airgap.md#a-stolen-kiosk)).
- Une borne est un lieu où des logiciels malveillants sont conservés : ne
  la laissez pas quitter l'organisation sans effacer son disque.

## Retrait d'une borne { #decommissioning }

1. Rapportez les journaux avec une clé de maintenance, s'ils sont encore
   utiles.
2. Effacez le disque (`blkdiscard`, ou un écrasement complet d'un disque
   dur) : il contient la quarantaine, les rapports, et les secrets d'une
   borne en ligne.
3. Dans le BIOS : Security → Secure Boot → **Restore Factory Keys**, et
   retirez le mot de passe superviseur, avant de rendre l'ordinateur à un
   autre usage.
4. Pour une borne en ligne ou une borne de transfert : révoquez ses secrets
   (Auth-Key abuse.ch, clé SSH sur le serveur) quand les autres bornes ne
   les partagent pas, et fermez ses flux réseau.
5. Retirez-la de la liste des bornes.
