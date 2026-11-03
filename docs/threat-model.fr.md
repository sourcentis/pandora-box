# Modèle de menace

Ce que PandoraBox protège, contre qui, comment, et ce qu'il ne couvre pas. Il
décrit l'image de la borne construite à partir de ce dépôt, sur le matériel
validé, installée comme dans [Installation initiale](install.md).

## En bref { #in-short }

Une borne reçoit des clés USB d'origine inconnue, analyse leurs fichiers avec
plusieurs moteurs et supprime les fichiers dangereux avant que les clés ne
soient utilisées sur un poste de travail. Elle part du principe que **toute
clé est hostile** : pas seulement ses fichiers, mais aussi son système de
fichiers et le périphérique USB lui-même. Tout ce qui lit la clé est
confiné, le système ne peut pas être modifié sans les clés de publication,
et la borne prévient l'utilisateur quand elle n'a pas pu vérifier une clé
entièrement.

PandoraBox réduit le risque ; il ne le supprime pas. Un fichier qu'aucun
moteur ne détecte est déclaré sain, et une clé au micrologiciel malveillant
peut montrer d'autres fichiers au poste de travail. Gardez les protections
des postes.

## Biens à protéger { #assets }

| Bien | Pourquoi |
|---|---|
| Le verdict montré à l'utilisateur | Une clé déclarée saine est utilisée sur un poste : un « sain » erroné est la principale défaillance |
| L'intégrité du système de la borne | Une borne compromise pourrait déclarer toutes les clés saines, ou infecter les clés qu'elle analyse |
| Les jeux de signatures | Des signatures anciennes ou falsifiées ne détectent rien |
| Les clés de publication (Secure Boot, mise à jour) | Qui les détient décide de ce qu'une borne démarre et accepte |
| Rapports d'analyse, journaux et quarantaine | Noms et empreintes des fichiers des utilisateurs, copies de logiciels malveillants |
| Les postes de travail et le réseau derrière la borne | Ce que la borne doit protéger |

## Attaquants { #attackers }

| Attaquant | Moyens | But |
|---|---|---|
| **Un utilisateur, sans le savoir** | Une clé infectée ailleurs | Aucun : le cas le plus fréquent, et la raison d'être de la borne |
| **Une clé forgée** | Fichiers malveillants, système de fichiers, table de partitions ou descripteurs USB forgés, un périphérique qui n'est pas un stockage (BadUSB) | Faire passer un logiciel malveillant pour sain ; prendre le contrôle de la borne |
| **Un passant** | Accès physique à la borne pendant quelques minutes : ports d'analyse, écran, boîtier | Modifier le système, lire les rapports et la quarantaine |
| **Le réseau** | Une borne en ligne échange avec des serveurs de mise à jour, NTP et un SIEM | Falsifier des signatures, retarder les mises à jour, lire les journaux |
| **La chaîne d'approvisionnement** | Paquets Debian, sources de signatures (ClamAV, YARA Forge, abuse.ch, CIRCL), machine de construction | Introduire une porte dérobée dans une image ou un jeu de signatures |

Les administrateurs qui construisent les images et détiennent les clés de
publication sont de confiance.

## Frontières de confiance { #trust-boundaries }

```
 Clé USB (hostile)
   │  descripteurs USB ────────► USBGuard : stockage de masse seulement, écran tactile par sa règle
   │  table de partitions, vfat ► noyau de la borne
   │  NTFS, exFAT, ext4 ───────► pilote FUSE, en bac à sable (pandora-box-scan, sans capacité)
   ▼
 processus de la borne (root, service systemd durci)
   │  liste, ouvre et calcule l'empreinte des fichiers ; n'interprète jamais leur contenu
   │  passe chaque fichier par un descripteur, reçoit du JSON validé
   ▼
 processus d'analyse, un par moteur, en bac à sable (bubblewrap, sans réseau, seccomp)
   libmagic, YARA-X, heuristiques, client clamd  ─►  clamd (son propre bac à sable, sans réseau)

 Jeux de signatures, mises à jour de l'image, demandes de maintenance (hostiles avant vérification)
   └─► signature Ed25519 vérifiée avec les clés du système de fichiers racine en lecture seule
 Démarrage : micrologiciel ─► systemd-boot ─► image noyau signée (Secure Boot) ─► racine sur dm-verity
```

## Menaces et parades { #threats-and-mitigations }

### Une clé forgée contre la borne { #a-crafted-key-against-the-kiosk }

| Menace | Parades |
|---|---|
| Un périphérique USB qui est un clavier, un adaptateur réseau ou un port série (BadUSB) | USBGuard n'autorise aucun périphérique avant de démarrer, puis seulement le stockage de masse ; claviers et souris sont bloqués ; pas de pilotes réseau USB, Bluetooth, Wi-Fi ni série ([Périphériques USB](image.md#usb-devices)) ; chaque périphérique refusé est consigné et envoyé au SIEM (`usb_device_blocked`) |
| Un système de fichiers forgé qui exploite un pilote du noyau | NTFS, exFAT et ext4 sont lus par des pilotes FUSE dans le bac à sable, le noyau n'a pas de pilote NTFS ni exFAT ; seul vfat reste dans le noyau ([Pilotes de systèmes de fichiers](image.md#filesystem-drivers)) |
| Un fichier qui exploite un analyseur (libmagic, YARA-X, ClamAV) | Chaque moteur dans son propre processus, en bac à sable : sans réseau, sans périphérique, sans donnée de la borne, utilisateur dédié, filtre d'appels système ; clamd dans son propre bac à sable ; un processus ne rend que le résultat de son moteur, la borne combine les résultats ([Bac à sable des processus d'analyse](image.md#scan-worker-sandbox)) |
| Liens, fichiers spéciaux, arborescences profondes, clés énormes, bombes de décompression | L'inventaire ne suit jamais un lien et ne sort jamais du périphérique ; limites de taille, de nombre de fichiers et de profondeur ; au-delà, la clé n'est pas vérifiée |
| Écrire sur la clé pendant l'analyse, rejouer un journal ext4 | La clé est montée en lecture seule sur un périphérique bloc en lecture seule ; une clé ext4 dont le journal doit être rejoué est refusée |
| Un processus d'analyse ou un pilote qui plante ou se bloque | Délais et chiens de garde ; les fichiers concernés ne sont pas entièrement analysés et la clé est déclarée **non vérifiée**, jamais saine |
| Une clé qui se déconnecte d'elle-même pendant son analyse, pour revenir avec un autre contenu ou comme un autre périphérique | Le périphérique USB de la clé est vérifié pendant l'analyse : une clé retirée ou énumérée à nouveau est un comportement suspect, consigné et envoyé au SIEM (`device_suspicious_behavior`) ; la clé est **non vérifiée**, ni nettoyée ni copiée vers un serveur |
| Une clé échangée entre l'analyse et le nettoyage | Un fichier n'est supprimé que si son SHA-256 est toujours celui qui a été analysé |

### Un logiciel malveillant qui passe pour sain { #malware-passed-off-as-clean }

| Menace | Parades |
|---|---|
| Un logiciel malveillant inconnu d'un moteur | Cinq moteurs : ClamAV, YARA-X (YARA Forge), MalwareBazaar, Hashlookup, heuristiques ; un verdict malveillant de n'importe quel moteur l'emporte |
| Un fichier connu utilisé comme déguisement | Un résultat Hashlookup signifie « connu », pas « bénin » : les moteurs de contenu l'analysent quand même par défaut |
| Archives et documents chiffrés, fichiers au-delà des limites | Non analysables : signalés, et la clé n'est pas vérifiée (`scan.on_error = "block"`) |
| Documents avec macros ou contenu actif, programmes déguisés en documents | Déclarés suspects, supprimés comme les fichiers malveillants par défaut (`scan.suspicious = "block"`) |
| Signatures anciennes | Avertissements de fraîcheur à l'écran ; les jeux de signatures sont mis à jour hors ligne ou en ligne |

### Le système de la borne { #the-system-of-the-kiosk }

| Menace | Parades |
|---|---|
| Modifier le système sur le disque | Système de fichiers racine EROFS en lecture seule vérifié par dm-verity, son empreinte racine dans l'image noyau signée pour Secure Boot ; le micrologiciel ne fait confiance qu'au certificat de l'image ; un bloc modifié ne peut pas être lu |
| Démarrer autre chose | Mot de passe superviseur du BIOS, Secure Boot en mode personnalisé, pas de menu du chargeur d'amorçage, clavier non lu au démarrage ([Installation initiale](install.md)) |
| Se connecter | Pas de programme `login`, pas de mot de passe root, pas de console, Ctrl-Alt-Suppr masqué ; les journaux sortent par une demande de maintenance signée avec la clé de mise à jour |
| Installer une version plus ancienne ou falsifiée | Mises à jour de l'image et jeux de signatures signés avec la clé de mise à jour, et plus récents que ceux installés ; emplacements A/B avec retour automatique à la version précédente |
| Attaques du noyau depuis un processus compromis | Lockdown `confidentiality`, pas d'espaces de noms utilisateur sans privilèges, d'eBPF ni d'userfaultfd, modules du noyau inutiles retirés, IOMMU |

### Le réseau (bornes en ligne) { #the-network-online-kiosks }

| Menace | Parades |
|---|---|
| Signatures falsifiées ou rejouées par un serveur malveillant | Les jeux construits sur la borne à partir des sources sont vérifiés par les moteurs, puis signés avec une clé générée sur la borne ; les jeux publiés doivent porter une signature de confiance et un numéro de série plus récent ; les bases ClamAV sont aussi signées par Cisco Talos |
| D'autres échanges depuis un processus compromis | Pare-feu : tout est rejeté sauf DHCP, DNS, NTP, le service de mise à jour et l'export vers le SIEM, chacun autorisé par son utilisateur système ; la borne et les processus d'analyse n'ont pas de réseau |
| Lire les journaux exportés | Syslog sur TLS par défaut, avec les autorités de certification du SIEM |
| Un faux serveur qui reçoit les clés copiées, ou les lit en chemin (air-gap) | La clé d'hôte du serveur SSH doit figurer dans l'image, jamais acceptée à la première connexion ; le service de copie a son propre utilisateur et ne lit de la borne que les fichiers sains préparés pour lui |

### Chaîne d'approvisionnement et publication { #supply-chain-and-releases }

| Menace | Parades |
|---|---|
| Une version publiée altérée | Clés de publication sur deux YubiKey ; sommes de contrôle signées avec la clé de mise à jour ; constructions reproductibles : chacun peut reconstruire une version à partir de son tag et la comparer ([Versions publiées](release.md)) |
| Un paquet altéré | Paquets Debian de snapshot.debian.org, figés à la date du tag ; paquets Python figés par empreinte ; une nomenclature logicielle (CycloneDX) par version |

## Ce que PandoraBox ne couvre pas { #what-pandorabox-does-not-cover }

- **Les logiciels malveillants non détectés.** Un fichier nouveau ou ciblé
  qu'aucun moteur ne connaît est déclaré sain. La borne est une couche :
  gardez les protections des postes de travail.
- **Une clé au micrologiciel malveillant.** Une clé USB peut montrer un
  contenu à la borne et un autre au poste de travail, ou changer une fois
  éjectée par la borne. Aucune analyse ne peut l'exclure : seules des clés
  de confiance le peuvent.
- **La pile USB et stockage du noyau.** Le noyau analyse encore les
  descripteurs USB, la table de partitions et vfat. Une faille du noyau à cet
  endroit est hors de tout bac à sable.
- **Un pilote FUSE ou un moteur compromis** ne prend pas le contrôle de la
  borne, mais il peut cacher des fichiers ou rendre un mauvais verdict pour
  son propre moteur.
- **Le processus de la borne lui-même** tourne en root : il liste les
  fichiers, calcule leur empreinte et dessine leur nom à l'écran (FreeType) ;
  une faille à cet endroit n'est pas confinée.
- **L'accès physique au-delà des ports d'analyse.** Ouvrir le boîtier donne
  accès au disque : `/var` n'est pas chiffré (pas de TPM), les rapports, les
  journaux et la quarantaine peuvent donc être lus. Une borne qui copie vers
  un serveur n'en garde aucun, ni les répertoires des clés sur le serveur :
  voir [Une borne volée](airgap.md#a-stolen-kiosk). Un mot de passe du BIOS
  perdu, un contacteur d'ouverture débranché ou des ports internes
  accessibles annulent les protections du démarrage.
- **Les clés de publication.** Qui détient les YubiKey et leur code PIN peut
  construire une image que les bornes démarrent et acceptent.
- **L'horloge d'une borne hors ligne.** Les avertissements de fraîcheur
  reposent sur l'horloge de l'ordinateur.
- **Le déni de service.** Une clé peut rendre une analyse longue ou la faire
  échouer ; les limites et les délais gardent la borne disponible, la clé
  n'est pas vérifiée.
- **Les périphériques chiffrés, les smartphones et les périphériques MTP**
  ne sont pas pris en charge.

## Hypothèses { #assumptions }

- La borne exécute une image construite à partir de ce dépôt, avec des clés
  de publication gardées comme décrit dans [Versions publiées](release.md).
- Elle est installée comme dans [Installation initiale](install.md) : mot de
  passe du BIOS, Secure Boot avec le seul certificat de l'image, boîtier qui
  n'expose que les ports d'analyse.
- Ses signatures sont mises à jour régulièrement.
- Les utilisateurs apportent les clés nettoyées à des postes de travail qui
  gardent leurs propres protections.

Pour signaler une vulnérabilité, suivez la [politique de sécurité](https://github.com/sourcentis/pandora-box/blob/main/SECURITY.md).
