# Fonctionnement de l'image

Comment l'image de la borne est faite et protégée. Pour la construire, la
tester, l'installer et la maintenir, voir
[Construction de l'image](build.md), [Test avec QEMU](vm.md),
[Installation initiale](install.md) et
[Mises à jour du système](update.md).

L'image est construite avec [mkosi](https://github.com/systemd/mkosi) à
partir des paquets Debian 13 (trixie).

## Partitions { #partitions }

L'image disque a deux emplacements système (mises à jour A/B) et une
partition de données :

| Partition | Système de fichiers | Contenu |
|---|---|---|
| ESP | vfat, 512 Mo | systemd-boot et les UKI (`pandora-box_<version>.efi`), tous signés |
| root, emplacement A (`pandora-box_<version>`) | EROFS, lecture seule, 1 Go | tout le système sauf `/var` (environ 400 Mo utilisés) |
| root-verity, emplacement A | 64 Mo | arbre de hachage dm-verity du système de fichiers racine |
| root-verity-sig, emplacement A | 16 Ko | signature du hash racine |
| root, root-verity, root-verity-sig, emplacement B (`_empty`) | mêmes tailles | la version suivante (mises à jour A/B) |
| données (`pandora-box-data`) | ext4, 1 Go dans l'image | `/var` : rapports d'analyse, quarantaine, journaux, jeux de signatures signés (clamd y lit ses bases) |

La version de l'image est la date et l'heure de sa construction, en UTC,
comme le numéro de série d'un jeu de signatures : `20261005143700`
(`image/build.sh` la fixe, `--image-version=N` la remplace). Elle figure dans
`/etc/os-release` (`IMAGE_VERSION`), dans les étiquettes de ses partitions
(`pandora-box_<version>`, `_verity`, `_veritysig` : 36 caractères au
maximum) et dans le nom de son UKI.

Le système de fichiers racine est en lecture seule par conception (EROFS ne
peut pas du tout être écrit) : le système et sa configuration ne changent
qu'avec une nouvelle image. Tout ce que la borne écrit est dans `/var`. La
partition de données est la dernière : à chaque démarrage, `systemd-repart`
l'agrandit pour remplir le disque (`/usr/lib/repart.d/20-var.conf`), puis
`systemd-growfs` agrandit son système de fichiers (`x-systemd.growfs` dans
`/etc/fstab`), si bien que l'image peut être écrite sur un disque de
n'importe quelle taille. Comme `/etc` est en lecture seule, l'identifiant de
machine est régénéré à chaque démarrage (un nouveau dossier de journal par
démarrage, dans les limites de taille de journald).

L'image contient :

- le noyau, systemd et udev, Python 3 et clamd (`clamav-daemon`), sans
  service réseau : `systemd-networkd`, `systemd-resolved`, freshclam et
  l'analyse à l'accès de ClamAV sont désactivés (`10-pandora-box.preset`) ;
- pandora-box dans `/usr/lib/pandora-box` (`/usr/bin/pandora-box`), sa
  configuration dans `/etc/pandora-box/pandora-box.toml` et son service, qui
  dessine l'interface graphique tactile sur la première console
  (framebuffer, voir [Écran](#screen)) ;
- ni programme `login` ni mot de passe root : aucune session interactive
  n'est possible.

## Signature, Secure Boot et dm-verity { #signing-secure-boot-and-dm-verity }

La chaîne de démarrage est vérifiée du firmware jusqu'à chaque bloc du
système :

1. avec Secure Boot, le firmware ne démarre systemd-boot que s'il est signé
   avec une clé de sa base `db`, et systemd-boot ne démarre qu'une UKI
   signée ;
2. l'UKI contient le noyau, l'initrd et la ligne de commande du noyau, qui
   contient le hash racine dm-verity (`roothash=`) : le modifier casse la
   signature ;
3. le système de fichiers racine est ouvert avec dm-verity : chaque bloc lu
   est vérifié par rapport à l'arbre de hachage, dont la racine est ce hash.
   Un bloc modifié ne peut pas être lu (erreur d'entrée-sortie,
   « data block ... is corrupted » dans le journal du noyau) ;
4. avec Secure Boot, le noyau Debian active son mode lockdown
   (`integrity`) : même root ne peut pas modifier le noyau en cours
   d'exécution.

`/var` n'est pas protégé par dm-verity : il contient les données de la
borne, jamais de programmes ni de configuration.

L'image est signée avec `image/mkosi.key` et `image/mkosi.crt` (systemd-boot,
UKI, hash racine). Quand ils n'existent pas, `image/build.sh` génère une
paire de clés de **développement**, valable 10 ans, qui ne quitte jamais
l'ordinateur du développeur (ignorée par git). Une borne ne doit faire
confiance qu'aux clés de publication du projet, qui ne sont pas encore
définies : elles seront gardées hors du dépôt, et mkosi peut signer avec une
clé dans un jeton matériel (`--secure-boot-key-source=provider:pkcs11`).

L'image fait aussi confiance aux jeux de signatures signés avec
`image/update.key` : sa clé publique `image/update.pem` est installée dans
`/usr/share/pandora-box/keys/` (sous dm-verity). `image/build.sh` génère une
paire de développement quand elles n'existent pas ; le profil de test signe
son jeu de signatures avec elle. Voir [Signatures](signatures.md).

Sur une borne, le certificat est enrôlé dans le firmware à la place des clés
Microsoft (PK, KEK et db), pour qu'elle ne démarre rien d'autre. L'ESP
contient les clés au format attendu par le firmware (`loader/keys/auto/`) :
avec le firmware en mode configuration de Secure Boot (clés effacées dans la
configuration du firmware), systemd-boot les enrôle au premier démarrage
(`secure-boot-enroll force`). N'enrôler que le certificat du projet refuse
aussi les option ROM signées par Microsoft : un ordinateur dont l'affichage
ou le contrôleur de disque en a besoin (une carte graphique, par exemple) ne
la démarrerait pas. Les machines virtuelles enrôlent plutôt le certificat
avec `virt-fw-vars` (`image/vm/machine.py`).

systemd-boot n'a pas de menu (`/efi/loader/loader.conf`, `timeout
menu-disabled`) : il démarre l'entrée par défaut, la version la plus récente
qui n'est pas marquée mauvaise, et ne lit pas le clavier. Un clavier branché
sur la borne ne peut ni choisir une autre version, ni modifier la ligne de
commande du noyau (refusé avec Secure Boot de toute façon), ni éteindre la
machine, ni redémarrer dans la configuration du firmware. L'ESP ne fait pas
partie des mises à jour de l'image : ce fichier reste tel qu'installé.

## Écran { #screen }

La borne dessine son interface graphique dans le framebuffer du pilote
graphique (`/dev/fb0`), sans serveur d'affichage ni navigateur, et met la
première console (`tty1`) en mode graphique pour que le noyau n'écrive pas
de texte par-dessus : voir [Interface](interface.md). L'écran du matériel de
référence est un Waveshare 7 pouces HDMI LCD (1024x600). Le firmware du
ThinkCentre démarre en 1024x768, et le pilote Intel garde ce mode : le bas
de l'interface serait hors de l'écran. La ligne de commande du noyau règle
donc le mode de l'écran, `video=1024x600M@60` (timings CVT, comme les
documente Waveshare) ; avec un autre écran, modifiez-le dans
`image/mkosi.conf`. Le pilote Intel garde tout de même le framebuffer du
firmware, assez grand pour ce mode : la borne ne dessine que sa partie
visible, de la taille de `video=`, et suit un changement de taille du
framebuffer. Elle journalise la taille et le format de pixel pour lesquels
elle dessine (`display_started`).

L'interface curses (`kiosk.interface = "curses"`, mode administrateur)
écrit plutôt du texte sur la console : elle réduit de la même façon la
console à l'écran de `video=` (police 8x16 : 37 lignes, 128 colonnes), et
journalise la taille pour laquelle elle dessine (`display_started`,
`display_resized`).

## Périphériques USB { #usb-devices }

Une borne ne doit utiliser que des périphériques de stockage USB : une clé
qui est aussi un clavier (BadUSB) pourrait taper des commandes, un
adaptateur réseau pourrait ouvrir un réseau.

- **USBGuard** (`/etc/usbguard/rules.conf`) autorise les concentrateurs et
  les périphériques dont toutes les interfaces sont du stockage de masse ;
  il bloque tous les autres, y compris une clé qui a une interface de
  stockage et une autre. Les périphériques bloqués sont listés dans
  `/var/log/usbguard/usbguard-audit.log`, et la borne signale chacun dans
  son propre journal par un événement `usb_device_blocked`, envoyé aussi au
  SIEM ([Périphériques USB refusés](logs.md#refused-usb-devices)).
- **Aucun périphérique n'est autorisé avant le démarrage d'USBGuard** : la
  ligne de commande du noyau fixe `usbcore.authorized_default=0`. Si
  USBGuard ne démarre pas, aucun périphérique USB n'est utilisable.
- **Pilotes retirés de l'image** (`KernelModulesExclude=` dans
  `image/mkosi.conf`) : adaptateurs réseau USB, sans-fil, Bluetooth,
  adaptateurs série et modems USB, ainsi que les pilotes staging et
  batman-adv, qui ramèneraient les modules sans-fil comme dépendances. De
  tels périphériques n'ont pas de pilote même s'ils étaient autorisés.
- **L'USB HID est gardé pour l'écran tactile** du matériel de référence, un
  Waveshare 7 pouces HDMI LCD (C), autorisé par sa propre règle :

    ```
    allow id 0eef:0005 serial "220211" name "WS170120" with-interface 03:00:00 via-port "1-8"
    ```

    son contrôleur tactile USB (eGalax) avec son unique interface HID
    générique (un clavier a `03:01:01`), sur le port interne du boîtier, cet
    exemplaire uniquement. Un périphérique qui copie ses identifiants sur un
    autre port, ou qui ajoute une interface clavier, est bloqué ; tout
    clavier et toute souris aussi. Pour un autre exemplaire ou un autre
    port : adaptez la règle d'après la ligne que montre le journal d'audit
    quand il est bloqué. Le noyau (`mousedev`) transforme un appui en clic
    gauche sur `/dev/input/mice`, que la borne lit pour confirmer un
    nettoyage.

    L'image de test autorise la tablette tactile de la machine virtuelle
    (QEMU `usb-tablet`, même interface) par sa propre règle
    (`/etc/usbguard/rules.d/50-vm-test.conf`) : le test confirme un
    nettoyage par un appui. Le clavier des machines virtuelles n'est pas un
    périphérique USB.

### Souris à la place de l'écran tactile { #mouse-instead-of-a-touchscreen }

Avec un écran qui n'est pas tactile, une souris confirme un nettoyage : le
noyau regroupe toutes les souris dans `/dev/input/mice`, et un clic gauche
est lu comme un appui. Rien ne change dans la borne, mais USBGuard bloque
toute souris : autorisez la vôtre par sa propre règle dans
`image/mkosi.extra/etc/usbguard/rules.conf`, puis reconstruisez l'image et
réécrivez-la. Le système de fichiers racine est en lecture seule et vérifié
par dm-verity : modifier une règle sur la borne elle-même n'est pas possible.

1. Branchez la souris sur la borne et relevez sa ligne dans
   `/var/log/usbguard/usbguard-audit.log`, ou dans `usb-devices.txt` d'un
   [export de maintenance](logs.md#maintenance-device) : son `id`, son
   `name`, son `serial` (si elle en a un) et son port.
2. Ajoutez une règle qui autorise cette souris, avec une seule interface de
   souris (`03:01:02`), sur le port où elle est branchée, par exemple :

    ```
    allow id 046d:c077 name "USB Optical Mouse" with-interface equals { 03:01:02 } via-port "1-5"
    ```

    Ajoutez `serial "..."` si la souris a un numéro de série : la règle
    n'autorise alors que cet exemplaire.

Choisissez une souris filaire simple. Beaucoup de souris sans fil
(récepteurs partagés avec un clavier) et de souris de jeu ont aussi une
interface clavier (`03:01:01`) : `equals` les garde bloquées, pour qu'un
clavier ne puisse pas passer pour une souris. Gardez la souris sur le port de
la règle. Modifiez le fichier avec des fins de ligne LF : le build refuse un
fichier avec des fins de ligne CRLF.

## Durcissement du système { #system-hardening }

D'après les recommandations de configuration d'un système GNU/Linux de
l'ANSSI :

- **Réglages du noyau** (`/usr/lib/sysctl.d/90-pandora-box.conf`) : journaux
  et adresses du noyau masqués, pas de ptrace, pas de kexec, pas d'eBPF,
  d'espaces de noms utilisateur ni d'userfaultfd sans privilèges, io_uring
  désactivé, pas de SysRq, pas de core dumps, liens et FIFO protégés, ni
  routage IP ni redirections.
- **Ligne de commande du noyau** : mémoire initialisée à l'allocation et à
  la libération, pas de fusion des slabs, allocateur de pages et pile du
  noyau aléatoires, pas de vsyscall historique, pas de debugfs, lockdown en
  mode `confidentiality` (Secure Boot n'active que `integrity` : même root
  ne peut pas lire la mémoire du noyau), IOMMU en mode strict et pas de DMA
  avant le démarrage du noyau (attaques DMA par les ports).
- **Pare-feu** (`/etc/nftables.conf`) : chaque paquet est rejeté, en entrée
  comme en sortie, sauf sur l'interface de bouclage.
- **Aucune session** : pas de console de connexion sur les écrans (`getty@`
  et `getty-static` désactivés), pas de programme `login`, pas de mot de
  passe root, Ctrl-Alt-Suppr masqué.
- **Bac à sable de clamd** (`clamav-daemon.service.d/50-pandora-box.conf`) :
  pas de réseau, système en lecture seule, pas de périphérique, filtre
  d'appels système, `MemoryDenyWriteExecute` (le clamd de Debian interprète
  les signatures bytecode, sans JIT) ; il tourne sous l'utilisateur
  `clamav`.
- **Service de la borne** (`packaging/systemd/pandora-box.service`) :
  système en lecture seule, filtre d'appels système, capacités limitées. Il
  garde `AF_NETLINK` (événements udev), les capacités nécessaires pour
  lancer le bac à sable des processus d'analyse (espaces de noms,
  changement d'utilisateur, interface de bouclage des processus) et ne peut
  pas avoir `MemoryDenyWriteExecute` ni `RestrictSUIDSGID` : le premier
  s'appliquerait aussi aux processus YARA-X, qui compilent les règles en
  code natif, le second refuse un appel système dont bubblewrap a besoin.
- **Modules du noyau retirés** : protocoles réseau que la borne n'utilise
  jamais (DCCP, SCTP, RDS, TIPC) et FireWire, un autre moyen d'atteindre la
  mémoire de la borne, en plus des pilotes réseau USB, Bluetooth et Wi-Fi,
  et des pilotes NTFS et exFAT (lus en espace utilisateur, voir
  [Pilotes de systèmes de fichiers](#filesystem-drivers)). Les protocoles,
  FireWire, NTFS et exFAT sont aussi listés dans
  `/etc/modprobe.d/pandora-box.conf`, où les outils d'audit les cherchent.
- **Journal d'audit** (`/etc/audit/audit.rules`, auditd) : chargement de
  modules du noyau, montages (sauf ceux de systemd et de bubblewrap), chaque
  programme lancé, ptrace, changements de l'horloge, des jeux de signatures
  et des mises à jour de l'image en attente. Les règles sont verrouillées
  (`-e 2`) : les modifier demande un redémarrage. Elles sont chargées par
  `auditctl -R` (`augenrules` écrit dans `/etc`, en lecture seule). Le
  journal est dans `/var/log/audit/audit.log`, par exemple
  `ausearch -k signatures -i`.

Le profil de test inclut `lynis`, lancé par le test automatisé : indice de
durcissement 73, aucun avertissement. Ses suggestions restantes ne
s'appliquent pas à une borne sans session (politique de mots de passe,
bannières, outils de paquets, fail2ban) ou viendront plus tard
(journalisation distante, phase 5).

## Bac à sable des processus d'analyse { #scan-worker-sandbox }

Les processus d'analyse examinent des fichiers hostiles avec plusieurs
moteurs (libmagic, YARA-X, le client clamd...) : ils sont supposés
compromettables (`scan.sandbox`, `src/pandora_box/sandbox.py`).

- **Un moteur par processus** : un moteur compromis (un fichier piégé qui
  exploite YARA-X ou libmagic) ne peut pas falsifier le résultat d'un autre
  moteur. La borne calcule elle-même les empreintes de chaque fichier,
  interroge le processus de chaque moteur d'empreintes (MalwareBazaar,
  Hashlookup) avec les empreintes seulement, puis passe le fichier à un
  processus de chaque moteur de contenu (ClamAV, YARA-X), et combine
  elle-même leurs résultats ; un processus ne rapporte que le résultat de
  son propre moteur. Les moteurs de contenu ont chacun `scan.workers`
  processus, les moteurs d'empreintes un seul. `scan.workers = "auto"` (par
  défaut) analyse un fichier par processeur en même temps, autant que la
  mémoire le permet (1,5 Go pour clamd et le système, puis 256 Mo chacun,
  surtout pour les règles YARA) : 6 sur le ThinkCentre M720q (6 cœurs,
  8 Go), 1 ou 2 sur un ordinateur avec 2 Go.
- **Pas d'accès à la clé** : la borne ouvre chaque fichier de façon sûre
  (aucun lien suivi, le fichier de l'inventaire) et passe le descripteur
  ouvert aux processus des moteurs de contenu, qui n'ouvrent jamais un
  fichier de la clé ; les processus des moteurs d'empreintes ne reçoivent
  jamais le fichier.
- **bubblewrap** : nouveaux espaces de noms PID, IPC, UTS, cgroup et réseau
  (aucune interface réseau à part le bouclage) ; un système de fichiers qui
  ne contient que `/usr`, quelques fichiers de `/etc`, les dossiers de
  signatures des moteurs activés (en lecture seule), le cache de YARA-X et
  le dossier du socket de clamd : ni point de montage de la clé, ni
  rapports, quarantaine, journaux ou configuration.
- **Utilisateur dédié** `pandora-box-scan` (`packaging/sysusers/`), adopté
  par `setpriv` : aucune capacité, aucun groupe supplémentaire,
  `no_new_privs`.
- **Filtre d'appels système** (`src/pandora_box/seccomp.py`), installé une
  fois les moteurs chargés : ni exécution de programme, ni débogage, ni
  montage, ni espace de noms, ni eBPF, ni module du noyau, ni io_uring, ni
  socket réseau...
- **Réponses non fiables** : les processus répondent en JSON (jamais en
  pickle), avec une taille limitée et validée
  (`src/pandora_box/protocol.py`) ; le chemin et la taille du fichier
  viennent toujours de la borne. Une réponse malformée tue le processus et
  le fichier est déclaré en erreur.

bubblewrap tourne en root (le service de la borne), si bien que les espaces
de noms utilisateur sans privilèges restent désactivés.

Le test en machine virtuelle vérifie ces réglages et affiche l'exposition
des services mesurée par `systemd-analyze security` (de 0 à 10, plus c'est
bas, mieux c'est) : environ 1,6 pour clamd, 3,8 pour la borne (qui lance le
bac à sable des processus d'analyse), 2,8 pour USBGuard.

## Pilotes de systèmes de fichiers { #filesystem-drivers }

Un pilote de système de fichiers du noyau analyse les structures écrites sur
la clé : une faille de ce pilote, sur une clé forgée, exécute du code dans
le noyau, avant tout bac à sable (les pilotes NTFS, exFAT et ext4 de Linux
font régulièrement l'objet de découvertes par fuzzing). NTFS, exFAT et ext4
sont donc lus par un pilote FUSE, dans le bac à sable des processus
d'analyse (`device.fuse`, `src/pandora_box/fuse.py`) :

| Système de fichiers | Pilote |
|---|---|
| vfat | noyau (son pilote le plus simple et le plus ancien) |
| exFAT | `exfat-fuse` |
| NTFS | `ntfs-3g` |
| ext4 | `fuse2fs` |

- **Aucun privilège** : la borne ouvre `/dev/fuse` et monte elle-même la
  connexion (`noexec,nosuid,nodev`, en lecture seule pour l'analyse) ; le
  pilote ne fait que la servir. Les pilotes libfuse 3 prennent la connexion
  montée comme point de montage `/dev/fd/N` ; ntfs-3g embarque sa propre
  bibliothèque FUSE, qui monte elle-même : une bibliothèque préchargée dans
  ntfs-3g seulement (`packaging/fuse/premounted.c`) lui donne la connexion.
  `fusermount3` n'est pas setuid.
- **Bac à sable** : le bac à sable bubblewrap des processus d'analyse, sous
  l'utilisateur `pandora-box-scan` avec le groupe du périphérique bloc, sans
  capacités. Le périphérique bloc est son seul périphérique ; il voit
  `/usr`, les noms d'utilisateur et rien de la borne.
- **Chien de garde** : un pilote planté fait échouer tous les accès ; un
  pilote dont les requêtes restent sans réponse alors que la clé ne lit
  rien est tué après `device.command_timeout`. Dans les deux cas, la clé est
  déclarée non vérifiée. Une fois la clé démontée, la borne attend la fin du
  pilote : il écrit ses dernières modifications (nettoyage).
- **Pilotes du noyau retirés** : l'image n'a pas les modules NTFS et exFAT
  du noyau ; ext4 reste pour la partition de données.

Un pilote compromis ne prend plus le contrôle de la borne, mais il peut
encore cacher des fichiers à l'analyse. fuse2fs refuse une clé ext4 dont le
journal doit être rejoué, comme le noyau.

## Image noyau unifiée { #unified-kernel-image }

L'UKI (environ 40 Mo) contient le noyau, l'initrd de l'image
(`image/mkosi.images/initrd/`, sans la base matérielle d'udev, les
conversions de jeux de caractères, Perl, la documentation et networkd) et un
initrd de modules du noyau. Celui-ci ne contient que ce qui monte le
système de fichiers racine (`KernelModulesInitrdInclude=` dans
`image/mkosi.conf`) : contrôleurs de disque (NVMe, SATA, Intel VMD, eMMC,
virtio), dm-verity, EROFS et CRC32C, qu'EROFS charge par son nom. Les autres
modules sont chargés depuis le système de fichiers racine. Un ordinateur
dont le contrôleur de disque n'est pas dans cette liste ne trouve pas son
système de fichiers racine : ajoutez-y son module.
