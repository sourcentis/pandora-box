# Test avec QEMU

L'image est testée dans une machine virtuelle QEMU/KVM, sans le matériel de
référence : firmware UEFI (OVMF) avec Secure Boot, un contrôleur USB 3 vide,
et des clés USB insérées et retirées pendant que la borne fonctionne, ce qui
déclenche les mêmes événements udev qu'un vrai périphérique. QEMU tourne
dans le conteneur de construction : seul Docker est nécessaire, et
`/dev/kvm` pour la vitesse.

## En bref { #in-short }

```sh
image/build-test.sh   # l'image de test et trois mises à jour de l'image
image/vm.sh test      # test automatisé, environ 7 minutes avec KVM
image/vm.sh run       # machine interactive, écran de la borne en VNC sur localhost:0
```

> [!NOTE]
> Les échantillons malveillants ne doivent jamais être copiés ailleurs que
> dans des images de clés, jamais sur le poste de développement.

## Profil de test { #test-profile }

`--profile test` construit `pandora-box-test.raw`, pour les tests en machine
virtuelle uniquement, **jamais pour une borne**. Il inclut le profil
[`online`](build.md#profile-online), et ajoute :

- un jeu de signatures réservé aux tests, généré à partir de
  `image/vm/corpus.py`, signé avec la clé de mise à jour de développement et
  installé (numéro de série 1) : une base ClamAV qui détecte le fichier de
  test EICAR, une base MalwareBazaar, un filtre Hashlookup et une règle
  YARA, chacun détectant un fichier de la clé de test ;
- la configuration correspondante, avec tous les moteurs activés, et des
  mises à jour en ligne depuis `http://10.0.2.2:8080/` (le conteneur de
  construction, vu depuis le réseau utilisateur de QEMU) ;
- un shell root sans mot de passe sur la console virtio (`hvc0`), et les
  messages du noyau sur le port série ;
- `kiosk-screen`, qui affiche les textes de l'écran de la borne dans ce
  shell (l'interface graphique les journalise, événements `display_screen`
  au niveau DEBUG) ;
- une règle USBGuard pour la tablette tactile de la machine virtuelle (QEMU
  `usb-tablet`, `/etc/usbguard/rules.d/50-vm-test.conf`) : le test confirme
  un nettoyage par un appui. Le clavier des machines virtuelles n'est pas un
  périphérique USB.

`image/build-test.sh` construit l'image de test (version 1) et trois mises à
jour signées vers des versions plus récentes (`image/mkosi.output/updates/`),
pour le test des mises à jour A/B.

## Test automatisé { #automated-test }

```sh
image/build-test.sh
image/vm.sh test
```

Le test démarre l'image de test dans QEMU (KVM quand `/dev/kvm` est
accessible en écriture, sinon une émulation beaucoup plus lente), avec un
firmware UEFI (OVMF) où le certificat de signature de l'image est enrôlé
(Secure Boot activé), et un contrôleur USB 3 vide. Il joue tout le parcours
de l'utilisateur, par QMP et par le shell de la console virtio :

1. la borne démarre avec ses cinq moteurs et le jeu de signatures 1,
   vérifié, et aucune unité systemd n'échoue ;
2. les processus d'analyse (un moteur chacun) tournent dans leur bac à sable
   (utilisateur, capacités, `no_new_privs`, seccomp, espace de noms réseau,
   aucun périphérique ni donnée de la borne dans leur système de fichiers) ;
   Secure Boot est activé, le noyau est verrouillé et le système de fichiers
   racine est sur dm-verity ;
3. le système de fichiers racine est en EROFS, en lecture seule, et `/var` a
   été agrandi pour remplir le disque de 8 Go de la machine ;
4. une clé USB émulée (une image disque vfat contenant le corpus) est
   insérée, ce qui déclenche les mêmes événements udev qu'un vrai
   périphérique ;
5. chaque fichier reçoit le verdict attendu du moteur attendu ;
6. le nettoyage est confirmé par un appui sur l'écran de la borne ; les
   fichiers infectés sont mis en quarantaine (vérifiés par leur SHA-256) et
   supprimés de la clé, qui est éjectée ;
7. la clé est retirée : il ne reste que les fichiers sains ;
8. la clé nettoyée est insérée à nouveau et déclarée saine ;
9. des clés des autres systèmes de fichiers passent par la même analyse et
   le même nettoyage, puis sont déclarées saines : exFAT, NTFS, ext4 (ses
   fichiers privés à leur propriétaire, comme sur la clé d'un utilisateur
   Linux), chacune lue par son pilote FUSE, et une clé avec une table de
   partitions MBR et une partition vfat ; une clé en EROFS (un système de
   fichiers que le noyau monte, mais non autorisé) est refusée ; une clé
   vfat avec une chaîne de clusters coupée et une clé ext4 dont les
   descripteurs de groupe sont écrasés sont montées, mais un fichier ou les
   dossiers ne peuvent pas être lus : la clé est déclarée non vérifiée
   (`image/vm/keys.py` ; exFAT et NTFS n'ont pas d'outil qui écrit des
   fichiers sans les monter : elles sont formatées dans le conteneur, puis
   remplies par les pilotes FUSE de la machine, la borne arrêtée) ; une clé
   de 4000 fichiers retirée pendant son analyse est un comportement suspect
   (`device_suspicious_behavior`, `removed`) : non vérifiée, l'écran
   `key_changed` affiché, le comportement dans son rapport ;
10. une clé de mise à jour des signatures avec un jeu plus récent (numéro de
    série 2) est installée, les moteurs sont rechargés et le nouvel
    échantillon qu'il détecte est trouvé ; un jeu modifié, un jeu signé avec
    une autre clé et un jeu plus ancien sont refusés ; un jeu plus récent
    publié sur un serveur HTTP par le test est téléchargé par le service de
    mise à jour (seulement son fichier modifié), installé et chargé par la
    borne au repos, et seul l'utilisateur du service de mise à jour peut
    ouvrir une connexion réseau (seul systemd-timesyncd envoie des requêtes
    NTP) ; les entrées du journal de la borne sont envoyées à un récepteur
    syslog du test (`[siem]`), par l'utilisateur de l'export SIEM, qui ne
    peut pas lire les rapports ; avec la copie vers un serveur activée
    (`[airgap]`, un serveur SFTP du test), les fichiers sains d'une clé sont
    copiés par l'utilisateur du service de copie, la clé garde ses fichiers
    malveillants et reçoit son identifiant, puis un fichier retiré de la clé
    est supprimé du serveur ; un clavier et un adaptateur réseau USB
    émulés sont bloqués par USBGuard (aucun périphérique d'entrée, aucune
    interface réseau), chacun expliqué à l'écran jusqu'à son retrait ; une
    clé USB qui est aussi un clavier, émulée dans la machine comme un gadget
    USB (`dummy_hcd`, `libcomposite` : une fonction de stockage de masse et
    une fonction clavier), est bloquée en entier, ni montée ni analysée,
    affichée sur l'écran `refused_composite` et consignée comme
    `usb_device_blocked` avec `composite` ; les pilotes exclus ne sont pas
    dans l'image ; les
    réglages du noyau, le pare-feu et les bacs à sable des services sont en
    place ;
11. après un redémarrage, les rapports d'analyse sont toujours là, le
    système de fichiers racine est inchangé et le jeu de signatures 5 est
    vérifié au démarrage ; une touche pressée pendant le démarrage du
    firmware et du chargeur de démarrage n'ouvre pas le menu du chargeur ;
12. une clé de mise à jour de l'image vers la version 2 est insérée : la
    borne l'installe dans l'emplacement libre et redémarre, la version 2
    démarre depuis l'emplacement B et est conservée (son UKI perd son
    compteur de démarrages), avec les mêmes données ; la version 3, publiée
    sur un serveur HTTP par le test, est téléchargée et installée par le
    service de mise à jour, puis la borne au repos redémarre dessus et elle
    est conservée ; enfin une version 4 dont le système de fichiers racine
    est modifié est installée depuis une clé : elle rate 3 démarrages
    (dm-verity, l'initrd redémarre) et systemd-boot revient à la version 3.

Deux autres machines démarrent la même image :

- avec un bloc du système de fichiers racine modifié sur le disque (un
  fichier témoin de l'image de test) : il ne peut pas être lu et le noyau
  signale la corruption ;
- avec un firmware qui fait confiance à une autre clé : le firmware refuse
  systemd-boot (« Access Denied ») et rien ne démarre.

Le test lance aussi `lynis` (indice de durcissement 73, aucun
avertissement) et affiche l'exposition des services mesurée par
`systemd-analyze security`.

L'image construite n'est jamais modifiée : la machine écrit dans une
nouvelle surcouche de disque (`system.qcow2`) à chaque démarrage. Le test
prend environ 7 minutes avec KVM. `image/vm.sh test --workdir DIR` garde
dans `DIR` les journaux de la console série, les journaux de QEMU et les
images des clés, et le journal de la borne (`kiosk.log`) quand le test
échoue.

## Machine interactive { #interactive-machine }

```sh
image/vm.sh run                                      # image de test
image/vm.sh run image/mkosi.output/pandora-box.raw   # image de production
```

L'écran de la borne est affiché en VNC, écran `:0` (port 5900), par exemple
avec `gvncviewer localhost:0` (la plupart des clients lisent `hôte:N` comme
un numéro d'écran, port 5900 + N) ; `kiosk-screen` l'affiche aussi dans le
shell de l'image de test. Le terminal montre ce shell (console virtio), pas
la borne, et, après `Ctrl-A C`, le moniteur QEMU ; `Ctrl-A X` arrête la
machine.

Une image de production n'a pas de jeu de signatures : elle affiche
`NO VALID SIGNATURES` jusqu'à l'insertion d'une clé de mise à jour des
signatures, comme une borne neuve
([Installation initiale](install.md#first-signature-set)).

### Clés de test { #test-keys }

Une clé de test est créée dans `image/vm/work/usbkey.img` ; insérez-la et
retirez-la depuis le moniteur QEMU :

```
(qemu) drive_add 0 if=none,id=key,format=raw,file=/src/image/vm/work/usbkey.img
(qemu) device_add usb-storage,bus=xhci.0,drive=key,id=usbkey,removable=on
(qemu) device_del usbkey
```

Les chemins sont vus depuis le conteneur, où le dépôt est monté sur `/src`.
N'importe quelle image disque peut servir de clé.

### Vraies clés USB { #real-usb-keys }

Une clé USB branchée sur cet ordinateur peut être transmise à la machine.
Listez les périphériques de stockage USB de cet ordinateur, avec leur port
(`BUS-PORT`) et leur identifiant (`VENDOR:PRODUCT`) :

```sh
image/vm.sh usb
```
```
1-4  abcd:1234  General UDisk
    sda     3,8G
    └─sda1  3,7G vfat   /media/didier/6B20-F9DE
```

Démarrez ensuite la machine avec `--usb`, suivi d'un port, qui transmet
toute clé branchée sur ce port, comme le port USB d'une borne, ou d'un
identifiant, qui transmet ce modèle de clé sur n'importe quel port :

```sh
image/vm.sh run --usb 1-4
```

QEMU attache la clé à la machine dès qu'elle est branchée (ou tout de suite
si elle l'est déjà) et la retire à cet ordinateur : son pilote noyau est
détaché. Avant de démarrer la machine, démontez la clé
(`udisksctl unmount -b /dev/sda1`) et désactivez le montage automatique des
périphériques USB du bureau, pour que cet ordinateur ne monte jamais une clé
destinée à la borne. `--usb` peut être donné plusieurs fois. Sous GNOME :

```sh
gsettings set org.gnome.desktop.media-handling automount false
gsettings set org.gnome.desktop.media-handling automount-open false
# après les tests : les mêmes commandes avec "true"
```

QEMU tourne alors en root dans le conteneur, avec accès aux périphériques
USB de cet ordinateur et à son réseau (pour recevoir les événements udev des
clés branchées ensuite) ; l'écran de la borne est sur `localhost:5900` comme
avant.
