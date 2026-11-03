# Moteurs de détection et politique de verdict

Ce document décrit la chaîne d'analyse de la phase 1 : chaque moteur de
détection, ses fichiers de données et comment les obtenir pour le
développement, et la façon dont les verdicts sont décidés.

> [!WARNING]
> Les téléchargements de signatures décrits ici sont réservés au
> **développement** : ces fichiers ne sont pas signés. Une borne n'utilise
> qu'un jeu de signatures signé, vérifié à chaque démarrage et installé
> depuis une clé de mise à jour des signatures : voir
> [Signatures](signatures.md).

## Chaîne d'analyse { #pipeline }

Pour chaque clé insérée :

1. **Inventaire** (processus de la borne, métadonnées uniquement) : le point
   de montage est parcouru avec `os.scandir`/`lstat`. Les liens ne sont
   jamais suivis, le parcours ne quitte jamais la clé, et les FIFO, sockets
   et fichiers de périphérique sont listés comme ignorés. Les limites
   s'appliquent ici (voir [Limites](#limits)).
2. **Analyse** (processus d'analyse, un fichier à la fois par processus) :
    1. ouvrir le fichier en lecture seule, composant par composant avec
       `O_NOFOLLOW`, et vérifier que c'est le fichier régulier enregistré
       par l'inventaire ;
    2. calculer SHA-256, SHA-1 et MD5 en une seule lecture ;
    3. identifier le type avec libmagic (type MIME et description) ;
    4. lancer les **moteurs d'empreintes** (MalwareBazaar, puis
       Hashlookup) ;
    5. lancer les **moteurs de contenu** (ClamAV, YARA-X), sauf si le
       fichier est un fichier connu qu'aucun moteur d'empreintes ne signale
       (voir [Hashlookup](#hashlookup-circl)) ;
    6. combiner les résultats des moteurs en un verdict pour le fichier.
3. **Verdict de la clé**, nettoyage et **rapport d'analyse JSON**.

Les moteurs reçoivent un `FileInfo` (chemin relatif, taille, empreintes,
type MIME, description et un descripteur de fichier en lecture seule). Ils
ne rouvrent jamais le fichier par son chemin et ne gardent aucun état d'un
fichier à l'autre.

## Moteurs { #engines }

Tous les moteurs sont activés par défaut. Si un moteur activé ne peut pas
charger ses données, la borne refuse de démarrer
(`pandora-box --check-config` indique pourquoi). Au moins un moteur de
contenu (ClamAV ou YARA-X) est requis : les recherches d'empreintes seules
ne reconnaissent que des fichiers déjà connus.

Pour le développement, `pandora-box-signatures publish dev-signatures
--sources yara-forge,malwarebazaar,hashlookup` télécharge les règles YARA,
la liste MalwareBazaar et le filtre Hashlookup dans `./dev-signatures/`, les
vérifie, et affiche la configuration correspondante (un jeu non signé : voir
[Signatures](signatures.md)).

### MalwareBazaar { #malwarebazaar }

Liste hors ligne des empreintes SHA-256 de logiciels malveillants connus,
issue de [abuse.ch MalwareBazaar](https://bazaar.abuse.ch/). Une
correspondance est **malveillante** (détection
`MalwareBazaar.KnownMalware`).

- **Entrée** : l'export SHA-256 complet. Le télécharger nécessite une
  Auth-Key abuse.ch gratuite ([auth.abuse.ch](https://auth.abuse.ch/)),
  envoyée dans l'en-tête HTTP `Auth-Key`, depuis
  `https://bazaar.abuse.ch/export/txt/sha256/full/`. L'export est une
  archive zip contenant `full_sha256.txt` : un en-tête de commentaires `#`,
  puis une empreinte SHA-256 hexadécimale en minuscules par ligne. Le
  convertisseur accepte l'archive zip ou le fichier texte. Toute autre ligne
  est une erreur : un export malformé n'est jamais chargé en partie. En
  octobre 2026, l'export contenait 1,1 million d'empreintes, soit une base de
  37 Mo.
- **Conversion** :
  `python -m pandora_box.hashdb build full_sha256.zip malwarebazaar.sha256.bin`
  (`python -m pandora_box.hashdb info <base>` décrit une base).
- **Format** (`pandora_box/hashdb.py`) : un en-tête de 64 octets (nombre
  magique, version, nombre d'empreintes, date de création, SHA-256 de
  l'export source) suivi des empreintes de 32 octets, triées. Le fichier est
  projeté en mémoire et parcouru par dichotomie : un million d'empreintes
  occupent 32 Mo, partagés par les processus d'analyse via le cache de
  pages.
- **Configuration** : `[engines.malwarebazaar] database`.

### Hashlookup (CIRCL) { #hashlookup-circl }

Le filtre de Bloom des fichiers connus de
[CIRCL hashlookup](https://www.circl.lu/services/hashlookup/) (NSRL,
distributions Linux, dépôts de logiciels).

- **Données** : `https://cra.circl.lu/hashlookup/hashlookup-full.bloom`
  (environ 1 Go et 418 millions d'empreintes en octobre 2026, mis à jour
  chaque mois). Il contient le **SHA-1** de chaque fichier connu, en
  hexadécimal majuscule, au format bloom de DCSO.
- **Format** : le format de l'outil Go `bloom` de DCSO et de la bibliothèque
  Python `flor`. `flor` charge tout le tableau de bits en mémoire (1 Go par
  processus d'analyse), c'est pourquoi PandoraBox a son propre lecteur
  projeté en mémoire (`pandora_box/bloom.py`). Les tests vérifient qu'il
  donne les mêmes réponses que `flor`. Sur le vrai filtre du CIRCL, il donne
  les mêmes réponses que `flor`, reconnaît la plupart des binaires système
  de Debian, et répond « connu » pour environ 1 empreinte aléatoire sur
  10 000, comme attendu.
- **Connu ne veut pas dire sans danger** : les sources de hashlookup
  contiennent aussi des outils offensifs et à double usage. Une
  correspondance Hashlookup est rapportée comme le fait `known = true` avec
  le verdict `clean` (aucune détection), jamais comme une preuve
  d'innocuité.
- **Faux positifs** : un filtre de Bloom répond « connu » pour certains
  fichiers inconnus. Le filtre du CIRCL est construit pour une probabilité
  de 1 sur 10 000. La probabilité est enregistrée avec chaque réponse
  (`fp_rate`) dans le rapport d'analyse.
- **Moteurs de contenu sur les fichiers connus** : par défaut, ClamAV et
  YARA-X analysent chaque fichier, connu ou non. Le filtre du CIRCL liste
  les fichiers qu'il a vus, parmi lesquels le fichier de test EICAR, des
  outils offensifs et des échantillons de logiciels malveillants : une borne
  qui les ignorait déclarait EICAR sain.
  `[engines.hashlookup] skip_content_engines = true` ne lance pas les
  moteurs de contenu sur les fichiers connus, ce qui fait gagner du temps sur
  les clés remplies de logiciels courants, à ce prix. Les moteurs
  d'empreintes tournent toujours, et **une correspondance MalwareBazaar
  l'emporte toujours** : les moteurs de contenu tournent quand même sur un
  fichier connu qu'un moteur d'empreintes signale. Les moteurs ignorés
  figurent dans le rapport avec la raison `known file (hashlookup)`, pour
  que la décision soit vérifiable.

### ClamAV { #clamav }

[ClamAV](https://www.clamav.net/) par le démon `clamd`, avec un petit client
intégré pour son protocole sur socket Unix (`pandora_box/clamd.py`) :
`zPING`, `zVERSION`, `zFILDES` et `zINSTREAM`.

- **Modes** (`[engines.clamav] mode`) : `fildes` passe le descripteur de
  fichier ouvert à clamd, qui n'a donc pas besoin de lire le point de
  montage ; `instream` envoie le contenu ; `auto` (par défaut) utilise
  `fildes`, et `instream` seulement quand clamd signale une erreur avec le
  descripteur.
- **Verdicts** : une détection est malveillante, ou suspecte quand son nom
  correspond à `suspicious_names` (par défaut `PUA.*`, `Heuristics.*`). Les
  noms qui correspondent à `error_names` (par défaut
  `Heuristics.Limits.Exceeded.*`) signifient que le fichier n'a pas été
  entièrement analysé : ce sont des erreurs. Les erreurs de limite de taille
  d'INSTREAM, les dépassements de délai et les réponses inattendues sont
  aussi des erreurs.
- **Versions** : la version du moteur, la version de la base et sa date
  viennent de `VERSION`, redemandé pour chaque rapport d'analyse (clamd
  recharge ses bases en fonctionnement).

Réglages de `clamd.conf` requis :

```
LocalSocket /run/clamav/clamd.ctl
# Sans ce réglage, le contenu au-delà des limites ci-dessous est déclaré
# sain sans avoir été analysé
AlertExceedsMax yes
# Au moins engines.clamav.max_file_size (100 Mio par défaut)
MaxFileSize 100M
MaxScanSize 400M
StreamMaxLength 100M
```

L'image de la borne règle aussi :

- `AlertEncrypted yes` : une archive ou un document chiffré ne peut pas être
  analysé ; ClamAV le signale (`Heuristics.Encrypted.Zip`, `.RAR`,
  `.PDF`...) et la borne le compte comme pas entièrement analysé
  (`error_names`) : la clé n'est pas vérifiée, le fichier n'est pas
  supprimé ;
- `AlertOLE2Macros yes` : un document Office avec des macros (VBA, y compris
  dans un `.docm` ou un `.xlsm`) est suspect
  (`Heuristics.OLE2.ContainsMacros`) : avec `scan.suspicious = "block"`, il
  est mis en quarantaine et supprimé comme un fichier malveillant ; `"warn"`
  se contente de le signaler.

Les archives (zip, rar, 7z, tar, cab...) sont décompressées et analysées par
ClamAV lui-même, dans ses limites (`MaxScanSize`, `MaxFileSize`,
`MaxRecursion`, `MaxFiles`) : au-delà, une bombe de décompression par
exemple, le fichier n'est pas entièrement analysé (`AlertExceedsMax`).

`ScanImageFuzzyHash no` : ClamAV décoderait chaque image, y compris celles
contenues dans un PDF ou un document Office, pour comparer une empreinte
floue à quelques signatures d'images connues. Cela prenait la moitié du
temps d'analyse d'un PDF d'images de 29 Mo (41 s, puis 19 s) ; les images
sont toujours analysées.

Les fichiers plus gros que `[engines.clamav] max_file_size` sont des erreurs
sans être envoyés : gardez cette valeur égale aux limites de clamd.

**Installation pour le développement** (Debian ou Ubuntu) :

```sh
sudo apt install clamav-daemon clamav-freshclam
sudo systemctl stop clamav-freshclam && sudo freshclam && sudo systemctl start clamav-freshclam
# modifiez /etc/clamav/clamd.conf comme ci-dessus, puis
sudo systemctl restart clamav-daemon
```

**Signatures tierces** (par exemple
[Sanesecurity](https://sanesecurity.com/usage/linux-scripts/)) : il suffit
que clamd puisse les charger. Placez les fichiers de base (`.ndb`, `.hdb`,
`.ldb`...) dans le `DatabaseDirectory` de clamd (`/var/lib/clamav`) et
rechargez clamd (`clamdscan --reload`). Le script amont
`clamav-unofficial-sigs` automatise cela (le paquet Debian n'existe que
jusqu'à Debian 12). Certaines signatures tierces donnent facilement des
faux positifs : listez leurs noms dans `suspicious_names` pour les signaler
comme suspectes plutôt que malveillantes.

### YARA-X { #yara-x }

[YARA-X](https://virustotal.github.io/yara-x/) par ses bindings Python
officiels, avec les règles [YARA Forge](https://yarahq.github.io/) et
[signature-base](https://github.com/Neo23x0/signature-base).

- **Jeux de règles** (`[engines.yara] rules`) : une liste de
  `{ name, path }`, où path est un fichier `.yar` ou un dossier de fichiers
  `.yar`/`.yara`. Chaque fichier a son propre espace de noms, si bien que
  des règles de même nom n'entrent jamais en conflit.
- **YARA Forge inclut déjà signature-base** : par défaut, seul le paquet
  `core` de YARA Forge est configuré. N'ajoutez le jeu complet
  signature-base que si vous avez besoin des règles que YARA Forge écarte.
- **Compilation** : une fois au démarrage. Les règles compilées sont mises
  en cache dans `cache_dir`, indexées par la version de YARA-X, les options
  et le contenu de chaque fichier de règles. Le cache contient du code
  natif : il doit être aussi digne de confiance que les règles elles-mêmes
  (dossier `0700`, appartenant à la borne).
- **Les erreurs de compilation** ne sont jamais ignorées en silence.
  `on_compile_error = "fail"` (par défaut) refuse de démarrer et liste
  chaque erreur ; `"skip_rule"` écarte les règles invalides, les journalise
  et les liste dans chaque rapport d'analyse
  (`engines[].extra.excluded_rules`). `exclude` ignore des fichiers de
  règles par motif glob. Avec YARA-X 1.21, YARA Forge core (5 110 règles) et
  signature-base (5 904 règles) compilent sans erreur.
- **Variables externes** utilisées par les règles de signature-base,
  remplies pour chaque fichier :

    | Variable | Valeur |
    |---|---|
    | `filename` | nom du fichier |
    | `filepath` | chemin complet sur la clé, commençant par `/` |
    | `extension` | extension en minuscules, avec le point (`.exe`) |
    | `filetype` | type à la manière de THOR, déduit du type MIME de libmagic (`EXE`, `ELF`, `ZIP`, `PDF`...), vide s'il est inconnu : une approximation de THOR |
    | `owner` | toujours vide : les systèmes de fichiers amovibles n'ont pas de propriétaire significatif |

- **Correspondance des verdicts**, d'après la métadonnée `score` de chaque
  règle qui correspond (0-100, utilisée par YARA Forge et signature-base) :

    | Score | Verdict |
    |---|---|
    | `>= malicious_score` (75) | malveillant |
    | `>= suspicious_score` (40) | suspect |
    | en dessous | informatif : enregistré dans le rapport (`facts.informational`), sans effet sur le verdict |
    | pas de score | `default_score` (60) : suspect |

- **Délai** : le délai natif de YARA-X (`timeout`, en secondes) ; un
  dépassement est une erreur.
- YARA-X compile les règles en code natif à l'exécution (wasmtime) : il ne
  fonctionne pas sous `MemoryDenyWriteExecute=yes` de systemd.

YARA ne décompresse pas les archives : EICAR dans un zip est détecté par
ClamAV, pas par YARA.

### Type de fichier (libmagic) { #file-type-libmagic }

`python-magic` (paquet Debian `python3-magic`) identifie le type MIME et la
description à partir du premier Mio de chaque fichier, transmis sous forme
de tampon : libmagic n'accède pas au système de fichiers et ne décompresse
rien. Le type est enregistré dans le rapport, utilisé pour la variable YARA
`filetype` et par les heuristiques.

### Heuristiques { #heuristics }

La structure des fichiers, sans signatures
(`src/pandora_box/engines/heuristics.py`, `[engines.heuristics]`) ; ce
qu'elles trouvent est suspect, jamais malveillant :

- **PDF avec contenu actif** (comme pdfid) : JavaScript (`/JavaScript`,
  `/JS`) ou une action de lancement (`Heuristics.PDF.JavaScript`,
  `Heuristics.PDF.Launch`). Les noms masqués par des échappements
  (`/J#61vaScript`) sont décodés. Les actions automatiques, les fichiers
  incorporés et les formulaires (`/OpenAction`, `/AA`, `/EmbeddedFile`,
  `/RichMedia`, `/XFA`, `/AcroForm`) sont comptés comme des faits du
  rapport. Les noms à l'intérieur des flux d'objets compressés ne sont pas
  vus : ClamAV et YARA y regardent.
- **Programme déguisé** : un programme (PE, ELF, Mach-O, MSI, d'après
  libmagic) dont l'extension prétend autre chose (`facture.pdf` :
  `Heuristics.Executable.Disguised`), ou une extension de document suivie
  d'une extension que Windows exécute (`facture.pdf.exe`,
  `rapport.docx.js` : `Heuristics.DoubleExtension`).

Les heuristiques seules ne détectent aucun logiciel malveillant : ClamAV ou
YARA-X reste requis.

### Faux moteur { #fake-engine }

`kiosk.fake_scan = true` remplace chaque moteur par le faux moteur, pour le
développement uniquement : il déclare le fichier de test EICAR malveillant
et tout le reste sain.

## Politique de verdict { #verdict-policy }

### Verdict d'un fichier { #file-verdict }

| Résultats des moteurs | Verdict du fichier |
|---|---|
| au moins `policy.min_malicious_engines` moteurs signalent un fichier malveillant (par défaut : un) | malveillant |
| sinon, un résultat malveillant ou suspect | suspect |
| sinon, une erreur ou un dépassement de délai d'un moteur, un moteur de contenu sans résultat, ou des moteurs de contenu ignorés pour une autre raison qu'un fichier connu | erreur |
| sinon | sain |

Un fichier n'est jamais sain à moins que chaque moteur de contenu activé
l'ait analysé, ou l'ait ignoré parce que c'est un fichier connu.

### Verdict d'une clé { #device-verdict }

Le pire verdict de ses fichiers : **malveillant**, puis **suspect**, puis
**non vérifié** (un fichier n'a pas pu être entièrement analysé, ou le
parcours s'est arrêté à une limite), puis **sain**. La borne applique
ensuite :

| Réglage | `block` (par défaut) | `warn` |
|---|---|---|
| `scan.suspicious` | les fichiers suspects sont mis en quarantaine et supprimés comme les malveillants | ils sont conservés et listés comme un avertissement |
| `scan.on_error` | la clé est déclarée **NON VÉRIFIÉE : ne pas l'utiliser** | l'utilisateur est averti |

Les fichiers qui n'ont pas pu être analysés sont listés mais **jamais
supprimés** : on ne sait pas s'ils sont malveillants.

Une clé retirée, ou énumérée à nouveau comme périphérique USB, pendant son
analyse est un **comportement suspect** : elle a pu se déconnecter d'elle-même
pour revenir avec un autre contenu ou comme un autre périphérique (BadUSB).
La borne vérifie le périphérique USB de la clé (son chemin sysfs et son
numéro de périphérique) avant chaque partition, chaque seconde pendant
l'analyse et avant le verdict. Une telle clé est **non vérifiée, quel que
soit `scan.on_error`** : elle n'est ni nettoyée, ni copiée vers un serveur,
ni mise en quarantaine, et la borne affiche l'écran `key_changed`. Le
comportement (`removed` ou `enumerated_again`) est consigné
(`device_suspicious_behavior`), dans `device_verdict` et dans le rapport
(`verdict.suspicious_behaviors`, avec sa raison dans
`verdict.incomplete_reasons`). Les fichiers infectés trouvés avant restent
dans le rapport.

### Clés à plusieurs partitions { #keys-with-several-partitions }

Une clé est analysée comme un tout : toutes ses partitions forment une seule
insertion, un seul verdict, un seul rapport et une seule confirmation. La
borne monte chaque système de fichiers tour à tour, en lecture seule, et
l'analyse ; pour nettoyer la clé, elle ne monte en lecture-écriture que les
partitions qui contiennent les fichiers à supprimer, puis éjecte la clé une
seule fois.

- Une clé avec un seul système de fichiers, avec ou sans table de
  partitions, est analysée comme avant.
- Une partition qui ne peut pas être analysée rend la clé **non vérifiée**
  (`scan.on_error`), puisqu'un ordinateur pourrait quand même la lire : une
  partition chiffrée (LUKS, BitLocker), une partition sans système de
  fichiers reconnu par la borne, un système de fichiers non autorisé
  (`device.allowed_filesystems`) ou qui ne peut pas être monté. Ses autres
  partitions sont quand même analysées et nettoyées. Quand aucune ne peut
  être montée, la borne affiche une erreur.
- Les partitions qui ne contiennent pas de fichiers sont ignorées :
  partitions étendues MBR (le conteneur des partitions logiques), partitions
  GPT BIOS boot et réservées Microsoft.
- À l'écran et dans le rapport, un fichier est nommé d'après sa partition
  (`sdb2/docs/report.pdf`). Le rapport liste les partitions
  (`device.partitions` : système de fichiers, taille, analysée ou pourquoi
  non), et chaque fichier indique sa `partition`, son `path` étant relatif à
  la racine de cette partition. Le manifeste de la quarantaine donne aussi
  la `partition` de chaque fichier.
- Une clé de maintenance, de mise à jour des signatures ou de l'image a un
  seul système de fichiers : les dossiers d'une telle clé ne sont pas
  cherchés sur une clé à plusieurs partitions, qui est analysée.

### Limites { #limits }

| Réglage | Par défaut | Au-delà |
|---|---|---|
| `limits.max_file_size` | 1 Gio | le fichier est ignoré, la clé n'est pas vérifiée |
| `limits.max_files` | 100 000 | fichiers et dossiers ; le parcours s'arrête, la clé n'est pas vérifiée |
| `limits.max_depth` | 64 | les dossiers plus profonds sont ignorés, la clé n'est pas vérifiée |

### Délais { #timeouts }

Chaque processus d'analyse traite un fichier à la fois. Le processus de la
borne les surveille avec deux échéances :

- l'**échéance du moteur** : le délai du moteur en cours plus 5 secondes ;
  les moteurs qui ont un délai natif (YARA-X, le socket de clamd) le
  signalent en premier ;
- l'**échéance du fichier** : `scan.file_timeout` pour tout le fichier.

Quand une échéance expire, le processus est tué et remplacé, et le fichier
est une erreur qui nomme le moteur. Un processus qui plante est traité de la
même façon. Une réponse « sain » qui arrive après le délai du moteur est
aussi une erreur.

## Fraîcheur des signatures { #signature-freshness }

Au démarrage, la borne avertit (journaux et écran) quand une base de
signatures est plus ancienne que `signatures.max_age_days` (7 jours), ou que
le `max_age_days` de son moteur (45 jours pour Hashlookup, publié chaque
mois). La date vient du `manifest.json` du dossier de signatures quand il
existe (`{"<fichier>": {"version", "date", "source", "sha256"}}`), sinon de
la date de modification du fichier ; ClamAV indique la date de sa propre
base. Une base sans date est seulement journalisée (`signatures_undated`),
pas affichée : une base ClamAV ne contenant que des signatures
personnalisées n'en a pas (la date vient de l'en-tête de la base officielle
`daily`).

## Rapport d'analyse { #scan-report }

Chaque analyse écrit un rapport JSON dans `report.folder`, décrit par
[`src/pandora_box/schemas/scan-report-v1.schema.json`](https://github.com/sourcentis/pandora-box/blob/main/src/pandora_box/schemas/scan-report-v1.schema.json) :
la clé, la configuration, les versions des moteurs et des signatures, chaque
fichier avec ses empreintes, son type, son verdict et les résultats par
moteur, le verdict de la clé et les actions effectuées. Le manifeste de la
quarantaine y fait référence.
