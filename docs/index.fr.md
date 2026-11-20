# Introduction

![Pandora-Box](images/pandora-box.png){ width="300" .no-border }

**PandoraBox** est une borne libre de décontamination de clés USB, une
« station blanche » : l'utilisateur insère une clé USB, la borne analyse
chaque fichier avec plusieurs moteurs de détection, affiche les fichiers
dangereux trouvés, et les supprime quand l'utilisateur touche l'écran. C'est
une réécriture complète de la première version de PandoraBox, sans
dépendance à Pandora (CIRCL).


## Objectif { #objective }

Les clés USB restent une porte d'entrée courante dans des systèmes
d'information par ailleurs bien protégés : partagées entre organisations,
utilisées sur des ordinateurs non gérés, branchées sur des réseaux isolés.
Une borne de décontamination les vérifie avant qu'elles ne servent sur un
poste de travail.

PandoraBox veut être une alternative **libre, auditable et durcie** aux
bornes commerciales, pour les environnements sensibles : santé, industrie,
administrations. Elle tourne sur un petit ordinateur reconditionné avec un
écran tactile, et fonctionne sans réseau.

## Fonctionnement { #how-it-works }

- **Plusieurs moteurs** : empreintes de logiciels malveillants connus
  (MalwareBazaar), fichiers connus (CIRCL Hashlookup), ClamAV, règles YARA-X
  (YARA Forge) et heuristiques de structure (programmes déguisés en
  documents, PDF avec JavaScript). Voir
  [Moteurs de détection](engines.md).
- **Échec sûr (« fail closed »)** : un fichier qui n'a pas pu être
  entièrement analysé (archive chiffrée, limite dépassée, erreur d'un moteur)
  n'est jamais déclaré sain. Chaque partition d'une clé est analysée ; une
  partition qui ne peut pas l'être (chiffrée, système de fichiers inconnu)
  rend la clé non vérifiée.
- **Rien n'est supprimé sans l'utilisateur** : les fichiers dangereux sont
  listés à l'écran, copiés dans la quarantaine de la borne, puis supprimés de
  la clé seulement après un appui sur l'écran.
- **Traçabilité** : chaque analyse produit un rapport JSON structuré.

## Principes { #guiding-principles }

- **Image minimale et durcie** : le système ne contient que ce qui sert à
  analyser. Système de fichiers racine en lecture seule avec dm-verity,
  Secure Boot, USBGuard, aucun compte et aucune session. Voir
  [Fonctionnement de l'image](image.md).
- **Défense en profondeur** : la clé USB est hostile, et les moteurs
  d'analyse sont supposés compromettables. Chaque moteur tourne dans son
  propre bac à sable, sans réseau.
- **Hors ligne par défaut** : aucun réseau n'est nécessaire pour analyser ;
  les signatures et les mises à jour du système arrivent sur des clés USB
  signées, ou par un canal en ligne dédié. Voir [Signatures](signatures.md).
- **Personnalisable** : l'organisation choisit son logo, ses couleurs et les
  textes de l'interface. Voir [Interface](interface.md).

## Documentation { #documentation }

### Installer une borne { #install-a-kiosk }

Pour préparer un déploiement dans une organisation (clés, emplacements,
réseau, exploitation), commencez par le [Guide de déploiement](deployment.md).

| Étape | Page |
|---|---|
| 1. Choisir le matériel | [Matériel](hardware.md) : ordinateur et écran validés, boîtier |
| 2. Construire l'image | [Construction de l'image](build.md) : configuration, clés, profil `online` |
| 3. La tester dans une machine virtuelle | [Test avec QEMU](vm.md) : test automatisé, machine interactive, vraies clés USB |
| 4. Installer la borne | [Installation initiale](install.md) : BIOS, écriture du disque, Secure Boot, premier jeu de signatures |

### Maintenir une borne { #maintain-a-kiosk }

| Tâche | Page |
|---|---|
| Mettre à jour les signatures | [Signatures](signatures.md) : clés de mise à jour des signatures, publication, mises à jour en ligne |
| Mettre à jour le système | [Mises à jour du système](update.md) : mises à jour A/B de l'image, par clé USB ou en ligne |
| Lire les journaux | [Journaux](logs.md) : clé de maintenance ; [Export vers un SIEM](siem.md) |

### Référence { #reference }

| Page | Contenu |
|---|---|
| [Interface](interface.md) | Écrans de la borne, thème de l'organisation |
| [Configuration](configuration.md) | Tous les réglages de `pandora-box.toml` |
| [Moteurs de détection](engines.md) | Moteurs, politique de verdict, rapport d'analyse |
| [Fonctionnement de l'image](image.md) | Partitions, chaîne de démarrage, périphériques USB, durcissement, bac à sable |
| [Modèle de menace](threat-model.md) | Ce que la borne protège, contre qui, et ce qu'elle ne couvre pas |
| [Développement](development.md) | Lancer la borne depuis les sources, tests |

L'avancement du projet est suivi dans la
[feuille de route](https://github.com/sourcentis/pandora-box/blob/main/ROADMAP.md).
PandoraBox est un logiciel libre, sous
[licence publique générale GNU v3.0](https://github.com/sourcentis/pandora-box/blob/main/LICENSE).
