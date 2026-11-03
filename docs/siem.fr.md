# Export des journaux vers un SIEM

La borne journalise chaque événement dans un fichier de lignes JSON,
`/var/log/pandora-box/pandora-box.log` : clés insérées et retirées, analyses
et leurs verdicts, fichiers infectés, quarantaine et nettoyage, mises à jour
des signatures et de l'image, clés de maintenance, erreurs. Une borne en
ligne peut envoyer ces entrées à un SIEM (Wazuh, Elastic, Graylog, Splunk,
ou tout serveur syslog), au fur et à mesure.

## Configuration { #configuration }

L'export est désactivé par défaut. Il nécessite le profil d'image `online`
([Construction de l'image](build.md#profile-online)), qui apporte le réseau
et le service `pandora-box-siem`, et la section `[siem]` de la configuration
(`packaging/pandora-box.toml`) :

```toml
[siem]
enabled = true
host = "siem.example.org"
# "tls" (par défaut), "tcp" ou "udp"
transport = "tls"
# 0 : 6514 pour tls, 514 pour tcp et udp
port = 0
# Autorités de certification du certificat du SIEM, pour tls ("" : celles du
# système)
ca = "/usr/share/pandora-box/siem-ca.pem"
# "syslog" (RFC 5424) ou "json"
format = "syslog"
facility = "local0"
```

`pandora-box --check-config` vérifie la section. Les autorités de
certification font partie de l'image : placez-les dans `image/siem-ca.pem`
(PEM), installé sous `/usr/share/pandora-box/siem-ca.pem` à la construction
de l'image.

## Messages { #messages }

Chaque entrée du journal est un message.

**`format = "syslog"`** : un message
[RFC 5424](https://www.rfc-editor.org/rfc/rfc5424) dont l'en-tête vient de
l'entrée, et dont le message est l'entrée JSON elle-même :

```text
<132>1 2026-10-14T10:25:32.123456+00:00 kiosk-01 pandora-box - infected_files - {"timestamp": "2026-10-14T10:25:32.123456+00:00", "level": "WARNING", "kiosk": "kiosk-01", "event": "infected_files", "count": 2}
```

| Champ | Valeur |
|---|---|
| PRI | `facility` et le niveau de l'entrée : DEBUG 7, INFO 6, WARNING 4, ERROR 3 |
| TIMESTAMP | Heure de l'entrée (UTC) |
| HOSTNAME | `kiosk.name` (les caractères autres que l'ASCII imprimable remplacés par `_`) |
| APP-NAME | `pandora-box` |
| MSGID | Nom de l'événement (`device_verdict`, `infected_files`...) |

Sur TCP et TLS, les messages sont délimités par comptage d'octets
(RFC 5425, RFC 6587), comme l'exige syslog sur TLS.

**`format = "json"`** : l'entrée JSON seule, une par ligne sur TCP et TLS,
une par datagramme sur UDP. Cela convient aux récepteurs de lignes JSON
(Logstash `json_lines`, Fluent Bit, Vector) et aux SIEM qui décodent le JSON
d'un message brut.

Chaque entrée contient `timestamp`, `level`, `kiosk` et `event`, puis les
champs de l'événement. Les horodatages viennent de l'horloge de la borne,
synchronisée par NTP dans le profil `online` ([Heure](build.md#time)).

## Tableaux de bord { #dashboards }

Les statistiques d'un parc de bornes (clés analysées, verdicts, détections,
nettoyages, état des signatures) sont calculées par le SIEM à partir des
entrées qu'il reçoit : rien à installer sur les bornes. Le travail est le
même dans tous les SIEM : décoder le JSON de l'entrée en champs, puis
compter les événements ci-dessous. `format = "json"` est le plus simple :
le message est l'entrée JSON seule ; avec `format = "syslog"`, c'est la
partie message (MSG) du message syslog.

### Événements { #events }

| Événement | Quand | Champs |
|---|---|---|
| `device_verdict` | Une fois par clé analysée : la synthèse à compter | `report_id`, `verdict` (`clean`, `malicious`, `suspicious`, `not_verified`), `complete`, `files`, `infected`, `suspicious`, `not_scanned`, `duration` (secondes), `used` (octets), `detections` (liste de `moteur: nom`), `suspicious_behaviors` (`removed`, `enumerated_again`) |
| `device_cleaned` | La clé a été nettoyée | `report_id`, `removed`, `infected` |
| `airgap_copied`, `airgap_received`, `airgap_refused`, `airgap_failed` | Copie vers et depuis un serveur ([Copie vers un serveur](airgap.md)) | `report_id`, compteurs, `status` |
| `kiosk_started` | Démarrage de la borne | `image_version`, `signature_set`, `engines`, `signatures` |
| `signatures_installed`, `signatures_changed` | Nouveau jeu de signatures | `serial`, `created` |
| `file_scanned` | Chaque fichier (beaucoup d'entrées) | `verdict`, `detail`, `engines`, `path` |
| `device_suspicious_behavior` | Une clé retirée ou énumérée à nouveau pendant son analyse | `behavior`, `node`, `usb_device`, `busnum`, `devnum` |
| `usb_device_blocked` | Un périphérique USB refusé par USBGuard : clavier, adaptateur réseau, clé qui est aussi un clavier ([Périphériques USB refusés](logs.md#refused-usb-devices)) | `usb_id`, `model`, `serial`, `port`, `interfaces`, `kinds`, `composite`, `rule` |

Chaque entrée contient aussi `timestamp` et `kiosk` (`kiosk.name`).
`report_id` relie les événements d'une clé entre eux, et à son rapport
d'analyse. `device_verdict` ne contient jamais de nom de fichier ;
`file_scanned` et `device_inserted` contiennent les noms des fichiers, le
libellé et le numéro de série de la clé, `usb_device_blocked` le nom et le
numéro de série du périphérique (omis sur une
[borne de transfert](airgap.md#a-stolen-kiosk)) : écartez-les dans le SIEM
s'ils ne servent pas.

### Indicateurs { #indicators }

| Indicateur | À partir de |
|---|---|
| Clés analysées, par jour et par borne | nombre de `device_verdict` |
| Verdicts | `device_verdict` par `verdict` |
| Détections les plus fréquentes | `detections` de `device_verdict`, une valeur à la fois |
| Clés non vérifiées (à examiner) | `device_verdict` avec `verdict` = `not_verified` |
| Clés nettoyées | nombre de `device_cleaned`, `removed` |
| Durée d'analyse | `duration` de `device_verdict` (moyenne, 95e centile) |
| Jeu de signatures de chaque borne | dernier `serial` de `signatures_installed` / `signatures_changed`, ou `signature_set` de `kiosk_started` |
| Bornes silencieuses | heure de la dernière entrée de chaque `kiosk` |
| Clés retirées ou énumérées à nouveau pendant leur analyse, à alerter (`enumerated_again` surtout) | `device_suspicious_behavior` par `behavior`, ou `suspicious_behaviors` de `device_verdict` |
| Périphériques USB refusés (tentatives BadUSB), à alerter | `usb_device_blocked`, par `kinds` ; `composite` = `true` pour une clé qui est aussi un clavier |

### Exemples { #examples }

Les mêmes indicateurs dans quelques SIEM, comme point de départ : les noms
des index et des champs dépendent de la façon dont les entrées sont reçues
(ici, les champs de l'entrée JSON au premier niveau).

**Splunk** (entrée TCP, `sourcetype = _json` ; une liste JSON est le champ
`detections{}`) :

```text
event=device_verdict | timechart span=1d count by verdict
event=device_verdict | stats count by kiosk
event=device_verdict | top limit=10 detections{}
event=device_verdict | stats avg(duration) perc95(duration) by kiosk
event=device_verdict verdict=not_verified | table _time kiosk report_id not_scanned
event=signatures_installed OR event=signatures_changed | stats latest(serial) by kiosk
event=usb_device_blocked | table _time kiosk usb_id model port kinds{} composite
```

**Elastic** (Logstash ou Elastic Agent, codec `json` ; ES|QL dans Kibana) :

```text
FROM pandora-box-* | WHERE event == "device_verdict"
  | STATS keys = COUNT(*) BY verdict, day = DATE_TRUNC(1 day, @timestamp)
FROM pandora-box-* | WHERE event == "device_verdict" | MV_EXPAND detections
  | STATS seen = COUNT(*) BY detections | SORT seen DESC | LIMIT 10
FROM pandora-box-* | WHERE event == "usb_device_blocked"
  | KEEP @timestamp, kiosk, usb_id, model, port, kinds, composite
```

**Graylog** (entrée Syslog TCP ; le JSON du message décodé par une règle de
pipeline, puis des recherches et des widgets d'agrégation sur
`event:device_verdict`, groupés par `verdict`, `kiosk` ou `detections`) :

```text
rule "PandoraBox JSON"
when
  starts_with(to_string($message.message), "{")
then
  set_fields(to_map(parse_json(to_string($message.message))));
end
```

**Wazuh** (décodé par son décodeur JSON) : Wazuh n'indexe que les entrées
qui correspondent à une règle ; une règle locale par événement à compter,
puis des tableaux de bord sur `data.event` dans OpenSearch Dashboards. Un
périphérique USB refusé, ou une clé retirée ou énumérée à nouveau pendant
son analyse, lève une alerte (niveau 10, 12 pour une clé qui est aussi un
autre périphérique) :

```xml
<group name="pandora-box,">
  <rule id="100100" level="3">
    <decoded_as>json</decoded_as>
    <field name="event">^device_verdict$</field>
    <description>PandoraBox $(kiosk): key scanned, $(verdict)</description>
  </rule>
  <rule id="100110" level="10">
    <decoded_as>json</decoded_as>
    <field name="event">^usb_device_blocked$</field>
    <description>PandoraBox $(kiosk): USB device refused, $(usb_id) $(model) on port $(port)</description>
    <group>attack,badusb,</group>
  </rule>
  <rule id="100111" level="12">
    <if_sid>100110</if_sid>
    <field name="composite">^true$</field>
    <description>PandoraBox $(kiosk): USB key that is also a keyboard or another device (BadUSB)</description>
  </rule>
  <rule id="100120" level="10">
    <decoded_as>json</decoded_as>
    <field name="event">^device_suspicious_behavior$</field>
    <description>PandoraBox $(kiosk): key $(behavior) during its scan</description>
    <group>attack,badusb,</group>
  </rule>
</group>
```

**Grafana Loki** (récepteur syslog de Grafana Alloy ; LogQL, dont
l'analyseur `json` ignore les listes, dont `detections`) :

```text
sum by (verdict) (count_over_time({app="pandora-box"} | json | event="device_verdict" [1d]))
avg_over_time({app="pandora-box"} | json | event="device_verdict" | unwrap duration [1d])
sum by (kiosk, usb_id) (count_over_time({app="pandora-box"} | json | event="usb_device_blocked" [1d]))
```

## Transport { #transport }

| `transport` | Port par défaut | |
|---|---|---|
| `tls` | 6514 | Recommandé : le certificat du SIEM est vérifié (autorités de certification de `ca`, nom d'hôte de `host`), TLS 1.2 au minimum |
| `tcp` | 514 | En clair, sur un réseau de confiance uniquement |
| `udp` | 514 | En clair ; un datagramme peut être perdu sans avertissement |

La borne ne s'authentifie pas avec un certificat client.

## Acheminement { #delivery }

Le fichier de journal sert de file d'attente. Le service enregistre la
position de la dernière entrée envoyée (`/var/lib/pandora-box-siem/state.json`) :
quand le SIEM est injoignable, il réessaie (après 1 seconde, puis deux fois
plus longtemps à chaque fois, jusqu'à 1 minute) et envoie, dans l'ordre,
chaque entrée journalisée entre-temps. Il en va de même quand le service ou
la borne redémarre. logrotate déplace le fichier de journal chaque mois : le
service envoie la fin du fichier déplacé avant le nouveau, donc une
interruption de plus d'un mois perd les entrées du mois le plus ancien.

Syslog n'a pas d'accusé de réception : sur TCP et TLS, les entrées envoyées
juste avant une coupure de connexion peuvent être perdues, ou envoyées deux
fois si la coupure survient pendant leur envoi. Sur UDP, rien n'est garanti.

## Le service { #the-service }

`pandora-box-siem.service` (`src/pandora_box/siem.py`) suit le fichier de
journal et envoie ses entrées. Il s'arrête aussitôt quand `[siem]` est
désactivé.

- La borne elle-même n'a pas de réseau (`IPAddressDeny=any`, aucun socket
  IP) : elle ne fait qu'écrire le fichier de journal. Le service tourne sous
  l'utilisateur `pandora-box-siem`, sans privilèges et dans un bac à sable
  systemd, et le pare-feu laisse sortir cet utilisateur (TCP et UDP), en
  plus du service de mise à jour.
- Il lit le fichier de journal grâce au groupe `pandora-box-log`, le groupe
  de `/var/log/pandora-box` et des fichiers de la borne : il ne peut lire ni
  les rapports d'analyse ni la quarantaine (`/var/lib/pandora-box`, mode
  0700).
- Ses messages, connexion perdue puis rétablie, sont dans son journal :
  `journalctl -u pandora-box-siem`.

## Récepteurs { #receivers }

**Wazuh** : le gestionnaire reçoit syslog sur TCP ou UDP, sans TLS, depuis
les adresses qu'il autorise (`<remote>` de `ossec.conf`, `connection`
`syslog`). Avec `format = "json"` et `transport = "tcp"`, chaque entrée
arrive telle quelle au décodeur JSON de Wazuh ; vérifiez le décodage avec
`wazuh-logtest`.

**rsyslog**, sur TLS (paquets `rsyslog` et `rsyslog-gnutls`) :

```text
global(
    DefaultNetstreamDriverCAFile="/etc/rsyslog.d/ca.pem"
    DefaultNetstreamDriverCertFile="/etc/rsyslog.d/siem.pem"
    DefaultNetstreamDriverKeyFile="/etc/rsyslog.d/siem.key"
)
module(load="imtcp" StreamDriver.Name="gtls" StreamDriver.Mode="1"
       StreamDriver.AuthMode="anon")
input(type="imtcp" port="6514")
```

## Développement { #development }

Le service fonctionne aussi en dehors de l'image, avec toute configuration
dont la section `[siem]` est activée, ici vers un récepteur local :

```sh
nc -lk 5514 &
pandora-box-siem --config pandora-box.toml --state /tmp/siem-state.json
```

avec `host = "127.0.0.1"`, `transport = "tcp"` et `port = 5514`. Le test en
machine virtuelle envoie les journaux de la borne à un récepteur syslog du
test ([Test avec QEMU](vm.md#automated-test)).
