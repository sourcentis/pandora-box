# Log export to a SIEM

The kiosk logs every event to a JSON lines file,
`/var/log/pandora-box/pandora-box.log`: devices inserted and removed, scans
and their verdicts, infected files, quarantine and cleaning, signature and
image updates, maintenance devices, errors. An online kiosk can send these
entries to a SIEM (Wazuh, Elastic, Graylog, Splunk, or any syslog server), as
they are logged.

## Configuration

The export is off by default. It needs the image profile `online`
([Building the image](build.md#profile-online)), which brings the network and the
`pandora-box-siem` service, and the `[siem]` section of the configuration
(`packaging/pandora-box.toml`):

```toml
[siem]
enabled = true
host = "siem.example.org"
# "tls" (default), "tcp" or "udp"
transport = "tls"
# 0: 6514 for tls, 514 for tcp and udp
port = 0
# Certificate authorities of the SIEM certificate, for tls ("": those of the
# system)
ca = "/usr/share/pandora-box/siem-ca.pem"
# "syslog" (RFC 5424) or "json"
format = "syslog"
facility = "local0"
```

`pandora-box --check-config` checks the section. The certificate
authorities are part of the image: put them in `image/siem-ca.pem` (PEM),
installed as `/usr/share/pandora-box/siem-ca.pem` when the image is built.

## Messages

Each log entry is one message.

**`format = "syslog"`**: an [RFC 5424](https://www.rfc-editor.org/rfc/rfc5424)
message whose header comes from the entry, and whose message is the JSON
entry itself:

```text
<132>1 2026-10-14T10:25:32.123456+00:00 kiosk-01 pandora-box - infected_files - {"timestamp": "2026-10-14T10:25:32.123456+00:00", "level": "WARNING", "kiosk": "kiosk-01", "event": "infected_files", "count": 2}
```

| Field | Value |
|---|---|
| PRI | `facility` and the level of the entry: DEBUG 7, INFO 6, WARNING 4, ERROR 3 |
| TIMESTAMP | Time of the entry (UTC) |
| HOSTNAME | `kiosk.name` (characters other than printable ASCII replaced by `_`) |
| APP-NAME | `pandora-box` |
| MSGID | Name of the event (`device_verdict`, `infected_files`...) |

Over TCP and TLS, the messages are framed by octet counting (RFC 5425,
RFC 6587), as syslog over TLS requires.

**`format = "json"`**: the JSON entry alone, one per line over TCP and TLS,
one per datagram over UDP. This suits receivers of JSON lines (Logstash
`json_lines`, Fluent Bit, Vector) and SIEMs that decode the JSON of a raw
message.

Every entry holds `timestamp`, `level`, `kiosk` and `event`, then the fields
of the event. The timestamps come from the clock of the kiosk, synchronized
by NTP in the profile `online` ([Time](build.md#time)).

## Dashboards

The statistics of a fleet of kiosks (keys scanned, verdicts, detections,
cleanings, state of the signatures) are computed by the SIEM from the
entries it receives: nothing to install on the kiosks. It is the same work
in every SIEM: decode the JSON of the entry into fields, then count the
events below. `format = "json"` is the simplest: the message is the JSON
entry alone; with `format = "syslog"`, it is the message part (MSG) of the
syslog message.

### Events

| Event | When | Fields |
|---|---|---|
| `device_verdict` | Once per scanned key: the summary to count | `report_id`, `verdict` (`clean`, `malicious`, `suspicious`, `not_verified`), `complete`, `files`, `infected`, `suspicious`, `not_scanned`, `duration` (seconds), `used` (bytes), `detections` (list of `engine: name`) |
| `device_cleaned` | The key was cleaned | `report_id`, `removed`, `infected` |
| `airgap_copied`, `airgap_received`, `airgap_refused`, `airgap_failed` | Copy to and from a server ([Copy to a server](airgap.md)) | `report_id`, counts, `status` |
| `kiosk_started` | Start of the kiosk | `image_version`, `signature_set`, `engines`, `signatures` |
| `signatures_installed`, `signatures_changed` | New signature set | `serial`, `created` |
| `file_scanned` | Each file (many entries) | `verdict`, `detail`, `engines`, `path` |
| `usb_device_blocked` | A USB device refused by USBGuard: keyboard, network adapter, key that is also a keyboard ([Refused USB devices](logs.md#refused-usb-devices)) | `usb_id`, `model`, `serial`, `port`, `interfaces`, `kinds`, `composite`, `rule` |

Every entry also holds `timestamp` and `kiosk` (`kiosk.name`). `report_id`
ties the events of a key together, and to its scan report. `device_verdict`
never holds a name of a file; `file_scanned` and `device_inserted` hold the
names of the files and the label and serial number of the key,
`usb_device_blocked` the name and serial number of the device (left out on
a [station](airgap.md#a-stolen-kiosk)): drop them in the SIEM when they are
not needed.

### Indicators

| Indicator | From |
|---|---|
| Keys scanned, per day and per kiosk | count of `device_verdict` |
| Verdicts | `device_verdict` by `verdict` |
| Most frequent detections | `detections` of `device_verdict`, one value each |
| Keys not verified (to look at) | `device_verdict` with `verdict` = `not_verified` |
| Keys cleaned | count of `device_cleaned`, `removed` |
| Scan time | `duration` of `device_verdict` (average, 95th percentile) |
| Signature set of each kiosk | latest `serial` of `signatures_installed` / `signatures_changed`, or `signature_set` of `kiosk_started` |
| Silent kiosks | time of the latest entry of each `kiosk` |
| Refused USB devices (BadUSB attempts), to alert on | `usb_device_blocked`, by `kinds`; `composite` = `true` for a key that is also a keyboard |

### Examples

The same indicators in a few SIEMs, as a starting point: index and field
names depend on how the entries are received (here, the fields of the JSON
entry at the top level).

**Splunk** (TCP input, `sourcetype = _json`; a JSON list is the field
`detections{}`):

```text
event=device_verdict | timechart span=1d count by verdict
event=device_verdict | stats count by kiosk
event=device_verdict | top limit=10 detections{}
event=device_verdict | stats avg(duration) perc95(duration) by kiosk
event=device_verdict verdict=not_verified | table _time kiosk report_id not_scanned
event=signatures_installed OR event=signatures_changed | stats latest(serial) by kiosk
```

**Elastic** (Logstash or Elastic Agent, `json` codec; ES|QL in Kibana):

```text
FROM pandora-box-* | WHERE event == "device_verdict"
  | STATS keys = COUNT(*) BY verdict, day = DATE_TRUNC(1 day, @timestamp)
FROM pandora-box-* | WHERE event == "device_verdict" | MV_EXPAND detections
  | STATS seen = COUNT(*) BY detections | SORT seen DESC | LIMIT 10
```

**Graylog** (Syslog TCP input; the JSON of the message decoded by a
pipeline rule, then searches and aggregation widgets on `event:device_verdict`,
grouped by `verdict`, `kiosk` or `detections`):

```text
rule "PandoraBox JSON"
when
  starts_with(to_string($message.message), "{")
then
  set_fields(to_map(parse_json(to_string($message.message))));
end
```

**Wazuh** (decoded by its JSON decoder): Wazuh only indexes the entries that
match a rule; a local rule per event to count, then dashboards on
`data.event` in OpenSearch Dashboards:

```xml
<group name="pandora-box,">
  <rule id="100100" level="3">
    <decoded_as>json</decoded_as>
    <field name="event">^device_verdict$</field>
    <description>PandoraBox $(kiosk): key scanned, $(verdict)</description>
  </rule>
</group>
```

**Grafana Loki** (syslog receiver of Grafana Alloy; LogQL, whose `json`
parser leaves the lists out, `detections` among them):

```text
sum by (verdict) (count_over_time({app="pandora-box"} | json | event="device_verdict" [1d]))
avg_over_time({app="pandora-box"} | json | event="device_verdict" | unwrap duration [1d])
```

## Transport

| `transport` | Default port | |
|---|---|---|
| `tls` | 6514 | Recommended: the certificate of the SIEM is verified (certificate authorities of `ca`, host name of `host`), TLS 1.2 at least |
| `tcp` | 514 | Clear text, on a trusted network only |
| `udp` | 514 | Clear text; a datagram may be lost without notice |

The kiosk does not authenticate itself with a client certificate.

## Delivery

The log file is the queue. The service saves the position of the last entry
sent (`/var/lib/pandora-box-siem/state.json`): when the SIEM cannot be
reached, it tries again (after 1 second, then twice longer each time, up to
1 minute) and sends every entry logged meanwhile, in order. The same applies
when the service or the kiosk restarts. logrotate moves the log file every
month: the service sends the end of the moved file before the new one, so an
outage longer than a month loses the entries of the oldest month.

Syslog has no acknowledgment: over TCP and TLS, the entries sent just before
a connection breaks may be lost, or sent twice when it is broken while they
are sent. Over UDP, nothing is guaranteed.

## The service

`pandora-box-siem.service` (`src/pandora_box/siem.py`) follows the log file
and sends its entries. It exits at once when `[siem]` is disabled.

- The kiosk itself has no network (`IPAddressDeny=any`, no IP socket): it
  only writes the log file. The service runs as the `pandora-box-siem` user,
  without privileges and in a systemd sandbox, and the firewall lets that
  user out (TCP and UDP) besides the update service.
- It reads the log file through the `pandora-box-log` group, the group of
  `/var/log/pandora-box` and of the files of the kiosk: it can read neither
  the scan reports nor the quarantine (`/var/lib/pandora-box`, mode 0700).
- Its messages, connection lost and back, are in its journal:
  `journalctl -u pandora-box-siem`.

## Receivers

**Wazuh**: the manager receives syslog over TCP or UDP, without TLS, from the
addresses it allows (`<remote>` of `ossec.conf`, `connection` `syslog`). With
`format = "json"` and `transport = "tcp"`, each entry reaches the JSON
decoder of Wazuh as is; check the decoding with `wazuh-logtest`.

**rsyslog**, over TLS (packages `rsyslog` and `rsyslog-gnutls`):

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

## Development

The service runs outside of the image too, with any configuration whose
`[siem]` is enabled, here towards a local receiver:

```sh
nc -lk 5514 &
pandora-box-siem --config pandora-box.toml --state /tmp/siem-state.json
```

with `host = "127.0.0.1"`, `transport = "tcp"` and `port = 5514`. The
virtual machine test sends the logs of the kiosk to a syslog receiver of the
test ([Testing with QEMU](vm.md#automated-test)).
