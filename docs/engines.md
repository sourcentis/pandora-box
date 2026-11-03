# Detection engines and verdict policy

This document describes the phase 1 scanning pipeline: each detection engine,
its data files and how to obtain them for development, and how verdicts are
decided.

> [!WARNING]
> Signature downloads described here are for **development only**: these
> files are not signed. A kiosk only uses a signed signature set, verified at
> each start and installed from a signature update device: see
> [signatures.md](signatures.md).

## Pipeline

For each inserted device:

1. **Inventory** (kiosk process, metadata only): the mount point is walked
   with `os.scandir`/`lstat`. Links are never followed, the walk never leaves
   the device, and FIFOs, sockets and device files are listed as skipped.
   The limits apply here (see [Limits](#limits)).
2. **Scan** (worker processes, one file at a time per worker):
   1. open the file read-only, component by component with `O_NOFOLLOW`, and
      check that it is the regular file the inventory recorded;
   2. compute SHA-256, SHA-1 and MD5 in a single streaming read;
   3. identify the type with libmagic (MIME type and description);
   4. run the **hash engines** (MalwareBazaar, then Hashlookup);
   5. run the **content engines** (ClamAV, YARA-X), unless the file is a
      known file and no hash engine reports it (see [Hashlookup](#hashlookup-circl));
   6. aggregate the engine results into the file verdict.
3. **Device verdict**, cleaning, and the **JSON scan report**.

Engines receive a `FileInfo` (relative path, size, hashes, MIME type,
description and a read-only file descriptor). They never reopen the file by
path and keep no state between files.

## Engines

Every engine is enabled by default. If an enabled engine cannot load its data,
the kiosk refuses to start (`pandora-box --check-config` shows why). At least
one content engine (ClamAV or YARA-X) is required: hash lookups alone only
recognize files that are already known.

For development, `pandora-box-signatures publish dev-signatures --sources
yara-forge,malwarebazaar,hashlookup` downloads the YARA rules, the
MalwareBazaar list and the Hashlookup filter into `./dev-signatures/`, checks
them, and prints the matching configuration (an unsigned set: see
[signatures.md](signatures.md)).

### MalwareBazaar

Offline list of SHA-256 hashes of known malware, from
[abuse.ch MalwareBazaar](https://bazaar.abuse.ch/). A match is **malicious**
(detection `MalwareBazaar.KnownMalware`).

- **Input**: the full SHA-256 export. Downloading it requires a free abuse.ch
  Auth-Key ([auth.abuse.ch](https://auth.abuse.ch/)), sent in the `Auth-Key`
  HTTP header, from `https://bazaar.abuse.ch/export/txt/sha256/full/`. The
  export is a zip archive holding `full_sha256.txt`: a `#` comment header,
  then one lower case hexadecimal SHA-256 per line. The converter accepts the
  zip archive or the text file. Any other line is an error: a malformed export
  is never partially loaded. In October 2026, the export held 1.1 million
  hashes, a 37 MB database.
- **Conversion**:
  `python -m pandora_box.hashdb build full_sha256.zip malwarebazaar.sha256.bin`
  (`python -m pandora_box.hashdb info <database>` describes a database).
- **Format** (`pandora_box/hashdb.py`): a 64-byte header (magic, version,
  count, creation time, SHA-256 of the source export) followed by the sorted
  32-byte digests. The file is memory-mapped and searched by bisection: one
  million hashes take 32 MB, shared by the workers through the page cache.
- **Configuration**: `[engines.malwarebazaar] database`.

### Hashlookup (CIRCL)

The [CIRCL hashlookup](https://www.circl.lu/services/hashlookup/) Bloom
filter of known files (NSRL, Linux distributions, software repositories).

- **Data**: `https://cra.circl.lu/hashlookup/hashlookup-full.bloom` (about
  1 GB and 418 million hashes in October 2026, updated monthly). It holds the **SHA-1** of every known file, in
  upper case hexadecimal, in the DCSO bloom format.
- **Format**: the format of the DCSO `bloom` Go tool and of the `flor` Python
  library. `flor` loads the whole bit array in memory (1 GB per worker), so
  PandoraBox has its own memory-mapped reader (`pandora_box/bloom.py`). The
  tests check that it agrees with `flor`. Against the real CIRCL filter, it
  agrees with `flor`, finds most Debian system binaries, and answers "known"
  for about 1 in 10,000 random hashes, as expected.
- **Known is not benign**: the sources of hashlookup also contain offensive
  and dual-use tools. A Hashlookup hit is reported as the fact `known = true`
  with the verdict `clean` (no detection), never as a proof of safety.
- **False positives**: a Bloom filter answers "known" for some unknown files.
  The CIRCL filter is built for a probability of 1 in 10,000. The probability
  is recorded with each answer (`fp_rate`) in the scan report.
- **Content engines on known files**: by default, ClamAV and YARA-X scan
  every file, known or not. The CIRCL filter lists the files it has seen,
  among them the EICAR test file, offensive tools and malware samples: a
  kiosk that skipped them reported EICAR clean.
  `[engines.hashlookup] skip_content_engines = true` skips the content
  engines on known files, which saves time on devices full of common
  software, at that cost. The hash engines always run, and **a MalwareBazaar
  match always wins**: content engines still run on a known file that a hash
  engine reports. The skipped engines appear in the report with the reason
  `known file (hashlookup)`, so the decision is auditable.

### ClamAV

[ClamAV](https://www.clamav.net/) through the `clamd` daemon, with a small
built-in client for its Unix socket protocol (`pandora_box/clamd.py`):
`zPING`, `zVERSION`, `zFILDES` and `zINSTREAM`.

- **Modes** (`[engines.clamav] mode`): `fildes` passes the open file
  descriptor to clamd, which therefore does not need to read the mount point;
  `instream` sends the content; `auto` (default) uses `fildes`, and
  `instream` only when clamd reports an error with the descriptor.
- **Verdicts**: a detection is malicious, or suspicious when its name matches
  `suspicious_names` (default `PUA.*`, `Heuristics.*`). Names matching
  `error_names` (default `Heuristics.Limits.Exceeded.*`) mean that the file
  was not fully scanned: they are errors. INSTREAM size limit errors,
  timeouts and unexpected replies are errors too.
- **Versions**: the engine version, the database version and its date come
  from `VERSION`, asked again for each scan report (clamd reloads its
  databases while running).

Required `clamd.conf` settings:

```
LocalSocket /run/clamav/clamd.ctl
# Without it, content beyond the limits below is reported as clean
# without being scanned
AlertExceedsMax yes
# At least engines.clamav.max_file_size (100 MiB by default)
MaxFileSize 100M
MaxScanSize 400M
StreamMaxLength 100M
```

The kiosk image also sets:

- `AlertEncrypted yes`: an encrypted archive or document cannot be scanned;
  ClamAV reports it (`Heuristics.Encrypted.Zip`, `.RAR`, `.PDF`...) and the
  kiosk counts it as not fully scanned (`error_names`): the device is not
  verified, the file is not removed;
- `AlertOLE2Macros yes`: an Office document with macros (VBA, also inside
  `.docm` or `.xlsm`) is suspicious (`Heuristics.OLE2.ContainsMacros`): with
  `scan.suspicious = "block"`, it is quarantined and removed like a
  malicious file; `"warn"` only reports it.

Archives (zip, rar, 7z, tar, cab...) are unpacked and scanned by ClamAV
itself, within its limits (`MaxScanSize`, `MaxFileSize`, `MaxRecursion`,
`MaxFiles`): beyond them, a decompression bomb for instance, the file is not
fully scanned (`AlertExceedsMax`).

`ScanImageFuzzyHash no`: ClamAV would decode every
image, also those inside a PDF or an Office document, to compare a fuzzy hash
with a few signatures of known images. It took half the scan time of a
29 MB PDF of images (41 s, then 19 s); the images are still scanned.

Files bigger than `[engines.clamav] max_file_size` are errors without being
sent: keep it equal to the clamd limits.

**Development setup** (Debian or Ubuntu):

```sh
sudo apt install clamav-daemon clamav-freshclam
sudo systemctl stop clamav-freshclam && sudo freshclam && sudo systemctl start clamav-freshclam
# edit /etc/clamav/clamd.conf as above, then
sudo systemctl restart clamav-daemon
```

**Third-party signatures** (for example [Sanesecurity](https://sanesecurity.com/usage/linux-scripts/))
only need to be loadable by clamd: put the database files (`.ndb`, `.hdb`,
`.ldb`...) in the clamd `DatabaseDirectory` (`/var/lib/clamav`) and reload
clamd (`clamdscan --reload`). The upstream `clamav-unofficial-sigs` script
automates this (the Debian package exists up to Debian 12 only). Some
third-party signatures are prone to false positives: list their names in
`suspicious_names` to report them as suspicious instead of malicious.

### YARA-X

[YARA-X](https://virustotal.github.io/yara-x/) through its official Python
bindings, with the [YARA Forge](https://yarahq.github.io/) and
[signature-base](https://github.com/Neo23x0/signature-base) rules.

- **Rule sets** (`[engines.yara] rules`): a list of `{ name, path }`, where
  path is a `.yar` file or a folder of `.yar`/`.yara` files. Each file gets its
  own namespace, so identical rule names never conflict.
- **YARA Forge already includes signature-base**: by default only the YARA
  Forge `core` package is configured. Add the full signature-base set only if
  you need the rules YARA Forge leaves out.
- **Compilation**: once at startup. The compiled rules are cached in
  `cache_dir`, keyed by the YARA-X version, the options and the content of
  every rule file. The cache holds native code: it must be as trusted as the
  rules themselves (folder `0700`, owned by the kiosk).
- **Compile errors** are never silently dropped. `on_compile_error = "fail"`
  (default) refuses to start and lists every error;
  `"skip_rule"` drops the invalid rules, logs them and lists them in every
  scan report (`engines[].extra.excluded_rules`). `exclude` ignores rule
  files by glob pattern. With YARA-X 1.21, YARA Forge core (5,110 rules) and
  signature-base (5,904 rules) compile without error.
- **External variables** used by the signature-base rules, filled for each
  file:

  | Variable | Value |
  |---|---|
  | `filename` | file name |
  | `filepath` | full path on the device, starting with `/` |
  | `extension` | extension in lower case, with the dot (`.exe`) |
  | `filetype` | THOR-like type mapped from the libmagic MIME type (`EXE`, `ELF`, `ZIP`, `PDF`...), empty when unknown: an approximation of THOR |
  | `owner` | always empty: removable filesystems have no meaningful owner |

- **Verdict mapping**, from the `score` metadata of each matching rule
  (0-100, used by YARA Forge and signature-base):

  | Score | Verdict |
  |---|---|
  | `>= malicious_score` (75) | malicious |
  | `>= suspicious_score` (40) | suspicious |
  | below | informational: recorded in the report (`facts.informational`), no effect on the verdict |
  | no score | `default_score` (60): suspicious |

- **Timeout**: the native YARA-X timeout (`timeout`, seconds); a timeout is an
  error.
- YARA-X compiles rules to native code at run time (wasmtime): it does not
  work under systemd `MemoryDenyWriteExecute=yes`.

YARA does not unpack archives: EICAR inside a zip is detected by ClamAV, not
by YARA.

### File type (libmagic)

`python-magic` (Debian package `python3-magic`) identifies the MIME type and
description from the first MiB of each file, given as a buffer: libmagic does
not access the filesystem and does not decompress. The type is recorded in
the report, used for the YARA `filetype` variable and by the heuristics.

### Heuristics

The structure of the files, without signatures
(`src/pandora_box/engines/heuristics.py`, `[engines.heuristics]`); findings
are suspicious, never malicious:

- **PDF with active content** (like pdfid): JavaScript (`/JavaScript`, `/JS`)
  or a Launch action (`Heuristics.PDF.JavaScript`, `Heuristics.PDF.Launch`).
  Names hidden with escapes (`/J#61vaScript`) are decoded. Automatic actions,
  embedded files and forms (`/OpenAction`, `/AA`, `/EmbeddedFile`,
  `/RichMedia`, `/XFA`, `/AcroForm`) are counted as facts of the report.
  Names inside compressed object streams are not seen: ClamAV and YARA look
  there.
- **Disguised program**: a program (PE, ELF, Mach-O, MSI, from libmagic)
  whose extension claims something else (`facture.pdf`:
  `Heuristics.Executable.Disguised`), or a document extension followed by
  one that Windows runs (`facture.pdf.exe`, `rapport.docx.js`:
  `Heuristics.DoubleExtension`).

The heuristics alone detect no malware: ClamAV or YARA-X stays required.

### Fake engine

`kiosk.fake_scan = true` replaces every engine with the fake engine, for
development only: it reports the EICAR test file as malicious and everything
else as clean.

## Verdict policy

### File verdict

| Engine results | File verdict |
|---|---|
| at least `policy.min_malicious_engines` engines report malicious (default: one) | malicious |
| otherwise, any malicious or suspicious result | suspicious |
| otherwise, any engine error or timeout, a content engine without result, or content engines skipped for another reason than a known file | error |
| otherwise | clean |

A file is never clean unless every enabled content engine scanned it, or
skipped it because it is a known file.

### Device verdict

The worst file verdict: **malicious**, then **suspicious**, then **not
verified** (a file could not be fully scanned, or the walk stopped at a limit),
then **clean**. The kiosk then applies:

| Setting | `block` (default) | `warn` |
|---|---|---|
| `scan.suspicious` | suspicious files are quarantined and removed like malicious ones | they are kept and listed as a warning |
| `scan.on_error` | the device is reported as **NOT VERIFIED: do not use it** | the user is warned |

Files that could not be scanned are listed but **never removed**: they are not
known to be malicious.

A key removed, or enumerated again as a USB device, during its scan is a
**suspicious behavior**: it may have disconnected itself to come back with
another content or as another device (BadUSB). The kiosk checks the USB
device of the key (its sysfs path and device number) before each partition,
every second during the scan and before the verdict. Such a key is **not
verified, whatever `scan.on_error`**: it is neither cleaned, nor copied to a
server, nor quarantined, and the kiosk shows the `key_changed` screen. The
behavior (`removed` or `enumerated_again`) is logged
(`device_suspicious_behavior`), in `device_verdict` and in the report
(`verdict.suspicious_behaviors`, with its reason in
`verdict.incomplete_reasons`). The infected files found before stay in the
report.

### Keys with several partitions

A key is scanned as a whole: all its partitions make one insertion, one
verdict, one report and one confirmation. The kiosk mounts each filesystem
in turn, read-only, and scans it; to clean the key, it mounts read-write only
the partitions that hold the files to remove, then ejects the key once.

- A key with a single filesystem, with or without a partition table, is
  scanned as before.
- A partition that cannot be scanned is a reason of a **not verified**
  device (`scan.on_error`), as a computer may still read it: an encrypted
  partition (LUKS, BitLocker), a partition without a filesystem the kiosk
  recognizes, a filesystem that is not allowed (`device.allowed_filesystems`)
  or that cannot be mounted. Its other partitions are still scanned and
  cleaned. When none can be mounted, the kiosk shows an error.
- Partitions that hold no files are ignored: MBR extended partitions (the
  container of the logical ones), GPT BIOS boot and Microsoft reserved
  partitions.
- On the screen and in the report, a file is named after its partition
  (`sdb2/docs/report.pdf`). The report lists the partitions
  (`device.partitions`: filesystem, size, scanned or why not), and each file
  gives its `partition`, its `path` being relative to the root of that
  partition. The quarantine manifest gives the `partition` of each file too.
- A maintenance, signature or image update device has a single filesystem:
  the folders of such a device are not looked for on a key with several
  partitions, which is scanned.

### Limits

| Setting | Default | Beyond it |
|---|---|---|
| `limits.max_file_size` | 1 GiB | the file is skipped, the device is not verified |
| `limits.max_files` | 100,000 | files and folders; the walk stops, the device is not verified |
| `limits.max_depth` | 64 | deeper folders are skipped, the device is not verified |

### Timeouts

Each worker process scans one file at a time. The kiosk process supervises
them with two deadlines:

- the **engine deadline**: the timeout of the running engine plus 5 seconds;
  engines with a native timeout (YARA-X, the clamd socket) report it first;
- the **file deadline**: `scan.file_timeout` for the whole file.

When a deadline expires, the worker is killed and replaced, and the file is an
error naming the engine. A crashed worker is handled the same way. A clean
answer that arrives after the engine timeout is an error too.

## Signature freshness

At startup, the kiosk warns (logs and screen) when a signature database is
older than `signatures.max_age_days` (7 days), or the `max_age_days` of its
engine (45 days for Hashlookup, published monthly). The date comes from the
`manifest.json` of the signature folder when present
(`{"<file>": {"version", "date", "source", "sha256"}}`), otherwise from the
file modification time; ClamAV reports its own database date. A database
without a date is only logged (`signatures_undated`), not shown: a ClamAV
database of custom signatures only has none (the date comes from the header
of the official `daily` database).

## Scan report

Every scan writes a JSON report in `report.folder`, described by
[`src/pandora_box/schemas/scan-report-v1.schema.json`](https://github.com/sourcentis/pandora-box/blob/main/src/pandora_box/schemas/scan-report-v1.schema.json):
device, configuration, engines and signature versions, every file with its
hashes, type, verdict and per-engine results, the device verdict and the
actions taken. The quarantine manifest references it.
