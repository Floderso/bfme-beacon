# Mod support: lobby game configurations

Status: v1 (2026-10-18). Background research: spec 10 ("BFME Workshop mods in
Beacon", not part of this repository). User guide (German):
[`docs/anleitung/spielen.md`](../anleitung/spielen.md#mods-spielen).

## 1. What it does

The lobby host picks a BFME1 package configuration, for example "Patch 2.22
7.0.5" or "Legends of the 3rd Age 0.5.2 (+ Patch 1.06)", and a language
variant. Every player's Beacon then prepares exactly that set of files and starts
BFME from a Beacon-managed **instance folder**. The real installation
(`C:\BFME1`, managed by the BFME All-In-One launcher, "AIO") is never written.
Without a selection the lobby is **vanilla**: everybody plays with their own
installation, exactly as before.

```
host UI ──select──▶ Beacon (host): resolve from the AIO library ──set_game_config──▶ beacon-server
                                                                                         │ validate, store,
                    ┌────────────────────────── game_config ◀────────────────────────────┘ broadcast
                    ▼
every Beacon: store check → import (AIO cache, game folder, user folders) → [workshop download]
              → instance folder (hardlinks) → status.config = ready ──▶ lobby shows ✓ per player
host "Alle starten" ── refused (not_ready) until every player reports ready for the configuration id
```

## 2. Why instance folders (and not `-mod`)

Spec 10 §5–§7: every popular BFME1 patch and mod ships `GameData.ini` (often
also `Default\GameData.ini` and `SubsystemLegend.ini`), which the engine parses
before it mounts `-mod` archives; several packages replace or blank out
lower-layer archives by name. `-mod` cannot express either, and the AIO itself
installs everything except type-1 packages into the game folder. A folder that
contains exactly the AIO's file set for a configuration reproduces the AIO's
mount order (so the INI CRC should match an AIO user's, see §9). Type-1
packages use a sibling folder passed with `-mod`, as the AIO does.

## 3. Protocol (`beacon-proto::control`)

* `GameConfig { id, guid, version, name, author, language, layers[], files[] }`
  * `files[]`: the **expected file set**, `{path, md5, size, dir?}`, sorted by
    `(dir, path)`. `path` is normalised like the AIO writes it (lower case,
    `\`, ≤ 8 components, every component a safe Windows file name); `dir` is
    `game` (default, omitted) or `mod`; `size` 0 = unknown (the workshop's sizes
    are unreliable, spec 10 §2.3). Clients prepare and verify against this set
    without fetching any manifest.
  * `layers[]`: every package, highest priority first (enhancement, package,
    type-0 dependencies, base game) with guid, version, name, author and type:
    attribution, and the manifests to fetch when downloads are enabled.
  * `id` = the first 32 hex digits of BLAKE3 (derive-key context
    `BFME Beacon 2026-10-18 game configuration v1`) over the sorted files as
    `dir ('g'|'m') ‖ path ‖ 0x00 ‖ md5 ‖ '\n'`. Sizes, names and the language
    are not part of it: the same files make the same instance folder.
  * `validate()`: ≤ 512 files (the base game plus Patch 1.06 has 352; 512 typical
    entries fit into one 60 KiB message), ≤ 16 layers, ≤ 4 GiB per file,
    ≤ 64 GiB in total, no duplicates or file/folder clashes, no `wsock32.dll` at
    the top of the game folder (Beacon's hook), well-formed guid, version,
    language (`EN`, `DE`, …), MD5s and display texts, and `id` must match.
* `ConfigStatus { id, state, progress?, missing?, text? }`: a player's readiness
  (`ready`, `preparing`, `missing`, `error`) for a configuration id or `vanilla`.
* Messages: `welcome.features` (`["game_config"]`), `set_game_config{config}`
  (host; `null` = vanilla), `game_config{config, by}` (after the login and after
  every change), `status.config`, `lobby.players[].config`, error `not_ready`.
* Compatibility: all new fields are optional and skipped when empty; unknown
  message types decode to `Unknown`. An older launcher ignores `game_config`
  and never reports readiness (shown as "keine Rückmeldung"; `launch_all` waits
  for it while a configuration is set). An older server ignores
  `set_game_config`; the launcher sees no `game_config` feature and stays at
  vanilla (the UI says the server is too old).

## 4. Server (`beacon-server`)

* `set_game_config`: host only; `GameConfig::validate`; at most one change per
  2 s (`CONFIG_COOLDOWN`); the same configuration again is a no-op; the message
  is encoded once and fanned out through a watch channel (every connection gets
  the latest one, also after a login); a chat notice names host and package.
* A change clears every ready flag and readiness report.
* `status.config` is sanitised (id format, progress ≤ 100, text ≤ 200 chars
  without control characters). Readiness state changes are published at once,
  percentages with the periodic lobby refresh.
* `launch_all` with a configuration: refused with `not_ready` and a German list
  ("Sam (bereitet vor, 40 %)", "Pippin (keine Rückmeldung …)") until every player
  reports `ready` for the configuration's id.
* Memory only: a restarted server starts at vanilla; the host selects again.
* `/status`: `server.game_config` summary and `players[].config`.

## 5. Launcher (`beacon-launcher::mods`)

### 5.1 Folders

All below one root (default `%APPDATA%\Beacon\mods`, setting `mods.dir`), so the
store and the instances share a volume:

```
store\<md5>                     verified files, read-only, owned by Beacon
store\index.json                md5 → size, BLAKE3
instances\<id>\game\            the game folder of a configuration (BFME starts here)
instances\<id>\mod\             the -mod folder of a type-1 package
instances\<id>\instance.json    record (complete, link mode, md5s), written last
downloads\<md5>.part            unfinished downloads (Range resume)
workshop\manifests\<guid>@<version>.json   fetched manifests (fetched once)
```

`instance.json` sits beside `game\` because the engine mounts every `*.big`
below the game folder recursively (spec 04 §6.2).

### 5.2 Store

A file enters only after MD5 (and the size, if known) was computed over exactly
the bytes written: copy into a temporary sibling while hashing, flush, rename.
Entries get the read-only attribute (spec 10 R10-1). Beacon links only to
files it owns; it never links to the AIO's game folder, which the AIO rewrites
in place (spec 10 §6.2). The index also stores BLAKE3, which seeds the
fingerprint cache of a fresh instance (no second pass over gigabytes).

### 5.3 Instance folders

A probe hardlink between `store\` and `instances\` decides between NTFS
hardlinks (no extra space) and copies (FAT32/exFAT, network shares, another
volume: the UI says so and shows the extra space). A failing hardlink during
the build switches the rest to copies. Building is incremental and in place:
matching files (same size and modification time as the store file) are kept,
others are linked to a temporary sibling and renamed over, everything not in the
configuration is removed except the hook DLL and `UserData\` (user maps with
`UseLocalUserMaps`). A forced delete of a read-only hardlink clears the shared
attribute, so the store's files are protected again afterwards. The hook DLL is
installed into the instance's game folder at launch (same rules as before:
marker check, temp + rename).

### 5.4 Resolution (host)

Sources: the AIO's library `%APPDATA%\BFME Workshop\Library\*.json` and
`Config\active_patch_0.json` (read-only, ≤ 8 MiB per manifest), plus Beacon's
manifest cache. Every BFME1 patch, mod and enhancement becomes a catalog entry;
entries that cannot be resolved carry the reason (e.g. a missing dependency).

The AIO's rules (spec 10 §3 step 5, R10-2): L1 the selected enhancement, L2 the
package it builds on (or the selected package), L3 type-0 dependencies
(breadth-first, `guid:version` pins honoured, otherwise the library's version),
L4 `original-BFME1`. Per layer every file is skipped if its name is one the AIO
ignores (`_zzlotr.big`, `mod.txt`, `timer_frame.png`), if it is a `.wps` script,
or if its language list is neither `ALL`/empty nor contains the chosen language.
Destination = folder + lower-cased name; the first layer that names a
destination wins. Sizes the manifests leave at 0 are filled from the host's store
index when known. Language variants offered = every code of a language-specific
file; default = the host's game language (registry `Language`), else `EN`.

Checked against the user's real library: the file counts and sizes of the
catalog equal spec 10 §4's "Config" column (Patch 1.06 352 files / 3.61 GB,
LOT3A 368 / 4.58 GB, Patch 2.22 351 / 3.85 GB, SaF 353 / 5.36 GB, MEE 361 /
4.39 GB, Edain 351 / 3.54 GB, SuB 352 / 3.38 GB, base 346 / 3.26 GB).

### 5.5 Import from the user's own files

For every file of the configuration the store lacks, in this order:

1. the AIO caches `<parent of the game folder>\BFME Workshop\Cache\<md5>.pfcache`
   and `%APPDATA%\BFME Workshop\Cache\<md5>.pfcache`;
2. the game folder (registry or setting) and the user-added folders at the
   file's own relative path;
3. the same folders searched (≤ 8 levels, ≤ 200 000 entries each, links and
   junctions not followed, Beacon's own folder excluded) for files of the right
   size, or of the right name where the size is unknown.

Every candidate is copied into the store and kept only if its MD5 matches.
Sources are only read.

**Executables** (`.exe`, `.dll`, `.asi`, Miles `.m3d`/`.flt`/`.mix`, scripts, …)
are only ever taken from the user's own installation **at the same relative path
with the same MD5**: never from a cache, a search by MD5 or a download. So the
base game's `lotrbfme.exe` always comes from the user's install, and a lobby host
cannot make a known DLL appear under another name.

### 5.6 Workshop downloads (`workshop_downloads`, off)

Implemented and tested against a local fake server, but **unavailable** in this
build: `mods::WORKSHOP_DOWNLOADS_AVAILABLE = false`, so the setting cannot be
switched on (API: `invalid_input`; UI: disabled with "Wartet auf die Zustimmung
des BFME-Foundation-Teams") and the real API and CDN are never contacted. Tests
inject an endpoint (`AppOptions::workshop`). When the BFME Foundation Team
agrees, flip the constant and enable the checkbox.

Behaviour when enabled (spec 10 R10-3 … R10-6):

* `GET <api>/workshop/download?guid=<guid>:<version>` with the AIO's anonymous
  headers (`AuthAccountUuid: unauthenticated`, empty `AuthAccountPassword`) and
  `User-Agent: BFME-Beacon/<version> (+https://github.com/Floderso/bfme-beacon)`;
  each `guid:version` is fetched **once** and cached on disk (every fetch counts
  as a download on the workshop); the answer must be that exact version; only
  manifests of the configuration's non-base layers are fetched.
* Files: only URLs from those manifests, only below the files host, exactly
  `<owner>/<md5>` with the expected MD5; never base-game files, never
  executables; at most **2** parallel downloads; `Range` resume from
  `downloads\<md5>.part`; exponential back-off (1 s · 2ⁿ, ≤ 60 s, + ≤ 25 %
  jitter, `Retry-After` honoured up to 300 s) on 408/429/5xx and network
  errors, 6 attempts; other 4xx fail at once; `Content-Length` must match the
  expected size; nothing beyond the expected size (or 4 GiB when unknown) is
  read; MD5 verified before the file enters the store, a corrupt file is deleted
  and fetched again; no redirects, no cookies, no decompression
  (`Content-Encoding` other than identity is refused). Files are never
  re-hosted.
* Transport: WinHTTP through `windows-sys` (`sys/winhttp.rs`): the system's TLS
  stack, certificate store and proxy; no TLS crate (`ring`/OpenSSL) in the
  dependency graph. Behind the `HttpTransport` trait.

### 5.7 Preparation and readiness

One preparation at a time, on its own thread, cancelled when the lobby's
configuration changes, on user request and at shutdown: validate the
configuration again; reuse a complete instance at once (quick metadata check);
**free-space check** (imports + downloads + instance copies + 512 MiB margin);
import; downloads (if enabled); executable check; link. The result is reported
as `status.config` (`preparing n %` → `ready` / `missing n` with the first file
names / `error`) and shown in the UI with the missing files and hints ("install
it once in the AIO, then 'Erneut prüfen'", "Dateien aus Ordner importieren").

### 5.8 Launch, fingerprint, maps

* With a configuration, `launch_game` requires the ready instance of that id
  (`not_ready` otherwise), installs the hook DLL there, starts
  `instances\<id>\game\lotrbfme.exe` with cwd there, and adds
  `-mod "<instances\<id>\mod>"` for type-1 packages.
* The fingerprint covers the folders BFME starts from (instance game folder +
  `mod\` as `mod/<path>`), seeded from the store's BLAKE3 hashes. The hash cache
  keeps entries of folders that are fingerprinted in turn (real installation,
  instances) instead of pruning them on every switch.
* With `UseLocalUserMaps` the user-map folder follows the instance
  (`<instance>\game\UserData\Maps`); otherwise maps stay in the user folder,
  which all instances and the AIO share (spec 10 §6.2).

### 5.9 Storage and clean-up

The UI shows the folder, stored files and size, free space, link mode and the
instance folders. "Aufräumen" removes instance folders other than the lobby's
current one (and the one a running game uses), then store files no remaining
instance needs (not while a preparation runs), and unfinished downloads.

### 5.10 CLI

`Beacon.exe mods list` prints the catalog; `Beacon.exe mods prepare
GUID@VERSION [--language XX] [--import DIR]... [--mods-dir DIR]` builds that
configuration's instance from local files only (never downloads) and prints the
result as JSON.

## 6. Safety rules (summary)

* Every name from a manifest or the network is normalised and checked
  (`is_safe_package_path`: no `..`, roots, drives, UNC, `:` streams, reserved
  device names, trailing dots/spaces, control characters, ≤ 255 bytes, ≤ 8
  components); MD5s, guids, versions and texts are bounded; the hook's name is
  reserved; configuration bounds are enforced by the server and again by every
  client.
* Bounded inputs: manifests ≤ 8 MiB and ≤ 4096 files, configurations ≤ 512 files,
  files ≤ 4 GiB, scans ≤ 200 000 entries, status texts ≤ 200 characters.
* Atomic writes (temporary sibling + rename) for store entries, instance files,
  records, the index, cached manifests and settings.
* Never written: the AIO's folders, the game installation, user-added import
  folders, the LOT3A copy or any other source. Never linked to: anything Beacon
  does not own.
* Free-space check before copying; cancellation at every file and every read.

## 7. Deviations from spec 10 and why

| Spec 10 | Here | Why |
|---|---|---|
| R10-1: "vanilla" is an instance too | vanilla = the current installation, no instance | Task decision: vanilla stays exactly as before (hook in the game folder); instances only for selected configurations. A "Vanilla (1.03)" package entry exists for a pure-1.03 instance. |
| §6.5: config hash over INI-relevant files only, so different game languages can play together | the full file set incl. the chosen language variant | Task decision: the host decides the language variant; every client prepares identical files. Players whose installation lacks that language's base files need them from a folder or the AIO. |
| §6.4 (d): delegate to the AIO and link from `C:\BFME1` ("b-lite") | copy from the AIO's folders into Beacon's store | Never link to files the AIO rewrites in place; the store also keeps working after the AIO switches patches. Costs one copy of each file. |
| R10-2: `IgnoredGameFiles` incl. intro-movie names | only `_zzlotr.big`, `mod.txt`, `timer_frame.png` | The intro-movie names were not recorded and occur in no BFME1 manifest seen. |
| §3 step 9: keybind archives from `Keybinds\<Game>-<Name>\` | not copied | User preference (`Lang\…\CommandMap.ini` is not CRC'd); the folders are empty on the dev PC. |
| §6.2: AppCompat `~ WINXPSP3` for the instance exe | not set | Q10-4 open; no registry writes without evidence that it is needed. |
| R10-5: listing queries with a 10-minute cache | no workshop browser; the catalog comes from the AIO library and the manifest cache | Not needed while downloads are off; avoids API traffic. |
| Type 3 (map packs), type 4 (snapshots), `package.wps` scripts | not supported | Map packs go into the shared user folder; snapshots are local; no BFME1 package uses scripts. |
| Executables | only from the user's installation at the same path | Stricter than the spec: a malicious host cannot place a known DLL under another name. |

## 8. Tests

* `beacon-proto`: JSON shapes, round trips, backward compatibility (old
  welcome/lobby/status, an old launcher's view of `game_config`), validation
  rules, id properties, status sanitising, the largest configuration fits.
* `beacon-server` (`tests/server.rs`): validation, broadcast, cool-down, late
  joiners, `/status`; readiness gating of `launch_all`, reset on change, reports
  for an old configuration, malformed reports; restart → vanilla.
* `beacon-launcher` unit tests: store (verification, read-only, index,
  tampering, temporaries), instances (hardlinks with a real NTFS probe, strays,
  UserData and hook kept, repair, copy mode, `-mod` folder, cancellation),
  manifest parsing with synthetic manifests shaped like the real ones (no real
  data in the repository), library reading (read-only), AIO resolution and
  catalog, import by MD5 (caches, same path, size search, renamed files,
  rejected candidates, executables, sources unchanged), preparation, readiness
  pacing, settings, CLI.
* `tests/mods.rs` (Windows, WinHTTP against a local fake HTTP server, never the
  real workshop): manifest cache + User-Agent, Range resume, corrupt downloads,
  back-off and 4xx, the 2-download limit, size limits, URL checks,
  cancellation; and an in-process lobby: two launchers and a real server agree
  on a configuration, the guest imports and downloads, `launch_all` is refused
  until both are ready, both instances are identical, back to vanilla,
  clean-up, the installations and the library unchanged.
* `tests/web.rs`: the new API routes and their validation.

## 9. Open issues

* **INI CRC (spec 10 Q10-2, §10):** that a Beacon instance yields the same INI
  CRC (GlobalData+0xBC8) as an AIO install of the same configuration is
  inferred from "same files, same mount order", not measured. Verify once with
  the hook reporting the CRC in both setups; until then the lobby's fingerprint
  comparison and BFME's own join check remain the safety net.
* **Read-only data files (Q10-3):** the store's files (and through hardlinks the
  instance's) are read-only; one launch test must confirm BFME is fine with
  that. If not, drop the attribute (`fsx::set_readonly` in `store.rs`) and rely
  on MD5 checks.
* **AppCompat layer (Q10-4)** for the instance exe: not set; check with a launch.
* **Workshop permission (Q10-1):** downloads stay off until the BFME Foundation
  Team agrees (then flip `WORKSHOP_DOWNLOADS_AVAILABLE`, ideally also ask whether
  manifest fetches should count as downloads, Q10-6 about immutable versions).
* **Shared user data:** all instances and the AIO share `Options.ini`, user maps
  (unless `UseLocalUserMaps`) and replays (spec 10 §6.2).
* **The AIO kills BFME when it syncs** (spec 10 §6.2): the user guide warns not
  to switch versions in the AIO during a Beacon game.
* **Language variants:** a host's language choice that a guest's installation
  lacks (e.g. German base archives on an English install) can only be satisfied
  from a folder or the AIO (base files are never downloaded).
* The first fingerprint of a fresh instance without store hashes (e.g. after a
  manual repair) reads the whole instance once (BLAKE3).
