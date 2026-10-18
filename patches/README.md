# patches — Open-BFME patch bundle

`openbfme-bundle.json` describes the Open-BFME mod build of `lotrbfme.exe` as an
**in-memory** patch set for the vanilla 1.03 executable: short original/patched
byte sequences at the patch sites, ten PE header changes, and the Open-BFME code
cave (`.bfmemod` section, base64). Beacon never writes these patches to the exe on
disk (BFME checks the exe's CRC when players join a LAN game); the hook DLL is
meant to apply them in the running process (architecture §10, not used yet).

## License and origin

The bundle is derived from [Open-BFME](https://github.com/Open-BFME/Open-BFME-1)
and is distributed under the **GNU General Public License, version 3** (field
`license` in the JSON). The corresponding source of the code cave is Open-BFME-1 at
commit `4d67f95f0502ec924fdcc67939e98d8e67be7761` (field `source.open_bfme_commit`;
the features are listed in `features[].id`). The bundle contains no other game data;
Open-BFME publishes the same patch sites and cave in its repository.

## Verification

`verify_patchset.py` checks the JSON against an Open-BFME checkout. It needs two
files that are **not** part of this repository: the vanilla workshop 1.03
`lotrbfme.exe` (sha256 `c1a907c4…`) and Open-BFME's `mods/dist/lotrbfme.exe`.

```sh
python patches/verify_patchset.py both --openbfme /path/to/Open-BFME-1
python patches/verify_patchset.py memory --base lotrbfme.exe --features 033-retrytime
```

`file` mode rebuilds the mod exe byte for byte in a temporary folder (and deletes
it); `memory` mode simulates the hook in a sparse memory image and writes no file.
