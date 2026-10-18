#!/usr/bin/env python3
"""Verify bfme-beacon/patches/openbfme-bundle.json against the Open-BFME build.

Two modes:

  file    (default) -- Reconstruct the full dist executable from a COPY of the
          base exe in a temp dir: append the .bfmemod section, apply every
          header change and every feature code site, then assert the result is
          byte-for-byte identical to mods/dist/lotrbfme.exe (and sha256 equal).
          This proves the JSON is a complete, exact description of the dist build.

  memory [--features a,b,...] -- Simulate the in-process hook. Build a sparse
          memory image (NO file is written): map the base exe at its ImageBase
          and reserve the cave VA range. For the chosen subset only, assert each
          site's ORIGINAL bytes are present in the live image BEFORE patching
          (the hook's safety gate), then install the 5-byte jmp / imm32 poke and
          place that feature's cave bytes + the shared mod bus. Finally check the
          detour at each site jumps into placed cave, and that re-applying a
          feature now FAILS the original-bytes gate (so a double-apply is caught).

Inputs (not part of this repository): the vanilla workshop-1.03 lotrbfme.exe and
Open-BFME's mods/dist/lotrbfme.exe. Pass --openbfme <Open-BFME-1 checkout> (or set
OPENBFME_DIR), or name the files with --base/--dist. Exit code 0 on pass.

License of the described artifact: GPL-3.0 (Open-BFME,
https://github.com/Open-BFME/Open-BFME-1).
"""
import argparse
import base64
import hashlib
import json
import os
import shutil
import struct
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
JSON = os.path.join(HERE, 'openbfme-bundle.json')
# Relative to an Open-BFME-1 checkout; overridden by --base/--dist (see main()).
BASE_REL = os.path.join('inputs', 'baselines', 'bfme1', 'workshop-vanilla-1.03', 'files', 'lotrbfme.exe')
DIST_REL = os.path.join('mods', 'dist', 'lotrbfme.exe')
BASE = None
DIST = None


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def load_json():
    with open(JSON, 'rb') as f:
        return json.load(f)


def apply_at(img, offset, original_hex, patched_hex, what):
    """Assert the original bytes are present, then write the patched bytes."""
    orig = bytes.fromhex(original_hex)
    patched = bytes.fromhex(patched_hex)
    have = bytes(img[offset:offset + len(orig)])
    if have != orig:
        raise AssertionError(
            f"{what}: original-byte check FAILED at offset 0x{offset:X}: "
            f"expected {orig.hex()}, found {have.hex()}")
    img[offset:offset + len(patched)] = patched


def mode_file(ps):
    base = open(BASE, 'rb').read()
    dist = open(DIST, 'rb').read()
    assert sha256(base) == ps['source']['base_sha256'], 'base exe sha256 mismatch vs JSON'
    assert sha256(dist) == ps['source']['dist_sha256'], 'dist exe sha256 mismatch vs JSON'

    tmp = tempfile.mkdtemp(prefix='bfme-verify-')
    try:
        work = os.path.join(tmp, 'lotrbfme.exe')
        shutil.copyfile(BASE, work)
        img = bytearray(open(work, 'rb').read())
        assert len(img) == ps['source']['base_size']

        # 1) append the .bfmemod section raw bytes at its file offset.
        sec = ps['sections'][0]
        raw = base64.b64decode(sec['data_b64'])
        assert sec['file_offset'] == len(img), 'section does not append at EOF'
        assert len(raw) == sec['raw_size']
        img.extend(raw)

        # 2) header changes (section table entry + SizeOfImage/NumberOfSections/CheckSum).
        for h in ps['header_changes']:
            apply_at(img, h['offset'], h['original_hex'], h['patched_hex'], 'header ' + h['desc'])

        # 3) feature code sites (detours + the retrytime imm32 poke).
        nsites = 0
        for feat in ps['features']:
            for s in feat['sites']:
                apply_at(img, s['file_offset'], s['original_hex'], s['patched_hex'],
                         f"{feat['id']} site VA 0x{s['va']:X}")
                nsites += 1

        # 4) verify SizeOfImage / NumberOfSections are internally consistent.
        e_lfanew = struct.unpack_from('<I', img, 0x3c)[0]
        nsec = struct.unpack_from('<H', img, e_lfanew + 6)[0]
        soi = struct.unpack_from('<I', img, e_lfanew + 24 + 56)[0]
        assert nsec == 8, f'NumberOfSections {nsec} != 8'
        assert soi == sec['va'] - ps['image_base'] + sec['virtual_size'], 'SizeOfImage inconsistent'

        out = bytes(img)
        os.remove(work)  # no patched exe is left on disk
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if out != dist:
        # locate first difference for diagnosis
        for i in range(min(len(out), len(dist))):
            if out[i] != dist[i]:
                raise AssertionError(f'reconstruction differs from dist at offset 0x{i:X}: '
                                     f'got {out[i]:02x} want {dist[i]:02x}')
        raise AssertionError(f'length mismatch: got {len(out)} want {len(dist)}')
    assert sha256(out) == ps['source']['dist_sha256']
    print(f"[file]   PASS  reconstructed dist byte-for-byte from base "
          f"({len(ps['header_changes'])} header changes, {nsites} feature sites, "
          f"1 appended section). sha256 {sha256(out)[:16]}... matches.")


def mode_memory(ps, chosen):
    IB = ps['image_base']
    base = open(BASE, 'rb').read()
    assert sha256(base) == ps['source']['base_sha256']

    # Mapped main image: for the patched code sections raddr==vaddr, so a byte at
    # VA v (< IB+base_size region covered by raddr==vaddr) lives at base[v-IB].
    image = bytearray(base)                       # indexable by RVA == VA-IB
    image_hi = IB + len(base)

    # Cave: a fresh RWX region at the fixed VA, all zero (as VirtualAlloc gives),
    # then we place only the chosen features' ranges + the always-present mod bus.
    sec = ps['sections'][0]
    cave_va = sec['va']
    cave = bytearray(sec['virtual_size'])         # zero-filled, like committed pages
    cave_src = base64.b64decode(sec['data_b64'])  # the authoritative cave content
    placed = []                                   # (start_va, end_va) actually committed/written

    def place(va0, va1):
        for off in range(va0 - cave_va, va1 - cave_va):
            cave[off] = cave_src[off]
        placed.append((va0, va1))

    # The mod bus (first 0x40 bytes) is shared and always present when any cave feature is on.
    feats = {f['id']: f for f in ps['features']}
    cave_features = [c for c in chosen if feats[c]['cave_ranges']]
    if cave_features:
        place(sec['mod_bus_va'], sec['mod_bus_va'] + sec['mod_bus_size'])

    def read_live(va, n):
        if IB <= va < image_hi and va + n <= image_hi:
            off = va - IB
            return bytes(image[off:off + n])
        if cave_va <= va < cave_va + len(cave):
            off = va - cave_va
            return bytes(cave[off:off + n])
        raise AssertionError(f'VA 0x{va:X} not mapped')

    def write_live(va, blob):
        off = va - IB
        image[off:off + len(blob)] = blob

    npatched = 0
    for fid in chosen:
        feat = feats[fid]
        # place this feature's cave payload + shims
        for (va0, va1) in feat['cave_ranges']:
            place(va0, va1)
        # safety gate + patch every site
        for s in feat['sites']:
            have = read_live(s['va'], s['length'])
            orig = bytes.fromhex(s['original_hex'])
            if have != orig:
                raise AssertionError(f"{fid} VA 0x{s['va']:X}: pre-patch original bytes "
                                     f"{have.hex()} != expected {orig.hex()}")
            write_live(s['va'], bytes.fromhex(s['patched_hex']))
            npatched += 1

    # Every detour's jmp rel32 must now land inside placed cave (the poke has none).
    def in_placed(va):
        return any(a <= va < b for a, b in placed)

    jmps = 0
    for fid in chosen:
        for s in feats[fid]['sites']:
            patched = bytes.fromhex(s['patched_hex'])
            if patched and patched[0] == 0xE9:            # jmp rel32 detour
                disp = struct.unpack_from('<i', patched, 1)[0]
                target = (s['va'] + 5 + disp) & 0xFFFFFFFF
                if not in_placed(target):
                    raise AssertionError(f"{fid} VA 0x{s['va']:X}: jmp target 0x{target:X} "
                                         f"is not in placed cave")
                # the target must be the start of one of this feature's cave ranges
                # (its detour blob: generated shim + relocated prologue + jmp back).
                starts = {a for a, _ in feats[fid]['cave_ranges']}
                assert target in starts, (f"{fid}: jmp 0x{target:X} is not a cave-range "
                                          f"start of this feature {sorted(hex(x) for x in starts)}")
                jmps += 1

    # Double-apply must be caught by the gate: re-patching a site now finds the jmp, not the original.
    caught = 0
    for fid in chosen:
        for s in feats[fid]['sites']:
            have = read_live(s['va'], s['length'])
            if have != bytes.fromhex(s['original_hex']):
                caught += 1
    total_sites = sum(len(feats[f]['sites']) for f in chosen)
    assert caught == total_sites, 'a re-apply would not be caught by the original-byte gate'

    print(f"[memory] PASS  subset {chosen}: {npatched} sites gated+patched, "
          f"{jmps} detours land in placed cave, {len(placed)} cave ranges committed, "
          f"double-apply blocked on all {total_sites} sites. No file written.")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('mode', nargs='?', default='file', choices=['file', 'memory', 'both'])
    ap.add_argument('--features', default=None,
                    help='comma-separated feature ids for memory mode (default: all 7)')
    ap.add_argument('--openbfme', default=os.environ.get('OPENBFME_DIR'),
                    help='Open-BFME-1 checkout (default: $OPENBFME_DIR)')
    ap.add_argument('--base', help='vanilla workshop-1.03 lotrbfme.exe')
    ap.add_argument('--dist', help="Open-BFME's mods/dist/lotrbfme.exe (file mode)")
    a = ap.parse_args()
    global BASE, DIST
    root = a.openbfme
    BASE = a.base or (root and os.path.join(root, BASE_REL))
    DIST = a.dist or (root and os.path.join(root, DIST_REL))
    if not BASE or (a.mode in ('file', 'both') and not DIST):
        ap.error('pass --openbfme <Open-BFME-1 checkout> (or set OPENBFME_DIR), or --base/--dist')
    ps = load_json()
    assert ps['license'].startswith('GPL-3.0'), 'license field missing'

    if a.mode in ('file', 'both'):
        mode_file(ps)
    if a.mode in ('memory', 'both'):
        allids = [f['id'] for f in ps['features']]
        chosen = a.features.split(',') if a.features else allids
        bad = [c for c in chosen if c not in allids]
        if bad:
            sys.exit(f'unknown feature(s): {bad}; known: {allids}')
        mode_memory(ps, chosen)
    print('OK')


if __name__ == '__main__':
    main()
