#!/usr/bin/env python3
r"""Verify a built beacon-hook wsock32.dll against the system's 32-bit wsock32.dll.

Checks (exit code 1 on any failure):

* the DLL is an i386 PE (machine 0x14c);
* exactly the same named exports with the same ordinals, no extra or unnamed ones;
* every export that is a forwarder in the system DLL and not implemented by the
  hook is a forwarder with the identical target string;
* the 27 implemented exports (gen_def.IMPLEMENTED) are code, not forwarders;
* the DLL's imports: ws2_32 is imported, wsock32 is never imported (no
  self-reference), and the DllMain-relevant import set is printed for review.

Usage:
    python crates/beacon-hook/tools/check_exports.py <built wsock32.dll> [system wsock32.dll]
"""
import sys
from pathlib import Path

import pefile

sys.dont_write_bytecode = True  # keep tools/ free of __pycache__
sys.path.insert(0, str(Path(__file__).resolve().parent))
from gen_def import DEFAULT_SYSTEM_DLL, IMPLEMENTED, read_exports  # noqa: E402


def imports_of(path: str):
    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
    )
    return {
        d.dll.decode("ascii").lower(): [
            (i.name.decode("ascii") if i.name else f"#{i.ordinal}") for i in d.imports
        ]
        for d in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])
    }


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    built, system = sys.argv[1], (sys.argv[2] if len(sys.argv) > 2 else DEFAULT_SYSTEM_DLL)
    errors = []
    pe = pefile.PE(built, fast_load=True)
    if pe.FILE_HEADER.Machine != 0x14C:
        errors.append(f"machine {pe.FILE_HEADER.Machine:#x}, expected i386 (0x14c)")
    pe.close()

    want = {name: (ordinal, fwd) for ordinal, name, fwd in read_exports(system)}
    try:
        have_list = read_exports(built)
    except SystemExit as e:  # unnamed export etc.
        print(f"FAIL: {e}")
        return 1
    have = {name: (ordinal, fwd) for ordinal, name, fwd in have_list}

    for name in sorted(set(want) - set(have)):
        errors.append(f"missing export {name} @{want[name][0]}")
    for name in sorted(set(have) - set(want)):
        errors.append(f"extra export {name} @{have[name][0]}")
    for name in sorted(set(want) & set(have)):
        (w_ord, w_fwd), (h_ord, h_fwd) = want[name], have[name]
        if w_ord != h_ord:
            errors.append(f"{name}: ordinal {h_ord}, system has {w_ord}")
        if name in IMPLEMENTED:
            if h_fwd is not None:
                errors.append(f"{name}: implemented export is a forwarder to {h_fwd}")
        elif h_fwd != w_fwd:
            errors.append(f"{name}: forwarder {h_fwd!r}, system forwards to {w_fwd!r}")

    imports = imports_of(built)
    if "ws2_32.dll" not in imports:
        errors.append("ws2_32.dll is not imported")
    if "wsock32.dll" in imports:
        errors.append("the proxy imports wsock32.dll (itself)")

    implemented = sum(1 for n in have if n in IMPLEMENTED)
    forwarders = sum(1 for n, (_, f) in have.items() if f is not None)
    print(f"{built}: {len(have)} named exports ({implemented} implemented, {forwarders} forwarders)")
    print("imports: " + ", ".join(f"{dll} ({len(funcs)})" for dll, funcs in sorted(imports.items())))
    if errors:
        for e in errors:
            print("FAIL:", e)
        return 1
    print(f"OK: names, ordinals and forwarders identical to {system}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
