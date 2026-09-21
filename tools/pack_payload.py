"""Pack payload.dll -> payload-<BUILD_ID>.enc (Phase 04).
XOR stream keyed by ASCII of BUILD_ID, repeated. MUST match crypto::DecryptBuildId
(XorInPlace with the BUILD_ID string): byte[i] ^= bid[i % len(bid)].
The loader compiled from the same tree shares the BUILD_ID -> decrypts. Mixing builds
fails closed at ManualMap ("not MZ"). Disk/network scanners see random bytes.
"""
import argparse, pathlib, re, sys

ap = argparse.ArgumentParser()
ap.add_argument("--in", dest="inp", required=True)
ap.add_argument("--out", required=True)
ap.add_argument("--build-id", default="",
                help="hex id; default: parsed from src/common/build_id.h")
ap.add_argument("--header", default="src/common/build_id.h")
ap.add_argument("--map", default="",
                help="linker .map for raw-DllMain resolution; default: <in-dir>/payload.map. "
                     "Copied next to the .enc (same basename) so the loader finds it. "
                     "Without it the loader falls back to the CRT entry, which is known-fragile.")
a = ap.parse_args()

bid = a.build_id
if not bid:
    h = pathlib.Path(a.header)
    if not h.exists():
        sys.exit(f"no --build-id and {a.header} missing (run gen_build_id.py first)")
    m = re.search(r'"([0-9a-fA-F]+)"', h.read_text())
    if not m:
        sys.exit(f"could not parse BUILD_ID from {a.header}")
    bid = m.group(1)

data = pathlib.Path(a.inp).read_bytes()
key = bid.encode("ascii")
enc = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
out = pathlib.Path(a.out)
out.write_bytes(enc)
print(f"[ok] packed {len(enc)} bytes build={bid} -> {out}")
print("verify: first bytes", enc[:4].hex(), "(must NOT be 4d5a)")

mapp = pathlib.Path(a.map) if a.map else pathlib.Path(a.inp).parent / "payload.map"
sidecar = out.with_suffix(".map")
if mapp.exists():
    sidecar.write_bytes(mapp.read_bytes())
    print(f"[ok] sidecar map -> {sidecar} (raw-DllMain resolution)")
else:
    print(f"[warn] no map at {mapp}: loader will use CRT-entry fallback")
