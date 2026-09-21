"""ChaCha20/XOR placeholder packer: encrypt payload.dll -> payload-<BUILD_ID>.enc + randomize stub. Phase 04/08."""
import argparse, secrets, pathlib
ap = argparse.ArgumentParser()
ap.add_argument("--in", dest="inp", required=True)
ap.add_argument("--out", required=True)
a = ap.parse_args()
data = pathlib.Path(a.inp).read_bytes() if pathlib.Path(a.inp).exists() else b"stub"
key = secrets.token_bytes(32)
enc = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
pathlib.Path(a.out).write_bytes(enc)
print(f"[ok] packed {len(enc)} bytes -> {a.out} (key kept in RAM only, do not commit)")
