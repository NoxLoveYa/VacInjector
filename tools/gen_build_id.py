"""Generate per-build BUILD_ID header. Phase 08."""
import argparse, secrets, pathlib
ap = argparse.ArgumentParser()
ap.add_argument("--header", default="src/common/build_id.h")
a = ap.parse_args()
bid = secrets.token_hex(8)
pathlib.Path(a.header).write_text(f'#pragma once\n#define VACSAFE_BUILD_ID "{bid}"\n')
print(f"BUILD_ID={bid}")
