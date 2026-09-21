@echo off
setlocal
python tools\gen_build_id.py --header src\common\build_id.h || exit /b 1
cmake --preset x64-release || exit /b 1
cmake --build build\x64 --config Release || exit /b 1
python tools\pack_payload.py --in build\x64\src\payload\payload.dll --out build\x64\payload-%BUILD_ID%.enc || echo [warn] payload pack skipped (build payload first)
echo [ok] x64 build done
