@echo off
setlocal EnableDelayedExpansion
REM VacSafe full build: IDs -> strings -> configure -> compile -> pack.
REM Proven toolchain: VS2022 BuildTools + CMake + Ninja (winget).
for /f "tokens=2 delims==" %%i in ('python tools\gen_build_id.py --header src\common\build_id.h ^| findstr BUILD_ID') do set BID=%%i
if "!BID!"=="" echo [fail] gen_build_id failed & exit /b 1
echo BUILD_ID=!BID!
python tools\gen_strings.py || exit /b 1
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >NUL || exit /b 1
cmake -S . -B build\x64 -G Ninja -DCMAKE_BUILD_TYPE=Release -DVACSAFE_BUILD_TESTS=ON -DVACSAFE_BUILD_DRIVER=OFF || exit /b 1
cmake --build build\x64 --config Release || exit /b 1
python tools\hash_imports.py || exit /b 1
python tools\pack_payload.py --in build\x64\src\payload\payload.dll --out build\x64\payload-!BID!.enc || exit /b 1
echo [ok] x64 build done BID=!BID!
