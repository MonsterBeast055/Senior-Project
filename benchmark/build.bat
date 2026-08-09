@echo off
REM Build the benchmark corpus in four variants.
REM
REM Run from a "x64 Native Tools Command Prompt for VS" (or run vcvarsall first),
REM otherwise cl.exe will not be on PATH.
REM
REM Why four variants: the optimiser changes control flow more than the source
REM does. /Od keeps a recognisable one-to-one shape; /O2 inlines, merges tails,
REM reorders blocks and turns loops inside out. If lifting accuracy holds up on
REM /O2 it will hold up on real binaries - if it only works on /Od, you have
REM measured the wrong thing.

setlocal
cd /d "%~dp0"
if not exist out mkdir out

echo === x64 debug (/Od) - clearest mapping to source ===
cl /nologo /Od /Zi /W3 /Fo:out\ /Fe:out\benchmark_x64_od.exe src\benchmark.c /link /DEBUG

echo === x64 release (/O2) - realistic, this is the one that matters ===
cl /nologo /O2 /W3 /Fo:out\ /Fe:out\benchmark_x64_o2.exe src\benchmark.c

echo === x86 release (/O2) - no .pdata, exercises the fallback path ===
if exist "%VCINSTALLDIR%" (
    echo   skipped: re-run from an x86 Native Tools prompt to build this one
) else (
    echo   skipped
)

echo === x64 release DLL - exports path, and a cleaner function list ===
cl /nologo /O2 /W3 /LD /Fo:out\ /Fe:out\benchmark_x64.dll src\benchmark.c

echo.
echo Done. Artifacts in benchmark\out\
dir /b out\*.exe out\*.dll
endlocal
