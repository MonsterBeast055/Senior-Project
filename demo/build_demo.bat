@echo off
rem ===========================================================================
rem  build_demo.bat - rebuild the demonstration target.
rem
rem  Run from a Developer Command Prompt for VS, or just double-click this file
rem  (it locates vcvars64 itself).
rem
rem  EVERY FLAG IS DELIBERATE. If a teacher asks why the demo binary is weak,
rem  this is the answer sheet.
rem
rem    /Od              no optimisation, so the decompiled output can be
rem                     compared against the source without the compiler having
rem                     rewritten the logic first
rem    /Zi              debug info, kept out of the exe but useful if you want
rem                     to check an address against the source
rem    /MD              import the C runtime instead of linking it statically.
rem                     This is what makes strcpy appear in the import table,
rem                     which is what lets the engine classify it as an
rem                     unbounded copy. With the default /MT the headline
rem                     finding disappears - a good thing to show deliberately.
rem
rem    /DYNAMICBASE:NO  ASLR off, so the Security tab has something to report
rem    /FIXED:NO        ...but KEEP the relocation table. Without it the image
rem                     cannot be rebased, and `sp harden` would be right to
rem                     refuse to set ASLR. This flag is what makes the
rem                     hardening demonstration possible at all.
rem    /NXCOMPAT:NO     DEP off
rem    /GUARD:NO        Control Flow Guard off. The hardener reports this one
rem                     and refuses to set it, because the flag without the
rem                     compiler's guard tables would be a lie in the header.
rem    /SECTION:.data,RWE
rem                     makes .data writable AND executable, so there is a real
rem                     W^X violation to find. The hardener reports it by
rem                     default and only removes it with --fix-wx.
rem ===========================================================================

setlocal

if "%VSINSTALLDIR%"=="" (
    set "VCVARS=C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
    if not exist "%VCVARS%" (
        echo Could not find vcvars64.bat. Open a Developer Command Prompt and
        echo run this script again.
        exit /b 1
    )
    call "%VCVARS%" >nul
)

cd /d "%~dp0"

cl /nologo /W3 /Zi /Od /MD demo_target.c ^
   /link /OUT:demo_target.exe ^
   /DYNAMICBASE:NO /FIXED:NO /NXCOMPAT:NO /GUARD:NO ^
   /SECTION:.data,RWE ^
   advapi32.lib

if errorlevel 1 (
    echo BUILD FAILED
    exit /b 1
)

del /q *.obj *.ilk 2>nul

echo.
echo Built demo_target.exe
echo.
echo The C4996 warning about strcpy is expected - the compiler is warning about
echo the defect the analysis is meant to find in the compiled binary.
echo.
endlocal
