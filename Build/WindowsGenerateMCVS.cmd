@ECHO OFF

::ms64
SET compiler=ms64

::Debug|Release
SET Config=Debug

PUSHD ..
SET MyRepository=%CD%
SET MyProjectDir=%CD%\bin_%compiler%
POPD

if exist "C:\Program Files (x86)\CMake 2.8\bin\cmake.exe" set CMAKE_EXE="C:\Program Files (x86)\CMake\bin\cmake.exe"
if exist "C:\Program Files (x86)\CMake 2.8\bin\cmake-gui.exe" set CMAKE_EXE_GUI="C:\Program Files (x86)\CMake\bin\cmake-gui.exe"

if exist "C:\Program Files (x86)\CMake\bin\cmake.exe" set CMAKE_EXE="C:\Program Files (x86)\CMake\bin\cmake.exe"
if exist "C:\Program Files (x86)\CMake\bin\cmake-gui.exe" set CMAKE_EXE_GUI="C:\Program Files (x86)\CMake\bin\cmake-gui.exe"

if exist "C:\Program Files\CMake\bin\cmake.exe" set CMAKE_EXE="C:\Program Files\CMake\bin\cmake.exe"
if exist "C:\Program Files\CMake\bin\cmake-gui.exe" set CMAKE_EXE_GUI="C:\Program Files\CMake\bin\cmake-gui.exe"

::if exist "%MyProjectDir%" RD /s /q "%MyProjectDir%"
MKDIR "%MyProjectDir%"
PUSHD "%MyProjectDir%"

%CMAKE_EXE% -A x64 %MyRepository%
call cmake --build . --config %Config%

POPD
