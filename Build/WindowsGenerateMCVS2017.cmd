@ECHO OFF

::ms64
SET compiler=ms64

::2012|2013|2015|2017
SET versionVS=2017

::Debug|Release
SET Config=Release

CALL config64.cmd

::if exist "%MyProjectDir%" RD /s /q "%MyProjectDir%"
MKDIR "%MyProjectDir%"
PUSHD "%MyProjectDir%"

%CMAKE_EXE% -G%CMAKE_GENERATOR_NAME% %MyRepository%
call cmake --build . --config %Config%

POPD
