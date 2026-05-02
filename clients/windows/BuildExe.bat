@echo off
setlocal enabledelayedexpansion
set "ROOT=%~dp0..\.."
set "DIST=%ROOT%\dist\windows-exe"
if not exist "%DIST%" mkdir "%DIST%"
py -3 -m pip install --user pyinstaller
py -3 -m PyInstaller --clean --onefile --name veil-node --distpath "%DIST%" "%ROOT%\bin\veil-node"
echo Built "%DIST%\veil-node.exe"
echo Run: "%DIST%\veil-node.exe" --help
