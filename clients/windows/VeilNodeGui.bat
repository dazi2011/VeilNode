@echo off
setlocal
set "ROOT=%~dp0..\.."
set "PYTHONPATH=%ROOT%;%PYTHONPATH%"
py -3 "%~dp0VeilNodeGui.pyw"
