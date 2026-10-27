# Windows-native demo + setup helper.  Usage:  .\demo.ps1          (runs the demo)
#                                              .\demo.ps1 -Setup   (create .venv and install deps first)
param([switch]$Setup)
Set-Location $PSScriptRoot
if ($Setup -or -not (Test-Path .\.venv)) {
    python -m venv .venv
    & .\.venv\Scripts\python.exe -m pip install -r requirements.txt
}
& .\.venv\Scripts\python.exe demo.py
