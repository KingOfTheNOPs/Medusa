param(
    [string]$Compiler = "C:\ProgramData\mingw64\mingw64\bin\x86_64-w64-mingw32-gcc.exe"
)

$ErrorActionPreference = "Stop"
$Source = Resolve-Path (Join-Path $PSScriptRoot "..\Payload_Type\medusa\medusa\native\coffloader")
$Output = Join-Path $Source "coffloader.x64.dll"

if (-not (Test-Path -LiteralPath $Compiler)) {
    $Compiler = (Get-Command x86_64-w64-mingw32-gcc -ErrorAction Stop).Source
}

& $Compiler -O2 -Wall -shared -static-libgcc '-Wl,--export-all-symbols' `
    (Join-Path $Source "beacon_compatibility.c") (Join-Path $Source "COFFLoader.c") -o $Output
if ($LASTEXITCODE -ne 0) { throw "COFF loader build failed" }
Write-Host "Built $Output"
