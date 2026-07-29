# Build fully-static Windows (MinGW) ASM2HEX binary
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$env:PATH = "C:\msys64\mingw64\bin;C:\Program Files\CMake\bin;" + $env:PATH

Set-Location $Root
New-Item -ItemType Directory -Force -Path dist, out | Out-Null
if (Test-Path build-win) { Remove-Item -Recurse -Force build-win }

cmake -S . -B build-win -G Ninja `
  -DCMAKE_BUILD_TYPE=Release `
  -DCMAKE_C_COMPILER=C:/msys64/mingw64/bin/gcc.exe `
  -DCMAKE_CXX_COMPILER=C:/msys64/mingw64/bin/g++.exe `
  -DBUILD_SHARED_LIBS=OFF
if ($LASTEXITCODE -ne 0) { throw "cmake configure failed" }

cmake --build build-win --config Release
if ($LASTEXITCODE -ne 0) { throw "cmake build failed" }

$bin = $null
foreach ($p in @("out\ASM2HEX.exe", "build-win\ASM2HEX.exe")) {
  if (Test-Path $p) { $bin = (Resolve-Path $p).Path; break }
}
if (-not $bin) { throw "ASM2HEX.exe not found" }

Copy-Item $bin "dist\ASM2HEX-win64.exe" -Force

# Verify no MinGW runtime DLLs
$dlls = & "C:\msys64\mingw64\bin\objdump.exe" -p "dist\ASM2HEX-win64.exe" |
  Select-String "DLL Name" |
  ForEach-Object { ($_ -split ":\s*")[-1].Trim() }
$bad = $dlls | Where-Object { $_ -match "lib(gcc|stdc\+\+|winpthread)" }
Write-Host "DLL imports:"
$dlls | ForEach-Object { Write-Host "  $_" }
if ($bad) {
  Write-Error "Still depends on MinGW runtime DLLs: $($bad -join ', ')"
  exit 1
}
Write-Host "STATIC_OK: no libgcc/libstdc++/libwinpthread DLLs"

# Release package: zip only (do not ship bare .exe for download)
$stage = Join-Path $env:TEMP "asm2hex-win-zip"
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Force -Path $stage | Out-Null
Copy-Item "dist\ASM2HEX-win64.exe" (Join-Path $stage "ASM2HEX.exe") -Force
$zipPath = Join-Path $Root "dist\ASM2HEX-win64.zip"
if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory($stage, $zipPath)
Get-Item "dist\ASM2HEX-win64.exe", "dist\ASM2HEX-win64.zip" | Format-List Name, Length, FullName
Write-Host "Release asset: dist\ASM2HEX-win64.zip (prefer this over bare .exe)"
