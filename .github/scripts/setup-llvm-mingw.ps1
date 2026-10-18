# Installs a pinned llvm-mingw release (msvcrt variant, x86_64 host) on a GitHub
# Windows runner and points cargo at it, like $CARGO_HOME/config.toml does on the
# dev PC (docs/dev/building.md). Used by ci.yml and release.yml.
#
# To update: change $Version and $Sha256 (the digest GitHub shows for the asset
# llvm-mingw-<version>-msvcrt-x86_64.zip on the release page).

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$Version = '20261006'
$Sha256 = '24847b37a951c8583c3f7ec061de2eb87f6394215c8ef3fdc4565ed0835396e1'

$Name = "llvm-mingw-$Version-msvcrt-x86_64"
$Url = "https://github.com/mstorsjo/llvm-mingw/releases/download/$Version/$Name.zip"
$Zip = Join-Path $env:RUNNER_TEMP "$Name.zip"
$Dest = Join-Path $env:RUNNER_TEMP 'llvm-mingw'

Write-Host "Downloading $Url"
Invoke-WebRequest -Uri $Url -OutFile $Zip
$Actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Zip).Hash.ToLowerInvariant()
if ($Actual -ne $Sha256) {
    throw "SHA-256 mismatch for $Name.zip: expected $Sha256, got $Actual"
}
Write-Host "SHA-256 verified: $Actual"

& 7z x $Zip "-o$Dest" -y | Out-Null
if ($LASTEXITCODE -ne 0) { throw "7z failed with exit code $LASTEXITCODE" }
Remove-Item -LiteralPath $Zip

$Bin = Join-Path $Dest "$Name\bin"
$Clang64 = Join-Path $Bin 'x86_64-w64-mingw32-clang.exe'
$Clang32 = Join-Path $Bin 'i686-w64-mingw32-clang.exe'
$Ar = Join-Path $Bin 'llvm-ar.exe'
foreach ($Tool in @($Clang64, $Clang32, $Ar)) {
    if (-not (Test-Path -LiteralPath $Tool)) { throw "missing $Tool" }
}
& $Clang64 --version
if ($LASTEXITCODE -ne 0) { throw "$Clang64 does not run" }

# Same settings as the dev PC's cargo config. +crt-static: no libunwind.dll at run time.
$Static = '-C target-feature=+crt-static'
@(
    "CARGO_TARGET_X86_64_PC_WINDOWS_GNULLVM_LINKER=$Clang64"
    "CARGO_TARGET_I686_PC_WINDOWS_GNULLVM_LINKER=$Clang32"
    "CARGO_TARGET_X86_64_PC_WINDOWS_GNULLVM_RUSTFLAGS=$Static"
    "CARGO_TARGET_I686_PC_WINDOWS_GNULLVM_RUSTFLAGS=$Static"
    "CC_x86_64_pc_windows_gnullvm=$Clang64"
    "CC_i686_pc_windows_gnullvm=$Clang32"
    "AR_x86_64_pc_windows_gnullvm=$Ar"
    "AR_i686_pc_windows_gnullvm=$Ar"
    "LLVM_MINGW_BIN=$Bin"
) | Out-File -FilePath $env:GITHUB_ENV -Append -Encoding utf8
