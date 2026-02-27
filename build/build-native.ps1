#!/usr/bin/env pwsh
# Build native libraries for all supported RIDs.
# Usage: ./build/build-native.ps1 [-Target <rust-target>]
param(
    [string]$Target
)

$ErrorActionPreference = 'Stop'
$nativeDir = Join-Path $PSScriptRoot '..' 'native'
$runtimesDir = Join-Path $PSScriptRoot '..' 'src' 'DTLS' 'runtimes'

$targets = @(
    @{ Rid = 'win-x64';          Target = 'x86_64-pc-windows-msvc';    Lib = 'dtls_native.dll' }
    @{ Rid = 'win-arm64';        Target = 'aarch64-pc-windows-msvc';   Lib = 'dtls_native.dll' }
    @{ Rid = 'linux-x64';        Target = 'x86_64-unknown-linux-gnu';  Lib = 'libdtls_native.so' }
    @{ Rid = 'linux-arm64';        Target = 'aarch64-unknown-linux-gnu';      Lib = 'libdtls_native.so' }
    @{ Rid = 'linux-loongarch64'; Target = 'loongarch64-unknown-linux-gnu'; Lib = 'libdtls_native.so' }
    @{ Rid = 'linux-musl-x64';   Target = 'x86_64-unknown-linux-musl'; Lib = 'libdtls_native.so' }
    @{ Rid = 'linux-musl-arm64';      Target = 'aarch64-unknown-linux-musl';     Lib = 'libdtls_native.so' }
    @{ Rid = 'linux-musl-loongarch64'; Target = 'loongarch64-unknown-linux-musl'; Lib = 'libdtls_native.so' }
    @{ Rid = 'osx-arm64';        Target = 'aarch64-apple-darwin';      Lib = 'libdtls_native.dylib' }
)

if ($Target) {
    $targets = $targets | Where-Object { $_.Target -eq $Target }
    if (-not $targets) { throw "Unknown target: $Target" }
}

foreach ($t in $targets) {
    Write-Host "Building $($t.Rid) ($($t.Target))..." -ForegroundColor Cyan
    cargo build --release --target $t.Target --manifest-path (Join-Path $nativeDir 'Cargo.toml')
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed for $($t.Target)" }

    $src = Join-Path $nativeDir 'target' $t.Target 'release' $t.Lib
    $dst = Join-Path $runtimesDir $t.Rid 'native'
    New-Item -ItemType Directory -Path $dst -Force | Out-Null
    Copy-Item $src $dst -Force
    Write-Host "  -> $dst/$($t.Lib)" -ForegroundColor Green
}
