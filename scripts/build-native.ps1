[CmdletBinding()]
param
(
	[Parameter(Mandatory)]
	[string] $RuntimeIdentifier,

	[ValidateSet('cargo', 'cross')]
	[string] $CargoCommand = 'cargo',

	[string] $OutputDirectory = "$PSScriptRoot/../artifacts/native"
)

$ErrorActionPreference = 'Stop'
$target = switch ($RuntimeIdentifier)
{
	'linux-x64' { 'x86_64-unknown-linux-gnu' }
	'linux-arm64' { 'aarch64-unknown-linux-gnu' }
	'linux-loongarch64' { 'loongarch64-unknown-linux-gnu' }
	'linux-riscv64' { 'riscv64gc-unknown-linux-gnu' }
	'linux-musl-x64' { 'x86_64-unknown-linux-musl' }
	'linux-musl-arm64' { 'aarch64-unknown-linux-musl' }
	'linux-musl-loongarch64' { 'loongarch64-unknown-linux-musl' }
	'linux-musl-riscv64' { 'riscv64gc-unknown-linux-musl' }
	'linux-bionic-x64' { 'x86_64-linux-android' }
	'linux-bionic-arm64' { 'aarch64-linux-android' }
	'win-x64' { 'x86_64-pc-windows-msvc' }
	'win-arm64' { 'aarch64-pc-windows-msvc' }
	'osx-arm64' { 'aarch64-apple-darwin' }
	default { throw "Unsupported native asset RID: $RuntimeIdentifier" }
}
$nativeRoot = [System.IO.Path]::GetFullPath("$PSScriptRoot/../native")
$releaseDirectory = Join-Path $nativeRoot "target/$target/release"
$outputRoot = [System.IO.Path]::GetFullPath($OutputDirectory)

$dynamicLibrary, $staticLibrary = switch -Wildcard ($RuntimeIdentifier)
{
	'win-*' { 'dtls_native.dll', 'dtls_native.lib' }
	'osx-*' { 'libdtls_native.dylib', 'libdtls_native.a' }
	'linux-*' { 'libdtls_native.so', 'libdtls_native.a' }
}

Push-Location -LiteralPath $nativeRoot
try
{
	rustup target add $target
	if ($LASTEXITCODE -ne 0)
	{
		throw "Rust target installation failed for '$target' with exit code $LASTEXITCODE."
	}
	$linkerArguments = $null
	& $CargoCommand rustc --release --target $target --color never '--' --print=native-static-libs 2>&1 | ForEach-Object {
		Write-Output $_
		if ([string] $_ -match 'native-static-libs:\s*(?<Arguments>.+?)\s*$')
		{
			$linkerArguments = $Matches.Arguments
		}
	}
	if ($LASTEXITCODE -ne 0)
	{
		throw "$CargoCommand rustc failed with exit code $LASTEXITCODE."
	}
	if ([string]::IsNullOrWhiteSpace($linkerArguments))
	{
		throw "rustc did not report native-static-libs for target '$target'."
	}

	foreach ($library in @($dynamicLibrary, $staticLibrary))
	{
		$path = Join-Path $releaseDirectory $library
		if (!(Test-Path -LiteralPath $path -PathType Leaf))
		{
			throw "Required native artifact was not produced: $path"
		}
	}

	$nativeDirectory = Join-Path $outputRoot "$RuntimeIdentifier/native"
	$nativeStaticDirectory = Join-Path $outputRoot "$RuntimeIdentifier/native-static"
	[System.IO.Directory]::CreateDirectory($nativeDirectory) | Out-Null
	[System.IO.Directory]::CreateDirectory($nativeStaticDirectory) | Out-Null
	Copy-Item -LiteralPath (Join-Path $releaseDirectory $dynamicLibrary) -Destination $nativeDirectory
	Copy-Item -LiteralPath (Join-Path $releaseDirectory $staticLibrary) -Destination $nativeStaticDirectory
	[System.IO.File]::WriteAllText((Join-Path $nativeStaticDirectory 'dtls_native.link.rsp'), "$linkerArguments`n")
	Write-Output "Native assets ready at '$(Join-Path $outputRoot $RuntimeIdentifier)'."
}
finally
{
	Pop-Location
}
