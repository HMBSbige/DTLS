[CmdletBinding()]
param
(
	[Parameter(Mandatory)]
	[ValidateSet('win-x64', 'win-arm64', 'linux-x64', 'linux-arm64', 'linux-musl-x64', 'linux-musl-arm64', 'osx-arm64')]
	[string] $RuntimeIdentifier,

	[Parameter(Mandatory)]
	[string] $PackageVersion,

	[string] $PackageDirectory = "$PSScriptRoot/../artifacts/package",

	[string] $OutputDirectory = "$PSScriptRoot/../artifacts/aot/$RuntimeIdentifier"
)

$ErrorActionPreference = 'Stop'
$repoRoot = [System.IO.Path]::GetFullPath("$PSScriptRoot/..")
$packageRoot = (Resolve-Path -LiteralPath $PackageDirectory).Path
$outputRoot = [System.IO.Path]::GetFullPath($OutputDirectory)
$packagePath = Join-Path $packageRoot "DTLS.$PackageVersion.nupkg"
# A repacked local version must not reuse an older package from the NuGet cache.
$packageHash = (Get-FileHash -LiteralPath $packagePath).Hash.Substring(0, 16)
$useContainer = $RuntimeIdentifier.StartsWith('linux-musl-')
$executionRoot = $useContainer ? '/workspace' : $repoRoot
$executionOutput = $useContainer ? '/output' : $outputRoot
$packageSource = $useContainer ? '/packages' : $packageRoot
$publishDirectory = "$executionOutput/publish"
$publishArguments = @(
	'publish', "$executionRoot/tests/DTLS.NativeAotSmoke/DTLS.NativeAotSmoke.csproj",
	'-r', $RuntimeIdentifier,
	'-p:PublishAot=true', "-p:DTLSPackageVersion=$PackageVersion",
	"-p:RestoreAdditionalProjectSources=$packageSource",
	"-p:RestorePackagesPath=$executionOutput/packages/$packageHash",
	'--artifacts-path', "$executionOutput/build",
	'--output', $publishDirectory
)

if ($useContainer)
{
	[System.IO.Directory]::CreateDirectory($outputRoot) | Out-Null
	$platform = $RuntimeIdentifier.EndsWith('-arm64') ? 'linux/arm64' : 'linux/amd64'
	$containerScript = @'
dotnet "$@"
test ! -e /output/publish/libdtls_native.so
/output/publish/DTLS.NativeAotSmoke
dependencies=$(readelf -d /output/publish/DTLS.NativeAotSmoke)
printf '%s\n' "$dependencies"
case "$dependencies" in
    *libdtls_native.so*) echo 'NativeAOT executable still imports libdtls_native.so.' >&2; exit 1 ;;
esac
'@
	$dockerArguments = @(
		'run', '--rm', '--platform', $platform,
		'--volume', "${repoRoot}:/workspace:ro",
		'--volume', "${packageRoot}:/packages:ro",
		'--volume', "${outputRoot}:/output",
		'--workdir', '/workspace',
		'mcr.microsoft.com/dotnet/sdk:10.0-alpine-aot',
		'sh', '-euc', $containerScript, 'dtls-native-aot'
	)
	docker @dockerArguments @publishArguments
	if ($LASTEXITCODE -ne 0)
	{
		throw "NativeAOT container test failed with exit code $LASTEXITCODE."
	}
	return
}

$previousPath = $env:PATH
try
{
	if ($IsWindows)
	{
		$installerDirectory = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer'
		# The VS environment scripts also invoke vswhere by name.
		$env:PATH = $installerDirectory + [System.IO.Path]::PathSeparator + $previousPath
		$hostArchitecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
		$component = $hostArchitecture -eq 'arm64' ? 'Microsoft.VisualStudio.Component.VC.Tools.ARM64' : 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64'
		$visualStudio = & (Join-Path $installerDirectory 'vswhere.exe') -latest -products * -requires $component -property installationPath
		if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($visualStudio))
		{
			throw "Visual Studio C++ tools for $hostArchitecture were not found."
		}
		$vcToolsVersion = (Get-Content -LiteralPath (Join-Path $visualStudio 'VC/Auxiliary/Build/Microsoft.VCToolsVersion.default.txt') -Raw).Trim()
		$dumpbin = Join-Path $visualStudio "VC/Tools/MSVC/$vcToolsVersion/bin/Host$hostArchitecture/$hostArchitecture/dumpbin.exe"
	}

	dotnet @publishArguments
	if ($LASTEXITCODE -ne 0)
	{
		throw "NativeAOT publish failed with exit code $LASTEXITCODE."
	}

	foreach ($library in @('dtls_native.dll', 'libdtls_native.so', 'libdtls_native.dylib'))
	{
		$path = Join-Path $publishDirectory $library
		if (Test-Path -LiteralPath $path)
		{
			throw "Unexpected dynamic native library: $path"
		}
	}
	$executable = Join-Path $publishDirectory ($IsWindows ? 'DTLS.NativeAotSmoke.exe' : 'DTLS.NativeAotSmoke')
	& $executable
	if ($LASTEXITCODE -ne 0)
	{
		throw "NativeAOT smoke test failed with exit code $LASTEXITCODE."
	}

	$dependencies = if ($IsWindows)
	{
		& $dumpbin /dependents $executable 2>&1
	}
	elseif ($IsMacOS)
	{
		otool -L $executable 2>&1
	}
	else
	{
		readelf -d $executable 2>&1
	}
	if ($LASTEXITCODE -ne 0)
	{
		throw "Native dependency inspection failed with exit code $LASTEXITCODE."
	}
	$dependencies
	if ($dependencies -match 'dtls_native\.(dll|so|dylib)')
	{
		throw 'NativeAOT executable still imports the DTLS dynamic native library.'
	}
}
finally
{
	$env:PATH = $previousPath
}
