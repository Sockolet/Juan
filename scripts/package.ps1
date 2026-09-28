param(
    [switch]$SkipBuild,
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]*$')]
    [string]$PackageName
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$previousFlags = $env:CARGO_ENCODED_RUSTFLAGS
Push-Location $root
try {
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        $cargoDirectory = Join-Path $env:USERPROFILE '.cargo\bin'
        if (-not (Test-Path -LiteralPath (Join-Path $cargoDirectory 'cargo.exe'))) {
            throw 'Rust is not installed. See the build prerequisites in README.md.'
        }
        $env:Path = "$cargoDirectory;$env:Path"
    }
    if (-not $SkipBuild) {
        $flags = @()
        if ($previousFlags) { $flags += $previousFlags.Split([char]31) }
        elseif ($env:RUSTFLAGS) { $flags += @($env:RUSTFLAGS -split '\s+' | Where-Object { $_ }) }
        $flags += '-C', 'target-feature=+crt-static'
        $flags += "--remap-path-prefix=$env:USERPROFILE=C:\juan-build"
        $flags += "--remap-path-prefix=$root=."
        $env:CARGO_ENCODED_RUSTFLAGS = $flags -join [char]31
        cargo build --release --locked --quiet
        if ($LASTEXITCODE -ne 0) { throw "Release build failed with exit code $LASTEXITCODE." }
    }
    $metadata = cargo metadata --format-version 1 --locked --filter-platform x86_64-pc-windows-msvc --quiet | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) { throw 'Could not read Cargo package metadata.' }
    $version = ($metadata.packages | Where-Object name -eq 'juan').version
    if (-not $PackageName) { $PackageName = "juan-$version-windows-x64" }
    $package = Join-Path $root "dist\$PackageName"
    [void][System.IO.Directory]::CreateDirectory($package)
    foreach ($name in 'juan.exe', 'juan-cli.exe') {
        $source = Join-Path $metadata.target_directory "release\$name"
        $bytes = [System.IO.File]::ReadAllBytes($source)
        foreach ($encoding in [System.Text.Encoding]::ASCII, [System.Text.Encoding]::Unicode) {
            $text = $encoding.GetString($bytes)
            if ($text.Contains($env:USERPROFILE) -or $text.Contains($env:USERPROFILE.Replace('\', '/'))) {
                throw "$name contains a local user-profile build path. Run package.ps1 without -SkipBuild to rebuild with path remapping."
            }
        }
        Copy-Item -LiteralPath $source -Destination $package -Force
    }
    foreach ($name in 'README.md', 'LICENSE', 'BACKLOG.md') {
        Copy-Item -LiteralPath (Join-Path $root $name) -Destination $package -Force
    }
    $docs = Join-Path $package 'docs'
    [void][System.IO.Directory]::CreateDirectory($docs)
    Copy-Item -LiteralPath (Join-Path $root 'docs\juan.png') -Destination $docs -Force

    $fallbacks = @{
        # Source: dropbox/rust-alloc-no-stdlib@ae42d22078b98549e987d2f03d12df7b984fde47, LICENSE
        'alloc-stdlib@0.2.4' = 'resources\licenses\alloc-stdlib-0.2.4-LICENSE'
        # Source: rusticata/asn1-rs@a20e5f7319c896737ad0f2557037817b91ad854f, LICENSE-MIT
        'asn1-rs-impl@0.2.0' = 'resources\licenses\asn1-rs-impl-0.2.0-LICENSE-MIT'
    }
    $notices = [System.Text.StringBuilder]::new()
    [void]$notices.AppendLine("Juan third-party dependency notices`n")
    foreach ($dependency in ($metadata.packages | Where-Object name -ne 'juan' | Sort-Object name, version)) {
        [void]$notices.AppendLine("========================================")
        [void]$notices.AppendLine("$($dependency.name) $($dependency.version)")
        [void]$notices.AppendLine("Declared license: $($dependency.license)")
        [void]$notices.AppendLine("Source: $($dependency.repository)")
        $directory = Split-Path -Parent $dependency.manifest_path
        $files = @(Get-ChildItem -LiteralPath $directory -File | Where-Object {
            $_.Name -match '^(LICENSE|LICENCE|COPYING|NOTICE|COPYRIGHT)([-._]|$)'
        } | Sort-Object Name)
        if ($files.Count -eq 0) {
            $fallback = $fallbacks["$($dependency.name)@$($dependency.version)"]
            if (-not $fallback) { throw "No packaged license notice found for $($dependency.name) $($dependency.version)." }
            $files = @(Get-Item -LiteralPath (Join-Path $root $fallback))
        }
        foreach ($file in $files) {
            [void]$notices.AppendLine("`n--- $($file.Name) ---`n")
            [void]$notices.AppendLine([System.IO.File]::ReadAllText($file.FullName))
        }
        [void]$notices.AppendLine()
    }
    [System.IO.File]::WriteAllText((Join-Path $package 'THIRD-PARTY-NOTICES.txt'), $notices.ToString())
    $sysroot = rustc --print sysroot
    if ($LASTEXITCODE -ne 0) { throw 'Could not locate Rust standard-library notices.' }
    Copy-Item -LiteralPath (Join-Path $sysroot 'share\doc\rust\COPYRIGHT-library.html') `
        -Destination (Join-Path $package 'RUST-STANDARD-LIBRARY-NOTICES.html') -Force
    $archive = "$package.zip"
    $temporaryArchive = Join-Path (Split-Path -Parent $archive) ([System.IO.Path]::GetRandomFileName())
    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
    try {
        $zip = [System.IO.Compression.ZipFile]::Open($temporaryArchive, [System.IO.Compression.ZipArchiveMode]::Create)
        try {
            # Never include incidental captures or keys someone saved beside the portable executables.
            foreach ($relative in 'juan.exe', 'juan-cli.exe', 'README.md', 'LICENSE', 'BACKLOG.md',
                'THIRD-PARTY-NOTICES.txt', 'RUST-STANDARD-LIBRARY-NOTICES.html', 'docs\juan.png') {
                $entry = "$(Split-Path -Leaf $package)/$($relative.Replace('\', '/'))"
                [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
                    $zip, (Join-Path $package $relative), $entry, [System.IO.Compression.CompressionLevel]::Optimal)
            }
        } finally {
            $zip.Dispose()
        }
        Move-Item -LiteralPath $temporaryArchive -Destination $archive -Force
    } finally {
        if (Test-Path -LiteralPath $temporaryArchive) { Remove-Item -LiteralPath $temporaryArchive }
    }
    $digest = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    [System.IO.File]::WriteAllText("$archive.sha256", "$digest  $([System.IO.Path]::GetFileName($archive))`n")
    Write-Output $archive
    Write-Output "SHA-256: $digest"
} finally {
    $env:CARGO_ENCODED_RUSTFLAGS = $previousFlags
    Pop-Location
}
