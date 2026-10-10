param([string]$Revision = 'master')
$ErrorActionPreference = 'Stop'
$repo = 'ipverse/country-ip-blocks'
if ($Revision -notmatch '^[a-f0-9]{40}$') {
    $commit = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/commits/$Revision" -Headers @{ 'User-Agent' = 'Zarp-build' }
    $Revision = $commit.sha
}
if ($Revision -notmatch '^[a-f0-9]{40}$') { throw 'Expected a pinned commit SHA' }
$root = Split-Path -Parent $PSScriptRoot
$destination = Join-Path $root 'app/src/main/assets/routes'
New-Item -ItemType Directory -Force -Path $destination | Out-Null
$manifest = @{ source = "https://github.com/$repo"; revision = $Revision; license = 'CC0-1.0'; countries = @{} }
foreach ($country in @('ru', 'ir', 'cn')) {
    $prefixes = @()
    foreach ($family in @('ipv4', 'ipv6')) {
        $url = "https://raw.githubusercontent.com/$repo/$Revision/country/$country/$family-aggregated.txt"
        $body = (Invoke-WebRequest -Uri $url -UseBasicParsing).Content
        foreach ($line in ($body -split '\r?\n')) {
            $value = $line.Trim()
            if (!$value -or $value.StartsWith('#')) { continue }
            $parts = $value.Split('/')
            if ($parts.Count -ne 2) { throw "Invalid CIDR: $value" }
            $address = [System.Net.IPAddress]::Parse($parts[0])
            $bits = $address.GetAddressBytes().Length * 8
            $mask = [int]$parts[1]
            if ($mask -le 0 -or $mask -gt $bits) { throw "Invalid prefix: $value" }
            $prefixes += $value
        }
    }
    if ($prefixes.Count -lt 100) { throw "Incomplete country dataset: $country" }
    $path = Join-Path $destination "$country.txt"
    [System.IO.File]::WriteAllText($path, "# Source: $repo@$Revision`n" + ($prefixes -join "`n") + "`n", [System.Text.Encoding]::ASCII)
    $manifest.countries[$country] = @{ prefixes = $prefixes.Count; sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLower() }
    Write-Output "$country`: $($prefixes.Count) prefixes"
}
[System.IO.File]::WriteAllText((Join-Path $destination 'manifest.json'), ($manifest | ConvertTo-Json -Depth 4) + "`n", [System.Text.Encoding]::ASCII)
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/$repo/$Revision/LICENSE" -UseBasicParsing -OutFile (Join-Path $root 'licenses/country-ip-blocks.txt')
