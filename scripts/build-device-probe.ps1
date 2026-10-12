param([string]$SdkDir = $env:ANDROID_HOME)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$probeBuild = Join-Path $projectRoot 'build/device-probe'
$toolsDir = Join-Path $SdkDir 'build-tools/36.1.0'
$androidJar = Join-Path $SdkDir 'platforms/android-37.0/android.jar'
$classes = Join-Path $probeBuild 'classes'
$dex = Join-Path $probeBuild 'dex'
New-Item -ItemType Directory -Force -Path $classes, $dex | Out-Null
$javaSources = @(Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'device-probe') -Filter '*.java' | ForEach-Object { $_.FullName })
& javac --release 8 -classpath $androidJar -d $classes @javaSources
if ($LASTEXITCODE -ne 0) { throw 'test client compilation failed' }
$compiledClasses = @(Get-ChildItem -LiteralPath $classes -Filter '*.class' -Recurse | ForEach-Object { $_.FullName })
& (Join-Path $toolsDir 'd8.bat') --lib $androidJar --output $dex @compiledClasses
if ($LASTEXITCODE -ne 0) { throw 'test client dex build failed' }
$keyFile = Join-Path $probeBuild 'verification.jks'
if (!(Test-Path -LiteralPath $keyFile)) {
    & keytool -genkeypair -keystore $keyFile -storepass test-only -keypass test-only -alias verification -keyalg RSA -keysize 2048 -validity 2 -dname 'CN=Local Verification'
    if ($LASTEXITCODE -ne 0) { throw 'test-only signing key creation failed' }
}
foreach ($variant in @('selected', 'excluded')) {
    $package = 'io.github.feg55.zarp.trafficprobe'
    if ($variant -eq 'excluded') { $package += '.excluded' }
    $unsigned = Join-Path $probeBuild "$variant-unsigned.apk"
    $aligned = Join-Path $probeBuild "$variant-aligned.apk"
    $signed = Join-Path $probeBuild "$variant.apk"
    & (Join-Path $toolsDir 'aapt2.exe') link -o $unsigned --manifest (Join-Path $PSScriptRoot 'device-probe/AndroidManifest.xml') -I $androidJar --min-sdk-version 26 --target-sdk-version 36 --rename-manifest-package $package
    if ($LASTEXITCODE -ne 0) { throw 'test client manifest build failed' }
    & jar uf $unsigned -C $dex classes.dex
    if ($LASTEXITCODE -ne 0) { throw 'test client archive failed' }
    & (Join-Path $toolsDir 'zipalign.exe') -f 4 $unsigned $aligned
    if ($LASTEXITCODE -ne 0) { throw 'test client alignment failed' }
    & (Join-Path $toolsDir 'apksigner.bat') sign --ks $keyFile --ks-pass pass:test-only --key-pass pass:test-only --ks-key-alias verification --out $signed $aligned
    if ($LASTEXITCODE -ne 0) { throw 'test client signing failed' }
}
Write-Output 'Built isolated selected and excluded traffic probe APKs.'
