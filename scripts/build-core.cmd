@echo off
rem Builds core\ into an Android AAR with gomobile. Called by the app's buildGoCore task.
rem Needs: Go, ANDROID_HOME, ANDROID_NDK_HOME, ZARP_GO_TARGETS, ZARP_CORE_OUT.
setlocal
where go >nul 2>nul || (echo Go is required to build core\ ^(https://go.dev/dl/^) 1>&2 & exit /b 1)
for /f "delims=" %%i in ('go env GOPATH') do set "GOPATH_DIR=%%i"
set "PATH=%GOPATH_DIR%\bin;%PATH%"
go install golang.org/x/mobile/cmd/gomobile golang.org/x/mobile/cmd/gobind || exit /b 1
for %%d in ("%ZARP_CORE_OUT%") do if not exist "%%~dpd" mkdir "%%~dpd"
rem sing-box 1.13 uses x/net/http2 internals; retain that implementation on Go 1.27+.
gomobile bind "-target=%ZARP_GO_TARGETS%" -androidapi 26 -javapkg io.github.feg55 -tags=with_quic,with_utls,http2legacy -trimpath "-ldflags=-s -w" -o "%ZARP_CORE_OUT%" ./zarpcore || exit /b 1
