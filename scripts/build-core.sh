#!/bin/sh
# Builds core/ into an Android AAR with gomobile. Called by the app's buildGoCore task.
# Needs: Go, ANDROID_HOME, ANDROID_NDK_HOME, ZARP_GO_TARGETS, ZARP_CORE_OUT.
set -eu
command -v go >/dev/null 2>&1 || { echo "Go is required to build core/ (https://go.dev/dl/)" >&2; exit 1; }
export PATH="$(go env GOPATH)/bin:$PATH"

go install golang.org/x/mobile/cmd/gomobile golang.org/x/mobile/cmd/gobind
mkdir -p "$(dirname "$ZARP_CORE_OUT")"
gomobile bind -target="$ZARP_GO_TARGETS" -androidapi 26 -javapkg io.github.feg55 \
    -tags=with_quic,with_utls,http2legacy -trimpath -ldflags="-s -w" -o "$ZARP_CORE_OUT" ./zarpcore
