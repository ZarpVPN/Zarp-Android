#!/usr/bin/env sh
set -eu

# Official pinned server binary for local/native integration tests.
# Output goes to the supplied build/temp directory, never into source control.
target_dir="${1:?usage: fetch-test-xray.sh output-directory}"
case "${2:-linux}" in
  linux)
    archive=Xray-linux-64.zip
    # SHA2-256 from the v26.9.30 release's Xray-linux-64.zip.dgst.
    digest=f851110beaff16e78d643f0ccfd9524b4a44dfd59bae3e34bb52bba378f7690e
    executable=xray
    ;;
  windows)
    archive=Xray-windows-64.zip
    digest=b17a619343c11b89d8faf36278298856749b15c52277d875d32051b33dcda617
    executable=xray.exe
    ;;
  *) echo "unsupported test platform" >&2; exit 1 ;;
esac
mkdir -p "$target_dir"
curl --fail --location --retry 2 --output "$target_dir/$archive" "https://github.com/XTLS/Xray-core/releases/download/v26.9.30/$archive"
printf '%s  %s\n' "$digest" "$target_dir/$archive" | sha256sum --check --status
unzip -q -o "$target_dir/$archive" -d "$target_dir/bin"
chmod +x "$target_dir/bin/$executable"
if [ -n "${GITHUB_ENV:-}" ]; then
  printf 'ZARP_TEST_XRAY=%s/bin/%s\n' "$target_dir" "$executable" >> "$GITHUB_ENV"
fi
