# Local changes to usque

Vendored from https://github.com/Diniboy1123/usque at commit
`6aa03fc97d12848dce34eedbd187fb1077b5d1ea` (MIT, see LICENSE.md).

Only the library packages are kept (`api`, `config`, `internal`, `models`);
the CLI (`cmd`, `main.go`) is not used on Android.

Additions (upstream files are unchanged):

- `pub/pub.go` re-exports helpers from `internal` (certificate generation,
  QUIC defaults, SOCKS5 server, DNS resolver, SNI/URI constants).
- `internal/socks5_zarp.go` adds `SOCKS5Server.Shutdown` and
  `SOCKS5Server.AllowUnassociatedUDP` (for hev-socks5-tunnel UDP relay).
- `api/client_zarp.go` adds an independent, context-bound registration/account
  client with bounded responses, safe HTTP errors and WARP+ license updates.
  It never changes the process-global default HTTP client.
