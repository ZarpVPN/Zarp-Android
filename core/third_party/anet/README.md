# anet stand-in

Local replacement for `github.com/wlynxg/anet` (BSD-3-Clause), selected with a `replace` directive in `core/go.mod`.

Why: the upstream android implementation uses `//go:linkname` on `net.zoneCache`, which Go 1.23+ refuses to link for android.
The package is pulled in by `pion/transport`, which Xray-core links for the STUN based `finalmask/realm` feature that Zarp never
configures. pion only calls `Interfaces` and `InterfaceAddrsByInterface`, so this module forwards both to the standard library.

Nothing from the upstream module is copied here.
