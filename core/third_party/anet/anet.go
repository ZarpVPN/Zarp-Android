// Package anet replaces github.com/wlynxg/anet for the Zarp build.
//
// The upstream module reads net.zoneCache through go:linkname, which the Go
// linker refuses for android targets since Go 1.23 ("invalid reference to
// net.zoneCache"). It reaches the build only through pion/transport, which Xray
// links for its STUN based finalmask. Zarp never configures that feature, and
// pion needs just these two calls, so plain net passthrough is enough.
package anet

import "net"

// Interfaces returns the network interfaces of the system.
func Interfaces() ([]net.Interface, error) { return net.Interfaces() }

// InterfaceAddrsByInterface returns the addresses of one interface.
func InterfaceAddrsByInterface(ifi *net.Interface) ([]net.Addr, error) { return ifi.Addrs() }
