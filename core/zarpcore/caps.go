package zarpcore

import "net"

// Some strategies need the app to change the TTL (hop limit) of its own sockets without root: the fake QUIC
// packets with a short TTL, and the TCP "disorder" split whose first segment leaves with TTL 1. Android lets
// an app do that, but the answer comes from the kernel of the device, so the app asks instead of assuming.

// CanSetUDPTTL reports whether this device lets the app change the TTL of a UDP socket.
func CanSetUDPTTL() bool {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		return false
	}
	defer func() { _ = pc.Close() }()
	raw, err := pc.(*net.UDPConn).SyscallConn()
	return err == nil && ttlRoundTrip(raw)
}

// CanSetTCPTTL reports whether this device lets the app change the TTL of a TCP socket.
func CanSetTCPTTL() bool {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return false
	}
	defer func() { _ = l.Close() }()
	raw, err := l.(*net.TCPListener).SyscallConn()
	return err == nil && ttlRoundTrip(raw)
}

type controller interface {
	Control(func(fd uintptr)) error
}

// ttlRoundTrip sets a distinctive TTL and reads it back.
func ttlRoundTrip(raw controller) bool {
	const probe = 37
	ok := false
	if err := raw.Control(func(fd uintptr) {
		old, err := getTTL(fd, false)
		if err != nil {
			return
		}
		if err := setTTL(fd, false, probe); err != nil {
			return
		}
		got, err := getTTL(fd, false)
		_ = setTTL(fd, false, old)
		ok = err == nil && got == probe
	}); err != nil {
		return false
	}
	return ok
}
