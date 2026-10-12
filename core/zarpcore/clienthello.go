package zarpcore

import "encoding/binary"

// isTLSClientHello reports whether b starts a TLS handshake record that carries a ClientHello.
// This is what zapret2 calls the payload type tls_client_hello.
func isTLSClientHello(b []byte) bool {
	return len(b) >= 6 && b[0] == 0x16 && b[1] == 0x03 && b[5] == 0x01
}

// clientHelloSNI finds the host name of the server_name extension in a TLS ClientHello record and returns
// its offsets inside rec. With Encrypted Client Hello this is the public name of the ECH configuration,
// which is the name a DPI box sees and the one the split markers have to follow.
func clientHelloSNI(rec []byte) (start, end int, host string, ok bool) {
	if !isTLSClientHello(rec) {
		return 0, 0, "", false
	}
	// record header (5) + handshake header (4) + version (2) + random (32)
	p := 5 + 4 + 2 + 32
	skip8 := func() bool { // a block with a one byte length
		if p+1 > len(rec) {
			return false
		}
		p += 1 + int(rec[p])
		return p <= len(rec)
	}
	skip16 := func() bool { // a block with a two byte length
		if p+2 > len(rec) {
			return false
		}
		p += 2 + int(binary.BigEndian.Uint16(rec[p:]))
		return p <= len(rec)
	}
	if !skip8() || !skip16() || !skip8() { // session id, cipher suites, compression methods
		return 0, 0, "", false
	}
	if p+2 > len(rec) {
		return 0, 0, "", false
	}
	extEnd := p + 2 + int(binary.BigEndian.Uint16(rec[p:]))
	p += 2
	if extEnd > len(rec) {
		extEnd = len(rec)
	}
	for p+4 <= extEnd {
		typ := binary.BigEndian.Uint16(rec[p:])
		size := int(binary.BigEndian.Uint16(rec[p+2:]))
		body := p + 4
		if body+size > extEnd {
			return 0, 0, "", false
		}
		if typ == 0 { // server_name: list length (2), then name type (1), name length (2), name
			if size < 5 || rec[body+2] != 0 {
				return 0, 0, "", false
			}
			n := int(binary.BigEndian.Uint16(rec[body+3:]))
			if body+5+n > body+size || n == 0 {
				return 0, 0, "", false
			}
			start = body + 5
			return start, start + n, string(rec[start : start+n]), true
		}
		p = body + size
	}
	return 0, 0, "", false
}
