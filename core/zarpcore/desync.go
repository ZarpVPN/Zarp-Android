package zarpcore

// TCP desync for MASQUE over HTTP/2. On Android without root there are no raw
// sockets, so only techniques that work through a normal TCP socket are here:
//
//   split    - the TLS ClientHello leaves as several TCP segments
//              (zapret: multisplit:pos=...)
//   disorder - like split, but the first segment is sent with TTL=1 so it dies
//              on the first hop; the kernel retransmits it later, after the
//              rest (zapret: multidisorder:pos=..., ByeDPI: --disorder)
//
// Positions: N (byte offset, negative = from the end), host (SNI start),
// endhost (SNI end), sld (second-level domain start), midsld (middle of it).

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type desyncMode int

const (
	desyncSplit desyncMode = iota
	desyncDisorder
)

type desyncSpec struct {
	mode desyncMode
	pos  []string
}

func parseDesync(s string) (*desyncSpec, error) {
	name, args, ok := strings.Cut(strings.TrimSpace(s), ":")
	if !ok || args == "" {
		return nil, fmt.Errorf("tcp desync %q: expected mode:positions", s)
	}
	spec := &desyncSpec{}
	switch name {
	case "split":
		spec.mode = desyncSplit
	case "disorder":
		spec.mode = desyncDisorder
	default:
		return nil, fmt.Errorf("tcp desync %q: unknown mode %q", s, name)
	}
	for _, p := range strings.Split(args, ",") {
		p = strings.TrimSpace(p)
		switch p {
		case "host", "endhost", "sld", "midsld":
		default:
			if _, err := strconv.Atoi(p); err != nil {
				return nil, fmt.Errorf("tcp desync %q: bad position %q", s, p)
			}
		}
		spec.pos = append(spec.pos, p)
	}
	return spec, nil
}

// splitPositions resolves the spec against a payload containing host.
// Returns sorted, unique offsets strictly inside the payload.
func splitPositions(data []byte, pos []string, host string) []int {
	hostAt := -1
	if host != "" {
		hostAt = bytes.Index(data, []byte(host))
	}
	return positionsAt(data, pos, hostAt, host)
}

// positionsAt is splitPositions for a host name already located at hostAt (-1: not in the payload).
func positionsAt(data []byte, pos []string, hostAt int, host string) []int {
	sldAt, sldLen := -1, 0
	if hostAt >= 0 {
		labels := strings.Split(host, ".")
		if len(labels) >= 2 {
			sld := labels[len(labels)-2]
			sldAt = hostAt + len(host) - len(labels[len(labels)-1]) - 1 - len(sld)
			sldLen = len(sld)
		}
	}
	seen := map[int]bool{}
	var out []int
	for _, p := range pos {
		off := -1
		switch p {
		case "host":
			off = hostAt
		case "endhost":
			if hostAt >= 0 {
				off = hostAt + len(host)
			}
		case "sld":
			off = sldAt
		case "midsld":
			if sldAt >= 0 {
				off = sldAt + sldLen/2
			}
		default:
			n, _ := strconv.Atoi(p)
			if n < 0 {
				n += len(data)
			}
			off = n
		}
		if off > 0 && off < len(data) && !seen[off] {
			seen[off] = true
			out = append(out, off)
		}
	}
	sort.Ints(out)
	return out
}

// desyncConn applies the desync to the first write (the TLS ClientHello).
type desyncConn struct {
	*net.TCPConn
	spec *desyncSpec
	host string
	once sync.Once
}

func newDesyncConn(c *net.TCPConn, spec *desyncSpec, host string) net.Conn {
	return &desyncConn{TCPConn: c, spec: spec, host: host}
}

func (c *desyncConn) Write(b []byte) (int, error) {
	first := false
	c.once.Do(func() { first = true })
	if !first || len(b) < 6 || b[0] != 0x16 { // not a TLS handshake record
		return c.TCPConn.Write(b)
	}
	parts := splitPositions(b, c.spec.pos, c.host)
	if len(parts) == 0 {
		return c.TCPConn.Write(b)
	}
	return sendSegments(c.TCPConn, c.spec.mode, b, parts)
}

// sendSegments writes b as several TCP segments cut at the given offsets (sorted, strictly inside b). With
// desyncDisorder the first segment leaves with TTL 1 and is lost on the first hop, so it reaches the server
// only when the kernel retransmits it, after the rest.
func sendSegments(conn segmentConn, mode desyncMode, b []byte, parts []int) (int, error) {
	if err := conn.SetNoDelay(true); err != nil {
		return 0, err
	}
	prev := 0
	written := 0
	for i, end := range append(parts, len(b)) {
		seg := b[prev:end]
		if i == 0 && mode == desyncDisorder {
			if err := writeLowTTL(conn, seg); err != nil {
				return written, err
			}
		} else if _, err := conn.Write(seg); err != nil {
			return written, err
		}
		written += len(seg)
		prev = end
		// give the kernel a chance to emit each piece as its own segment
		time.Sleep(time.Millisecond)
	}
	return written, nil
}

// segmentConn is the part of *net.TCPConn that sendSegments needs; the tests substitute a recorder.
type segmentConn interface {
	Write([]byte) (int, error)
	SetNoDelay(bool) error
	SyscallConn() (syscall.RawConn, error)
	RemoteAddr() net.Addr
}

func writeLowTTL(conn segmentConn, seg []byte) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	addr, _ := conn.RemoteAddr().(*net.TCPAddr)
	v6 := addr != nil && addr.IP.To4() == nil
	var old int
	var serr error
	if err := raw.Control(func(fd uintptr) { old, serr = getTTL(fd, v6) }); err != nil {
		return err
	}
	if serr != nil {
		return serr
	}
	if err := raw.Control(func(fd uintptr) { serr = setTTL(fd, v6, 1) }); err != nil {
		return err
	}
	if serr != nil {
		return serr
	}
	_, werr := conn.Write(seg)
	if err := raw.Control(func(fd uintptr) { serr = setTTL(fd, v6, old) }); err != nil {
		return err
	}
	if werr != nil {
		return werr
	}
	if serr != nil {
		return errors.Join(errors.New("restore TTL"), serr)
	}
	return nil
}
