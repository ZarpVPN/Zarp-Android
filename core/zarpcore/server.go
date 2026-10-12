package zarpcore

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// typeZarpDial is the sing-box outbound type that opens the connections to the user's server. A protocol outbound
// (vless, trojan, hysteria2) names it as its detour, so the protocol keeps its own server name, SNI and headers.
const typeZarpDial = "zarp-dial"

// ServerOptions describes one connection to the user's own server and the strategy applied to it.
// Create it with NewServerOptions.
type ServerOptions struct {
	host         string
	address      string
	port         int
	quic         bool
	tcpDesync    string
	fakes        []fakeStep
	blobs        map[string][]byte
	xrayOutbound string
	timeoutMs    int
}

// NewServerOptions returns empty options.
func NewServerOptions() *ServerOptions {
	return &ServerOptions{blobs: map[string][]byte{}}
}

// SetServer names the server as the link does (host) and the IP address the app resolved for it. The
// protocols keep using the name; the sockets go to the address.
func (o *ServerOptions) SetServer(host, address string, port int) {
	o.host, o.address, o.port = host, address, port
}

// SetQUIC marks the outer transport of the server as QUIC over UDP (Hysteria2, XHTTP over h3). Otherwise it is
// TLS over TCP.
func (o *ServerOptions) SetQUIC(quic bool) { o.quic = quic }

// SetTCPDesync sets the ClientHello desync for a TLS over TCP server, e.g. "split:1,midsld".
func (o *ServerOptions) SetTCPDesync(spec string) { o.tcpDesync = spec }

// AddBlob loads a fake packet under the name the strategy uses.
func (o *ServerOptions) AddBlob(name string, data []byte) {
	o.blobs[name] = append([]byte(nil), data...)
}

// AddFake adds a `fake` step for a QUIC server: repeats copies of the blob before the first datagram of every
// flow. ttl4 and ttl6 (0 = unchanged) apply to the fakes only.
func (o *ServerOptions) AddFake(blob string, repeats, ttl4, ttl6 int) {
	o.fakes = append(o.fakes, fakeStep{blob: blob, repeats: repeats, ttl4: ttl4, ttl6: ttl6})
}

// SetXrayOutbound makes the server an XHTTP one: the JSON object is the Xray outbound built from the link, and
// the proxy reaches it through an in-process Xray bridge instead of a sing-box protocol outbound.
func (o *ServerOptions) SetXrayOutbound(outboundJSON string) { o.xrayOutbound = outboundJSON }

// SetConnectTimeoutMs bounds every connection attempt to the server.
func (o *ServerOptions) SetConnectTimeoutMs(ms int) { o.timeoutMs = ms }

func newServerSession(o *ServerOptions, sockets SocketFactory) (*serverSession, error) {
	if o == nil {
		return nil, errors.New("server options are required")
	}
	if strings.TrimSpace(o.host) == "" || o.port < 1 || o.port > 65535 {
		return nil, errors.New("the server needs a name and a port")
	}
	if net.ParseIP(o.address) == nil {
		return nil, errors.New("the server address must be an IP address")
	}
	s := &serverSession{
		host: o.host, address: o.address, port: o.port, quic: o.quic,
		fakes: o.fakes, blobs: o.blobs, sockets: sockets,
		timeout: time.Duration(o.timeoutMs) * time.Millisecond,
	}
	if o.tcpDesync != "" {
		if o.quic {
			return nil, errors.New("a TCP desync cannot be applied to a QUIC server")
		}
		spec, err := parseDesync(o.tcpDesync)
		if err != nil {
			return nil, err
		}
		s.tcp = spec
	}
	if len(o.fakes) > 0 && !o.quic {
		return nil, errors.New("fake QUIC packets cannot be applied to a TLS over TCP server")
	}
	for _, f := range o.fakes {
		if f.repeats < 1 || f.repeats > 50 || f.ttl4 < 0 || f.ttl4 > 255 || f.ttl6 < 0 || f.ttl6 > 255 {
			return nil, errors.New("bad fake packet parameters")
		}
		if len(o.blobs[f.blob]) == 0 {
			return nil, errors.New("a fake packet is not loaded")
		}
	}
	return s, nil
}

// ---------------------------------------------------------------------------------------------- the outbound

type sessionKey struct{}

func sessionFrom(ctx context.Context) *serverSession {
	s, _ := ctx.Value(sessionKey{}).(*serverSession)
	return s
}

type zarpDialOptions struct {
	Server     string `json:"server"`
	ServerPort uint16 `json:"server_port"`
}

type zarpDial struct {
	outbound.Adapter
	sess *serverSession
}

func registerZarpDial(registry *outbound.Registry) {
	outbound.Register[zarpDialOptions](registry, typeZarpDial, newZarpDial)
}

func newZarpDial(ctx context.Context, _ adapter.Router, _ log.ContextLogger, tag string, options zarpDialOptions) (adapter.Outbound, error) {
	sess := sessionFrom(ctx)
	if sess == nil {
		return nil, errors.New("zarp-dial needs a server session")
	}
	if !sess.matches(options.Server, int(options.ServerPort)) {
		return nil, errors.New("zarp-dial is not for this server")
	}
	return &zarpDial{
		Adapter: outbound.NewAdapter(typeZarpDial, tag, []string{N.NetworkTCP, N.NetworkUDP}, nil),
		sess:    sess,
	}, nil
}

func (d *zarpDial) own(destination M.Socksaddr) error {
	if !d.sess.matches(destination.AddrString(), int(destination.Port)) {
		return d.sess.fail(errors.New("zarp-dial only dials its own server"))
	}
	return nil
}

func (d *zarpDial) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if err := d.own(destination); err != nil {
		return nil, err
	}
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		if d.sess.quic {
			return nil, d.sess.fail(errors.New("zarp-dial only dials its own server over its own transport"))
		}
		return d.sess.dialTCP(ctx)
	case N.NetworkUDP:
		if !d.sess.quic {
			return nil, d.sess.fail(errors.New("zarp-dial only dials its own server over its own transport"))
		}
		return d.sess.dialUDP(ctx)
	}
	return nil, os.ErrInvalid
}

func (d *zarpDial) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if err := d.own(destination); err != nil {
		return nil, err
	}
	if !d.sess.quic {
		return nil, d.sess.fail(errors.New("zarp-dial only dials its own server over its own transport"))
	}
	pc, _, err := d.sess.listenUDP(ctx)
	return pc, err
}

// ---------------------------------------------------------------------------------------------- the proxy

// NewServerProxy starts a loopback SOCKS5 proxy for the user's server. configJSON is built by the app (the
// sing-box configuration: inbound, the protocol outbound with "detour":"server-dial", the "zarp-dial" outbound,
// DNS and routing). The strategy of the pair is applied to every connection the proxy opens to the server.
// For an XHTTP server the outbound tagged "proxy" is a placeholder SOCKS outbound that gets the port and the
// login of the Xray bridge. Errors never echo credentials.
func NewServerProxy(configJSON string, opts *ServerOptions, sockets SocketFactory) (*Proxy, error) {
	sess, err := newServerSession(opts, sockets)
	if err != nil {
		return nil, err
	}
	var bridge *xrayBridge
	if opts.xrayOutbound != "" {
		bridge, err = startXrayBridge(sess, opts.xrayOutbound)
		if err != nil {
			return nil, err
		}
	}
	patch := func(options *option.Options) error {
		if bridge == nil {
			return nil
		}
		for i := range options.Outbounds {
			o := &options.Outbounds[i]
			if o.Tag != "proxy" || o.Type != "socks" {
				continue
			}
			socks, ok := o.Options.(*option.SOCKSOutboundOptions)
			if !ok {
				break
			}
			socks.Server = "127.0.0.1"
			socks.ServerPort = uint16(bridge.port)
			socks.Username = bridge.user
			socks.Password = bridge.pass
			return nil
		}
		return errors.New("the configuration has no SOCKS outbound named proxy for the bridge")
	}
	p, err := startProxy(withSession(context.Background(), sess), configJSON, patch)
	if err != nil {
		bridge.close()
		return nil, err
	}
	p.session, p.bridge = sess, bridge
	return p, nil
}

func withSession(ctx context.Context, s *serverSession) context.Context {
	return context.WithValue(ctx, sessionKey{}, s)
}

// LastError is the class of the last failure to reach the server: refused, timeout, unreachable, reset,
// certificate, ech, reality, status, ttl, protect, blocked or other. Empty when nothing failed.
func (p *Proxy) LastError() string {
	if p.session == nil {
		return ""
	}
	return p.session.lastClass()
}

// LastDetail is the last failure line of the Xray bridge (without page addresses), or empty. It is meant for the
// log; the app removes the credentials of the link from it.
func (p *Proxy) LastDetail() string { return p.bridge.detail() }

// SplitCount is the number of ClientHellos that were cut up.
func (p *Proxy) SplitCount() int64 {
	return p.counter(func(s *serverSession) int64 { return s.splitDials.Load() })
}

// FakeFlowCount is the number of UDP flows that got fake packets before their first datagram.
func (p *Proxy) FakeFlowCount() int64 {
	return p.counter(func(s *serverSession) int64 { return s.fakeFlows.Load() })
}

// FakePacketCount is the number of fake packets sent.
func (p *Proxy) FakePacketCount() int64 {
	return p.counter(func(s *serverSession) int64 { return s.fakePackets.Load() })
}

// ServerConnections is the number of TCP connections and UDP flows opened to the server.
func (p *Proxy) ServerConnections() int64 {
	return p.counter(func(s *serverSession) int64 { return s.tcpDials.Load() + s.udpFlows.Load() })
}

// ForeignConnections is the number of connections to addresses other than the server (an XHTTP
// downloadSettings address, for example). The strategy is not applied to them.
func (p *Proxy) ForeignConnections() int64 {
	return p.counter(func(s *serverSession) int64 { return s.foreign.Load() })
}

func (p *Proxy) counter(f func(*serverSession) int64) int64 {
	if p.session == nil {
		return 0
	}
	return f(p.session)
}
