package zarpcore

import (
	"context"
	"errors"
	"net/netip"
	"sync"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	boxservice "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/hysteria2"
	"github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing-box/protocol/trojan"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing/common/json"
)

// Proxy is a local SOCKS5 listener with an explicitly configured outbound and
// CIDR routing. Android excludes Zarp's UID in both per-app and all-app mode,
// so outbound sockets (including direct bypass sockets) cannot loop into TUN.
type Proxy struct {
	box    *box.Box
	port   int
	cancel context.CancelFunc
	once   sync.Once

	// only for a connection to the user's own server (NewServerProxy)
	session *serverSession
	bridge  *xrayBridge
}

func proxyContext(ctx context.Context) context.Context {
	in := inbound.NewRegistry()
	socks.RegisterInbound(in)
	out := outbound.NewRegistry()
	direct.RegisterOutbound(out)
	socks.RegisterOutbound(out)
	vless.RegisterOutbound(out)
	trojan.RegisterOutbound(out)
	hysteria2.RegisterOutbound(out)
	registerZarpDial(out)
	resolver := dns.NewTransportRegistry()
	local.RegisterTransport(resolver)
	transport.RegisterUDP(resolver)
	transport.RegisterTCP(resolver)
	return box.Context(ctx, in, out, endpoint.NewRegistry(), resolver, boxservice.NewRegistry())
}

// debugSetupErrors makes setup errors carry the cause. Off in the app, because causes can echo credentials;
// the tests turn it on.
var debugSetupErrors = false

func setupError(text string, cause error) error {
	if debugSetupErrors && cause != nil {
		return errors.New(text + ": " + cause.Error())
	}
	return errors.New(text)
}

// NewProxy starts a loopback-only SOCKS server. configJSON is constructed by the
// application, never arbitrary imported sing-box configuration. Imported links
// are parsed into a single validated outbound. Errors never echo credentials.
func NewProxy(configJSON string) (*Proxy, error) {
	return startProxy(context.Background(), configJSON, nil)
}

// startProxy builds and starts the sing-box instance. patch, if not nil, may change the parsed options before it starts.
func startProxy(parent context.Context, configJSON string, patch func(*option.Options) error) (*Proxy, error) {
	ctx, cancel := context.WithCancel(parent)
	ctx = proxyContext(ctx)
	var options option.Options
	if err := json.UnmarshalContext(ctx, []byte(configJSON), &options); err != nil {
		cancel()
		return nil, setupError("invalid proxy configuration", err)
	}
	if len(options.Inbounds) != 1 || options.Inbounds[0].Type != "socks" {
		cancel()
		return nil, errors.New("one SOCKS inbound required")
	}
	in, ok := options.Inbounds[0].Options.(*option.SocksInboundOptions)
	if !ok || in.Listen == nil || !in.Listen.Build(netip.Addr{}).IsLoopback() {
		cancel()
		return nil, errors.New("proxy must listen on loopback")
	}
	if patch != nil {
		if err := patch(&options); err != nil {
			cancel()
			return nil, setupError("invalid proxy configuration", err)
		}
	}
	port, err := freePort()
	if err != nil {
		cancel()
		return nil, err
	}
	in.ListenPort = uint16(port)
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		cancel()
		return nil, setupError("proxy setup failed; check server parameters", err)
	}
	if err = instance.Start(); err != nil {
		_ = instance.Close()
		cancel()
		return nil, setupError("proxy listener failed to start", err)
	}
	return &Proxy{box: instance, port: port, cancel: cancel}, nil
}

func (p *Proxy) SocksPort() int { return p.port }

func (p *Proxy) Close() {
	p.once.Do(func() {
		p.cancel()
		_ = p.box.Close()
		p.bridge.close()
	})
}
