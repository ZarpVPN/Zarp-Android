package zarpcore

// VLESS over XHTTP for the proxy engine. sing-box cannot speak XHTTP, so for such servers an Xray-core
// instance runs inside this process as a SOCKS5 bridge on 127.0.0.1 (random port, random login) and sing-box
// uses it as its outbound. Xray gets only the outbound object of the link; the inbound, the credentials and
// the logging are made here. Routing, DNS and per-app selection stay in sing-box.
//
// Every connection Xray opens to the server goes through the system dialer installed below, so the strategy
// of the pair is applied to all of them (new streams, reconnects, xmux connections), and only to them.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	xlog "github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
	xcore "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/transport/internet"

	// Only what the bridge needs. The JSON loader (main/json) pulls in the configuration code of the other
	// features anyway, but nothing else is registered or started.
	_ "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	_ "github.com/xtls/xray-core/main/json"
	_ "github.com/xtls/xray-core/proxy/freedom"
	_ "github.com/xtls/xray-core/proxy/socks"
	_ "github.com/xtls/xray-core/proxy/vless/outbound"
	_ "github.com/xtls/xray-core/transport/internet/reality"
	_ "github.com/xtls/xray-core/transport/internet/splithttp"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	_ "github.com/xtls/xray-core/transport/internet/tls"
	_ "github.com/xtls/xray-core/transport/internet/udp"
)

type xrayBridge struct {
	inst *xcore.Instance
	port int
	user string
	pass string
	sess *serverSession
	log  *xrayLog
	once sync.Once
}

// startXrayBridge starts Xray with the given outbound (the "outbounds" entry made from the link) and waits
// until the SOCKS5 inbound listens.
func startXrayBridge(sess *serverSession, outboundJSON string) (*xrayBridge, error) {
	var outbound map[string]any
	if err := json.Unmarshal([]byte(outboundJSON), &outbound); err != nil {
		return nil, errors.New("xray: the outbound is not a JSON object")
	}
	port, err := freePort()
	if err != nil {
		return nil, err
	}
	b := &xrayBridge{port: port, user: randomHex(8), pass: randomHex(16), sess: sess}
	config := map[string]any{
		// The access log lists the places the user visits and stays off. Failures are kept by our own handler.
		"log": map[string]any{"loglevel": "info", "access": "none"},
		"inbounds": []any{map[string]any{
			"tag": "bridge", "listen": "127.0.0.1", "port": port, "protocol": "socks",
			"settings": map[string]any{
				"auth": "password", "udp": true, "ip": "127.0.0.1",
				"users": []any{map[string]any{"user": b.user, "pass": b.pass}},
			},
		}},
		"outbounds": []any{outbound},
	}
	data, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	cfg, err := xcore.LoadConfig("json", bytes.NewReader(data))
	if err != nil {
		return nil, xrayConfigError(err)
	}
	inst, err := xcore.New(cfg)
	if err != nil {
		return nil, xrayConfigError(err)
	}
	b.inst = inst
	// core.New registers the log app as the handler; ours replaces it so that nothing is written anywhere.
	b.log = &xrayLog{}
	xlog.RegisterHandler(b.log)
	installXrayDialer()
	xrayDialers.register(sess)
	if err := inst.Start(); err != nil {
		b.close()
		return nil, xrayConfigError(err)
	}
	if err := waitListening(port, 3*time.Second); err != nil {
		b.close()
		return nil, errors.New("xray: the bridge did not start listening")
	}
	return b, nil
}

func randomHex(n int) string {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		panic(err) // the system has no entropy: nothing sensible can follow
	}
	return hex.EncodeToString(raw)
}

func (b *xrayBridge) close() {
	if b == nil {
		return
	}
	b.once.Do(func() {
		if b.inst != nil {
			_ = b.inst.Close()
		}
		xrayDialers.unregister(b.sess)
		xlog.RegisterHandler(discardXrayLog{})
	})
}

// detail is the last failure Xray reported, without addresses of pages (they hold the XHTTP path, which can be a secret).
func (b *xrayBridge) detail() string {
	if b == nil || b.log == nil {
		return ""
	}
	return b.log.last()
}

var urlInText = regexp.MustCompile(`https?://[^\s"']+`)

// xrayConfigError turns a configuration error of Xray into a short text. Xray's errors form a chain
// "reason > reason > ..."; the last links say what is wrong. URLs never stay in it.
func xrayConfigError(err error) error {
	text := strings.TrimSpace(strings.ReplaceAll(err.Error(), "\r", ""))
	if i := strings.Index(text, "Failed to start:"); i >= 0 {
		text = strings.TrimSpace(text[i+len("Failed to start:"):])
	}
	chain := strings.Split(text, " > ")
	if len(chain) > 3 {
		chain = chain[len(chain)-3:]
	}
	text = urlInText.ReplaceAllString(strings.Join(chain, " > "), "<url>")
	if len(text) > 300 {
		text = text[:300] + "..."
	}
	return errors.New("xray: " + text)
}

// ---------------------------------------------------------------------------------------------- log

var failureWords = regexp.MustCompile(`(?i)fail|error|refused|timeout|reset|denied|invalid|eof|unexpected|reject|ech|certificate|reality`)

// xrayLog keeps the last failure line. It implements Xray's log.Handler and SeverityLogger.
type xrayLog struct {
	mu   sync.Mutex
	text string
}

func (l *xrayLog) Severity() xlog.Severity { return xlog.Severity_Info }

func (l *xrayLog) Handle(msg xlog.Message) {
	gm, ok := msg.(*xlog.GeneralMessage)
	if !ok { // access messages and anything else: never stored
		return
	}
	text := fmt.Sprint(gm.Content)
	if gm.Severity > xlog.Severity_Warning && !failureWords.MatchString(text) {
		return
	}
	text = urlInText.ReplaceAllString(text, "<url>")
	if len(text) > 300 {
		text = text[:300] + "..."
	}
	l.mu.Lock()
	l.text = text
	l.mu.Unlock()
}

func (l *xrayLog) last() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.text
}

type discardXrayLog struct{}

func (discardXrayLog) Severity() xlog.Severity { return xlog.Severity_Error }
func (discardXrayLog) Handle(xlog.Message)     {}

// ---------------------------------------------------------------------------------------------- dialer

// xrayMux is Xray's system dialer. It replaces the one in the process (a package variable), so it is
// installed once and dispatches by destination to the sessions that are running.
type xrayMux struct {
	mu       sync.RWMutex
	sessions []*serverSession
}

var (
	xrayDialers = &xrayMux{}
	dialerOnce  sync.Once
)

func installXrayDialer() {
	dialerOnce.Do(func() { internet.UseAlternativeSystemDialer(xrayDialers) })
}

func (m *xrayMux) register(s *serverSession) {
	m.mu.Lock()
	m.sessions = append(m.sessions, s)
	m.mu.Unlock()
}

func (m *xrayMux) unregister(s *serverSession) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, x := range m.sessions {
		if x == s {
			m.sessions = append(m.sessions[:i], m.sessions[i+1:]...)
			return
		}
	}
}

// find returns the session whose server is host:port. When only one session runs, it also owns every other
// destination (such connections are plain and counted); with several the owner cannot be known.
func (m *xrayMux) find(host string, port int) (owner *serverSession, own bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, s := range m.sessions {
		if s.matches(host, port) {
			return s, true
		}
	}
	if len(m.sessions) == 1 {
		return m.sessions[0], false
	}
	return nil, false
}

// Dial implements internet.SystemDialer.
func (m *xrayMux) Dial(ctx context.Context, _ xnet.Address, dest xnet.Destination, _ *internet.SocketConfig) (xnet.Conn, error) {
	host := dest.Address.String()
	port := int(dest.Port)
	s, own := m.find(host, port)
	if !own {
		return m.foreign(ctx, s, dest)
	}
	switch dest.Network {
	case xnet.Network_TCP:
		if s.quic {
			return nil, s.fail(errors.New("zarp-dial only dials its own server over its own transport"))
		}
		return s.dialTCP(ctx)
	case xnet.Network_UDP:
		if !s.quic {
			return nil, s.fail(errors.New("zarp-dial only dials its own server over its own transport"))
		}
		pc, to, err := s.listenUDP(ctx)
		if err != nil {
			return nil, err
		}
		return &xnet.PacketConnWrapper{PacketConn: pc, Dest: to}, nil
	}
	return nil, errors.New("zarp-dial: unsupported network")
}

// foreign dials an address that is not the server of any running session.
func (m *xrayMux) foreign(ctx context.Context, s *serverSession, dest xnet.Destination) (xnet.Conn, error) {
	address := dest.NetAddr()
	if dest.Network == xnet.Network_UDP {
		to, err := net.ResolveUDPAddr("udp", address)
		if err != nil {
			return nil, err
		}
		var pc net.PacketConn
		if s != nil {
			s.foreign.Add(1)
			lc := net.ListenConfig{Control: s.control}
			pc, err = lc.ListenPacket(ctx, "udp", ":0")
		} else {
			pc, err = net.ListenPacket("udp", ":0")
		}
		if err != nil {
			return nil, err
		}
		return &xnet.PacketConnWrapper{PacketConn: pc, Dest: to}, nil
	}
	if s != nil {
		return s.dialForeign(ctx, "tcp", address)
	}
	return (&net.Dialer{Timeout: 16 * time.Second}).DialContext(ctx, "tcp", address)
}

// DestIpAddress implements internet.SystemDialer.
func (m *xrayMux) DestIpAddress() xnet.IP { return nil }
