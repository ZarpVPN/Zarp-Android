package zarpcore

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/models"
	"github.com/Diniboy1123/usque/pub"
)

// AccountProtector excludes only this operation's HTTPS sockets from an active VPN.
type AccountProtector interface{ Protect(fd int) bool }

// AccountOperation is cancellable and owns a private HTTPS transport. TLS strategies
// apply only to the Cloudflare registration API, never to unrelated app traffic.
type AccountOperation struct {
	ctx       context.Context
	cancel    context.CancelFunc
	transport *http.Transport
	client    *api.Client
	path      string
}

// Serialize config creation across operations, without blocking cancellation.
var accountConfigLock = make(chan struct{}, 1)
var warpLicensePattern = regexp.MustCompile(`^[A-Za-z0-9]{8}-[A-Za-z0-9]{8}-[A-Za-z0-9]{8}$`)
var errAccountProtect = errors.New("account:protect")

// Cloudflare's published orchestration IPs; TLS still authenticates the API name.
// https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/deployment/firewall/#client-orchestration-api
var accountAPIAddresses = []string{"162.159.137.105:443", "162.159.138.105:443", "[2606:4700:7::a29f:8969]:443", "[2606:4700:7::a29f:8a69]:443"}

func NewAccountOperation(configPath, tcpDesync string, timeoutMs int, protector AccountProtector) (*AccountOperation, error) {
	if timeoutMs < 1000 || timeoutMs > 120000 {
		timeoutMs = 25000
	}
	var spec *desyncSpec
	var err error
	if tcpDesync != "" {
		spec, err = parseDesync(tcpDesync)
		if err != nil {
			return nil, errors.New("account:strategy")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMs)*time.Millisecond)
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	if protector != nil {
		dialer.Control = func(_, _ string, raw syscall.RawConn) error {
			var protectErr error
			err := raw.Control(func(fd uintptr) {
				if !protector.Protect(int(fd)) {
					protectErr = errAccountProtect
				}
			})
			if err != nil {
				return err
			}
			return protectErr
		}
	}
	tr := &http.Transport{
		Proxy: nil, ForceAttemptHTTP2: false, DisableKeepAlives: true,
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 15 * time.Second,
	}
	tr.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil || host != "api.cloudflareclient.com" || port != "443" {
			return nil, errors.New("account:destination")
		}
		targets := []string{address}
		if spec != nil {
			targets = append([]string{address}, accountAPIAddresses...)
		}
		var last error
		for _, target := range targets {
			attempt, stop := context.WithTimeout(ctx, 5*time.Second)
			conn, err := dialAccountTLS(attempt, dialer, target, host, spec)
			stop()
			if err == nil {
				return conn, nil
			}
			last = err
			if ctx.Err() != nil || errors.Is(err, errAccountProtect) {
				break
			}
		}
		return nil, last
	}
	client := &http.Client{Transport: tr, CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return errors.New("account:redirect")
	}}
	return &AccountOperation{ctx: ctx, cancel: cancel, transport: tr, client: &api.Client{HTTP: client}, path: configPath}, nil
}

func dialAccountTLS(ctx context.Context, dialer *net.Dialer, address, host string, spec *desyncSpec) (net.Conn, error) {
	raw, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	var conn net.Conn = raw
	if spec != nil {
		conn = newDesyncConn(raw.(*net.TCPConn), spec, host)
	}
	secured := tls.Client(conn, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
	if err = secured.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	return secured, nil
}

func (o *AccountOperation) Close() { o.cancel(); o.transport.CloseIdleConnections() }

type pendingAccount struct {
	ID         string `json:"id"`
	Token      string `json:"token"`
	PrivateKey []byte `json:"private_key"`
	PublicKey  []byte `json:"public_key"`
}

func (o *AccountOperation) EnsureRegistered(deviceName string) error {
	select {
	case accountConfigLock <- struct{}{}:
		defer func() { <-accountConfigLock }()
	case <-o.ctx.Done():
		return accountError(o.ctx.Err())
	}
	if HasAccount(o.path) {
		return nil
	}
	return accountError(o.register(deviceName))
}

func (o *AccountOperation) register(deviceName string) error {
	// Keep an issued identity and key after a failed enrollment. A protected retry
	// resumes PATCH rather than creating another device and consuming quota.
	var pending pendingAccount
	data, err := os.ReadFile(o.path + ".pending")
	if err == nil {
		if json.Unmarshal(data, &pending) != nil || pending.ID == "" || pending.Token == "" || len(pending.PrivateKey) == 0 || len(pending.PublicKey) == 0 {
			return errors.New("account:config")
		}
	} else if !os.IsNotExist(err) {
		return errors.New("account:config")
	} else {
		priv, pubKey, err := pub.GenerateEcKeyPair()
		if err != nil {
			return errors.New("account:config")
		}
		acc, err := o.client.Register(o.ctx, registerModel, registerLocale)
		if err != nil {
			return err
		}
		if acc.ID == "" || acc.Token == "" {
			return errors.New("account:response")
		}
		pending = pendingAccount{acc.ID, acc.Token, priv, pubKey}
		data, _ = json.Marshal(pending)
		if err := writeAccountFile(o.path+".pending", data); err != nil {
			return errors.New("account:config")
		}
	}
	upd, err := o.client.EnrollKey(o.ctx, pending.ID, pending.Token, pending.PublicKey, deviceName)
	if err != nil {
		return err
	}
	if upd.ID != pending.ID {
		return errors.New("account:response")
	}
	cfg, err := configFromAccount(upd, pending.Token, pending.PrivateKey)
	if err != nil {
		return errors.New("account:response")
	}
	if err := writeConfig(o.path, cfg); err != nil {
		return errors.New("account:config")
	}
	_ = os.Remove(o.path + ".pending")
	return nil
}

func writeAccountFile(path string, data []byte) error {
	// The caller's directory is private app storage; rename publishes complete JSON.
	if err := os.WriteFile(path+".tmp", data, 0600); err != nil {
		return err
	}
	defer os.Remove(path + ".tmp")
	return os.Rename(path+".tmp", path)
}

// ReadAccount returns only a normalized account type. No account data crosses JNI.
func (o *AccountOperation) ReadAccount() (string, error) {
	cfg, err := readConfig(o.path)
	if err != nil {
		return "unknown", errors.New("account:missing")
	}
	if cfg.ID == "" || cfg.AccessToken == "" {
		return "unknown", errors.New("account:config")
	}
	acc, err := o.client.ReadAccount(o.ctx, cfg.ID, cfg.AccessToken)
	if err != nil {
		return "unknown", accountError(err)
	}
	return accountType(acc), nil
}

func accountType(acc *models.Account) string {
	switch strings.ToLower(acc.AccountType) {
	case "free":
		return "free"
	case "limited", "plus", "warp+":
		return "plus"
	case "unlimited", "warp+ unlimited":
		return "unlimited"
	case "team", "enterprise", "zero trust":
		return "zerotrust"
	default:
		return "unknown"
	}
}

func (o *AccountOperation) ApplyLicense(license string) (string, error) {
	license = strings.TrimSpace(license)
	if !warpLicensePattern.MatchString(license) {
		return "unknown", errors.New("account:invalid")
	}
	cfg, err := readConfig(o.path)
	if err != nil {
		return "unknown", errors.New("account:missing")
	}
	if cfg.ID == "" || cfg.AccessToken == "" {
		return "unknown", errors.New("account:config")
	}
	if err := o.client.ApplyLicense(o.ctx, cfg.ID, cfg.AccessToken, license); err != nil {
		return "unknown", accountError(err)
	}
	typ, err := o.ReadAccount()
	if err != nil {
		return "unknown", nil
	} // accepted, but not confirmed; never claim WARP+ success
	return typ, nil
}

func accountError(err error) error {
	if err == nil {
		return nil
	}
	if strings.HasPrefix(err.Error(), "account:") {
		return err
	}
	if errors.Is(err, context.Canceled) {
		return errors.New("account:cancelled")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return errors.New("account:timeout")
	}
	if errors.Is(err, errAccountProtect) {
		return errAccountProtect
	}
	var status *api.ResponseError
	if errors.As(err, &status) {
		switch status.Status {
		case 408, 502, 503, 504:
			return errors.New("account:network")
		case 429:
			return errors.New("account:rateLimit")
		case 400, 403, 409:
			return errors.New("account:rejected")
		default:
			return errors.New("account:api")
		}
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return errors.New("account:network")
	}
	return errors.New("account:response")
}
