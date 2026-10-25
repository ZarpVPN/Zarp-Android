package zarpcore

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/models"
)

const (
	registerModel  = "PC"
	registerLocale = "en_US"
)

// Register creates a new WARP device, enrolls a MASQUE (P-256) key for it and
// writes the resulting usque-compatible config to configPath.
//
// The caller must have obtained the user's consent to the Cloudflare WARP
// Terms of Service before calling it.
func Register(configPath string, deviceName string) error {
	op, err := NewAccountOperation(configPath, "", 25000, nil)
	if err != nil {
		return err
	}
	defer op.Close()
	return op.EnsureRegistered(deviceName)
}

func configFromAccount(upd *models.AccountData, token string, privKey []byte) (*config.Config, error) {
	if len(upd.Config.Peers) == 0 {
		return nil, errors.New("enroll key: response has no peers")
	}
	peer := upd.Config.Peers[0]
	v4, err := stripPort(peer.Endpoint.V4)
	if err != nil {
		return nil, fmt.Errorf("endpoint v4 %q: %w", peer.Endpoint.V4, err)
	}
	v6, _ := stripPort(peer.Endpoint.V6) // IPv6 endpoint is optional
	return &config.Config{
		PrivateKey:     base64.StdEncoding.EncodeToString(privKey),
		EndpointV4:     v4,
		EndpointV6:     v6,
		EndpointH2V4:   config.DefaultEndpointH2V4,
		EndpointH2V6:   config.DefaultEndpointH2V6,
		EndpointPubKey: peer.PublicKey,
		ID:             upd.ID,
		AccessToken:    token,
		IPv4:           upd.Config.Interface.Addresses.V4,
		IPv6:           upd.Config.Interface.Addresses.V6,
	}, nil
}

// stripPort turns "162.159.198.1:0" or "[2606:4700::1]:0" into a bare IP.
func stripPort(hostPort string) (string, error) {
	if hostPort == "" {
		return "", errors.New("empty")
	}
	host := hostPort
	if h, _, err := net.SplitHostPort(hostPort); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if net.ParseIP(host) == nil {
		return "", errors.New("not an IP address")
	}
	return host, nil
}

func writeConfig(path string, cfg *config.Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readConfig(path string) (*config.Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg config.Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	if cfg.PrivateKey == "" || cfg.EndpointPubKey == "" {
		return nil, fmt.Errorf("config %s: missing keys", path)
	}
	return &cfg, nil
}

// HasAccount reports whether configPath holds a usable WARP registration.
func HasAccount(configPath string) bool {
	_, err := readConfig(configPath)
	return err == nil
}

// AccountEndpoint returns the MASQUE endpoint IPv4 address assigned at registration.
func AccountEndpoint(configPath string) (string, error) {
	cfg, err := readConfig(configPath)
	if err != nil {
		return "", err
	}
	return cfg.EndpointV4, nil
}
