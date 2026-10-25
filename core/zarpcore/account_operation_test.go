package zarpcore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/models"
)

func testAccountOperation(t *testing.T, path string, handler http.HandlerFunc) *AccountOperation {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	op, err := NewAccountOperation(path, "", 25000, nil)
	if err != nil {
		t.Fatal(err)
	}
	op.client = &api.Client{HTTP: server.Client(), BaseURL: server.URL}
	t.Cleanup(op.Close)
	return op
}

func enrolledAccount() models.AccountData {
	acc := models.AccountData{ID: "device-test"}
	peer := models.Peer{PublicKey: "test-public-key"}
	peer.Endpoint.V4 = "162.159.198.1:0"
	acc.Config.Peers = []models.Peer{peer}
	acc.Config.Interface.Addresses.V4 = "172.16.0.2"
	return acc
}

func TestAccountRegistrationResumesEnrollmentAndPreservesIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "account.json")
	var registrations, enrollments atomic.Int32
	var keys []string
	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/reg" {
			registrations.Add(1)
			json.NewEncoder(w).Encode(models.AccountData{ID: "device-test", Token: "private-token"})
			return
		}
		if r.Method != http.MethodPatch || r.URL.Path != "/reg/device-test" || r.Header.Get("Authorization") != "Bearer private-token" {
			t.Error("incorrect enrollment")
			w.WriteHeader(400)
			return
		}
		var update models.DeviceUpdate
		json.NewDecoder(r.Body).Decode(&update)
		keys = append(keys, update.Key)
		if update.KeyType != "secp256r1" || update.TunType != "masque" || update.Key == "" {
			t.Error("incorrect MASQUE key")
		}
		if enrollments.Add(1) == 1 {
			w.WriteHeader(503)
			return
		}
		json.NewEncoder(w).Encode(enrolledAccount())
	}
	op := testAccountOperation(t, path, handler)
	if err := op.EnsureRegistered("Zarp test"); err == nil || err.Error() != "account:network" {
		t.Fatalf("first: %v", err)
	}
	if HasAccount(path) {
		t.Fatal("partial enrollment became a usable account")
	}
	if _, err := os.Stat(path + ".pending"); err != nil {
		t.Fatal("lost resumable registration", err)
	}
	if err := op.EnsureRegistered("Zarp test"); err != nil {
		t.Fatal(err)
	}
	if registrations.Load() != 1 || enrollments.Load() != 2 || len(keys) != 2 || keys[0] != keys[1] {
		t.Fatal("retry replaced registration or key")
	}
	if !HasAccount(path) {
		t.Fatal("account not published")
	}
	if _, err := os.Stat(path + ".pending"); !os.IsNotExist(err) {
		t.Fatal("pending identity not removed")
	}
	before, _ := os.ReadFile(path)
	if err := op.EnsureRegistered("different name"); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) || registrations.Load() != 1 || enrollments.Load() != 2 {
		t.Fatal("existing registration changed")
	}
}

func TestWarpLicenseAccountPrivacyAndConfirmation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "account.json")
	writeConfig(path, &config.Config{ID: "device-test", AccessToken: "private-token", PrivateKey: "private-key", EndpointPubKey: "public-key"})
	before, _ := os.ReadFile(path)
	license := "12345678-abcdefgh-ABCD1234"
	var updates, reads int
	unconfirmed := false
	op := testAccountOperation(t, path, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/reg/device-test/account" || r.Header.Get("Authorization") != "Bearer private-token" {
			t.Error("incorrect authenticated request")
		}
		if r.Method == http.MethodPut {
			updates++
			var payload map[string]string
			json.NewDecoder(r.Body).Decode(&payload)
			if len(payload) != 1 || payload["license"] != license {
				t.Error("incorrect license payload")
			}
			return
		}
		reads++
		if unconfirmed {
			w.WriteHeader(503)
			return
		}
		json.NewEncoder(w).Encode(models.Account{AccountType: "unlimited", License: license, ID: "do-not-expose"})
	})
	if _, err := op.ApplyLicense("malformed-secret"); err == nil || err.Error() != "account:invalid" {
		t.Fatal(err)
	}
	if updates != 0 || reads != 0 {
		t.Fatal("invalid key sent to network")
	}
	if typ, err := op.ApplyLicense(" " + license + " "); err != nil || typ != "unlimited" {
		t.Fatalf("%s %v", typ, err)
	}
	unconfirmed = true
	if typ, err := op.ApplyLicense(license); err != nil || typ != "unknown" {
		t.Fatalf("unconfirmed %s %v", typ, err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) || bytes.Contains(after, []byte(license)) {
		t.Fatal("license operation modified config or persisted key")
	}
}

func TestAccountCancellationAndSafeErrors(t *testing.T) {
	started := make(chan struct{})
	op := testAccountOperation(t, filepath.Join(t.TempDir(), "account.json"), func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		close(started)
		<-r.Context().Done()
	})
	done := make(chan error, 1)
	go func() { done <- op.EnsureRegistered("test") }()
	<-started
	op.Close()
	select {
	case err := <-done:
		if err == nil || err.Error() != "account:cancelled" {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancel did not abort request")
	}
	for status, want := range map[int]string{400: "rejected", 403: "rejected", 409: "rejected", 429: "rateLimit", 408: "network", 502: "network", 503: "network", 504: "network", 500: "api"} {
		err := accountError(&api.ResponseError{Status: status})
		if err.Error() != "account:"+want {
			t.Fatal(status, err)
		}
	}
	if got := accountError(errors.New("secret-license private-token")); got.Error() != "account:response" {
		t.Fatal("unsafe diagnostics", got)
	}
	if accountError(context.DeadlineExceeded).Error() != "account:timeout" {
		t.Fatal("deadline classification")
	}
}

func TestAccountTypesAndTransportScope(t *testing.T) {
	for input, want := range map[string]string{"free": "free", "limited": "plus", "unlimited": "unlimited", "team": "zerotrust", "unknown": "unknown"} {
		if got := accountType(&models.Account{AccountType: input}); got != want {
			t.Fatal(input, got)
		}
	}
	if accountType(&models.Account{WarpPlus: true}) != "unknown" || accountType(&models.Account{AccountType: "free", WarpPlus: true}) != "free" {
		t.Fatal("ambiguous WARP+ flag must not override the explicit account type")
	}
	op, err := NewAccountOperation(filepath.Join(t.TempDir(), "account.json"), "split:1,midsld", 25000, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer op.Close()
	if op.transport.Proxy != nil {
		t.Fatal("system proxy would carry protected registration")
	}
	for _, address := range []string{"example.com:443", "api.cloudflareclient.com:80", "127.0.0.1:443"} {
		_, err := op.transport.DialTLSContext(op.ctx, "tcp", address)
		if err == nil || !strings.Contains(err.Error(), "account:destination") {
			t.Fatal("unscoped API connection", address, err)
		}
	}
	if _, err := NewAccountOperation("unused", "raw:1", 25000, nil); err == nil {
		t.Fatal("accepted unavailable primitive")
	}
}
