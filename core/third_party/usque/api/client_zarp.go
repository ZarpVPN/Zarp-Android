package api

// Per-operation API client for Android. It never changes http.DefaultClient.
import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Diniboy1123/usque/internal"
	"github.com/Diniboy1123/usque/models"
)

// Client keeps API registration, enrollment and license requests on one transport.
type Client struct {
	HTTP    *http.Client
	BaseURL string
}

// ResponseError contains only the status, never an account, token or API body.
type ResponseError struct{ Status int }

func (e *ResponseError) Error() string { return fmt.Sprintf("WARP API HTTP %d", e.Status) }

func (c *Client) request(ctx context.Context, method, path, token string, input, output any) error {
	var body io.Reader
	if input != nil {
		data, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	base := c.BaseURL
	if base == "" {
		base = internal.ApiUrl + "/" + internal.ApiVersion
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, body)
	if err != nil {
		return err
	}
	for key, value := range internal.Headers {
		req.Header.Set(key, value)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return &ResponseError{Status: resp.StatusCode}
	}
	if output == nil {
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil {
		return err
	}
	if len(data) > 1<<20 {
		return fmt.Errorf("WARP API response too large")
	}
	return json.Unmarshal(data, output)
}

func (c *Client) Register(ctx context.Context, model, locale string) (*models.AccountData, error) {
	key, err := internal.GenerateRandomWgPubkey()
	if err != nil {
		return nil, err
	}
	serial, err := internal.GenerateRandomAndroidSerial()
	if err != nil {
		return nil, err
	}
	data := models.Registration{Key: key, Tos: internal.TimeAsCfString(time.Now()), Model: model,
		Serial: serial, KeyType: internal.KeyTypeWg, TunType: internal.TunTypeWg, Locale: locale}
	var account models.AccountData
	err = c.request(ctx, http.MethodPost, "/reg", "", data, &account)
	return &account, err
}

func (c *Client) EnrollKey(ctx context.Context, id, token string, key []byte, name string) (*models.AccountData, error) {
	data := models.DeviceUpdate{Key: base64.StdEncoding.EncodeToString(key), KeyType: internal.KeyTypeMasque,
		TunType: internal.TunTypeMasque, Name: name}
	var account models.AccountData
	err := c.request(ctx, http.MethodPatch, "/reg/"+id, token, data, &account)
	return &account, err
}

func (c *Client) ReadAccount(ctx context.Context, id, token string) (*models.Account, error) {
	var account models.Account
	err := c.request(ctx, http.MethodGet, "/reg/"+id+"/account", token, nil, &account)
	return &account, err
}

func (c *Client) ApplyLicense(ctx context.Context, id, token, license string) error {
	return c.request(ctx, http.MethodPut, "/reg/"+id+"/account", token, struct {
		License string `json:"license"`
	}{license}, nil)
}
