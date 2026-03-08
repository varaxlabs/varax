package license

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const DefaultAPIURL = "https://api.varax.io/v1"

type Client struct {
	BaseURL    string
	HTTPClient *http.Client
	UserAgent  string
}

func NewClient(baseURL string, httpClient *http.Client) *Client {
	if baseURL == "" {
		baseURL = DefaultAPIURL
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{
		BaseURL:    baseURL,
		HTTPClient: httpClient,
		UserAgent:  "varax",
	}
}

func (c *Client) RefreshLicense(ctx context.Context, currentKey string) (string, error) {
	reqBody, err := json.Marshal(map[string]string{"key": currentKey})
	if err != nil {
		return "", fmt.Errorf("marshalling request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/license/refresh", strings.NewReader(string(reqBody)))
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", c.UserAgent)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("sending request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("reading response: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		// handled below
	case http.StatusUnauthorized:
		return "", ErrSubscriptionInactive
	case http.StatusNotFound:
		return "", ErrLicenseNotFound
	case http.StatusTooManyRequests:
		return "", ErrRateLimited
	default:
		if resp.StatusCode >= 500 {
			return "", ErrServerError
		}
		var errResp struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return "", fmt.Errorf("unexpected status %d: %s", resp.StatusCode, errResp.Error)
		}
		return "", fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	var result struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("invalid response JSON: %w", err)
	}
	if result.Key == "" {
		return "", fmt.Errorf("server returned empty key")
	}

	return result.Key, nil
}
