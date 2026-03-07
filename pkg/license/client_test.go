package license

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRefreshLicense_Success(t *testing.T) {
	pub, priv := generateTestKeypair(t)
	l := validLicense()
	newKey := signForTesting(t, l, priv)
	_ = pub

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"key": newKey})
	}))
	defer srv.Close()

	client := NewClient(srv.URL, nil)
	key, err := client.RefreshLicense(context.Background(), "old-key")
	require.NoError(t, err)
	assert.Equal(t, newKey, key)
}

func TestRefreshLicense_SubscriptionInactive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "subscription inactive"})
	}))
	defer srv.Close()

	client := NewClient(srv.URL, nil)
	_, err := client.RefreshLicense(context.Background(), "some-key")
	assert.ErrorIs(t, err, ErrSubscriptionInactive)
}

func TestRefreshLicense_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "unknown license"})
	}))
	defer srv.Close()

	client := NewClient(srv.URL, nil)
	_, err := client.RefreshLicense(context.Background(), "some-key")
	assert.ErrorIs(t, err, ErrLicenseNotFound)
}

func TestRefreshLicense_RateLimited(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]string{"error": "rate limited"})
	}))
	defer srv.Close()

	client := NewClient(srv.URL, nil)
	_, err := client.RefreshLicense(context.Background(), "some-key")
	assert.ErrorIs(t, err, ErrRateLimited)
}

func TestRefreshLicense_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "internal error"})
	}))
	defer srv.Close()

	client := NewClient(srv.URL, nil)
	_, err := client.RefreshLicense(context.Background(), "some-key")
	assert.ErrorIs(t, err, ErrServerError)
}

func TestRefreshLicense_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("not json"))
	}))
	defer srv.Close()

	client := NewClient(srv.URL, nil)
	_, err := client.RefreshLicense(context.Background(), "some-key")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid response JSON")
}

func TestRefreshLicense_EmptyKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"key": ""})
	}))
	defer srv.Close()

	client := NewClient(srv.URL, nil)
	_, err := client.RefreshLicense(context.Background(), "some-key")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty key")
}

func TestRefreshLicense_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"key": "new-key"})
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	client := NewClient(srv.URL, nil)
	_, err := client.RefreshLicense(ctx, "some-key")
	assert.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestRefreshLicense_SendsCorrectRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/license/refresh", r.URL.Path)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Equal(t, "varax", r.Header.Get("User-Agent"))

		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		var reqBody map[string]string
		require.NoError(t, json.Unmarshal(body, &reqBody))
		assert.Equal(t, "my-current-key", reqBody["key"])

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"key": "refreshed-key"})
	}))
	defer srv.Close()

	client := NewClient(srv.URL, nil)
	key, err := client.RefreshLicense(context.Background(), "my-current-key")
	require.NoError(t, err)
	assert.Equal(t, "refreshed-key", key)
}
