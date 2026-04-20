package discovery

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPublicKeysDecodeErrorIncludesTruncatedBody(t *testing.T) {
	badBody := strings.Repeat("a", decodeErrorBodyMaxChars+100)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(badBody))
	}))
	defer ts.Close()

	c := &Client{
		md: &ProviderMetadata{JWKSURI: ts.URL},
		hc: ts.Client(),
	}

	_, err := c.PublicKeys(context.Background())
	if err == nil {
		t.Fatal("wanted decode error, got nil")
	}

	errMsg := err.Error()
	wantSnippet := strings.Repeat("a", decodeErrorBodyMaxChars)
	if !strings.Contains(errMsg, wantSnippet) {
		t.Fatalf("wanted error to contain body snippet, got: %q", errMsg)
	}
	if strings.Contains(errMsg, strings.Repeat("a", decodeErrorBodyMaxChars+1)) {
		t.Fatalf("wanted body snippet to be truncated to %d chars, got: %q", decodeErrorBodyMaxChars, errMsg)
	}
	if !strings.Contains(errMsg, "...(truncated)") {
		t.Fatalf("wanted truncation marker in error, got: %q", errMsg)
	}
}

func TestNewClientUsesMetadataCache(t *testing.T) {
	tmpDir := t.TempDir()
	var requests int32

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != oidcwk {
			http.NotFound(w, r)
			return
		}
		atomic.AddInt32(&requests, 1)
		issuer := "http://" + r.Host
		_, _ = w.Write([]byte(`{"issuer":"` + issuer + `","jwks_uri":"` + issuer + `/jwks"}`))
	}))

	cl, err := NewClient(context.Background(), ts.URL,
		WithHTTPClient(ts.Client()),
		WithMetadataCache(tmpDir, time.Hour),
	)
	if err != nil {
		t.Fatalf("first NewClient() failed: %v", err)
	}
	if cl.Metadata().Issuer != ts.URL {
		t.Fatalf("got issuer %q, want %q", cl.Metadata().Issuer, ts.URL)
	}
	ts.Close()

	cl, err = NewClient(context.Background(), ts.URL,
		WithHTTPClient(ts.Client()),
		WithMetadataCache(tmpDir, time.Hour),
	)
	if err != nil {
		t.Fatalf("second NewClient() should use cache: %v", err)
	}
	if cl.Metadata().Issuer != ts.URL {
		t.Fatalf("got issuer %q, want %q", cl.Metadata().Issuer, ts.URL)
	}
	if got := atomic.LoadInt32(&requests); got != 1 {
		t.Fatalf("expected 1 network discovery call, got %d", got)
	}
}

func TestNewClientMetadataCacheExpiredRefetches(t *testing.T) {
	tmpDir := t.TempDir()
	var requests int32

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != oidcwk {
			http.NotFound(w, r)
			return
		}
		atomic.AddInt32(&requests, 1)
		issuer := "http://" + r.Host
		_, _ = w.Write([]byte(`{"issuer":"` + issuer + `","jwks_uri":"` + issuer + `/jwks"}`))
	}))
	defer ts.Close()

	_, err := NewClient(context.Background(), ts.URL,
		WithHTTPClient(ts.Client()),
		WithMetadataCache(tmpDir, time.Hour),
	)
	if err != nil {
		t.Fatalf("first NewClient() failed: %v", err)
	}

	path := metadataCachePath(tmpDir, ts.URL)
	entry := providerMetadataCacheEntry{
		Metadata: ProviderMetadata{Issuer: ts.URL, JWKSURI: ts.URL + "/jwks"},
		CachedAt: time.Now().Add(-2 * time.Hour),
	}
	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("json.Marshal() failed: %v", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("os.WriteFile() failed: %v", err)
	}

	_, err = NewClient(context.Background(), ts.URL,
		WithHTTPClient(ts.Client()),
		WithMetadataCache(tmpDir, time.Hour),
	)
	if err != nil {
		t.Fatalf("second NewClient() failed: %v", err)
	}
	if got := atomic.LoadInt32(&requests); got != 2 {
		t.Fatalf("expected 2 network discovery calls after expiry, got %d", got)
	}
}

func TestNewClientCorruptMetadataCacheFallsBackToNetwork(t *testing.T) {
	tmpDir := t.TempDir()
	var requests int32

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != oidcwk {
			http.NotFound(w, r)
			return
		}
		atomic.AddInt32(&requests, 1)
		issuer := "http://" + r.Host
		_, _ = w.Write([]byte(`{"issuer":"` + issuer + `","jwks_uri":"` + issuer + `/jwks"}`))
	}))
	defer ts.Close()

	path := metadataCachePath(tmpDir, ts.URL)
	if err := os.MkdirAll(tmpDir, 0700); err != nil {
		t.Fatalf("os.MkdirAll() failed: %v", err)
	}
	if err := os.WriteFile(path, []byte("not-json"), 0600); err != nil {
		t.Fatalf("os.WriteFile() failed: %v", err)
	}

	cl, err := NewClient(context.Background(), ts.URL,
		WithHTTPClient(ts.Client()),
		WithMetadataCache(tmpDir, time.Hour),
	)
	if err != nil {
		t.Fatalf("NewClient() failed: %v", err)
	}
	if cl.Metadata().Issuer != ts.URL {
		t.Fatalf("got issuer %q, want %q", cl.Metadata().Issuer, ts.URL)
	}
	if got := atomic.LoadInt32(&requests); got != 1 {
		t.Fatalf("expected 1 network discovery call, got %d", got)
	}
}
