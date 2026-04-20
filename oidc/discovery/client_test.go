package discovery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
