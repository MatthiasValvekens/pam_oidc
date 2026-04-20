package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v3"
)

const oidcwk = "/.well-known/openid-configuration"
const decodeErrorBodyMaxChars = 1024
const defaultMetadataCacheTTL = 12 * time.Hour

// keep us looking like a keysource, for consistency
var _ KeySource = (*Client)(nil)

// Client can be used to fetch the provider metadata for a given issuer, and can
// also return the signing keys on demand.
//
// It should be created via `NewClient` to ensure it is initialized correctly.
type Client struct {
	md *ProviderMetadata

	hc *http.Client

	metadataCacheDir string
	metadataCacheTTL time.Duration

	jwks   *jose.JSONWebKeySet
	jwksMu sync.Mutex
}

// ClientOpt is an option that can configure a client
type ClientOpt func(c *Client)

// WithHTTPClient will set a http.Client for the initial discovery, and key
// fetching. If not set, http.DefaultClient will be used.
func WithHTTPClient(hc *http.Client) func(c *Client) {
	return func(c *Client) {
		c.hc = hc
	}
}

// WithMetadataCache enables filesystem caching for provider metadata
// (/.well-known/openid-configuration).
func WithMetadataCache(cacheDir string, ttl time.Duration) func(c *Client) {
	if ttl <= 0 {
		ttl = defaultMetadataCacheTTL
	}

	return func(c *Client) {
		c.metadataCacheDir = cacheDir
		c.metadataCacheTTL = ttl
	}
}

// NewClient will initialize a Client, performing the initial discovery.
func NewClient(ctx context.Context, issuer string, opts ...ClientOpt) (*Client, error) {
	c := &Client{
		md: &ProviderMetadata{},
		hc: http.DefaultClient,
	}

	for _, o := range opts {
		o(c)
	}

	if c.metadataCacheDir != "" {
		if md, err := readProviderMetadataFile(metadataCachePath(c.metadataCacheDir, issuer), c.metadataCacheTTL); err == nil {
			c.md = md
			return c, nil
		}
	}

	mdr, err := c.hc.Get(issuer + oidcwk)
	if err != nil {
		return nil, fmt.Errorf("error fetching %s: %v", issuer+oidcwk, err)
	}
	md := &ProviderMetadata{}
	err = json.NewDecoder(mdr.Body).Decode(md)
	_ = mdr.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("error decoding provider metadata response: %v", err)
	}

	c.md = md
	if c.metadataCacheDir != "" {
		_ = writeProviderMetadataFile(metadataCachePath(c.metadataCacheDir, issuer), md)
	}

	return c, nil
}

// Metadata returns the ProviderMetadata that was retrieved when the client was
// instantiated
func (c *Client) Metadata() *ProviderMetadata {
	return c.md
}

// PublicKeys will fetch and return the JWKS endpoint for this metadata. each
// request will perform a new HTTP request to the endpoint.
func (c *Client) PublicKeys(ctx context.Context) (*jose.JSONWebKeySet, error) {
	if c.md.JWKSURI == "" {
		return nil, fmt.Errorf("metadata has no JWKS endpoint, cannot fetch keys")
	}

	res, err := c.hc.Get(c.md.JWKSURI)
	if err != nil {
		return nil, fmt.Errorf("failed to get keys from %s: %v", c.md.JWKSURI, err)
	}

	ks := &jose.JSONWebKeySet{}
	body, readErr := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if readErr != nil {
		return nil, fmt.Errorf("failed reading JWKS response body: %v", readErr)
	}

	err = json.Unmarshal(body, ks)
	if err != nil {
		return nil, fmt.Errorf("failed decoding JWKS response: %v (body: %q)", err, truncateForLog(string(body), decodeErrorBodyMaxChars))
	}

	return ks, nil
}

func truncateForLog(s string, maxChars int) string {
	if maxChars <= 0 {
		return ""
	}

	runes := []rune(s)
	if len(runes) <= maxChars {
		return s
	}

	return string(runes[:maxChars]) + "...(truncated)"
}

// GetKey will return the key for the given kid. If the key has already
// been fetched, no network request will be made - the cached version will be
// returned. Otherwise, a call to the keys endpoint will be made.
func (c *Client) GetKey(ctx context.Context, kid string) (*jose.JSONWebKey, error) {
	c.jwksMu.Lock()
	defer c.jwksMu.Unlock()

	if c.jwks != nil {
		for _, k := range c.jwks.Keys {
			if k.KeyID == kid {
				return &k, nil
			}
		}
	}

	ks, err := c.PublicKeys(ctx)
	if err != nil {
		return nil, err
	}
	c.jwks = ks

	// try again, with the fresh set
	for _, k := range c.jwks.Keys {
		if k.KeyID == kid {
			return &k, nil
		}
	}

	return nil, fmt.Errorf("key %s not found", kid)
}
