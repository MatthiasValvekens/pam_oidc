// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
// For full license text, see the LICENSE.txt file in the repo root or https://opensource.org/licenses/BSD-3-Clause

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/pardot/oidc"
)

// cachedKeySource wraps an oidc.KeySource and caches each retrieved key on the
// filesystem, keyed by its `kid`. Cache entries are evicted after the configured TTL.
// Filesystem-level atomicity (via temp file + rename) ensures safe concurrent
// writes from multiple PAM processes.
type cachedKeySource struct {
	inner  oidc.KeySource
	dir    string
	ttl    time.Duration
}

func newCachedKeySource(inner oidc.KeySource, dir string, ttl time.Duration) *cachedKeySource {
	return &cachedKeySource{inner: inner, dir: dir, ttl: ttl}
}

// GetKey returns the key for the given kid. It checks the on-disk cache first
// and falls back to the upstream KeySource on a miss, persisting the result.
func (c *cachedKeySource) GetKey(ctx context.Context, kid string) (*jose.JSONWebKey, error) {
	path := c.keyPath(kid)

	// Try to read from cache.
	if key, err := readKeyFile(path, c.ttl); err == nil {
		return key, nil
	}

	// Cache miss: fetch from upstream.
	key, err := c.inner.GetKey(ctx, kid)
	if err != nil {
		return nil, err
	}

	// Persist to cache (best-effort; don't fail auth on write error).
	_ = writeKeyFile(path, key)

	return key, nil
}

// keyPath returns the cache file path for a given kid, sanitising the kid so
// it is safe to use as a filename.
func (c *cachedKeySource) keyPath(kid string) string {
	// First, strip any path traversal attempts using filepath.Base
	safe := filepath.Base(kid)
	// Then, replace special characters that could be problematic in filenames
	safe = strings.NewReplacer("/", "_", ".", "_", " ", "_").Replace(safe)
	return filepath.Join(c.dir, safe+".json")
}

// cacheEntry is the structure stored on disk, including a timestamp for TTL.
type cacheEntry struct {
	Key       jose.JSONWebKey `json:"key"`
	CachedAt  time.Time       `json:"cached_at"`
	cachedTTL time.Duration
}

func (ce *cacheEntry) isExpired() bool {
	return time.Since(ce.CachedAt) >= ce.cachedTTL
}

func readKeyFile(path string, ttl time.Duration) (*jose.JSONWebKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var entry cacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, err
	}

	// Check TTL.
	entry.cachedTTL = ttl
	if entry.isExpired() {
		// Evict stale entry.
		_ = os.Remove(path)
		return nil, fmt.Errorf("cache entry expired")
	}

	return &entry.Key, nil
}

func writeKeyFile(path string, key *jose.JSONWebKey) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}

	entry := cacheEntry{
		Key:      *key,
		CachedAt: time.Now(),
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	// Atomic write: write to temp file, then rename.
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return err
	}

	return os.Rename(tmpPath, path)
}
