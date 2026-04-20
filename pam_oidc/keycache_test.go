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
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
)

// mockKeySource implements oidc.KeySource for testing.
type mockKeySource struct {
	keys  map[string]*jose.JSONWebKey
	calls int
}

func (m *mockKeySource) GetKey(ctx context.Context, kid string) (*jose.JSONWebKey, error) {
	m.calls++
	if key, ok := m.keys[kid]; ok {
		return key, nil
	}
	return nil, fmt.Errorf("key %s not found", kid)
}

func testJWK(kid string) *jose.JSONWebKey {
	return &jose.JSONWebKey{
		KeyID: kid,
		Key:   []byte(fmt.Sprintf("test-key-data-%s", kid)),
		Use:   "sig",
	}
}

func TestCachedKeySourceCacheMiss(t *testing.T) {
	tmpdir := t.TempDir()

	mock := &mockKeySource{
		keys: map[string]*jose.JSONWebKey{
			"key1": testJWK("key1"),
		},
	}

	cache := newCachedKeySource(mock, tmpdir, 12*time.Hour)

	// First call should hit the upstream source.
	key, err := cache.GetKey(context.Background(), "key1")
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}
	if key.KeyID != "key1" {
		t.Errorf("got KeyID %q, want %q", key.KeyID, "key1")
	}
	if mock.calls != 1 {
		t.Errorf("got %d upstream calls, want 1", mock.calls)
	}

	// Verify the key was persisted to disk.
	path := cache.keyPath("key1")
	_, err = os.Stat(path)
	if err != nil {
		t.Errorf("cache file not created: %v", err)
	}
}

func TestCachedKeySourceCacheHit(t *testing.T) {
	tmpdir := t.TempDir()

	mock := &mockKeySource{
		keys: map[string]*jose.JSONWebKey{
			"key1": testJWK("key1"),
		},
	}

	cache := newCachedKeySource(mock, tmpdir, 12*time.Hour)

	// First call primes the cache.
	cache.GetKey(context.Background(), "key1")

	// Second call should hit the cache, not the upstream source.
	key, err := cache.GetKey(context.Background(), "key1")
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}
	if key.KeyID != "key1" {
		t.Errorf("got KeyID %q, want %q", key.KeyID, "key1")
	}
	if mock.calls != 1 {
		t.Errorf("got %d upstream calls, want 1 (cache should have been used)", mock.calls)
	}
}

func TestCachedKeySourceCacheExpiration(t *testing.T) {
	tmpdir := t.TempDir()

	mock := &mockKeySource{
		keys: map[string]*jose.JSONWebKey{
			"key1": testJWK("key1"),
		},
	}

	cache := newCachedKeySource(mock, tmpdir, 12*time.Hour)

	// Prime the cache.
	cache.GetKey(context.Background(), "key1")
	if mock.calls != 1 {
		t.Fatalf("expected 1 upstream call, got %d", mock.calls)
	}

	// Manually write an expired cache entry.
	path := cache.keyPath("key1")
	entry := cacheEntry{
		Key:      *testJWK("key1"),
		CachedAt: time.Now().Add(-13 * time.Hour), // 13 hours old
	}
	data, _ := json.Marshal(entry)
	os.WriteFile(path, data, 0600)

	// Reading should evict the expired entry and fetch from upstream.
	key, err := cache.GetKey(context.Background(), "key1")
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}
	if key.KeyID != "key1" {
		t.Errorf("got KeyID %q, want %q", key.KeyID, "key1")
	}
	if mock.calls != 2 {
		t.Errorf("got %d upstream calls, want 2 (expired cache should have triggered refetch)", mock.calls)
	}

	// Verify a new file exists (rewritten after refetch).
	_, err = os.Stat(path)
	if err != nil {
		t.Errorf("cache file should exist after refetch: %v", err)
	}
}

func TestCachedKeySourceKeyPathSanitization(t *testing.T) {
	tmpdir := t.TempDir()
	cache := newCachedKeySource(nil, tmpdir, 12*time.Hour)

	cases := []struct {
		kid  string
		want string
	}{
		{"key1", "key1.json"},
		{"key/with/slash", "slash.json"},          // filepath.Base extracts "slash"
		{"key.with.dot", "key_with_dot.json"},     // dots are sanitized to underscores
		{"key with space", "key_with_space.json"}, // spaces are sanitized to underscores
		{"/absolute/path/to/key", "key.json"},     // filepath.Base extracts "key"
		{"../../../etc/passwd", "passwd.json"},    // filepath.Base extracts "passwd"
	}

	for _, tc := range cases {
		path := cache.keyPath(tc.kid)
		base := filepath.Base(path)
		if base != tc.want {
			t.Errorf("keyPath(%q) = %q, want %q", tc.kid, base, tc.want)
		}
		// Ensure it stays within tmpdir
		if !filepath.HasPrefix(path, tmpdir) {
			t.Errorf("keyPath(%q) = %q escapes tmpdir %q", tc.kid, path, tmpdir)
		}
	}
}

func TestCachedKeySourceMissingKey(t *testing.T) {
	tmpdir := t.TempDir()

	mock := &mockKeySource{keys: map[string]*jose.JSONWebKey{}}

	cache := newCachedKeySource(mock, tmpdir, 12*time.Hour)

	key, err := cache.GetKey(context.Background(), "nonexistent")
	if err == nil {
		t.Error("expected error for missing key")
	}
	if key != nil {
		t.Error("expected nil key for missing key")
	}
}

func TestCachedKeySourceUpstreamError(t *testing.T) {
	tmpdir := t.TempDir()

	mock := &mockKeySource{keys: map[string]*jose.JSONWebKey{}}

	cache := newCachedKeySource(mock, tmpdir, 12*time.Hour)

	// First call fails.
	_, err := cache.GetKey(context.Background(), "missing")
	if err == nil {
		t.Error("expected error from upstream")
	}

	// Verify nothing was cached.
	path := cache.keyPath("missing")
	_, err = os.Stat(path)
	if err == nil {
		t.Error("cache file should not exist for failed upstream call")
	}
}

func TestCachedKeySourceAtomicWrite(t *testing.T) {
	tmpdir := t.TempDir()

	mock := &mockKeySource{
		keys: map[string]*jose.JSONWebKey{
			"key1": testJWK("key1"),
		},
	}

	cache := newCachedKeySource(mock, tmpdir, 12*time.Hour)

	cache.GetKey(context.Background(), "key1")

	// Verify the temp file was cleaned up (atomic write completed).
	tmpPath := cache.keyPath("key1") + ".tmp"
	_, err := os.Stat(tmpPath)
	if err == nil {
		t.Error("temp file should have been cleaned up after write")
	}
	if !os.IsNotExist(err) {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCachedKeySourceCreatesCacheDir(t *testing.T) {
	tmpdir := t.TempDir()
	cachedir := filepath.Join(tmpdir, "nonexistent", "nested", "cache")

	mock := &mockKeySource{
		keys: map[string]*jose.JSONWebKey{
			"key1": testJWK("key1"),
		},
	}

	cache := newCachedKeySource(mock, cachedir, 12*time.Hour)

	cache.GetKey(context.Background(), "key1")

	// Verify the nested directory was created.
	_, err := os.Stat(cachedir)
	if err != nil {
		t.Errorf("cache directory not created: %v", err)
	}

	// Verify file is in the correct location.
	path := cache.keyPath("key1")
	_, err = os.Stat(path)
	if err != nil {
		t.Errorf("cache file not in expected location: %v", err)
	}
}

func TestCachedKeySourceMultipleKeys(t *testing.T) {
	tmpdir := t.TempDir()

	mock := &mockKeySource{
		keys: map[string]*jose.JSONWebKey{
			"key1": testJWK("key1"),
			"key2": testJWK("key2"),
			"key3": testJWK("key3"),
		},
	}

	cache := newCachedKeySource(mock, tmpdir, 12*time.Hour)

	// Fetch multiple keys.
	for i := 1; i <= 3; i++ {
		kid := fmt.Sprintf("key%d", i)
		key, err := cache.GetKey(context.Background(), kid)
		if err != nil {
			t.Errorf("GetKey(%q) failed: %v", kid, err)
		}
		if key.KeyID != kid {
			t.Errorf("got KeyID %q, want %q", key.KeyID, kid)
		}
	}

	if mock.calls != 3 {
		t.Errorf("got %d upstream calls, want 3", mock.calls)
	}

	// Fetch them again; should all hit cache.
	for i := 1; i <= 3; i++ {
		kid := fmt.Sprintf("key%d", i)
		cache.GetKey(context.Background(), kid)
	}

	if mock.calls != 3 {
		t.Errorf("got %d upstream calls, want 3 (all should be cached)", mock.calls)
	}

	// Verify all files exist.
	for i := 1; i <= 3; i++ {
		kid := fmt.Sprintf("key%d", i)
		path := cache.keyPath(kid)
		_, err := os.Stat(path)
		if err != nil {
			t.Errorf("cache file for %q not found: %v", kid, err)
		}
	}
}

func TestCacheEntryExpiration(t *testing.T) {
	cases := []struct {
		age    time.Duration
		expire bool
	}{
		{0 * time.Hour, false},
		{6 * time.Hour, false},
		{11 * time.Hour, false},
		{11*time.Hour + 59*time.Minute, false},
		{12 * time.Hour, true},
		{13 * time.Hour, true},
		{24 * time.Hour, true},
	}

	for _, tc := range cases {
		entry := cacheEntry{
			CachedAt: time.Now().Add(-tc.age),
		}
		entry.cachedTTL = 12 * time.Hour

		got := entry.isExpired()
		if got != tc.expire {
			t.Errorf("cacheEntry with age %v: isExpired()=%v, want %v", tc.age, got, tc.expire)
		}
	}
}

func TestWriteKeyFilePermissions(t *testing.T) {
	tmpdir := t.TempDir()
	path := filepath.Join(tmpdir, "test.json")

	key := testJWK("key1")
	if err := writeKeyFile(path, key); err != nil {
		t.Fatalf("writeKeyFile failed: %v", err)
	}

	// Check file permissions.
	stat, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}

	perms := stat.Mode().Perm()
	expected := os.FileMode(0600)
	if perms != expected {
		t.Errorf("file permissions %#o, want %#o", perms, expected)
	}
}

func TestWriteKeyFileDirPermissions(t *testing.T) {
	tmpdir := t.TempDir()
	path := filepath.Join(tmpdir, "a", "b", "c", "test.json")

	key := testJWK("key1")
	if err := writeKeyFile(path, key); err != nil {
		t.Fatalf("writeKeyFile failed: %v", err)
	}

	// Check directory permissions.
	dirpath := filepath.Dir(path)
	stat, err := os.Stat(dirpath)
	if err != nil {
		t.Fatalf("stat dir failed: %v", err)
	}

	perms := stat.Mode().Perm()
	expected := os.FileMode(0700)
	if perms != expected {
		t.Errorf("dir permissions %#o, want %#o", perms, expected)
	}
}

func TestReadWriteRoundtrip(t *testing.T) {
	tmpdir := t.TempDir()
	path := filepath.Join(tmpdir, "key.json")

	originalKey := testJWK("key1")
	originalKey.Algorithm = "RSA" // Add some more fields

	if err := writeKeyFile(path, originalKey); err != nil {
		t.Fatalf("writeKeyFile failed: %v", err)
	}

	readKey, err := readKeyFile(path, 12*time.Hour)
	if err != nil {
		t.Fatalf("readKeyFile failed: %v", err)
	}

	if readKey.KeyID != originalKey.KeyID {
		t.Errorf("KeyID mismatch: got %q, want %q", readKey.KeyID, originalKey.KeyID)
	}
	if readKey.Use != originalKey.Use {
		t.Errorf("Use mismatch: got %q, want %q", readKey.Use, originalKey.Use)
	}
}

func TestCachedKeySourceWriteFailureDoesntBlockAuth(t *testing.T) {
	// Use an invalid path that will cause write to fail.
	cachedir := "/nonexistent/path/that/cannot/be/created"

	mock := &mockKeySource{
		keys: map[string]*jose.JSONWebKey{
			"key1": testJWK("key1"),
		},
	}

	cache := newCachedKeySource(mock, cachedir, 12*time.Hour)

	// GetKey should still succeed even if write fails (best-effort).
	key, err := cache.GetKey(context.Background(), "key1")
	if err != nil {
		t.Fatalf("GetKey should not fail even with write error: %v", err)
	}
	if key.KeyID != "key1" {
		t.Errorf("got KeyID %q, want %q", key.KeyID, "key1")
	}
}

func TestCachedKeySourceCustomTTL(t *testing.T) {
	tmpdir := t.TempDir()

	mock := &mockKeySource{
		keys: map[string]*jose.JSONWebKey{
			"key1": testJWK("key1"),
		},
	}

	// Use a short TTL of 1 second.
	ttl := 1 * time.Second
	cache := newCachedKeySource(mock, tmpdir, ttl)

	// Prime the cache.
	cache.GetKey(context.Background(), "key1")
	if mock.calls != 1 {
		t.Fatalf("expected 1 upstream call, got %d", mock.calls)
	}

	// Wait for cache to expire.
	time.Sleep(2 * time.Second)

	// Reading should fetch from upstream again since cache expired.
	key, err := cache.GetKey(context.Background(), "key1")
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}
	if key.KeyID != "key1" {
		t.Errorf("got KeyID %q, want %q", key.KeyID, "key1")
	}
	if mock.calls != 2 {
		t.Errorf("got %d upstream calls, want 2 (short TTL should have expired)", mock.calls)
	}
}

func TestCachedKeySourceLongTTL(t *testing.T) {
	tmpdir := t.TempDir()

	mock := &mockKeySource{
		keys: map[string]*jose.JSONWebKey{
			"key1": testJWK("key1"),
		},
	}

	// Use a very long TTL (1 year).
	ttl := 365 * 24 * time.Hour
	cache := newCachedKeySource(mock, tmpdir, ttl)

	// Prime the cache.
	cache.GetKey(context.Background(), "key1")
	if mock.calls != 1 {
		t.Fatalf("expected 1 upstream call, got %d", mock.calls)
	}

	// Manually write an entry that's 100 hours old.
	path := cache.keyPath("key1")
	entry := cacheEntry{
		Key:      *testJWK("key1"),
		CachedAt: time.Now().Add(-100 * time.Hour),
	}
	data, _ := json.Marshal(entry)
	os.WriteFile(path, data, 0600)

	// Reading should use cache (100h < 365d).
	key, err := cache.GetKey(context.Background(), "key1")
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}
	if key.KeyID != "key1" {
		t.Errorf("got KeyID %q, want %q", key.KeyID, "key1")
	}
	if mock.calls != 1 {
		t.Errorf("got %d upstream calls, want 1 (cache should still be valid)", mock.calls)
	}
}

