package discovery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMetadataCachePath(t *testing.T) {
	cacheDir := "/tmp/pam-oidc-cache"
	issuer := "https://issuer.example.com"

	sum := sha256.Sum256([]byte(issuer))
	expectedName := "openid-configuration-" + hex.EncodeToString(sum[:]) + ".json"
	expectedPath := filepath.Join(cacheDir, expectedName)

	got := metadataCachePath(cacheDir, issuer)
	if got != expectedPath {
		t.Fatalf("metadataCachePath() = %q, want %q", got, expectedPath)
	}

	if metadataCachePath(cacheDir, issuer) != got {
		t.Fatalf("metadataCachePath() should be deterministic for the same issuer")
	}

	other := metadataCachePath(cacheDir, "https://other.example.com")
	if other == got {
		t.Fatalf("metadataCachePath() returned the same path for different issuers")
	}
}

func TestWriteReadProviderMetadataFileRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "nested", "metadata.json")

	want := &ProviderMetadata{
		Issuer:                "https://issuer.example.com",
		JWKSURI:               "https://issuer.example.com/keys",
		AuthorizationEndpoint: "https://issuer.example.com/auth",
	}

	if err := writeProviderMetadataFile(path, want); err != nil {
		t.Fatalf("writeProviderMetadataFile() failed: %v", err)
	}

	got, err := readProviderMetadataFile(path, 12*time.Hour)
	if err != nil {
		t.Fatalf("readProviderMetadataFile() failed: %v", err)
	}

	if got.Issuer != want.Issuer {
		t.Fatalf("Issuer = %q, want %q", got.Issuer, want.Issuer)
	}
	if got.JWKSURI != want.JWKSURI {
		t.Fatalf("JWKSURI = %q, want %q", got.JWKSURI, want.JWKSURI)
	}
	if got.AuthorizationEndpoint != want.AuthorizationEndpoint {
		t.Fatalf("AuthorizationEndpoint = %q, want %q", got.AuthorizationEndpoint, want.AuthorizationEndpoint)
	}
}

func TestReadProviderMetadataFileExpiredEvicts(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "metadata.json")

	entry := providerMetadataCacheEntry{
		Metadata: ProviderMetadata{
			Issuer:  "https://issuer.example.com",
			JWKSURI: "https://issuer.example.com/keys",
		},
		CachedAt: time.Now().Add(-2 * time.Hour),
	}
	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("json.Marshal() failed: %v", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("os.WriteFile() failed: %v", err)
	}

	_, err = readProviderMetadataFile(path, time.Hour)
	if err == nil {
		t.Fatal("readProviderMetadataFile() expected expiry error, got nil")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("readProviderMetadataFile() error = %q, want expiry-related error", err.Error())
	}

	_, statErr := os.Stat(path)
	if !os.IsNotExist(statErr) {
		t.Fatalf("expired cache file should be removed, stat err = %v", statErr)
	}
}

func TestReadProviderMetadataFileInvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "metadata.json")

	if err := os.WriteFile(path, []byte("not-json"), 0600); err != nil {
		t.Fatalf("os.WriteFile() failed: %v", err)
	}

	_, err := readProviderMetadataFile(path, time.Hour)
	if err == nil {
		t.Fatal("readProviderMetadataFile() expected decode error, got nil")
	}

	if _, statErr := os.Stat(path); statErr != nil {
		t.Fatalf("invalid json cache file should remain on disk, stat err = %v", statErr)
	}
}

func TestWriteProviderMetadataFileCreatesDirAndOverwrites(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "a", "b", "metadata.json")

	first := &ProviderMetadata{Issuer: "https://first.example.com", JWKSURI: "https://first.example.com/keys"}
	second := &ProviderMetadata{Issuer: "https://second.example.com", JWKSURI: "https://second.example.com/keys"}

	if err := writeProviderMetadataFile(path, first); err != nil {
		t.Fatalf("first writeProviderMetadataFile() failed: %v", err)
	}
	if err := writeProviderMetadataFile(path, second); err != nil {
		t.Fatalf("second writeProviderMetadataFile() failed: %v", err)
	}

	got, err := readProviderMetadataFile(path, 12*time.Hour)
	if err != nil {
		t.Fatalf("readProviderMetadataFile() failed: %v", err)
	}
	if got.Issuer != second.Issuer {
		t.Fatalf("Issuer after overwrite = %q, want %q", got.Issuer, second.Issuer)
	}

	matches, err := filepath.Glob(path + ".tmp-*")
	if err != nil {
		t.Fatalf("filepath.Glob() failed: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary files should be cleaned up, found: %v", matches)
	}
}
