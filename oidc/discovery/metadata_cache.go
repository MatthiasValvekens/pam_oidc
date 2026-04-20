package discovery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type providerMetadataCacheEntry struct {
	Metadata ProviderMetadata `json:"metadata"`
	CachedAt time.Time        `json:"cached_at"`
}

func metadataCachePath(cacheDir string, issuer string) string {
	sum := sha256.Sum256([]byte(issuer))
	name := "openid-configuration-" + hex.EncodeToString(sum[:]) + ".json"
	return filepath.Join(cacheDir, name)
}

func readProviderMetadataFile(path string, ttl time.Duration) (*ProviderMetadata, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var entry providerMetadataCacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, err
	}

	if time.Since(entry.CachedAt) >= ttl {
		_ = os.Remove(path)
		return nil, fmt.Errorf("metadata cache entry expired")
	}

	md := entry.Metadata
	return &md, nil
}

func writeProviderMetadataFile(path string, md *ProviderMetadata) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}

	entry := providerMetadataCacheEntry{
		Metadata: *md,
		CachedAt: time.Now(),
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	tmpFile, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	defer func() {
		_ = os.Remove(tmpPath)
	}()

	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}

	return os.Rename(tmpPath, path)
}
