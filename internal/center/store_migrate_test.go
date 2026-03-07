package center

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStoreMigrationFileToSQLiteAndBack(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	srcFile := filepath.Join(tmpDir, "src-devices.json")
	sqlitePath := filepath.Join(tmpDir, "center.db")
	dstFile := filepath.Join(tmpDir, "dst-devices.json")

	srcStore, err := loadDeviceStore(StorageConfig{
		Backend:    storageBackendFile,
		Path:       srcFile,
		SQLitePath: sqlitePath,
	})
	if err != nil {
		t.Fatalf("load src file store: %v", err)
	}

	now := time.Now().UTC()
	nowRFC3339 := now.Format(time.RFC3339Nano)
	device := DeviceRecord{
		DeviceID:                   "device-migrate",
		KeyID:                      "key-migrate",
		KeyVersion:                 1,
		PublicKeyPEMBase64:         "pk",
		PublicKeyFingerprintSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		FirstSeenAt:                nowRFC3339,
		LastSeenAt:                 nowRFC3339,
		EnrolledAt:                 nowRFC3339,
	}
	if _, err := srcStore.upsertEnroll(device); err != nil {
		t.Fatalf("upsert enroll: %v", err)
	}
	pol, err := srcStore.upsertPolicy(PolicyRecord{Version: "policy-migrate-v1", WAFRaw: "SecRuleEngine On"}, now)
	if err != nil {
		t.Fatalf("upsert policy: %v", err)
	}
	if _, err := srcStore.approvePolicy(pol.Version, now); err != nil {
		t.Fatalf("approve policy: %v", err)
	}
	rel, err := srcStore.upsertRelease(ReleaseRecord{
		Version:   "release-migrate-v1",
		Platform:  "linux-amd64",
		BinaryB64: base64.StdEncoding.EncodeToString([]byte("binary")),
	}, now)
	if err != nil {
		t.Fatalf("upsert release: %v", err)
	}
	if _, err := srcStore.approveRelease(rel.Version, now); err != nil {
		t.Fatalf("approve release: %v", err)
	}

	got, err := MigrateFileStoreToSQLite(srcFile, sqlitePath, false)
	if err != nil {
		t.Fatalf("migrate file->sqlite: %v", err)
	}
	if got.Devices != 1 || got.Policies != 1 || got.Releases != 1 {
		t.Fatalf("unexpected migration result: %+v", got)
	}

	sqliteStore, err := loadDeviceStore(StorageConfig{
		Backend:    storageBackendSQLite,
		Path:       dstFile,
		SQLitePath: sqlitePath,
	})
	if err != nil {
		t.Fatalf("load sqlite store: %v", err)
	}
	defer closeStoreDB(sqliteStore)
	if _, ok := sqliteStore.get(device.DeviceID); !ok {
		t.Fatalf("missing migrated device in sqlite")
	}

	got, err = MigrateSQLiteStoreToFile(sqlitePath, dstFile, false)
	if err != nil {
		t.Fatalf("migrate sqlite->file: %v", err)
	}
	if got.Devices != 1 || got.Policies != 1 || got.Releases != 1 {
		t.Fatalf("unexpected reverse migration result: %+v", got)
	}
	dstStore, err := loadDeviceStore(StorageConfig{
		Backend:    storageBackendFile,
		Path:       dstFile,
		SQLitePath: sqlitePath,
	})
	if err != nil {
		t.Fatalf("load dst file store: %v", err)
	}
	if _, ok := dstStore.get(device.DeviceID); !ok {
		t.Fatalf("missing migrated device in file")
	}
}

func TestStoreMigrationDestinationExistsNeedsOverwrite(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	srcFile := filepath.Join(tmpDir, "src-devices.json")
	sqlitePath := filepath.Join(tmpDir, "center.db")
	if err := os.WriteFile(srcFile, []byte(`{"devices":[]}`), 0o600); err != nil {
		t.Fatalf("write src file: %v", err)
	}
	if err := os.WriteFile(sqlitePath, []byte("already-exists"), 0o600); err != nil {
		t.Fatalf("write sqlite file: %v", err)
	}
	if _, err := MigrateFileStoreToSQLite(srcFile, sqlitePath, false); err == nil {
		t.Fatalf("expected migration to fail without overwrite")
	}
}

func TestStoreMigrationSourceMissing(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	_, err := MigrateFileStoreToSQLite(filepath.Join(tmpDir, "missing.json"), filepath.Join(tmpDir, "center.db"), false)
	if err == nil {
		t.Fatalf("expected missing source error")
	}
	if !errors.Is(err, os.ErrNotExist) && !strings.Contains(err.Error(), "not found") {
		t.Fatalf("unexpected error: %v", err)
	}
}
