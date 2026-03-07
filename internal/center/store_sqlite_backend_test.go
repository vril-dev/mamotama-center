package center

import (
	"encoding/base64"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSQLiteBackendRoundTripForDevicePolicyRelease(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	cfg := defaultConfig()
	cfg.Storage.Backend = storageBackendSQLite
	cfg.Storage.Path = filepath.Join(tmpDir, "devices.json")
	cfg.Storage.SQLitePath = filepath.Join(tmpDir, "center.db")

	store, err := loadDeviceStore(cfg.Storage)
	if err != nil {
		t.Fatalf("load sqlite store: %v", err)
	}

	now := time.Now().UTC()
	nowRFC3339 := now.Format(time.RFC3339Nano)

	dev := DeviceRecord{
		DeviceID:                   "device-001",
		KeyID:                      "key-001",
		KeyVersion:                 1,
		PublicKeyPEMBase64:         "public-key-placeholder",
		PublicKeyFingerprintSHA256: strings.Repeat("a", 64),
		FirstSeenAt:                nowRFC3339,
		LastSeenAt:                 nowRFC3339,
		EnrolledAt:                 nowRFC3339,
	}
	if _, err := store.upsertEnroll(dev); err != nil {
		t.Fatalf("upsert enroll: %v", err)
	}

	policy, err := store.upsertPolicy(PolicyRecord{
		Version: "policy-v1",
		WAFRaw:  "SecRuleEngine On",
	}, now)
	if err != nil {
		t.Fatalf("upsert policy: %v", err)
	}
	if _, err := store.approvePolicy(policy.Version, now); err != nil {
		t.Fatalf("approve policy: %v", err)
	}

	release, err := store.upsertRelease(ReleaseRecord{
		Version:   "release-v1",
		Platform:  "linux-amd64",
		BinaryB64: base64.StdEncoding.EncodeToString([]byte("edge-binary")),
	}, now)
	if err != nil {
		t.Fatalf("upsert release: %v", err)
	}
	if _, err := store.approveRelease(release.Version, now); err != nil {
		t.Fatalf("approve release: %v", err)
	}

	if _, _, err := store.assignDesiredPolicy(dev.DeviceID, policy.Version, now); err != nil {
		t.Fatalf("assign desired policy: %v", err)
	}
	if _, _, err := store.assignDesiredRelease(dev.DeviceID, release.Version, now, nil); err != nil {
		t.Fatalf("assign desired release: %v", err)
	}

	reloaded, err := loadDeviceStore(cfg.Storage)
	if err != nil {
		t.Fatalf("reload sqlite store: %v", err)
	}
	gotDev, ok := reloaded.get(dev.DeviceID)
	if !ok {
		t.Fatalf("device not found after reload")
	}
	if gotDev.DesiredPolicyVersion != policy.Version {
		t.Fatalf("desired policy mismatch: got=%q want=%q", gotDev.DesiredPolicyVersion, policy.Version)
	}
	if gotDev.DesiredReleaseVersion != release.Version {
		t.Fatalf("desired release mismatch: got=%q want=%q", gotDev.DesiredReleaseVersion, release.Version)
	}
	if _, ok := reloaded.getPolicy(policy.Version); !ok {
		t.Fatalf("policy not found after reload")
	}
	if _, ok := reloaded.getRelease(release.Version); !ok {
		t.Fatalf("release not found after reload")
	}
}

func TestUpsertEnrollRejectsDuplicateFingerprintAcrossDevices(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	cfg.Storage.Path = filepath.Join(t.TempDir(), "devices.json")
	store, err := loadDeviceStore(cfg.Storage)
	if err != nil {
		t.Fatalf("load store: %v", err)
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	fp := strings.Repeat("b", 64)
	first := DeviceRecord{
		DeviceID:                   "device-a",
		KeyID:                      "key-a",
		KeyVersion:                 1,
		PublicKeyPEMBase64:         "pk-a",
		PublicKeyFingerprintSHA256: fp,
		FirstSeenAt:                now,
		LastSeenAt:                 now,
		EnrolledAt:                 now,
	}
	if _, err := store.upsertEnroll(first); err != nil {
		t.Fatalf("upsert first enroll: %v", err)
	}

	second := first
	second.DeviceID = "device-b"
	second.KeyID = "key-b"
	second.PublicKeyPEMBase64 = "pk-b"
	if _, err := store.upsertEnroll(second); !errors.Is(err, errStoreConflict) {
		t.Fatalf("expected errStoreConflict, got=%v", err)
	}
}
