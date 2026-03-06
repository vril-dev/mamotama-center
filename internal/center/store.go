package center

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type RevokedKeyRecord struct {
	KeyID                      string `json:"key_id"`
	PublicKeyPEMBase64         string `json:"public_key_pem_b64"`
	PublicKeyFingerprintSHA256 string `json:"public_key_fingerprint_sha256"`
	RevokedAt                  string `json:"revoked_at"`
	Reason                     string `json:"reason,omitempty"`
}

type DeviceRecord struct {
	DeviceID                   string             `json:"device_id"`
	KeyID                      string             `json:"key_id,omitempty"`
	KeyVersion                 int                `json:"key_version,omitempty"`
	PublicKeyPEMBase64         string             `json:"public_key_pem_b64"`
	PublicKeyFingerprintSHA256 string             `json:"public_key_fingerprint_sha256"`
	RevokedKeys                []RevokedKeyRecord `json:"revoked_keys,omitempty"`
	FirstSeenAt                string             `json:"first_seen_at"`
	LastSeenAt                 string             `json:"last_seen_at"`
	EnrolledAt                 string             `json:"enrolled_at"`
	LastEnrollMessageAt        string             `json:"last_enroll_message_at,omitempty"`
	LastEnrollNonce            string             `json:"last_enroll_nonce,omitempty"`
	LastEnrollIP               string             `json:"last_enroll_ip,omitempty"`
	LastHeartbeatAt            string             `json:"last_heartbeat_at,omitempty"`
	LastHeartbeatMessageAt     string             `json:"last_heartbeat_message_at,omitempty"`
	LastHeartbeatNonce         string             `json:"last_heartbeat_nonce,omitempty"`
	LastHeartbeatStatusHash    string             `json:"last_heartbeat_status_hash,omitempty"`
	RetiredAt                  string             `json:"retired_at,omitempty"`
	RetireReason               string             `json:"retire_reason,omitempty"`
}

type storedDevices struct {
	Devices []DeviceRecord `json:"devices"`
}

type deviceStore struct {
	mu      sync.RWMutex
	path    string
	devices map[string]DeviceRecord
}

func loadDeviceStore(path string) (*deviceStore, error) {
	s := &deviceStore{
		path:    path,
		devices: map[string]DeviceRecord{},
	}

	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, fmt.Errorf("read store: %w", err)
	}
	if len(b) == 0 {
		return s, nil
	}

	var payload storedDevices
	if err := json.Unmarshal(b, &payload); err != nil {
		return nil, fmt.Errorf("decode store: %w", err)
	}
	for _, rec := range payload.Devices {
		if rec.DeviceID == "" {
			continue
		}
		rec.PublicKeyFingerprintSHA256 = strings.ToLower(strings.TrimSpace(rec.PublicKeyFingerprintSHA256))
		rec.KeyID = strings.TrimSpace(rec.KeyID)
		rec.LastEnrollNonce = strings.TrimSpace(rec.LastEnrollNonce)
		rec.LastHeartbeatNonce = strings.TrimSpace(rec.LastHeartbeatNonce)
		if rec.KeyID == "" && rec.PublicKeyFingerprintSHA256 != "" {
			rec.KeyID = defaultKeyIDFromFingerprint(rec.PublicKeyFingerprintSHA256)
		}
		if rec.KeyVersion == 0 && rec.KeyID != "" {
			rec.KeyVersion = 1
		}
		if len(rec.RevokedKeys) > 0 {
			for i := range rec.RevokedKeys {
				rec.RevokedKeys[i].KeyID = strings.TrimSpace(rec.RevokedKeys[i].KeyID)
				rec.RevokedKeys[i].PublicKeyFingerprintSHA256 = strings.ToLower(strings.TrimSpace(rec.RevokedKeys[i].PublicKeyFingerprintSHA256))
				if rec.RevokedKeys[i].KeyID == "" && rec.RevokedKeys[i].PublicKeyFingerprintSHA256 != "" {
					rec.RevokedKeys[i].KeyID = defaultKeyIDFromFingerprint(rec.RevokedKeys[i].PublicKeyFingerprintSHA256)
				}
			}
		}
		s.devices[rec.DeviceID] = rec
	}
	return s, nil
}

func (s *deviceStore) get(deviceID string) (DeviceRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.devices[deviceID]
	return rec, ok
}

func (s *deviceStore) list() []DeviceRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	devices := make([]DeviceRecord, 0, len(s.devices))
	for _, rec := range s.devices {
		devices = append(devices, rec)
	}
	sort.Slice(devices, func(i, j int) bool {
		return devices[i].DeviceID < devices[j].DeviceID
	})
	return devices
}

func (s *deviceStore) findByFingerprint(fingerprint string) (DeviceRecord, bool) {
	fingerprint = strings.ToLower(strings.TrimSpace(fingerprint))
	if fingerprint == "" {
		return DeviceRecord{}, false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, rec := range s.devices {
		if rec.PublicKeyFingerprintSHA256 == fingerprint {
			return rec, true
		}
		for _, revoked := range rec.RevokedKeys {
			if revoked.PublicKeyFingerprintSHA256 == fingerprint {
				return rec, true
			}
		}
	}
	return DeviceRecord{}, false
}

func (s *deviceStore) upsertEnroll(rec DeviceRecord) (DeviceRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, ok := s.devices[rec.DeviceID]
	if ok {
		rec.FirstSeenAt = prev.FirstSeenAt
		rec.LastHeartbeatAt = prev.LastHeartbeatAt
		rec.LastHeartbeatMessageAt = prev.LastHeartbeatMessageAt
		rec.LastHeartbeatNonce = prev.LastHeartbeatNonce
		rec.LastHeartbeatStatusHash = prev.LastHeartbeatStatusHash
		if rec.KeyVersion == 0 {
			rec.KeyVersion = prev.KeyVersion
		}
		if len(rec.RevokedKeys) == 0 && len(prev.RevokedKeys) > 0 {
			rec.RevokedKeys = append([]RevokedKeyRecord(nil), prev.RevokedKeys...)
		}
	}
	if rec.KeyVersion == 0 && rec.KeyID != "" {
		rec.KeyVersion = 1
	}
	s.devices[rec.DeviceID] = rec
	if err := s.saveLocked(); err != nil {
		return DeviceRecord{}, err
	}
	return rec, nil
}

func (s *deviceStore) updateHeartbeat(deviceID string, receivedAt time.Time, messageAt time.Time, nonce string, statusHash string) (DeviceRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.devices[deviceID]
	if !ok {
		return DeviceRecord{}, os.ErrNotExist
	}
	rec.LastHeartbeatAt = receivedAt.UTC().Format(time.RFC3339Nano)
	rec.LastHeartbeatMessageAt = messageAt.UTC().Format(time.RFC3339Nano)
	rec.LastHeartbeatNonce = nonce
	rec.LastHeartbeatStatusHash = statusHash
	rec.LastSeenAt = rec.LastHeartbeatAt
	s.devices[deviceID] = rec
	if err := s.saveLocked(); err != nil {
		return DeviceRecord{}, err
	}
	return rec, nil
}

func (s *deviceStore) retire(deviceID string, retiredAt time.Time, reason string) (DeviceRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.devices[deviceID]
	if !ok {
		return DeviceRecord{}, os.ErrNotExist
	}
	rec.RetiredAt = retiredAt.UTC().Format(time.RFC3339Nano)
	rec.RetireReason = reason
	s.devices[deviceID] = rec
	if err := s.saveLocked(); err != nil {
		return DeviceRecord{}, err
	}
	return rec, nil
}

func (s *deviceStore) revokeKey(deviceID string, keyID string, revokedAt time.Time, reason string) (DeviceRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.devices[deviceID]
	if !ok {
		return DeviceRecord{}, os.ErrNotExist
	}
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		keyID = rec.KeyID
	}
	if keyID == "" {
		return DeviceRecord{}, os.ErrNotExist
	}

	for _, revoked := range rec.RevokedKeys {
		if revoked.KeyID == keyID {
			return rec, nil
		}
	}

	if rec.KeyID != keyID {
		return DeviceRecord{}, os.ErrNotExist
	}

	rec.RevokedKeys = append(rec.RevokedKeys, RevokedKeyRecord{
		KeyID:                      rec.KeyID,
		PublicKeyPEMBase64:         rec.PublicKeyPEMBase64,
		PublicKeyFingerprintSHA256: rec.PublicKeyFingerprintSHA256,
		RevokedAt:                  revokedAt.UTC().Format(time.RFC3339Nano),
		Reason:                     reason,
	})
	rec.KeyID = ""
	rec.PublicKeyPEMBase64 = ""
	rec.PublicKeyFingerprintSHA256 = ""
	s.devices[deviceID] = rec
	if err := s.saveLocked(); err != nil {
		return DeviceRecord{}, err
	}
	return rec, nil
}

func defaultKeyIDFromFingerprint(fingerprint string) string {
	fingerprint = strings.ToLower(strings.TrimSpace(fingerprint))
	if fingerprint == "" {
		return ""
	}
	if len(fingerprint) >= 16 {
		return "ed25519-" + fingerprint[:16]
	}
	return "ed25519-" + fingerprint
}

func (s *deviceStore) saveLocked() error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir store dir: %w", err)
	}
	devices := make([]DeviceRecord, 0, len(s.devices))
	for _, rec := range s.devices {
		devices = append(devices, rec)
	}
	sort.Slice(devices, func(i, j int) bool {
		return devices[i].DeviceID < devices[j].DeviceID
	})
	payload := storedDevices{Devices: devices}
	out, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal store: %w", err)
	}
	tmp, err := os.CreateTemp(dir, "devices-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp store: %w", err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(out); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("write temp store: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close temp store: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("chmod temp store: %w", err)
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename store: %w", err)
	}
	return nil
}
