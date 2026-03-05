package center

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

type DeviceRecord struct {
	DeviceID                   string `json:"device_id"`
	PublicKeyPEMBase64         string `json:"public_key_pem_b64"`
	PublicKeyFingerprintSHA256 string `json:"public_key_fingerprint_sha256"`
	FirstSeenAt                string `json:"first_seen_at"`
	LastSeenAt                 string `json:"last_seen_at"`
	EnrolledAt                 string `json:"enrolled_at"`
	LastEnrollIP               string `json:"last_enroll_ip,omitempty"`
	LastHeartbeatAt            string `json:"last_heartbeat_at,omitempty"`
	LastHeartbeatMessageAt     string `json:"last_heartbeat_message_at,omitempty"`
	LastHeartbeatNonce         string `json:"last_heartbeat_nonce,omitempty"`
	LastHeartbeatStatusHash    string `json:"last_heartbeat_status_hash,omitempty"`
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

func (s *deviceStore) upsertEnroll(rec DeviceRecord) (DeviceRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, ok := s.devices[rec.DeviceID]
	if ok {
		rec.FirstSeenAt = prev.FirstSeenAt
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
