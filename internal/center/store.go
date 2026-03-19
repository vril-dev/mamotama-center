package center

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	errStoreConflict = errors.New("store conflict")
	errStoreInvalid  = errors.New("store invalid")
	errStoreInUse    = errors.New("store in use")
)

const (
	policyStatusDraft     = "draft"
	policyStatusApproved  = "approved"
	releaseStatusDraft    = "draft"
	releaseStatusApproved = "approved"
)

type RevokedKeyRecord struct {
	KeyID                      string `json:"key_id"`
	PublicKeyPEMBase64         string `json:"public_key_pem_b64"`
	PublicKeyFingerprintSHA256 string `json:"public_key_fingerprint_sha256"`
	RevokedAt                  string `json:"revoked_at"`
	Reason                     string `json:"reason,omitempty"`
}

type PolicyRecord struct {
	Version      string `json:"version"`
	SHA256       string `json:"sha256"`
	WAFRaw       string `json:"waf_raw"`
	BundleTGZB64 string `json:"bundle_tgz_b64,omitempty"`
	BundleSHA256 string `json:"bundle_sha256,omitempty"`
	Status       string `json:"status"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at,omitempty"`
	ApprovedAt   string `json:"approved_at,omitempty"`
	Note         string `json:"note,omitempty"`
}

type ReleaseRecord struct {
	Version    string `json:"version"`
	Platform   string `json:"platform"`
	SHA256     string `json:"sha256"`
	BinaryB64  string `json:"binary_b64,omitempty"`
	Status     string `json:"status"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at,omitempty"`
	ApprovedAt string `json:"approved_at,omitempty"`
	Note       string `json:"note,omitempty"`
}

type DeviceRecord struct {
	DeviceID                          string             `json:"device_id"`
	KeyID                             string             `json:"key_id,omitempty"`
	KeyVersion                        int                `json:"key_version,omitempty"`
	PublicKeyPEMBase64                string             `json:"public_key_pem_b64"`
	PublicKeyFingerprintSHA256        string             `json:"public_key_fingerprint_sha256"`
	RevokedKeys                       []RevokedKeyRecord `json:"revoked_keys,omitempty"`
	FirstSeenAt                       string             `json:"first_seen_at"`
	LastSeenAt                        string             `json:"last_seen_at"`
	EnrolledAt                        string             `json:"enrolled_at"`
	LastEnrollMessageAt               string             `json:"last_enroll_message_at,omitempty"`
	LastEnrollNonce                   string             `json:"last_enroll_nonce,omitempty"`
	LastEnrollIP                      string             `json:"last_enroll_ip,omitempty"`
	LastHeartbeatAt                   string             `json:"last_heartbeat_at,omitempty"`
	LastHeartbeatMessageAt            string             `json:"last_heartbeat_message_at,omitempty"`
	LastHeartbeatNonce                string             `json:"last_heartbeat_nonce,omitempty"`
	LastHeartbeatStatusHash           string             `json:"last_heartbeat_status_hash,omitempty"`
	DesiredPolicyVersion              string             `json:"desired_policy_version,omitempty"`
	DesiredPolicySHA256               string             `json:"desired_policy_sha256,omitempty"`
	DesiredPolicyAssignedAt           string             `json:"desired_policy_assigned_at,omitempty"`
	CurrentPolicyVersion              string             `json:"current_policy_version,omitempty"`
	CurrentPolicySHA256               string             `json:"current_policy_sha256,omitempty"`
	LastPolicySyncAt                  string             `json:"last_policy_sync_at,omitempty"`
	LastPolicyAckAt                   string             `json:"last_policy_ack_at,omitempty"`
	LastPolicyAckStatus               string             `json:"last_policy_ack_status,omitempty"`
	LastPolicyAckMessage              string             `json:"last_policy_ack_message,omitempty"`
	DesiredReleaseVersion             string             `json:"desired_release_version,omitempty"`
	DesiredReleaseSHA256              string             `json:"desired_release_sha256,omitempty"`
	DesiredReleaseAssignedAt          string             `json:"desired_release_assigned_at,omitempty"`
	DesiredReleaseNotBeforeAt         string             `json:"desired_release_not_before_at,omitempty"`
	CurrentReleaseVersion             string             `json:"current_release_version,omitempty"`
	CurrentReleaseSHA256              string             `json:"current_release_sha256,omitempty"`
	LastReleaseSyncAt                 string             `json:"last_release_sync_at,omitempty"`
	LastReleaseAckAt                  string             `json:"last_release_ack_at,omitempty"`
	LastReleaseAckStatus              string             `json:"last_release_ack_status,omitempty"`
	LastReleaseAckMessage             string             `json:"last_release_ack_message,omitempty"`
	LastLogUploadAt                   string             `json:"last_log_upload_at,omitempty"`
	LastLogUploadEntries              int                `json:"last_log_upload_entries,omitempty"`
	LastLogUploadBytes                int64              `json:"last_log_upload_bytes,omitempty"`
	LastLogUploadSHA256               string             `json:"last_log_upload_sha256,omitempty"`
	UpstreamHealthStatus              string             `json:"upstream_health_status,omitempty"`
	UpstreamHealthEndpoint            string             `json:"upstream_health_endpoint,omitempty"`
	UpstreamHealthLastChangedAt       string             `json:"upstream_health_last_changed_at,omitempty"`
	UpstreamHealthLastError           string             `json:"upstream_health_last_error,omitempty"`
	UpstreamHealthConsecutiveFailures int                `json:"upstream_health_consecutive_failures,omitempty"`
	RetiredAt                         string             `json:"retired_at,omitempty"`
	RetireReason                      string             `json:"retire_reason,omitempty"`
}

type LogDeviceRecord struct {
	DeviceID             string `json:"device_id"`
	BatchFiles           int    `json:"batch_files"`
	LastLogUploadAt      string `json:"last_log_upload_at,omitempty"`
	LastLogUploadEntries int    `json:"last_log_upload_entries,omitempty"`
	LastLogUploadBytes   int64  `json:"last_log_upload_bytes,omitempty"`
	LastLogUploadSHA256  string `json:"last_log_upload_sha256,omitempty"`
}

type LogQueryOptions struct {
	From      time.Time
	HasFrom   bool
	To        time.Time
	HasTo     bool
	Before    time.Time
	HasBefore bool
	Kind      string
	Level     string
	Limit     int
}

type LogQueryResult struct {
	Entries    []json.RawMessage `json:"entries"`
	NextCursor string            `json:"next_cursor,omitempty"`
}

type LogSummaryOptions struct {
	DeviceID string
	From     time.Time
	HasFrom  bool
	To       time.Time
	HasTo    bool
	Kind     string
	Level    string
}

type LogDeviceSummary struct {
	DeviceID        string `json:"device_id"`
	Entries         int64  `json:"entries"`
	LatestTimestamp string `json:"latest_timestamp,omitempty"`
}

type LogSummaryResult struct {
	TotalEntries    int64              `json:"total_entries"`
	LatestTimestamp string             `json:"latest_timestamp,omitempty"`
	ByDevice        []LogDeviceSummary `json:"by_device"`
	ByKind          map[string]int64   `json:"by_kind"`
	ByLevel         map[string]int64   `json:"by_level"`
}

type logBatchFile struct {
	path    string
	modTime time.Time
	size    int64
}

type storedDevices struct {
	Devices  []DeviceRecord  `json:"devices"`
	Policies []PolicyRecord  `json:"policies,omitempty"`
	Releases []ReleaseRecord `json:"releases,omitempty"`
}

type deviceStore struct {
	mu           sync.RWMutex
	backend      string
	path         string
	sqlitePath   string
	db           *sql.DB
	logRetention time.Duration
	logMaxBytes  int64
	devices      map[string]DeviceRecord
	policies     map[string]PolicyRecord
	releases     map[string]ReleaseRecord
}

func loadDeviceStore(cfg StorageConfig) (*deviceStore, error) {
	path := strings.TrimSpace(cfg.Path)
	backend := cfg.BackendName()
	s := &deviceStore{
		backend:      backend,
		path:         path,
		sqlitePath:   cfg.SQLiteDBPath(),
		logRetention: cfg.LogRetention.Duration,
		logMaxBytes:  cfg.LogMaxBytes,
		devices:      map[string]DeviceRecord{},
		policies:     map[string]PolicyRecord{},
		releases:     map[string]ReleaseRecord{},
	}
	if backend == storageBackendSQLite {
		if err := InitSQLiteStore(s.sqlitePath); err != nil {
			return nil, fmt.Errorf("init sqlite store: %w", err)
		}
		db, err := openSQLite(s.sqlitePath, true)
		if err != nil {
			return nil, fmt.Errorf("open sqlite store: %w", err)
		}
		s.db = db
		if err := s.loadSQLiteIntoMemory(); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("load sqlite store: %w", err)
		}
		return s, nil
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
		rec.DesiredPolicyVersion = normalizePolicyVersion(rec.DesiredPolicyVersion)
		rec.DesiredPolicySHA256 = strings.ToLower(strings.TrimSpace(rec.DesiredPolicySHA256))
		rec.CurrentPolicyVersion = normalizePolicyVersion(rec.CurrentPolicyVersion)
		rec.CurrentPolicySHA256 = strings.ToLower(strings.TrimSpace(rec.CurrentPolicySHA256))
		rec.LastPolicyAckStatus = strings.TrimSpace(strings.ToLower(rec.LastPolicyAckStatus))
		rec.DesiredReleaseVersion = normalizePolicyVersion(rec.DesiredReleaseVersion)
		rec.DesiredReleaseSHA256 = strings.ToLower(strings.TrimSpace(rec.DesiredReleaseSHA256))
		rec.DesiredReleaseNotBeforeAt = strings.TrimSpace(rec.DesiredReleaseNotBeforeAt)
		rec.CurrentReleaseVersion = normalizePolicyVersion(rec.CurrentReleaseVersion)
		rec.CurrentReleaseSHA256 = strings.ToLower(strings.TrimSpace(rec.CurrentReleaseSHA256))
		rec.LastReleaseAckStatus = strings.TrimSpace(strings.ToLower(rec.LastReleaseAckStatus))
		rec.LastLogUploadSHA256 = strings.ToLower(strings.TrimSpace(rec.LastLogUploadSHA256))
		rec.UpstreamHealthStatus = normalizeUpstreamHealthStatus(rec.UpstreamHealthStatus)
		rec.UpstreamHealthEndpoint = strings.TrimSpace(rec.UpstreamHealthEndpoint)
		rec.UpstreamHealthLastChangedAt = normalizeStoreTimestamp(rec.UpstreamHealthLastChangedAt)
		rec.UpstreamHealthLastError = strings.TrimSpace(rec.UpstreamHealthLastError)
		if rec.UpstreamHealthConsecutiveFailures < 0 {
			rec.UpstreamHealthConsecutiveFailures = 0
		}
		if rec.UpstreamHealthStatus == "healthy" {
			rec.UpstreamHealthConsecutiveFailures = 0
			rec.UpstreamHealthLastError = ""
		}
		if rec.UpstreamHealthStatus == "" {
			rec.UpstreamHealthConsecutiveFailures = 0
			rec.UpstreamHealthLastError = ""
		}
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
	for _, rec := range payload.Policies {
		if rec.Version == "" {
			continue
		}
		rec.Version = normalizePolicyVersion(rec.Version)
		rec.SHA256 = strings.ToLower(strings.TrimSpace(rec.SHA256))
		rec.WAFRaw = strings.TrimSpace(rec.WAFRaw)
		bundleB64, bundleSHA, err := normalizeAndValidatePolicyBundle(rec.BundleTGZB64, rec.BundleSHA256)
		if err != nil {
			continue
		}
		rec.BundleTGZB64 = bundleB64
		rec.BundleSHA256 = bundleSHA
		if rec.SHA256 == "" && rec.WAFRaw != "" {
			rec.SHA256 = hashStringHex(rec.WAFRaw)
		}
		rec.Status = strings.ToLower(strings.TrimSpace(rec.Status))
		switch rec.Status {
		case "":
			// Backward compatibility: policies created before approval workflow
			// are treated as approved.
			rec.Status = policyStatusApproved
			if rec.ApprovedAt == "" {
				rec.ApprovedAt = rec.CreatedAt
			}
		case policyStatusDraft, policyStatusApproved:
		default:
			continue
		}
		if rec.Version == "" || rec.WAFRaw == "" || rec.SHA256 == "" {
			continue
		}
		s.policies[rec.Version] = rec
	}
	for _, rec := range payload.Releases {
		if rec.Version == "" {
			continue
		}
		rec.Version = normalizePolicyVersion(rec.Version)
		rec.Platform = normalizeReleasePlatform(rec.Platform)
		rec.SHA256 = strings.ToLower(strings.TrimSpace(rec.SHA256))
		rec.BinaryB64, rec.SHA256 = normalizeAndValidateReleaseBinary(rec.BinaryB64, rec.SHA256)
		if rec.Version == "" || rec.Platform == "" || rec.SHA256 == "" || rec.BinaryB64 == "" {
			continue
		}
		rec.Status = strings.ToLower(strings.TrimSpace(rec.Status))
		switch rec.Status {
		case "":
			rec.Status = releaseStatusApproved
			if rec.ApprovedAt == "" {
				rec.ApprovedAt = rec.CreatedAt
			}
		case releaseStatusDraft, releaseStatusApproved:
		default:
			continue
		}
		s.releases[rec.Version] = rec
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

func (s *deviceStore) listPolicies() []PolicyRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	policies := make([]PolicyRecord, 0, len(s.policies))
	for _, rec := range s.policies {
		policies = append(policies, rec)
	}
	sort.Slice(policies, func(i, j int) bool {
		return policies[i].Version < policies[j].Version
	})
	return policies
}

func (s *deviceStore) getPolicy(version string) (PolicyRecord, bool) {
	version = normalizePolicyVersion(version)
	if version == "" {
		return PolicyRecord{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.policies[version]
	return rec, ok
}

func (s *deviceStore) listReleases() []ReleaseRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	releases := make([]ReleaseRecord, 0, len(s.releases))
	for _, rec := range s.releases {
		releases = append(releases, rec)
	}
	sort.Slice(releases, func(i, j int) bool {
		return releases[i].Version < releases[j].Version
	})
	return releases
}

func (s *deviceStore) getRelease(version string) (ReleaseRecord, bool) {
	version = normalizePolicyVersion(version)
	if version == "" {
		return ReleaseRecord{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.releases[version]
	return rec, ok
}

func (s *deviceStore) upsertPolicy(rec PolicyRecord, now time.Time) (PolicyRecord, error) {
	rec.Version = normalizePolicyVersion(rec.Version)
	rec.WAFRaw = strings.TrimSpace(rec.WAFRaw)
	rec.SHA256 = strings.ToLower(strings.TrimSpace(rec.SHA256))
	rec.Note = strings.TrimSpace(rec.Note)
	var err error
	rec.BundleTGZB64, rec.BundleSHA256, err = normalizeAndValidatePolicyBundle(rec.BundleTGZB64, rec.BundleSHA256)
	if err != nil {
		return PolicyRecord{}, errStoreInvalid
	}
	if rec.Version == "" || rec.WAFRaw == "" {
		return PolicyRecord{}, errStoreInvalid
	}
	if rec.SHA256 == "" {
		rec.SHA256 = hashStringHex(rec.WAFRaw)
	}
	if rec.SHA256 != hashStringHex(rec.WAFRaw) {
		return PolicyRecord{}, errStoreInvalid
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.policies[rec.Version]
	if ok {
		if existing.SHA256 == rec.SHA256 && existing.WAFRaw == rec.WAFRaw {
			if rec.BundleTGZB64 != "" && (existing.BundleSHA256 != rec.BundleSHA256 || existing.BundleTGZB64 != rec.BundleTGZB64) {
				return PolicyRecord{}, errStoreConflict
			}
			if rec.Note != "" && existing.Note == "" {
				existing.Note = rec.Note
				existing.UpdatedAt = now.UTC().Format(time.RFC3339Nano)
				s.policies[rec.Version] = existing
				if err := s.saveLocked(); err != nil {
					return PolicyRecord{}, err
				}
			}
			return existing, nil
		}
		return PolicyRecord{}, errStoreConflict
	}
	rec.Status = policyStatusDraft
	rec.CreatedAt = now.UTC().Format(time.RFC3339Nano)
	rec.UpdatedAt = rec.CreatedAt
	s.policies[rec.Version] = rec
	if err := s.saveLocked(); err != nil {
		return PolicyRecord{}, err
	}
	return rec, nil
}

func (s *deviceStore) approvePolicy(version string, approvedAt time.Time) (PolicyRecord, error) {
	version = normalizePolicyVersion(version)
	if version == "" {
		return PolicyRecord{}, errStoreInvalid
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.policies[version]
	if !ok {
		return PolicyRecord{}, os.ErrNotExist
	}
	if rec.Status == policyStatusApproved {
		return rec, nil
	}
	rec.Status = policyStatusApproved
	rec.ApprovedAt = approvedAt.UTC().Format(time.RFC3339Nano)
	rec.UpdatedAt = rec.ApprovedAt
	s.policies[version] = rec
	if err := s.saveLocked(); err != nil {
		return PolicyRecord{}, err
	}
	return rec, nil
}

func (s *deviceStore) putPolicy(rec PolicyRecord, now time.Time) (PolicyRecord, error) {
	rec.Version = normalizePolicyVersion(rec.Version)
	rec.WAFRaw = strings.TrimSpace(rec.WAFRaw)
	rec.SHA256 = strings.ToLower(strings.TrimSpace(rec.SHA256))
	rec.Note = strings.TrimSpace(rec.Note)
	var err error
	rec.BundleTGZB64, rec.BundleSHA256, err = normalizeAndValidatePolicyBundle(rec.BundleTGZB64, rec.BundleSHA256)
	if err != nil {
		return PolicyRecord{}, errStoreInvalid
	}
	if rec.Version == "" || rec.WAFRaw == "" {
		return PolicyRecord{}, errStoreInvalid
	}
	if rec.SHA256 == "" {
		rec.SHA256 = hashStringHex(rec.WAFRaw)
	}
	if rec.SHA256 != hashStringHex(rec.WAFRaw) {
		return PolicyRecord{}, errStoreInvalid
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	existing, ok := s.policies[rec.Version]
	if !ok {
		rec.Status = policyStatusDraft
		rec.CreatedAt = now.UTC().Format(time.RFC3339Nano)
		rec.UpdatedAt = rec.CreatedAt
		s.policies[rec.Version] = rec
		if err := s.saveLocked(); err != nil {
			return PolicyRecord{}, err
		}
		return rec, nil
	}

	nextBundleB64 := rec.BundleTGZB64
	nextBundleSHA := rec.BundleSHA256
	if nextBundleB64 == "" && nextBundleSHA == "" {
		nextBundleB64 = existing.BundleTGZB64
		nextBundleSHA = existing.BundleSHA256
	}
	if existing.SHA256 == rec.SHA256 && existing.WAFRaw == rec.WAFRaw &&
		existing.BundleSHA256 == nextBundleSHA && existing.BundleTGZB64 == nextBundleB64 {
		if rec.Note != "" && existing.Note == "" {
			existing.Note = rec.Note
			existing.UpdatedAt = now.UTC().Format(time.RFC3339Nano)
			s.policies[rec.Version] = existing
			if err := s.saveLocked(); err != nil {
				return PolicyRecord{}, err
			}
		}
		return existing, nil
	}
	if s.policyInUseLocked(rec.Version) {
		return PolicyRecord{}, errStoreInUse
	}

	existing.WAFRaw = rec.WAFRaw
	existing.SHA256 = rec.SHA256
	existing.BundleTGZB64 = nextBundleB64
	existing.BundleSHA256 = nextBundleSHA
	if rec.Note != "" {
		existing.Note = rec.Note
	}
	existing.Status = policyStatusDraft
	existing.ApprovedAt = ""
	existing.UpdatedAt = now.UTC().Format(time.RFC3339Nano)
	s.policies[rec.Version] = existing
	if err := s.saveLocked(); err != nil {
		return PolicyRecord{}, err
	}
	return existing, nil
}

func (s *deviceStore) deletePolicy(version string) error {
	version = normalizePolicyVersion(version)
	if version == "" {
		return errStoreInvalid
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.policies[version]; !ok {
		return os.ErrNotExist
	}
	if s.policyInUseLocked(version) {
		return errStoreInUse
	}
	delete(s.policies, version)
	if err := s.saveLocked(); err != nil {
		return err
	}
	return nil
}

func (s *deviceStore) upsertRelease(rec ReleaseRecord, now time.Time) (ReleaseRecord, error) {
	rec.Version = normalizePolicyVersion(rec.Version)
	rec.Platform = normalizeReleasePlatform(rec.Platform)
	rec.SHA256 = strings.ToLower(strings.TrimSpace(rec.SHA256))
	rec.BinaryB64, rec.SHA256 = normalizeAndValidateReleaseBinary(rec.BinaryB64, rec.SHA256)
	rec.Note = strings.TrimSpace(rec.Note)
	if rec.Version == "" || rec.Platform == "" || rec.SHA256 == "" || rec.BinaryB64 == "" {
		return ReleaseRecord{}, errStoreInvalid
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.releases[rec.Version]
	if ok {
		if existing.SHA256 == rec.SHA256 && existing.BinaryB64 == rec.BinaryB64 && existing.Platform == rec.Platform {
			if rec.Note != "" && existing.Note == "" {
				existing.Note = rec.Note
				existing.UpdatedAt = now.UTC().Format(time.RFC3339Nano)
				s.releases[rec.Version] = existing
				if err := s.saveLocked(); err != nil {
					return ReleaseRecord{}, err
				}
			}
			return existing, nil
		}
		return ReleaseRecord{}, errStoreConflict
	}
	rec.Status = releaseStatusDraft
	rec.CreatedAt = now.UTC().Format(time.RFC3339Nano)
	rec.UpdatedAt = rec.CreatedAt
	s.releases[rec.Version] = rec
	if err := s.saveLocked(); err != nil {
		return ReleaseRecord{}, err
	}
	return rec, nil
}

func (s *deviceStore) approveRelease(version string, approvedAt time.Time) (ReleaseRecord, error) {
	version = normalizePolicyVersion(version)
	if version == "" {
		return ReleaseRecord{}, errStoreInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.releases[version]
	if !ok {
		return ReleaseRecord{}, os.ErrNotExist
	}
	if rec.Status == releaseStatusApproved {
		return rec, nil
	}
	rec.Status = releaseStatusApproved
	rec.ApprovedAt = approvedAt.UTC().Format(time.RFC3339Nano)
	rec.UpdatedAt = rec.ApprovedAt
	s.releases[version] = rec
	if err := s.saveLocked(); err != nil {
		return ReleaseRecord{}, err
	}
	return rec, nil
}

func (s *deviceStore) putRelease(rec ReleaseRecord, now time.Time) (ReleaseRecord, error) {
	rec.Version = normalizePolicyVersion(rec.Version)
	rec.Platform = normalizeReleasePlatform(rec.Platform)
	rec.SHA256 = strings.ToLower(strings.TrimSpace(rec.SHA256))
	rec.BinaryB64, rec.SHA256 = normalizeAndValidateReleaseBinary(rec.BinaryB64, rec.SHA256)
	rec.Note = strings.TrimSpace(rec.Note)
	if rec.Version == "" || rec.Platform == "" || rec.SHA256 == "" || rec.BinaryB64 == "" {
		return ReleaseRecord{}, errStoreInvalid
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.releases[rec.Version]
	if !ok {
		rec.Status = releaseStatusDraft
		rec.CreatedAt = now.UTC().Format(time.RFC3339Nano)
		rec.UpdatedAt = rec.CreatedAt
		s.releases[rec.Version] = rec
		if err := s.saveLocked(); err != nil {
			return ReleaseRecord{}, err
		}
		return rec, nil
	}

	if existing.SHA256 == rec.SHA256 && existing.BinaryB64 == rec.BinaryB64 && existing.Platform == rec.Platform {
		if rec.Note != "" && existing.Note == "" {
			existing.Note = rec.Note
			existing.UpdatedAt = now.UTC().Format(time.RFC3339Nano)
			s.releases[rec.Version] = existing
			if err := s.saveLocked(); err != nil {
				return ReleaseRecord{}, err
			}
		}
		return existing, nil
	}
	if s.releaseInUseLocked(rec.Version) {
		return ReleaseRecord{}, errStoreInUse
	}

	existing.Platform = rec.Platform
	existing.SHA256 = rec.SHA256
	existing.BinaryB64 = rec.BinaryB64
	if rec.Note != "" {
		existing.Note = rec.Note
	}
	existing.Status = releaseStatusDraft
	existing.ApprovedAt = ""
	existing.UpdatedAt = now.UTC().Format(time.RFC3339Nano)
	s.releases[rec.Version] = existing
	if err := s.saveLocked(); err != nil {
		return ReleaseRecord{}, err
	}
	return existing, nil
}

func (s *deviceStore) deleteRelease(version string) error {
	version = normalizePolicyVersion(version)
	if version == "" {
		return errStoreInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.releases[version]; !ok {
		return os.ErrNotExist
	}
	if s.releaseInUseLocked(version) {
		return errStoreInUse
	}
	delete(s.releases, version)
	if err := s.saveLocked(); err != nil {
		return err
	}
	return nil
}

func (s *deviceStore) policyInUseLocked(version string) bool {
	for _, rec := range s.devices {
		if rec.DesiredPolicyVersion == version || rec.CurrentPolicyVersion == version {
			return true
		}
	}
	return false
}

func (s *deviceStore) releaseInUseLocked(version string) bool {
	for _, rec := range s.devices {
		if rec.DesiredReleaseVersion == version || rec.CurrentReleaseVersion == version {
			return true
		}
	}
	return false
}

func normalizeAndValidatePolicyBundle(rawB64, rawSHA string) (string, string, error) {
	b64v := strings.TrimSpace(rawB64)
	shav := strings.ToLower(strings.TrimSpace(rawSHA))
	if b64v == "" && shav == "" {
		return "", "", nil
	}
	if b64v == "" || shav == "" {
		return "", "", errStoreInvalid
	}
	payload, err := decodeBase64String(b64v)
	if err != nil || len(payload) == 0 {
		return "", "", errStoreInvalid
	}
	if hashBytesHex(payload) != shav {
		return "", "", errStoreInvalid
	}
	if err := validateTGZArchive(payload); err != nil {
		return "", "", errStoreInvalid
	}
	return b64v, shav, nil
}

const maxReleaseBinaryBytes = 128 << 20 // 128 MiB

func normalizeReleasePlatform(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}

func normalizeAndValidateReleaseBinary(rawB64, rawSHA string) (string, string) {
	b64v := strings.TrimSpace(rawB64)
	shav := strings.ToLower(strings.TrimSpace(rawSHA))
	if b64v == "" {
		return "", ""
	}
	payload, err := decodeBase64String(b64v)
	if err != nil || len(payload) == 0 || len(payload) > maxReleaseBinaryBytes {
		return "", ""
	}
	got := hashBytesHex(payload)
	if shav != "" && shav != got {
		return "", ""
	}
	return b64v, got
}

func validateTGZArchive(payload []byte) error {
	zr, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		return err
	}
	defer zr.Close()

	tr := tar.NewReader(zr)
	seenRegular := false
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		name := strings.TrimSpace(h.Name)
		if name == "" {
			continue
		}
		clean := filepath.Clean(name)
		if clean == "." || strings.HasPrefix(clean, "../") || filepath.IsAbs(clean) {
			return errStoreInvalid
		}
		switch h.Typeflag {
		case tar.TypeReg, tar.TypeRegA:
			seenRegular = true
		case tar.TypeDir:
		default:
			return errStoreInvalid
		}
	}
	if !seenRegular {
		return errStoreInvalid
	}
	return nil
}

func decodeBase64String(raw string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(strings.TrimSpace(raw))
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
	fingerprint := strings.ToLower(strings.TrimSpace(rec.PublicKeyFingerprintSHA256))
	if fingerprint != "" {
		for deviceID, existing := range s.devices {
			if deviceID == rec.DeviceID {
				continue
			}
			if existing.PublicKeyFingerprintSHA256 == fingerprint {
				return DeviceRecord{}, errStoreConflict
			}
			for _, revoked := range existing.RevokedKeys {
				if revoked.PublicKeyFingerprintSHA256 == fingerprint {
					return DeviceRecord{}, errStoreConflict
				}
			}
		}
	}
	prev, ok := s.devices[rec.DeviceID]
	if ok {
		rec.FirstSeenAt = prev.FirstSeenAt
		rec.LastHeartbeatAt = prev.LastHeartbeatAt
		rec.LastHeartbeatMessageAt = prev.LastHeartbeatMessageAt
		rec.LastHeartbeatNonce = prev.LastHeartbeatNonce
		rec.LastHeartbeatStatusHash = prev.LastHeartbeatStatusHash
		rec.DesiredPolicyVersion = prev.DesiredPolicyVersion
		rec.DesiredPolicySHA256 = prev.DesiredPolicySHA256
		rec.DesiredPolicyAssignedAt = prev.DesiredPolicyAssignedAt
		rec.CurrentPolicyVersion = prev.CurrentPolicyVersion
		rec.CurrentPolicySHA256 = prev.CurrentPolicySHA256
		rec.LastPolicySyncAt = prev.LastPolicySyncAt
		rec.LastPolicyAckAt = prev.LastPolicyAckAt
		rec.LastPolicyAckStatus = prev.LastPolicyAckStatus
		rec.LastPolicyAckMessage = prev.LastPolicyAckMessage
		rec.DesiredReleaseVersion = prev.DesiredReleaseVersion
		rec.DesiredReleaseSHA256 = prev.DesiredReleaseSHA256
		rec.DesiredReleaseAssignedAt = prev.DesiredReleaseAssignedAt
		rec.DesiredReleaseNotBeforeAt = prev.DesiredReleaseNotBeforeAt
		rec.CurrentReleaseVersion = prev.CurrentReleaseVersion
		rec.CurrentReleaseSHA256 = prev.CurrentReleaseSHA256
		rec.LastReleaseSyncAt = prev.LastReleaseSyncAt
		rec.LastReleaseAckAt = prev.LastReleaseAckAt
		rec.LastReleaseAckStatus = prev.LastReleaseAckStatus
		rec.LastReleaseAckMessage = prev.LastReleaseAckMessage
		rec.LastLogUploadAt = prev.LastLogUploadAt
		rec.LastLogUploadEntries = prev.LastLogUploadEntries
		rec.LastLogUploadBytes = prev.LastLogUploadBytes
		rec.LastLogUploadSHA256 = prev.LastLogUploadSHA256
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

func (s *deviceStore) updateHeartbeat(deviceID string, receivedAt time.Time, messageAt time.Time, nonce string, statusHash string, policyVersion string, policyHash string) (DeviceRecord, error) {
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
	policyVersion = normalizePolicyVersion(policyVersion)
	policyHash = strings.ToLower(strings.TrimSpace(policyHash))
	if policyVersion != "" {
		rec.CurrentPolicyVersion = policyVersion
		rec.CurrentPolicySHA256 = policyHash
		rec.LastPolicySyncAt = rec.LastHeartbeatAt
	}
	s.devices[deviceID] = rec
	if err := s.saveLocked(); err != nil {
		return DeviceRecord{}, err
	}
	return rec, nil
}

func (s *deviceStore) assignDesiredPolicy(deviceID, version string, assignedAt time.Time) (DeviceRecord, PolicyRecord, error) {
	version = normalizePolicyVersion(version)
	if version == "" {
		return DeviceRecord{}, PolicyRecord{}, errStoreInvalid
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.devices[deviceID]
	if !ok {
		return DeviceRecord{}, PolicyRecord{}, os.ErrNotExist
	}
	pol, ok := s.policies[version]
	if !ok {
		return DeviceRecord{}, PolicyRecord{}, os.ErrNotExist
	}
	if pol.Status != policyStatusApproved {
		return DeviceRecord{}, PolicyRecord{}, errStoreConflict
	}
	rec.DesiredPolicyVersion = pol.Version
	rec.DesiredPolicySHA256 = pol.SHA256
	rec.DesiredPolicyAssignedAt = assignedAt.UTC().Format(time.RFC3339Nano)
	s.devices[deviceID] = rec
	if err := s.saveLocked(); err != nil {
		return DeviceRecord{}, PolicyRecord{}, err
	}
	return rec, pol, nil
}

func (s *deviceStore) assignDesiredRelease(deviceID, version string, assignedAt time.Time, notBefore *time.Time) (DeviceRecord, ReleaseRecord, error) {
	version = normalizePolicyVersion(version)
	if version == "" {
		return DeviceRecord{}, ReleaseRecord{}, errStoreInvalid
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.devices[deviceID]
	if !ok {
		return DeviceRecord{}, ReleaseRecord{}, os.ErrNotExist
	}
	rel, ok := s.releases[version]
	if !ok {
		return DeviceRecord{}, ReleaseRecord{}, os.ErrNotExist
	}
	if rel.Status != releaseStatusApproved {
		return DeviceRecord{}, ReleaseRecord{}, errStoreConflict
	}
	rec.DesiredReleaseVersion = rel.Version
	rec.DesiredReleaseSHA256 = rel.SHA256
	rec.DesiredReleaseAssignedAt = assignedAt.UTC().Format(time.RFC3339Nano)
	rec.DesiredReleaseNotBeforeAt = ""
	if notBefore != nil && !notBefore.IsZero() {
		rec.DesiredReleaseNotBeforeAt = notBefore.UTC().Format(time.RFC3339Nano)
	}
	s.devices[deviceID] = rec
	if err := s.saveLocked(); err != nil {
		return DeviceRecord{}, ReleaseRecord{}, err
	}
	return rec, rel, nil
}

func (s *deviceStore) updatePolicyAck(deviceID, version, hash, status, message string, ackAt time.Time) (DeviceRecord, error) {
	version = normalizePolicyVersion(version)
	hash = strings.ToLower(strings.TrimSpace(hash))
	status = strings.ToLower(strings.TrimSpace(status))
	message = strings.TrimSpace(message)

	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.devices[deviceID]
	if !ok {
		return DeviceRecord{}, os.ErrNotExist
	}
	rec.LastPolicyAckAt = ackAt.UTC().Format(time.RFC3339Nano)
	rec.LastPolicyAckStatus = status
	rec.LastPolicyAckMessage = message
	if status == "applied" && version != "" {
		rec.CurrentPolicyVersion = version
		rec.CurrentPolicySHA256 = hash
		rec.LastPolicySyncAt = rec.LastPolicyAckAt
	}
	s.devices[deviceID] = rec
	if err := s.saveLocked(); err != nil {
		return DeviceRecord{}, err
	}
	return rec, nil
}

func (s *deviceStore) updateReleaseAck(deviceID, version, hash, status, message string, ackAt time.Time) (DeviceRecord, error) {
	version = normalizePolicyVersion(version)
	hash = strings.ToLower(strings.TrimSpace(hash))
	status = strings.ToLower(strings.TrimSpace(status))
	message = strings.TrimSpace(message)

	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.devices[deviceID]
	if !ok {
		return DeviceRecord{}, os.ErrNotExist
	}
	rec.LastReleaseAckAt = ackAt.UTC().Format(time.RFC3339Nano)
	rec.LastReleaseAckStatus = status
	rec.LastReleaseAckMessage = message
	if status == "applied" && version != "" {
		rec.CurrentReleaseVersion = version
		rec.CurrentReleaseSHA256 = hash
		rec.LastReleaseSyncAt = rec.LastReleaseAckAt
	}
	s.devices[deviceID] = rec
	if err := s.saveLocked(); err != nil {
		return DeviceRecord{}, err
	}
	return rec, nil
}

func (s *deviceStore) saveLogBatch(deviceID string, messageAt time.Time, nonce string, payload []byte, entryCount int, contentSHA256 string) (DeviceRecord, string, error) {
	nonce = strings.TrimSpace(nonce)
	contentSHA256 = strings.ToLower(strings.TrimSpace(contentSHA256))

	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.devices[deviceID]
	if !ok {
		return DeviceRecord{}, "", os.ErrNotExist
	}
	if len(payload) == 0 {
		return DeviceRecord{}, "", errStoreInvalid
	}
	if contentSHA256 == "" {
		contentSHA256 = hashBytesHex(payload)
	}
	if contentSHA256 != hashBytesHex(payload) {
		return DeviceRecord{}, "", errStoreInvalid
	}

	baseDir := filepath.Join(filepath.Dir(s.path), "logs", safePathComponent(deviceID))
	if err := os.MkdirAll(baseDir, 0o700); err != nil {
		return DeviceRecord{}, "", fmt.Errorf("mkdir logs dir: %w", err)
	}
	stamp := messageAt.UTC().Format("20060102T150405.000000000Z")
	nonceToken := safePathComponent(nonce)
	if nonceToken == "" {
		nonceToken = "nonce"
	}
	name := fmt.Sprintf("%s-%s.ndjson.gz", stamp, nonceToken)
	tmp, err := os.CreateTemp(baseDir, "batch-*.tmp")
	if err != nil {
		return DeviceRecord{}, "", fmt.Errorf("create temp log batch: %w", err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(payload); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return DeviceRecord{}, "", fmt.Errorf("write temp log batch: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return DeviceRecord{}, "", fmt.Errorf("close temp log batch: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		_ = os.Remove(tmpPath)
		return DeviceRecord{}, "", fmt.Errorf("chmod temp log batch: %w", err)
	}
	outPath := filepath.Join(baseDir, name)
	if err := os.Rename(tmpPath, outPath); err != nil {
		_ = os.Remove(tmpPath)
		return DeviceRecord{}, "", fmt.Errorf("rename log batch: %w", err)
	}
	if err := s.enforceLogLimitsLocked(time.Now().UTC()); err != nil {
		return DeviceRecord{}, "", err
	}

	rec.LastLogUploadAt = messageAt.UTC().Format(time.RFC3339Nano)
	rec.LastLogUploadEntries = entryCount
	rec.LastLogUploadBytes = int64(len(payload))
	rec.LastLogUploadSHA256 = contentSHA256
	s.devices[deviceID] = rec
	if err := s.saveLocked(); err != nil {
		return DeviceRecord{}, "", err
	}
	return rec, outPath, nil
}

func (s *deviceStore) updateUpstreamHealth(deviceID string, snapshot upstreamHealthSnapshot, fallbackChangedAt time.Time) (DeviceRecord, error) {
	status := normalizeUpstreamHealthStatus(snapshot.Status)
	if status == "" {
		return DeviceRecord{}, errStoreInvalid
	}
	endpoint := strings.TrimSpace(snapshot.Endpoint)
	lastError := strings.TrimSpace(snapshot.LastError)
	failures := snapshot.ConsecutiveFailures
	if failures < 0 {
		failures = 0
	}
	changedAt := snapshot.LastChangedAt.UTC()
	if changedAt.IsZero() {
		changedAt = fallbackChangedAt.UTC()
	}
	if changedAt.IsZero() {
		changedAt = time.Now().UTC()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.devices[deviceID]
	if !ok {
		return DeviceRecord{}, os.ErrNotExist
	}
	rec.UpstreamHealthStatus = status
	if endpoint != "" {
		rec.UpstreamHealthEndpoint = endpoint
	}
	rec.UpstreamHealthLastChangedAt = changedAt.Format(time.RFC3339Nano)
	if status == "healthy" {
		rec.UpstreamHealthConsecutiveFailures = 0
		rec.UpstreamHealthLastError = ""
	} else {
		if failures <= 0 {
			if rec.UpstreamHealthConsecutiveFailures > 0 {
				failures = rec.UpstreamHealthConsecutiveFailures + 1
			} else {
				failures = 1
			}
		}
		rec.UpstreamHealthConsecutiveFailures = failures
		rec.UpstreamHealthLastError = lastError
	}
	s.devices[deviceID] = rec
	if err := s.saveLocked(); err != nil {
		return DeviceRecord{}, err
	}
	return rec, nil
}

func (s *deviceStore) enforceLogLimitsLocked(now time.Time) error {
	if s.logRetention <= 0 && s.logMaxBytes <= 0 {
		return nil
	}
	logsRoot := filepath.Join(filepath.Dir(s.path), "logs")
	rootEntries, err := os.ReadDir(logsRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read logs root: %w", err)
	}

	files := make([]logBatchFile, 0, 256)
	for _, deviceEntry := range rootEntries {
		if !deviceEntry.IsDir() {
			continue
		}
		deviceDir := filepath.Join(logsRoot, deviceEntry.Name())
		entries, err := os.ReadDir(deviceDir)
		if err != nil {
			return fmt.Errorf("read device logs dir: %w", err)
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := strings.ToLower(entry.Name())
			if !strings.HasSuffix(name, ".ndjson.gz") {
				continue
			}
			info, err := entry.Info()
			if err != nil {
				return fmt.Errorf("stat log batch: %w", err)
			}
			files = append(files, logBatchFile{
				path:    filepath.Join(deviceDir, entry.Name()),
				modTime: info.ModTime().UTC(),
				size:    info.Size(),
			})
		}
	}
	if len(files) == 0 {
		return nil
	}

	sort.Slice(files, func(i, j int) bool {
		if files[i].modTime.Equal(files[j].modTime) {
			return files[i].path < files[j].path
		}
		return files[i].modTime.Before(files[j].modTime)
	})

	keep := make([]logBatchFile, 0, len(files))
	if s.logRetention > 0 {
		cutoff := now.Add(-s.logRetention)
		for _, f := range files {
			if f.modTime.Before(cutoff) {
				if err := os.Remove(f.path); err != nil && !os.IsNotExist(err) {
					return fmt.Errorf("remove expired log batch: %w", err)
				}
				continue
			}
			keep = append(keep, f)
		}
	} else {
		keep = append(keep, files...)
	}

	if s.logMaxBytes > 0 {
		var total int64
		for _, f := range keep {
			total += f.size
		}
		for len(keep) > 1 && total > s.logMaxBytes {
			f := keep[0]
			keep = keep[1:]
			total -= f.size
			if err := os.Remove(f.path); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("remove over-capacity log batch: %w", err)
			}
		}
	}

	for _, deviceEntry := range rootEntries {
		if !deviceEntry.IsDir() {
			continue
		}
		deviceDir := filepath.Join(logsRoot, deviceEntry.Name())
		entries, err := os.ReadDir(deviceDir)
		if err != nil {
			continue
		}
		if len(entries) == 0 {
			_ = os.Remove(deviceDir)
		}
	}
	return nil
}

func (s *deviceStore) listLogDevices() ([]LogDeviceRecord, error) {
	s.mu.RLock()
	devices := make([]DeviceRecord, 0, len(s.devices))
	for _, rec := range s.devices {
		devices = append(devices, rec)
	}
	s.mu.RUnlock()

	out := make([]LogDeviceRecord, 0, len(devices))
	logsRoot := filepath.Join(filepath.Dir(s.path), "logs")

	for _, rec := range devices {
		safeID := safePathComponent(rec.DeviceID)
		if safeID == "" {
			continue
		}
		deviceDir := filepath.Join(logsRoot, safeID)
		batchFiles := 0
		entries, err := os.ReadDir(deviceDir)
		if err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("read log device dir: %w", err)
		}
		if err == nil {
			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}
				if strings.HasSuffix(strings.ToLower(entry.Name()), ".ndjson.gz") {
					batchFiles++
				}
			}
		}
		if batchFiles == 0 && strings.TrimSpace(rec.LastLogUploadAt) == "" {
			continue
		}
		out = append(out, LogDeviceRecord{
			DeviceID:             rec.DeviceID,
			BatchFiles:           batchFiles,
			LastLogUploadAt:      rec.LastLogUploadAt,
			LastLogUploadEntries: rec.LastLogUploadEntries,
			LastLogUploadBytes:   rec.LastLogUploadBytes,
			LastLogUploadSHA256:  rec.LastLogUploadSHA256,
		})
	}

	sort.Slice(out, func(i, j int) bool {
		return out[i].DeviceID < out[j].DeviceID
	})
	return out, nil
}

func (s *deviceStore) queryLogs(deviceID string, opts LogQueryOptions) (LogQueryResult, error) {
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return LogQueryResult{}, errStoreInvalid
	}
	if opts.Limit <= 0 {
		opts.Limit = 100
	}
	if opts.Limit > 1000 {
		opts.Limit = 1000
	}
	opts.Kind = strings.ToLower(strings.TrimSpace(opts.Kind))
	opts.Level = strings.ToLower(strings.TrimSpace(opts.Level))

	s.mu.RLock()
	_, ok := s.devices[deviceID]
	s.mu.RUnlock()
	if !ok {
		return LogQueryResult{}, os.ErrNotExist
	}

	logsRoot := filepath.Join(filepath.Dir(s.path), "logs")
	deviceDir := filepath.Join(logsRoot, safePathComponent(deviceID))

	dirEntries, err := os.ReadDir(deviceDir)
	if err != nil {
		if os.IsNotExist(err) {
			return LogQueryResult{Entries: []json.RawMessage{}}, nil
		}
		return LogQueryResult{}, fmt.Errorf("read log dir: %w", err)
	}
	files := make([]string, 0, len(dirEntries))
	for _, entry := range dirEntries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(strings.ToLower(name), ".ndjson.gz") {
			files = append(files, filepath.Join(deviceDir, name))
		}
	}
	sort.Slice(files, func(i, j int) bool {
		return filepath.Base(files[i]) > filepath.Base(files[j])
	})

	type parsedLogLine struct {
		raw   json.RawMessage
		ts    time.Time
		hasTS bool
		kind  string
		level string
	}

	readBatch := func(path string) ([]parsedLogLine, error) {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()

		zr, err := gzip.NewReader(f)
		if err != nil {
			return nil, err
		}
		defer zr.Close()

		sc := bufio.NewScanner(zr)
		sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
		lines := make([]parsedLogLine, 0, 64)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			raw := json.RawMessage(append([]byte(nil), []byte(line)...))
			var meta struct {
				Timestamp string `json:"timestamp"`
				Kind      string `json:"kind"`
				Level     string `json:"level"`
			}
			if err := json.Unmarshal(raw, &meta); err != nil {
				continue
			}
			ts, hasTS := parseStoreRFC3339Any(meta.Timestamp)
			lines = append(lines, parsedLogLine{
				raw:   raw,
				ts:    ts,
				hasTS: hasTS,
				kind:  strings.ToLower(strings.TrimSpace(meta.Kind)),
				level: strings.ToLower(strings.TrimSpace(meta.Level)),
			})
		}
		if err := sc.Err(); err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		return lines, nil
	}

	result := LogQueryResult{Entries: make([]json.RawMessage, 0, opts.Limit)}
	hasMore := false
	for _, filePath := range files {
		lines, err := readBatch(filePath)
		if err != nil {
			return LogQueryResult{}, fmt.Errorf("read log batch: %w", err)
		}
		for i := len(lines) - 1; i >= 0; i-- {
			line := lines[i]
			if opts.Kind != "" && line.kind != opts.Kind {
				continue
			}
			if opts.Level != "" && line.level != opts.Level {
				continue
			}
			if opts.HasFrom || opts.HasTo || opts.HasBefore {
				if !line.hasTS {
					continue
				}
				if opts.HasFrom && line.ts.Before(opts.From) {
					continue
				}
				if opts.HasTo && line.ts.After(opts.To) {
					continue
				}
				if opts.HasBefore && !line.ts.Before(opts.Before) {
					continue
				}
			}
			result.Entries = append(result.Entries, line.raw)
			if len(result.Entries) >= opts.Limit {
				hasMore = true
				if line.hasTS {
					result.NextCursor = line.ts.Format(time.RFC3339Nano)
				}
				break
			}
		}
		if hasMore {
			break
		}
	}
	return result, nil
}

func (s *deviceStore) summarizeLogs(opts LogSummaryOptions) (LogSummaryResult, error) {
	opts.DeviceID = strings.TrimSpace(opts.DeviceID)
	opts.Kind = strings.ToLower(strings.TrimSpace(opts.Kind))
	opts.Level = strings.ToLower(strings.TrimSpace(opts.Level))

	switch opts.Kind {
	case "", "access", "security", "system":
	default:
		return LogSummaryResult{}, errStoreInvalid
	}
	switch opts.Level {
	case "", "info", "warn", "error":
	default:
		return LogSummaryResult{}, errStoreInvalid
	}

	s.mu.RLock()
	deviceIDs := make([]string, 0, len(s.devices))
	if opts.DeviceID != "" {
		if _, ok := s.devices[opts.DeviceID]; !ok {
			s.mu.RUnlock()
			return LogSummaryResult{}, os.ErrNotExist
		}
		deviceIDs = append(deviceIDs, opts.DeviceID)
	} else {
		for deviceID := range s.devices {
			deviceIDs = append(deviceIDs, deviceID)
		}
		sort.Strings(deviceIDs)
	}
	s.mu.RUnlock()

	result := LogSummaryResult{
		ByDevice: make([]LogDeviceSummary, 0, len(deviceIDs)),
		ByKind: map[string]int64{
			"access":   0,
			"security": 0,
			"system":   0,
		},
		ByLevel: map[string]int64{
			"info":  0,
			"warn":  0,
			"error": 0,
		},
	}
	var globalLatest time.Time

	logsRoot := filepath.Join(filepath.Dir(s.path), "logs")
	for _, deviceID := range deviceIDs {
		deviceDir := filepath.Join(logsRoot, safePathComponent(deviceID))
		dirEntries, err := os.ReadDir(deviceDir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return LogSummaryResult{}, fmt.Errorf("read log dir: %w", err)
		}

		files := make([]string, 0, len(dirEntries))
		for _, entry := range dirEntries {
			if entry.IsDir() {
				continue
			}
			if strings.HasSuffix(strings.ToLower(entry.Name()), ".ndjson.gz") {
				files = append(files, filepath.Join(deviceDir, entry.Name()))
			}
		}
		sort.Strings(files)

		var deviceCount int64
		var deviceLatest time.Time
		for _, filePath := range files {
			f, err := os.Open(filePath)
			if err != nil {
				return LogSummaryResult{}, fmt.Errorf("open log batch: %w", err)
			}
			zr, err := gzip.NewReader(f)
			if err != nil {
				_ = f.Close()
				return LogSummaryResult{}, fmt.Errorf("open gzip log batch: %w", err)
			}

			sc := bufio.NewScanner(zr)
			sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				if line == "" {
					continue
				}
				var meta struct {
					Timestamp string `json:"timestamp"`
					Kind      string `json:"kind"`
					Level     string `json:"level"`
				}
				if err := json.Unmarshal([]byte(line), &meta); err != nil {
					continue
				}
				kind := strings.ToLower(strings.TrimSpace(meta.Kind))
				level := strings.ToLower(strings.TrimSpace(meta.Level))
				if opts.Kind != "" && kind != opts.Kind {
					continue
				}
				if opts.Level != "" && level != opts.Level {
					continue
				}
				ts, hasTS := parseStoreRFC3339Any(meta.Timestamp)
				if opts.HasFrom || opts.HasTo {
					if !hasTS {
						continue
					}
					if opts.HasFrom && ts.Before(opts.From) {
						continue
					}
					if opts.HasTo && ts.After(opts.To) {
						continue
					}
				}

				deviceCount++
				result.TotalEntries++
				if _, ok := result.ByKind[kind]; ok {
					result.ByKind[kind]++
				}
				if _, ok := result.ByLevel[level]; ok {
					result.ByLevel[level]++
				}
				if hasTS {
					if deviceLatest.IsZero() || ts.After(deviceLatest) {
						deviceLatest = ts
					}
					if globalLatest.IsZero() || ts.After(globalLatest) {
						globalLatest = ts
					}
				}
			}
			if err := sc.Err(); err != nil && !errors.Is(err, io.EOF) {
				_ = zr.Close()
				_ = f.Close()
				return LogSummaryResult{}, fmt.Errorf("scan log batch: %w", err)
			}
			_ = zr.Close()
			_ = f.Close()
		}
		if deviceCount == 0 {
			continue
		}
		item := LogDeviceSummary{
			DeviceID: deviceID,
			Entries:  deviceCount,
		}
		if !deviceLatest.IsZero() {
			item.LatestTimestamp = deviceLatest.UTC().Format(time.RFC3339Nano)
		}
		result.ByDevice = append(result.ByDevice, item)
	}

	sort.Slice(result.ByDevice, func(i, j int) bool {
		return result.ByDevice[i].DeviceID < result.ByDevice[j].DeviceID
	})
	if !globalLatest.IsZero() {
		result.LatestTimestamp = globalLatest.UTC().Format(time.RFC3339Nano)
	}
	return result, nil
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

func normalizePolicyVersion(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if len(raw) > 128 {
		return ""
	}
	for _, r := range raw {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.', r == ':':
		default:
			return ""
		}
	}
	return raw
}

func parseStoreRFC3339Any(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false
	}
	if ts, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return ts.UTC(), true
	}
	if ts, err := time.Parse(time.RFC3339, raw); err == nil {
		return ts.UTC(), true
	}
	return time.Time{}, false
}

func normalizeStoreTimestamp(raw string) string {
	ts, ok := parseStoreRFC3339Any(raw)
	if !ok {
		return ""
	}
	return ts.Format(time.RFC3339Nano)
}

func normalizeUpstreamHealthStatus(raw string) string {
	switch strings.TrimSpace(strings.ToLower(raw)) {
	case "healthy":
		return "healthy"
	case "unhealthy":
		return "unhealthy"
	default:
		return ""
	}
}

func safePathComponent(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	out := strings.Builder{}
	for _, r := range raw {
		switch {
		case r >= 'a' && r <= 'z':
			out.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			out.WriteRune(r)
		case r >= '0' && r <= '9':
			out.WriteRune(r)
		case r == '-', r == '_', r == '.':
			out.WriteRune(r)
		default:
			out.WriteByte('_')
		}
	}
	return out.String()
}

func hashBytesHex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
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
	if s.backend == storageBackendSQLite {
		return s.saveSQLiteSnapshotLocked()
	}
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
	policies := make([]PolicyRecord, 0, len(s.policies))
	for _, rec := range s.policies {
		policies = append(policies, rec)
	}
	sort.Slice(policies, func(i, j int) bool {
		return policies[i].Version < policies[j].Version
	})
	releases := make([]ReleaseRecord, 0, len(s.releases))
	for _, rec := range s.releases {
		releases = append(releases, rec)
	}
	sort.Slice(releases, func(i, j int) bool {
		return releases[i].Version < releases[j].Version
	})
	payload := storedDevices{Devices: devices, Policies: policies, Releases: releases}
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
