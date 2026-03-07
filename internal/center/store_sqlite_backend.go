package center

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

func (s *deviceStore) loadSQLiteIntoMemory() error {
	if s.db == nil {
		return fmt.Errorf("sqlite db is nil")
	}

	if err := s.loadSQLiteDevices(); err != nil {
		return err
	}
	if err := s.loadSQLitePolicies(); err != nil {
		return err
	}
	if err := s.loadSQLiteReleases(); err != nil {
		return err
	}
	return nil
}

func (s *deviceStore) loadSQLiteDevices() error {
	rows, err := s.db.Query(`SELECT record_json FROM devices ORDER BY device_id`)
	if err != nil {
		return fmt.Errorf("query sqlite devices: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return fmt.Errorf("scan sqlite devices: %w", err)
		}
		var rec DeviceRecord
		if err := json.Unmarshal([]byte(raw), &rec); err != nil {
			continue
		}
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
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate sqlite devices: %w", err)
	}
	return nil
}

func (s *deviceStore) loadSQLitePolicies() error {
	rows, err := s.db.Query(`SELECT record_json FROM policies ORDER BY version`)
	if err != nil {
		return fmt.Errorf("query sqlite policies: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return fmt.Errorf("scan sqlite policies: %w", err)
		}
		var rec PolicyRecord
		if err := json.Unmarshal([]byte(raw), &rec); err != nil {
			continue
		}
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
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate sqlite policies: %w", err)
	}
	return nil
}

func (s *deviceStore) loadSQLiteReleases() error {
	rows, err := s.db.Query(`SELECT record_json FROM releases ORDER BY version`)
	if err != nil {
		return fmt.Errorf("query sqlite releases: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return fmt.Errorf("scan sqlite releases: %w", err)
		}
		var rec ReleaseRecord
		if err := json.Unmarshal([]byte(raw), &rec); err != nil {
			continue
		}
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
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate sqlite releases: %w", err)
	}
	return nil
}

func (s *deviceStore) saveSQLiteSnapshotLocked() error {
	if s.db == nil {
		return fmt.Errorf("sqlite db is nil")
	}

	devices := make([]DeviceRecord, 0, len(s.devices))
	for _, rec := range s.devices {
		devices = append(devices, rec)
	}
	sort.Slice(devices, func(i, j int) bool { return devices[i].DeviceID < devices[j].DeviceID })

	policies := make([]PolicyRecord, 0, len(s.policies))
	for _, rec := range s.policies {
		policies = append(policies, rec)
	}
	sort.Slice(policies, func(i, j int) bool { return policies[i].Version < policies[j].Version })

	releases := make([]ReleaseRecord, 0, len(s.releases))
	for _, rec := range s.releases {
		releases = append(releases, rec)
	}
	sort.Slice(releases, func(i, j int) bool { return releases[i].Version < releases[j].Version })

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin sqlite tx: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	if err := replaceSQLiteDeviceRows(tx, devices); err != nil {
		return err
	}
	if err := replaceSQLitePolicyRows(tx, policies); err != nil {
		return err
	}
	if err := replaceSQLiteReleaseRows(tx, releases); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit sqlite tx: %w", err)
	}
	return nil
}

func replaceSQLiteDeviceRows(tx *sql.Tx, devices []DeviceRecord) error {
	if _, err := tx.Exec(`DELETE FROM devices`); err != nil {
		return fmt.Errorf("delete sqlite devices: %w", err)
	}
	stmt, err := tx.Prepare(`
		INSERT INTO devices(
			device_id, public_key_fingerprint_sha256, key_id, record_json, created_at, updated_at
		) VALUES(?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("prepare sqlite device insert: %w", err)
	}
	defer stmt.Close()

	for _, rec := range devices {
		fingerprint := strings.ToLower(strings.TrimSpace(rec.PublicKeyFingerprintSHA256))
		keyID := strings.TrimSpace(rec.KeyID)
		if keyID == "" && fingerprint != "" {
			keyID = defaultKeyIDFromFingerprint(fingerprint)
		}
		createdAt := strings.TrimSpace(rec.EnrolledAt)
		if createdAt == "" {
			createdAt = strings.TrimSpace(rec.FirstSeenAt)
		}
		updatedAt := strings.TrimSpace(rec.LastSeenAt)
		if updatedAt == "" {
			updatedAt = createdAt
		}
		raw, err := json.Marshal(rec)
		if err != nil {
			return fmt.Errorf("marshal sqlite device json: %w", err)
		}
		if _, err := stmt.Exec(rec.DeviceID, fingerprint, keyID, string(raw), createdAt, updatedAt); err != nil {
			return fmt.Errorf("insert sqlite device: %w", err)
		}
	}
	return nil
}

func replaceSQLitePolicyRows(tx *sql.Tx, policies []PolicyRecord) error {
	if _, err := tx.Exec(`DELETE FROM policies`); err != nil {
		return fmt.Errorf("delete sqlite policies: %w", err)
	}
	stmt, err := tx.Prepare(`
		INSERT INTO policies(
			version, status, record_json, created_at, updated_at
		) VALUES(?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("prepare sqlite policy insert: %w", err)
	}
	defer stmt.Close()

	for _, rec := range policies {
		status := strings.TrimSpace(strings.ToLower(rec.Status))
		if status == "" {
			status = policyStatusApproved
		}
		createdAt := strings.TrimSpace(rec.CreatedAt)
		updatedAt := strings.TrimSpace(rec.UpdatedAt)
		if updatedAt == "" {
			updatedAt = createdAt
		}
		raw, err := json.Marshal(rec)
		if err != nil {
			return fmt.Errorf("marshal sqlite policy json: %w", err)
		}
		if _, err := stmt.Exec(rec.Version, status, string(raw), createdAt, updatedAt); err != nil {
			return fmt.Errorf("insert sqlite policy: %w", err)
		}
	}
	return nil
}

func replaceSQLiteReleaseRows(tx *sql.Tx, releases []ReleaseRecord) error {
	if _, err := tx.Exec(`DELETE FROM releases`); err != nil {
		return fmt.Errorf("delete sqlite releases: %w", err)
	}
	stmt, err := tx.Prepare(`
		INSERT INTO releases(
			version, status, record_json, created_at, updated_at
		) VALUES(?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("prepare sqlite release insert: %w", err)
	}
	defer stmt.Close()

	for _, rec := range releases {
		status := strings.TrimSpace(strings.ToLower(rec.Status))
		if status == "" {
			status = releaseStatusApproved
		}
		createdAt := strings.TrimSpace(rec.CreatedAt)
		updatedAt := strings.TrimSpace(rec.UpdatedAt)
		if updatedAt == "" {
			updatedAt = createdAt
		}
		raw, err := json.Marshal(rec)
		if err != nil {
			return fmt.Errorf("marshal sqlite release json: %w", err)
		}
		if _, err := stmt.Exec(rec.Version, status, string(raw), createdAt, updatedAt); err != nil {
			return fmt.Errorf("insert sqlite release: %w", err)
		}
	}
	return nil
}
