package center

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	adminroutes "github.com/vril/mamotama-center/internal/center/http/admin"
	edgeroutes "github.com/vril/mamotama-center/internal/center/http/edge"
)

type Server struct {
	cfg        Config
	logger     *log.Logger
	store      *deviceStore
	nonceCache *nonceReplayCache
	nowFn      func() time.Time
	mux        *http.ServeMux
}

type nonceReplayCache struct {
	mu       sync.Mutex
	ttl      time.Duration
	maxItems int
	byDevice map[string]map[string]time.Time
}

type enrollRequest struct {
	DeviceID                   string `json:"device_id"`
	KeyID                      string `json:"key_id,omitempty"`
	PublicKeyPEMBase64         string `json:"public_key_pem_b64"`
	PublicKeyFingerprintSHA256 string `json:"public_key_fingerprint_sha256,omitempty"`
	BodyHash                   string `json:"body_hash"`
	Nonce                      string `json:"nonce,omitempty"`
	Timestamp                  string `json:"timestamp,omitempty"`
	SignatureB64               string `json:"signature_b64,omitempty"`
}

type heartbeatRequest struct {
	DeviceID             string `json:"device_id"`
	KeyID                string `json:"key_id"`
	Timestamp            string `json:"timestamp"`
	Nonce                string `json:"nonce"`
	StatusHash           string `json:"status_hash,omitempty"`
	CurrentPolicyVersion string `json:"current_policy_version,omitempty"`
	CurrentPolicySHA256  string `json:"current_policy_sha256,omitempty"`
	BodyHash             string `json:"body_hash"`
	SignatureB64         string `json:"signature_b64"`
}

type policyUpsertRequest struct {
	Version        string   `json:"version"`
	SHA256         string   `json:"sha256,omitempty"`
	WAFRaw         string   `json:"waf_raw,omitempty"`
	WAFRawTemplate string   `json:"waf_raw_template,omitempty"`
	WAFRuleFiles   []string `json:"waf_rule_files,omitempty"`
	BundleTGZB64   string   `json:"bundle_tgz_b64,omitempty"`
	BundleSHA256   string   `json:"bundle_sha256,omitempty"`
	Note           string   `json:"note,omitempty"`
}

type releaseUpsertRequest struct {
	Version   string `json:"version"`
	Platform  string `json:"platform"`
	SHA256    string `json:"sha256,omitempty"`
	BinaryB64 string `json:"binary_b64,omitempty"`
	Note      string `json:"note,omitempty"`
}

type bundleInspectRequest struct {
	BundleTGZB64 string `json:"bundle_tgz_b64"`
	BundleSHA256 string `json:"bundle_sha256,omitempty"`
}

type policyAssignRequest struct {
	Version string `json:"version"`
}

type releaseAssignRequest struct {
	Version string `json:"version"`
	ApplyAt string `json:"apply_at,omitempty"`
}

type policyPullRequest struct {
	DeviceID             string `json:"device_id"`
	KeyID                string `json:"key_id"`
	Timestamp            string `json:"timestamp"`
	Nonce                string `json:"nonce"`
	CurrentPolicyVersion string `json:"current_policy_version,omitempty"`
	CurrentPolicySHA256  string `json:"current_policy_sha256,omitempty"`
	BodyHash             string `json:"body_hash"`
	SignatureB64         string `json:"signature_b64"`
}

type policyAckRequest struct {
	DeviceID      string `json:"device_id"`
	KeyID         string `json:"key_id"`
	Timestamp     string `json:"timestamp"`
	Nonce         string `json:"nonce"`
	PolicyVersion string `json:"policy_version"`
	PolicySHA256  string `json:"policy_sha256,omitempty"`
	ResultStatus  string `json:"result_status"`
	Message       string `json:"message,omitempty"`
	BodyHash      string `json:"body_hash"`
	SignatureB64  string `json:"signature_b64"`
}

type releasePullRequest struct {
	DeviceID              string `json:"device_id"`
	KeyID                 string `json:"key_id"`
	Timestamp             string `json:"timestamp"`
	Nonce                 string `json:"nonce"`
	CurrentReleaseVersion string `json:"current_release_version,omitempty"`
	CurrentReleaseSHA256  string `json:"current_release_sha256,omitempty"`
	BodyHash              string `json:"body_hash"`
	SignatureB64          string `json:"signature_b64"`
}

type releaseAckRequest struct {
	DeviceID       string `json:"device_id"`
	KeyID          string `json:"key_id"`
	Timestamp      string `json:"timestamp"`
	Nonce          string `json:"nonce"`
	ReleaseVersion string `json:"release_version"`
	ReleaseSHA256  string `json:"release_sha256,omitempty"`
	ResultStatus   string `json:"result_status"`
	Message        string `json:"message,omitempty"`
	BodyHash       string `json:"body_hash"`
	SignatureB64   string `json:"signature_b64"`
}

type logsPushRequest struct {
	DeviceID        string `json:"device_id"`
	KeyID           string `json:"key_id"`
	Timestamp       string `json:"timestamp"`
	Nonce           string `json:"nonce"`
	EntryCount      int    `json:"entry_count"`
	ContentSHA256   string `json:"content_sha256,omitempty"`
	ContentEncoding string `json:"content_encoding,omitempty"`
	PayloadB64      string `json:"payload_b64"`
	BodyHash        string `json:"body_hash"`
	SignatureB64    string `json:"signature_b64"`
}

type retireRequest struct {
	Reason string `json:"reason,omitempty"`
}

type revokeKeyRequest struct {
	KeyID  string `json:"key_id,omitempty"`
	Reason string `json:"reason,omitempty"`
}

type deviceStatusView struct {
	DeviceRecord
	Status               string `json:"status"`
	Flagged              bool   `json:"flagged"`
	HasHeartbeat         bool   `json:"has_heartbeat"`
	SecondsSinceLastSeen int64  `json:"seconds_since_last_seen"`
}

func NewServer(cfg Config, logger *log.Logger) (*Server, error) {
	store, err := loadDeviceStore(cfg.Storage)
	if err != nil {
		return nil, fmt.Errorf("load device store: %w", err)
	}
	s := &Server{
		cfg:        cfg,
		logger:     logger,
		store:      store,
		nonceCache: newNonceReplayCache(cfg.Auth.NonceTTL.Duration, cfg.Auth.MaxNoncesPerDevice),
		nowFn:      time.Now,
		mux:        http.NewServeMux(),
	}
	s.routes()
	return s, nil
}

func (s *Server) Handler() http.Handler {
	return s.mux
}

func (s *Server) routes() {
	s.mux.HandleFunc("/healthz", s.handleHealthz)
	edgeroutes.Register(s.mux, edgeroutes.Handlers{
		Enroll:      s.handleEnroll,
		Heartbeat:   s.handleHeartbeat,
		PolicyPull:  s.handlePolicyPull,
		PolicyAck:   s.handlePolicyAck,
		ReleasePull: s.handleReleasePull,
		ReleaseAck:  s.handleReleaseAck,
		LogsPush:    s.handleLogsPush,
	})
	adminroutes.Register(s.mux, adminroutes.Handlers{
		Policies:       s.handlePolicies,
		PolicyTools:    s.handlePolicyTools,
		PolicyByID:     s.handlePolicyByVersion,
		Releases:       s.handleReleases,
		ReleaseByID:    s.handleReleaseByVersion,
		Devices:        s.handleDevices,
		DeviceByID:     s.handleDevice,
		LogDevices:     s.handleAdminLogDevices,
		LogEntries:     s.handleAdminLogs,
		LogSummary:     s.handleAdminLogsSummary,
		LogDownload:    s.handleAdminLogsDownload,
		LogUI:          s.handleAdminLogsUI,
		LogUIAssets:    s.handleAdminLogsUIAssets,
		DeviceUI:       s.handleAdminDevicesUI,
		DeviceUIAssets: s.handleAdminDevicesUIAssets,
	})
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.ensureSecureTransport(w, r) {
		return
	}
	if !s.hasValidLicense(r.Header.Get("X-License-Key")) {
		writeError(w, http.StatusUnauthorized, "invalid license key")
		return
	}

	var req enrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json payload")
		return
	}
	req.DeviceID = strings.TrimSpace(req.DeviceID)
	req.KeyID = strings.TrimSpace(req.KeyID)
	req.PublicKeyPEMBase64 = strings.TrimSpace(req.PublicKeyPEMBase64)
	req.PublicKeyFingerprintSHA256 = strings.ToLower(strings.TrimSpace(req.PublicKeyFingerprintSHA256))
	req.BodyHash = strings.ToLower(strings.TrimSpace(req.BodyHash))
	req.Nonce = strings.TrimSpace(req.Nonce)
	req.Timestamp = strings.TrimSpace(req.Timestamp)
	req.SignatureB64 = strings.TrimSpace(req.SignatureB64)
	if req.DeviceID == "" || req.KeyID == "" || req.PublicKeyPEMBase64 == "" || req.PublicKeyFingerprintSHA256 == "" || req.BodyHash == "" || req.Nonce == "" || req.Timestamp == "" || req.SignatureB64 == "" {
		writeError(w, http.StatusBadRequest, "device_id, key_id, public_key_pem_b64, public_key_fingerprint_sha256, timestamp, nonce, body_hash, and signature_b64 are required")
		return
	}
	if !isValidKeyID(req.KeyID) {
		writeError(w, http.StatusBadRequest, "key_id is invalid")
		return
	}
	msgTS, ok := parseRFC3339Any(req.Timestamp)
	if !ok {
		writeError(w, http.StatusBadRequest, "timestamp must be RFC3339")
		return
	}

	fingerprint, err := validatePublicKeyPEMBase64(req.PublicKeyPEMBase64)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid public key")
		return
	}
	if req.PublicKeyFingerprintSHA256 != fingerprint {
		writeError(w, http.StatusUnprocessableEntity, "public key fingerprint mismatch")
		return
	}
	if !secureTextEqual(req.BodyHash, hashStringHex(enrollBodyCanonical(req))) {
		writeError(w, http.StatusUnauthorized, "body_hash mismatch")
		return
	}

	signature, err := base64.StdEncoding.DecodeString(req.SignatureB64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "signature_b64 is invalid base64")
		return
	}
	pub, err := parseEd25519PublicKeyFromBase64PEM(req.PublicKeyPEMBase64)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid public key")
		return
	}
	if !ed25519.Verify(pub, []byte(signedEnvelopeMessage(req.DeviceID, req.KeyID, req.Timestamp, req.Nonce, req.BodyHash)), signature) {
		writeError(w, http.StatusUnauthorized, "invalid enroll signature")
		return
	}

	now := s.nowFn().UTC()
	if !withinSkew(now, msgTS.UTC(), s.cfg.Heartbeat.MaxClockSkew.Duration) {
		writeError(w, http.StatusUnauthorized, "timestamp out of allowed skew")
		return
	}

	if existingByFP, fpExists := s.store.findByFingerprint(fingerprint); fpExists && existingByFP.DeviceID != req.DeviceID {
		writeError(w, http.StatusConflict, "public key already bound to another device_id")
		return
	}
	if s.nonceCache.remember("enroll", req.DeviceID, req.Nonce, now) {
		writeError(w, http.StatusConflict, "reused enroll nonce")
		return
	}

	addr := remoteAddressOnly(r.RemoteAddr)
	current, exists := s.store.get(req.DeviceID)
	if exists && current.LastEnrollMessageAt != "" {
		lastTS, parsed := parseRFC3339Any(current.LastEnrollMessageAt)
		if parsed && !msgTS.UTC().After(lastTS.UTC()) {
			writeError(w, http.StatusConflict, "stale or replayed enroll request")
			return
		}
	}
	rotated := false
	reactivated := exists && strings.TrimSpace(current.RetiredAt) != ""
	if exists && (current.KeyID == "" || current.PublicKeyPEMBase64 == "" || current.PublicKeyFingerprintSHA256 == "") {
		if !allowKeyRotation(r.Header.Get("X-Allow-Key-Rotation")) {
			writeError(w, http.StatusConflict, "device key is revoked (set X-Allow-Key-Rotation: true to activate a new key)")
			return
		}
		rotated = true
	}
	if exists && !rotated && (current.KeyID != req.KeyID || current.PublicKeyPEMBase64 != req.PublicKeyPEMBase64) {
		if !allowKeyRotation(r.Header.Get("X-Allow-Key-Rotation")) {
			writeError(w, http.StatusConflict, "key mismatch for existing device_id (set X-Allow-Key-Rotation: true to rotate)")
			return
		}
		rotated = true
	}

	keyVersion := 1
	firstSeenAt := now.Format(time.RFC3339Nano)
	revokedKeys := []RevokedKeyRecord(nil)
	if exists {
		if strings.TrimSpace(current.FirstSeenAt) != "" {
			firstSeenAt = current.FirstSeenAt
		}
		keyVersion = current.KeyVersion
		if keyVersion == 0 {
			keyVersion = 1
		}
		if len(current.RevokedKeys) > 0 {
			revokedKeys = append(revokedKeys, current.RevokedKeys...)
		}
		if rotated {
			if current.KeyID != "" && current.PublicKeyPEMBase64 != "" && current.PublicKeyFingerprintSHA256 != "" {
				revokedKeys = append(revokedKeys, RevokedKeyRecord{
					KeyID:                      current.KeyID,
					PublicKeyPEMBase64:         current.PublicKeyPEMBase64,
					PublicKeyFingerprintSHA256: current.PublicKeyFingerprintSHA256,
					RevokedAt:                  now.Format(time.RFC3339Nano),
					Reason:                     "rotated",
				})
			}
			keyVersion++
			s.logger.Printf(`{"level":"warn","msg":"public key rotated","device_id":"%s","from_key_id":"%s","to_key_id":"%s","remote_addr":"%s"}`, req.DeviceID, current.KeyID, req.KeyID, addr)
		}
	}

	rec := DeviceRecord{
		DeviceID:                   req.DeviceID,
		KeyID:                      req.KeyID,
		KeyVersion:                 keyVersion,
		PublicKeyPEMBase64:         req.PublicKeyPEMBase64,
		PublicKeyFingerprintSHA256: fingerprint,
		RevokedKeys:                revokedKeys,
		FirstSeenAt:                firstSeenAt,
		LastSeenAt:                 now.Format(time.RFC3339Nano),
		EnrolledAt:                 now.Format(time.RFC3339Nano),
		LastEnrollMessageAt:        msgTS.UTC().Format(time.RFC3339Nano),
		LastEnrollNonce:            req.Nonce,
		LastEnrollIP:               addr,
	}
	saved, err := s.store.upsertEnroll(rec)
	if err != nil {
		s.logger.Printf(`{"level":"error","msg":"persist enroll failed","device_id":"%s","error":"%s"}`, req.DeviceID, err)
		writeError(w, http.StatusInternalServerError, "failed to persist enrollment")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":        "ok",
		"device_id":     saved.DeviceID,
		"key_id":        saved.KeyID,
		"key_version":   saved.KeyVersion,
		"enrolled_at":   saved.EnrolledAt,
		"fingerprint":   saved.PublicKeyFingerprintSHA256,
		"already_known": exists,
		"rotated":       rotated,
		"reactivated":   reactivated,
		"device_status": s.buildDeviceStatus(saved, now),
	})
}

func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.ensureSecureTransport(w, r) {
		return
	}

	var req heartbeatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json payload")
		return
	}
	req.DeviceID = strings.TrimSpace(req.DeviceID)
	req.KeyID = strings.TrimSpace(req.KeyID)
	req.Timestamp = strings.TrimSpace(req.Timestamp)
	req.Nonce = strings.TrimSpace(req.Nonce)
	req.BodyHash = strings.ToLower(strings.TrimSpace(req.BodyHash))
	req.SignatureB64 = strings.TrimSpace(req.SignatureB64)
	req.StatusHash = strings.TrimSpace(req.StatusHash)
	req.CurrentPolicyVersion = normalizePolicyVersion(req.CurrentPolicyVersion)
	req.CurrentPolicySHA256 = strings.ToLower(strings.TrimSpace(req.CurrentPolicySHA256))
	if req.DeviceID == "" || req.KeyID == "" || req.Timestamp == "" || req.Nonce == "" || req.BodyHash == "" || req.SignatureB64 == "" {
		writeError(w, http.StatusBadRequest, "device_id, key_id, timestamp, nonce, body_hash, and signature_b64 are required")
		return
	}
	if !isValidKeyID(req.KeyID) {
		writeError(w, http.StatusBadRequest, "key_id is invalid")
		return
	}

	rec, ok := s.store.get(req.DeviceID)
	if !ok {
		writeError(w, http.StatusNotFound, "device is not enrolled")
		return
	}
	if strings.TrimSpace(rec.RetiredAt) != "" {
		writeError(w, http.StatusGone, "device is retired")
		return
	}
	if strings.TrimSpace(rec.KeyID) == "" || strings.TrimSpace(rec.PublicKeyPEMBase64) == "" {
		writeError(w, http.StatusGone, "device key is revoked")
		return
	}
	if rec.KeyID != req.KeyID {
		writeError(w, http.StatusUnauthorized, "key_id mismatch")
		return
	}

	msgTS, ok := parseRFC3339Any(req.Timestamp)
	if !ok {
		writeError(w, http.StatusBadRequest, "timestamp must be RFC3339")
		return
	}
	now := s.nowFn().UTC()
	if !withinSkew(now, msgTS.UTC(), s.cfg.Heartbeat.MaxClockSkew.Duration) {
		writeError(w, http.StatusUnauthorized, "timestamp out of allowed skew")
		return
	}

	if rec.LastHeartbeatMessageAt != "" {
		lastTS, parsed := parseRFC3339Any(rec.LastHeartbeatMessageAt)
		if parsed && !msgTS.UTC().After(lastTS.UTC()) {
			writeError(w, http.StatusConflict, "stale or replayed heartbeat")
			return
		}
	}
	if s.nonceCache.remember("heartbeat", req.DeviceID, req.Nonce, now) {
		writeError(w, http.StatusConflict, "reused heartbeat nonce")
		return
	}
	if !secureTextEqual(req.BodyHash, hashStringHex(heartbeatBodyCanonical(req))) {
		writeError(w, http.StatusUnauthorized, "body_hash mismatch")
		return
	}

	pub, err := parseEd25519PublicKeyFromBase64PEM(rec.PublicKeyPEMBase64)
	if err != nil {
		s.logger.Printf(`{"level":"error","msg":"stored public key decode failed","device_id":"%s","error":"%s"}`, req.DeviceID, err)
		writeError(w, http.StatusInternalServerError, "stored key is invalid")
		return
	}
	signature, err := base64.StdEncoding.DecodeString(req.SignatureB64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "signature_b64 is invalid base64")
		return
	}
	message := signedEnvelopeMessage(req.DeviceID, req.KeyID, req.Timestamp, req.Nonce, req.BodyHash)
	if !ed25519.Verify(pub, []byte(message), signature) {
		writeError(w, http.StatusUnauthorized, "invalid heartbeat signature")
		return
	}

	saved, err := s.store.updateHeartbeat(req.DeviceID, now, msgTS.UTC(), req.Nonce, req.StatusHash, req.CurrentPolicyVersion, req.CurrentPolicySHA256)
	if err != nil {
		s.logger.Printf(`{"level":"error","msg":"persist heartbeat failed","device_id":"%s","error":"%s"}`, req.DeviceID, err)
		writeError(w, http.StatusInternalServerError, "failed to persist heartbeat")
		return
	}
	updateRequired := saved.DesiredPolicyVersion != "" && (saved.CurrentPolicyVersion != saved.DesiredPolicyVersion || !secureTextEqual(saved.CurrentPolicySHA256, saved.DesiredPolicySHA256))
	releaseReady := releaseScheduleReached(saved.DesiredReleaseNotBeforeAt, now)
	releaseUpdateRequired := saved.DesiredReleaseVersion != "" && releaseReady && (saved.CurrentReleaseVersion != saved.DesiredReleaseVersion || !secureTextEqual(saved.CurrentReleaseSHA256, saved.DesiredReleaseSHA256))
	policy := map[string]any{
		"desired_version":  saved.DesiredPolicyVersion,
		"desired_sha256":   saved.DesiredPolicySHA256,
		"desired_assigned": saved.DesiredPolicyAssignedAt,
		"current_version":  saved.CurrentPolicyVersion,
		"current_sha256":   saved.CurrentPolicySHA256,
		"last_sync_at":     saved.LastPolicySyncAt,
		"update_required":  updateRequired,
		"fetch_path":       "",
	}
	if updateRequired {
		policy["fetch_path"] = "/v1/policy/pull"
	}
	release := map[string]any{
		"desired_version":    saved.DesiredReleaseVersion,
		"desired_sha256":     saved.DesiredReleaseSHA256,
		"desired_assigned":   saved.DesiredReleaseAssignedAt,
		"desired_not_before": saved.DesiredReleaseNotBeforeAt,
		"update_ready":       releaseReady,
		"current_version":    saved.CurrentReleaseVersion,
		"current_sha256":     saved.CurrentReleaseSHA256,
		"last_sync_at":       saved.LastReleaseSyncAt,
		"update_required":    releaseUpdateRequired,
		"fetch_path":         "",
	}
	if releaseUpdateRequired {
		release["fetch_path"] = "/v1/release/pull"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":            "ok",
		"device_id":         saved.DeviceID,
		"last_heartbeat_at": saved.LastHeartbeatAt,
		"device_status":     s.buildDeviceStatus(saved, now),
		"policy":            policy,
		"release":           release,
	})
}

func (s *Server) handlePolicies(w http.ResponseWriter, r *http.Request) {
	if !s.ensureSecureTransport(w, r) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		if !s.requireAdminRead(w, r) {
			return
		}
		policies := s.store.listPolicies()
		devices := s.store.list()
		assigned := make(map[string]int, len(policies))
		applied := make(map[string]int, len(policies))
		for _, rec := range devices {
			if rec.DesiredPolicyVersion != "" {
				assigned[rec.DesiredPolicyVersion]++
			}
			if rec.CurrentPolicyVersion != "" {
				applied[rec.CurrentPolicyVersion]++
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"policies": policies,
			"summary": map[string]any{
				"count":               len(policies),
				"assigned_by_version": assigned,
				"applied_by_version":  applied,
			},
		})
	case http.MethodPost:
		if !s.requireAdminWrite(w, r) {
			return
		}
		var req policyUpsertRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json payload")
			return
		}
		wafRaw, err := resolvePolicyWAFRaw(req.WAFRaw, req.WAFRawTemplate, req.WAFRuleFiles, req.BundleTGZB64, req.BundleSHA256)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		now := s.nowFn().UTC()
		pol, err := s.store.upsertPolicy(PolicyRecord{
			Version:      req.Version,
			SHA256:       req.SHA256,
			WAFRaw:       wafRaw,
			BundleTGZB64: req.BundleTGZB64,
			BundleSHA256: req.BundleSHA256,
			Note:         req.Note,
		}, now)
		if err != nil {
			switch {
			case errors.Is(err, errStoreConflict):
				writeError(w, http.StatusConflict, "policy version already exists with different content")
			case errors.Is(err, errStoreInvalid):
				writeError(w, http.StatusUnprocessableEntity, "invalid policy payload")
			default:
				s.logger.Printf(`{"level":"error","msg":"persist policy failed","version":"%s","error":"%s"}`, strings.TrimSpace(req.Version), err)
				writeError(w, http.StatusInternalServerError, "failed to persist policy")
			}
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "ok",
			"policy": pol,
		})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handlePolicyByVersion(w http.ResponseWriter, r *http.Request) {
	if !s.ensureSecureTransport(w, r) {
		return
	}
	version, action, ok := parsePolicyVersionPath(r.URL.Path)
	if !ok {
		writeError(w, http.StatusBadRequest, "policy version is required in path")
		return
	}
	if action == "approve" {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if !s.requireAdminWrite(w, r) {
			return
		}
		pol, err := s.store.approvePolicy(version, s.nowFn().UTC())
		if err != nil {
			switch {
			case errors.Is(err, os.ErrNotExist):
				writeError(w, http.StatusNotFound, "policy not found")
			case errors.Is(err, errStoreInvalid):
				writeError(w, http.StatusBadRequest, "policy version is invalid")
			default:
				s.logger.Printf(`{"level":"error","msg":"policy approve failed","version":"%s","error":"%s"}`, version, err)
				writeError(w, http.StatusInternalServerError, "failed to approve policy")
			}
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "ok",
			"policy": pol,
		})
		return
	}
	switch r.Method {
	case http.MethodGet:
		if !s.requireAdminRead(w, r) {
			return
		}
		pol, found := s.store.getPolicy(version)
		if !found {
			writeError(w, http.StatusNotFound, "policy not found")
			return
		}
		devices := s.store.list()
		var desired, current int
		for _, rec := range devices {
			if rec.DesiredPolicyVersion == pol.Version {
				desired++
			}
			if rec.CurrentPolicyVersion == pol.Version {
				current++
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"policy": pol,
			"usage": map[string]any{
				"desired_device_count": desired,
				"current_device_count": current,
			},
		})
	case http.MethodPut:
		if !s.requireAdminWrite(w, r) {
			return
		}
		var req policyUpsertRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json payload")
			return
		}
		req.Version = strings.TrimSpace(req.Version)
		if req.Version != "" && normalizePolicyVersion(req.Version) != version {
			writeError(w, http.StatusBadRequest, "version in body must match version in path")
			return
		}
		templateBundleB64 := req.BundleTGZB64
		if strings.TrimSpace(templateBundleB64) == "" && strings.TrimSpace(req.WAFRawTemplate) != "" {
			if existing, ok := s.store.getPolicy(version); ok {
				templateBundleB64 = existing.BundleTGZB64
			}
		}
		templateBundleSHA := req.BundleSHA256
		if strings.TrimSpace(templateBundleSHA) == "" && strings.TrimSpace(req.WAFRawTemplate) != "" {
			if existing, ok := s.store.getPolicy(version); ok {
				templateBundleSHA = existing.BundleSHA256
			}
		}
		wafRaw, err := resolvePolicyWAFRaw(req.WAFRaw, req.WAFRawTemplate, req.WAFRuleFiles, templateBundleB64, templateBundleSHA)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		pol, err := s.store.putPolicy(PolicyRecord{
			Version:      version,
			SHA256:       req.SHA256,
			WAFRaw:       wafRaw,
			BundleTGZB64: req.BundleTGZB64,
			BundleSHA256: req.BundleSHA256,
			Note:         req.Note,
		}, s.nowFn().UTC())
		if err != nil {
			switch {
			case errors.Is(err, errStoreInvalid):
				writeError(w, http.StatusUnprocessableEntity, "invalid policy payload")
			case errors.Is(err, errStoreInUse):
				writeError(w, http.StatusConflict, "policy is in use and cannot be overwritten")
			default:
				s.logger.Printf(`{"level":"error","msg":"policy put failed","version":"%s","error":"%s"}`, version, err)
				writeError(w, http.StatusInternalServerError, "failed to put policy")
			}
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "ok",
			"policy": pol,
		})
	case http.MethodDelete:
		if !s.requireAdminWrite(w, r) {
			return
		}
		err := s.store.deletePolicy(version)
		if err != nil {
			switch {
			case errors.Is(err, os.ErrNotExist):
				writeError(w, http.StatusNotFound, "policy not found")
			case errors.Is(err, errStoreInvalid):
				writeError(w, http.StatusBadRequest, "policy version is invalid")
			case errors.Is(err, errStoreInUse):
				writeError(w, http.StatusConflict, "policy is in use and cannot be deleted")
			default:
				s.logger.Printf(`{"level":"error","msg":"policy delete failed","version":"%s","error":"%s"}`, version, err)
				writeError(w, http.StatusInternalServerError, "failed to delete policy")
			}
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"status":  "ok",
			"version": version,
			"deleted": true,
		})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleReleases(w http.ResponseWriter, r *http.Request) {
	if !s.ensureSecureTransport(w, r) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		if !s.requireAdminRead(w, r) {
			return
		}
		releases := s.store.listReleases()
		devices := s.store.list()
		assigned := make(map[string]int, len(releases))
		applied := make(map[string]int, len(releases))
		for _, rec := range devices {
			if rec.DesiredReleaseVersion != "" {
				assigned[rec.DesiredReleaseVersion]++
			}
			if rec.CurrentReleaseVersion != "" {
				applied[rec.CurrentReleaseVersion]++
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"releases": releases,
			"summary": map[string]any{
				"count":               len(releases),
				"assigned_by_version": assigned,
				"applied_by_version":  applied,
			},
		})
	case http.MethodPost:
		if !s.requireAdminWrite(w, r) {
			return
		}
		var req releaseUpsertRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json payload")
			return
		}
		now := s.nowFn().UTC()
		rel, err := s.store.upsertRelease(ReleaseRecord{
			Version:   req.Version,
			Platform:  req.Platform,
			SHA256:    req.SHA256,
			BinaryB64: req.BinaryB64,
			Note:      req.Note,
		}, now)
		if err != nil {
			switch {
			case errors.Is(err, errStoreConflict):
				writeError(w, http.StatusConflict, "release version already exists with different content")
			case errors.Is(err, errStoreInvalid):
				writeError(w, http.StatusUnprocessableEntity, "invalid release payload")
			default:
				s.logger.Printf(`{"level":"error","msg":"persist release failed","version":"%s","error":"%s"}`, strings.TrimSpace(req.Version), err)
				writeError(w, http.StatusInternalServerError, "failed to persist release")
			}
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"status":  "ok",
			"release": rel,
		})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleReleaseByVersion(w http.ResponseWriter, r *http.Request) {
	if !s.ensureSecureTransport(w, r) {
		return
	}
	version, action, ok := parseReleaseVersionPath(r.URL.Path)
	if !ok {
		writeError(w, http.StatusBadRequest, "release version is required in path")
		return
	}
	if action == "approve" {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if !s.requireAdminWrite(w, r) {
			return
		}
		rel, err := s.store.approveRelease(version, s.nowFn().UTC())
		if err != nil {
			switch {
			case errors.Is(err, os.ErrNotExist):
				writeError(w, http.StatusNotFound, "release not found")
			case errors.Is(err, errStoreInvalid):
				writeError(w, http.StatusBadRequest, "release version is invalid")
			default:
				s.logger.Printf(`{"level":"error","msg":"release approve failed","version":"%s","error":"%s"}`, version, err)
				writeError(w, http.StatusInternalServerError, "failed to approve release")
			}
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"status":  "ok",
			"release": rel,
		})
		return
	}

	switch r.Method {
	case http.MethodGet:
		if !s.requireAdminRead(w, r) {
			return
		}
		rel, found := s.store.getRelease(version)
		if !found {
			writeError(w, http.StatusNotFound, "release not found")
			return
		}
		devices := s.store.list()
		var desired, current int
		for _, rec := range devices {
			if rec.DesiredReleaseVersion == rel.Version {
				desired++
			}
			if rec.CurrentReleaseVersion == rel.Version {
				current++
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"release": rel,
			"usage": map[string]any{
				"desired_device_count": desired,
				"current_device_count": current,
			},
		})
	case http.MethodPut:
		if !s.requireAdminWrite(w, r) {
			return
		}
		var req releaseUpsertRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json payload")
			return
		}
		req.Version = strings.TrimSpace(req.Version)
		if req.Version != "" && normalizePolicyVersion(req.Version) != version {
			writeError(w, http.StatusBadRequest, "version in body must match version in path")
			return
		}
		rel, err := s.store.putRelease(ReleaseRecord{
			Version:   version,
			Platform:  req.Platform,
			SHA256:    req.SHA256,
			BinaryB64: req.BinaryB64,
			Note:      req.Note,
		}, s.nowFn().UTC())
		if err != nil {
			switch {
			case errors.Is(err, errStoreInvalid):
				writeError(w, http.StatusUnprocessableEntity, "invalid release payload")
			case errors.Is(err, errStoreInUse):
				writeError(w, http.StatusConflict, "release is in use and cannot be overwritten")
			default:
				s.logger.Printf(`{"level":"error","msg":"release put failed","version":"%s","error":"%s"}`, version, err)
				writeError(w, http.StatusInternalServerError, "failed to put release")
			}
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"status":  "ok",
			"release": rel,
		})
	case http.MethodDelete:
		if !s.requireAdminWrite(w, r) {
			return
		}
		err := s.store.deleteRelease(version)
		if err != nil {
			switch {
			case errors.Is(err, os.ErrNotExist):
				writeError(w, http.StatusNotFound, "release not found")
			case errors.Is(err, errStoreInvalid):
				writeError(w, http.StatusBadRequest, "release version is invalid")
			case errors.Is(err, errStoreInUse):
				writeError(w, http.StatusConflict, "release is in use and cannot be deleted")
			default:
				s.logger.Printf(`{"level":"error","msg":"release delete failed","version":"%s","error":"%s"}`, version, err)
				writeError(w, http.StatusInternalServerError, "failed to delete release")
			}
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"status":  "ok",
			"version": version,
			"deleted": true,
		})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handlePolicyTools(w http.ResponseWriter, r *http.Request) {
	if !s.ensureSecureTransport(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.requireAdminWrite(w, r) {
		return
	}

	var req bundleInspectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json payload")
		return
	}
	confFiles, recommended, bundleSHA, err := inspectBundle(req.BundleTGZB64, req.BundleSHA256)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"bundle": map[string]any{
			"sha256":                 bundleSHA,
			"conf_files":             confFiles,
			"conf_count":             len(confFiles),
			"recommended_rule_files": recommended,
		},
	})
}

func (s *Server) handlePolicyPull(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.ensureSecureTransport(w, r) {
		return
	}
	var req policyPullRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json payload")
		return
	}
	req.DeviceID = strings.TrimSpace(req.DeviceID)
	req.KeyID = strings.TrimSpace(req.KeyID)
	req.Timestamp = strings.TrimSpace(req.Timestamp)
	req.Nonce = strings.TrimSpace(req.Nonce)
	req.CurrentPolicyVersion = normalizePolicyVersion(req.CurrentPolicyVersion)
	req.CurrentPolicySHA256 = strings.ToLower(strings.TrimSpace(req.CurrentPolicySHA256))
	req.BodyHash = strings.ToLower(strings.TrimSpace(req.BodyHash))
	req.SignatureB64 = strings.TrimSpace(req.SignatureB64)
	if req.DeviceID == "" || req.KeyID == "" || req.Timestamp == "" || req.Nonce == "" || req.BodyHash == "" || req.SignatureB64 == "" {
		writeError(w, http.StatusBadRequest, "device_id, key_id, timestamp, nonce, body_hash, and signature_b64 are required")
		return
	}

	rec, _, now, ok := s.authenticateSignedDeviceRequest(
		w,
		"policy_pull",
		req.DeviceID,
		req.KeyID,
		req.Timestamp,
		req.Nonce,
		req.BodyHash,
		req.SignatureB64,
		policyPullBodyCanonical(req),
	)
	if !ok {
		return
	}

	updateRequired := rec.DesiredPolicyVersion != "" && (rec.CurrentPolicyVersion != rec.DesiredPolicyVersion || !secureTextEqual(rec.CurrentPolicySHA256, rec.DesiredPolicySHA256))
	if !updateRequired {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":          "ok",
			"device_id":       rec.DeviceID,
			"update_required": false,
			"policy": map[string]any{
				"desired_version": rec.DesiredPolicyVersion,
				"desired_sha256":  rec.DesiredPolicySHA256,
				"current_version": rec.CurrentPolicyVersion,
				"current_sha256":  rec.CurrentPolicySHA256,
			},
			"device_status": s.buildDeviceStatus(rec, now),
		})
		return
	}
	pol, found := s.store.getPolicy(rec.DesiredPolicyVersion)
	if !found {
		writeError(w, http.StatusConflict, "assigned policy is missing")
		return
	}
	if pol.Status != policyStatusApproved {
		writeError(w, http.StatusConflict, "assigned policy is not approved")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":          "ok",
		"device_id":       rec.DeviceID,
		"update_required": true,
		"policy": map[string]any{
			"version":        pol.Version,
			"sha256":         pol.SHA256,
			"waf_raw":        pol.WAFRaw,
			"bundle_tgz_b64": pol.BundleTGZB64,
			"bundle_sha256":  pol.BundleSHA256,
			"note":           pol.Note,
			"created_at":     pol.CreatedAt,
			"updated_at":     pol.UpdatedAt,
			"assigned_at":    rec.DesiredPolicyAssignedAt,
			"current_seen":   rec.CurrentPolicyVersion,
		},
		"device_status": s.buildDeviceStatus(rec, now),
	})
}

func (s *Server) handlePolicyAck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.ensureSecureTransport(w, r) {
		return
	}
	var req policyAckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json payload")
		return
	}
	req.DeviceID = strings.TrimSpace(req.DeviceID)
	req.KeyID = strings.TrimSpace(req.KeyID)
	req.Timestamp = strings.TrimSpace(req.Timestamp)
	req.Nonce = strings.TrimSpace(req.Nonce)
	req.PolicyVersion = normalizePolicyVersion(req.PolicyVersion)
	req.PolicySHA256 = strings.ToLower(strings.TrimSpace(req.PolicySHA256))
	req.ResultStatus = strings.ToLower(strings.TrimSpace(req.ResultStatus))
	req.Message = strings.TrimSpace(req.Message)
	req.BodyHash = strings.ToLower(strings.TrimSpace(req.BodyHash))
	req.SignatureB64 = strings.TrimSpace(req.SignatureB64)
	if req.DeviceID == "" || req.KeyID == "" || req.Timestamp == "" || req.Nonce == "" || req.BodyHash == "" || req.SignatureB64 == "" || req.ResultStatus == "" {
		writeError(w, http.StatusBadRequest, "device_id, key_id, timestamp, nonce, result_status, body_hash, and signature_b64 are required")
		return
	}
	switch req.ResultStatus {
	case "applied", "failed", "rolled_back":
	default:
		writeError(w, http.StatusBadRequest, "result_status must be applied|failed|rolled_back")
		return
	}
	if len(req.Message) > 512 {
		writeError(w, http.StatusBadRequest, "message must be 512 chars or less")
		return
	}

	rec, _, now, ok := s.authenticateSignedDeviceRequest(
		w,
		"policy_ack",
		req.DeviceID,
		req.KeyID,
		req.Timestamp,
		req.Nonce,
		req.BodyHash,
		req.SignatureB64,
		policyAckBodyCanonical(req),
	)
	if !ok {
		return
	}

	if req.ResultStatus == "applied" {
		if req.PolicyVersion == "" || req.PolicySHA256 == "" {
			writeError(w, http.StatusBadRequest, "policy_version and policy_sha256 are required when result_status=applied")
			return
		}
		if rec.DesiredPolicyVersion != "" && req.PolicyVersion != rec.DesiredPolicyVersion {
			writeError(w, http.StatusConflict, "ack policy_version does not match desired policy")
			return
		}
		if rec.DesiredPolicySHA256 != "" && !secureTextEqual(req.PolicySHA256, rec.DesiredPolicySHA256) {
			writeError(w, http.StatusConflict, "ack policy_sha256 does not match desired policy")
			return
		}
	}

	saved, err := s.store.updatePolicyAck(req.DeviceID, req.PolicyVersion, req.PolicySHA256, req.ResultStatus, req.Message, now)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeError(w, http.StatusNotFound, "device is not enrolled")
			return
		}
		s.logger.Printf(`{"level":"error","msg":"persist policy ack failed","device_id":"%s","error":"%s"}`, req.DeviceID, err)
		writeError(w, http.StatusInternalServerError, "failed to persist policy ack")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":    "ok",
		"device_id": saved.DeviceID,
		"policy": map[string]any{
			"desired_version":  saved.DesiredPolicyVersion,
			"desired_sha256":   saved.DesiredPolicySHA256,
			"current_version":  saved.CurrentPolicyVersion,
			"current_sha256":   saved.CurrentPolicySHA256,
			"last_sync_at":     saved.LastPolicySyncAt,
			"last_ack_at":      saved.LastPolicyAckAt,
			"last_ack_status":  saved.LastPolicyAckStatus,
			"last_ack_message": saved.LastPolicyAckMessage,
		},
		"device_status": s.buildDeviceStatus(saved, now),
	})
}

func (s *Server) handleReleasePull(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.ensureSecureTransport(w, r) {
		return
	}
	var req releasePullRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json payload")
		return
	}
	req.DeviceID = strings.TrimSpace(req.DeviceID)
	req.KeyID = strings.TrimSpace(req.KeyID)
	req.Timestamp = strings.TrimSpace(req.Timestamp)
	req.Nonce = strings.TrimSpace(req.Nonce)
	req.CurrentReleaseVersion = normalizePolicyVersion(req.CurrentReleaseVersion)
	req.CurrentReleaseSHA256 = strings.ToLower(strings.TrimSpace(req.CurrentReleaseSHA256))
	req.BodyHash = strings.ToLower(strings.TrimSpace(req.BodyHash))
	req.SignatureB64 = strings.TrimSpace(req.SignatureB64)
	if req.DeviceID == "" || req.KeyID == "" || req.Timestamp == "" || req.Nonce == "" || req.BodyHash == "" || req.SignatureB64 == "" {
		writeError(w, http.StatusBadRequest, "device_id, key_id, timestamp, nonce, body_hash, and signature_b64 are required")
		return
	}

	rec, _, now, ok := s.authenticateSignedDeviceRequest(
		w,
		"release_pull",
		req.DeviceID,
		req.KeyID,
		req.Timestamp,
		req.Nonce,
		req.BodyHash,
		req.SignatureB64,
		releasePullBodyCanonical(req),
	)
	if !ok {
		return
	}
	releaseReady := releaseScheduleReached(rec.DesiredReleaseNotBeforeAt, now)
	updateRequired := rec.DesiredReleaseVersion != "" && releaseReady && (rec.CurrentReleaseVersion != rec.DesiredReleaseVersion || !secureTextEqual(rec.CurrentReleaseSHA256, rec.DesiredReleaseSHA256))
	if !updateRequired {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":          "ok",
			"device_id":       rec.DeviceID,
			"update_required": false,
			"release": map[string]any{
				"desired_version":    rec.DesiredReleaseVersion,
				"desired_sha256":     rec.DesiredReleaseSHA256,
				"desired_not_before": rec.DesiredReleaseNotBeforeAt,
				"update_ready":       releaseReady,
				"current_version":    rec.CurrentReleaseVersion,
				"current_sha256":     rec.CurrentReleaseSHA256,
			},
			"device_status": s.buildDeviceStatus(rec, now),
		})
		return
	}
	rel, found := s.store.getRelease(rec.DesiredReleaseVersion)
	if !found {
		writeError(w, http.StatusConflict, "assigned release is missing")
		return
	}
	if rel.Status != releaseStatusApproved {
		writeError(w, http.StatusConflict, "assigned release is not approved")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":          "ok",
		"device_id":       rec.DeviceID,
		"update_required": true,
		"release": map[string]any{
			"version":      rel.Version,
			"platform":     rel.Platform,
			"sha256":       rel.SHA256,
			"binary_b64":   rel.BinaryB64,
			"note":         rel.Note,
			"created_at":   rel.CreatedAt,
			"updated_at":   rel.UpdatedAt,
			"assigned_at":  rec.DesiredReleaseAssignedAt,
			"not_before":   rec.DesiredReleaseNotBeforeAt,
			"current_seen": rec.CurrentReleaseVersion,
		},
		"device_status": s.buildDeviceStatus(rec, now),
	})
}

func (s *Server) handleReleaseAck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.ensureSecureTransport(w, r) {
		return
	}
	var req releaseAckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json payload")
		return
	}
	req.DeviceID = strings.TrimSpace(req.DeviceID)
	req.KeyID = strings.TrimSpace(req.KeyID)
	req.Timestamp = strings.TrimSpace(req.Timestamp)
	req.Nonce = strings.TrimSpace(req.Nonce)
	req.ReleaseVersion = normalizePolicyVersion(req.ReleaseVersion)
	req.ReleaseSHA256 = strings.ToLower(strings.TrimSpace(req.ReleaseSHA256))
	req.ResultStatus = strings.ToLower(strings.TrimSpace(req.ResultStatus))
	req.Message = strings.TrimSpace(req.Message)
	req.BodyHash = strings.ToLower(strings.TrimSpace(req.BodyHash))
	req.SignatureB64 = strings.TrimSpace(req.SignatureB64)
	if req.DeviceID == "" || req.KeyID == "" || req.Timestamp == "" || req.Nonce == "" || req.BodyHash == "" || req.SignatureB64 == "" || req.ResultStatus == "" {
		writeError(w, http.StatusBadRequest, "device_id, key_id, timestamp, nonce, result_status, body_hash, and signature_b64 are required")
		return
	}
	switch req.ResultStatus {
	case "applied", "failed":
	default:
		writeError(w, http.StatusBadRequest, "result_status must be one of: applied, failed")
		return
	}
	if req.ResultStatus == "applied" {
		if req.ReleaseVersion == "" || req.ReleaseSHA256 == "" {
			writeError(w, http.StatusBadRequest, "release_version and release_sha256 are required when result_status=applied")
			return
		}
	}

	rec, _, now, ok := s.authenticateSignedDeviceRequest(
		w,
		"release_ack",
		req.DeviceID,
		req.KeyID,
		req.Timestamp,
		req.Nonce,
		req.BodyHash,
		req.SignatureB64,
		releaseAckBodyCanonical(req),
	)
	if !ok {
		return
	}
	if req.ResultStatus == "applied" && rec.DesiredReleaseVersion != "" && req.ReleaseVersion != rec.DesiredReleaseVersion {
		writeError(w, http.StatusConflict, "ack release_version does not match desired release")
		return
	}
	saved, err := s.store.updateReleaseAck(req.DeviceID, req.ReleaseVersion, req.ReleaseSHA256, req.ResultStatus, req.Message, now)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeError(w, http.StatusNotFound, "device is not enrolled")
			return
		}
		s.logger.Printf(`{"level":"error","msg":"persist release ack failed","device_id":"%s","error":"%s"}`, req.DeviceID, err)
		writeError(w, http.StatusInternalServerError, "failed to persist release ack")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":    "ok",
		"device_id": saved.DeviceID,
		"release": map[string]any{
			"desired_version": saved.DesiredReleaseVersion,
			"desired_sha256":  saved.DesiredReleaseSHA256,
			"current_version": saved.CurrentReleaseVersion,
			"current_sha256":  saved.CurrentReleaseSHA256,
			"last_ack_at":     saved.LastReleaseAckAt,
			"last_ack_status": saved.LastReleaseAckStatus,
		},
		"device_status": s.buildDeviceStatus(saved, now),
	})
}

func (s *Server) handleLogsPush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.ensureSecureTransport(w, r) {
		return
	}
	var req logsPushRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json payload")
		return
	}
	req.DeviceID = strings.TrimSpace(req.DeviceID)
	req.KeyID = strings.TrimSpace(req.KeyID)
	req.Timestamp = strings.TrimSpace(req.Timestamp)
	req.Nonce = strings.TrimSpace(req.Nonce)
	req.ContentSHA256 = strings.ToLower(strings.TrimSpace(req.ContentSHA256))
	req.ContentEncoding = strings.ToLower(strings.TrimSpace(req.ContentEncoding))
	req.PayloadB64 = strings.TrimSpace(req.PayloadB64)
	req.BodyHash = strings.ToLower(strings.TrimSpace(req.BodyHash))
	req.SignatureB64 = strings.TrimSpace(req.SignatureB64)
	if req.DeviceID == "" || req.KeyID == "" || req.Timestamp == "" || req.Nonce == "" || req.PayloadB64 == "" || req.BodyHash == "" || req.SignatureB64 == "" {
		writeError(w, http.StatusBadRequest, "device_id, key_id, timestamp, nonce, payload_b64, body_hash, and signature_b64 are required")
		return
	}
	if req.EntryCount < 0 {
		writeError(w, http.StatusBadRequest, "entry_count must be >= 0")
		return
	}
	switch req.ContentEncoding {
	case "", "gzip+base64":
		if req.ContentEncoding == "" {
			req.ContentEncoding = "gzip+base64"
		}
	default:
		writeError(w, http.StatusBadRequest, "content_encoding must be gzip+base64")
		return
	}

	_, msgTS, now, ok := s.authenticateSignedDeviceRequest(
		w,
		"logs_push",
		req.DeviceID,
		req.KeyID,
		req.Timestamp,
		req.Nonce,
		req.BodyHash,
		req.SignatureB64,
		logsPushBodyCanonical(req),
	)
	if !ok {
		return
	}

	payload, err := base64.StdEncoding.DecodeString(req.PayloadB64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "payload_b64 is invalid base64")
		return
	}
	if len(payload) == 0 {
		writeError(w, http.StatusBadRequest, "payload_b64 is empty")
		return
	}
	zr, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		writeError(w, http.StatusBadRequest, "payload must be gzip stream")
		return
	}
	_, _ = io.CopyN(io.Discard, zr, 1)
	if err := zr.Close(); err != nil {
		writeError(w, http.StatusBadRequest, "payload must be valid gzip stream")
		return
	}

	saved, outPath, err := s.store.saveLogBatch(req.DeviceID, msgTS, req.Nonce, payload, req.EntryCount, req.ContentSHA256)
	if err != nil {
		switch {
		case errors.Is(err, os.ErrNotExist):
			writeError(w, http.StatusNotFound, "device is not enrolled")
		case errors.Is(err, errStoreInvalid):
			writeError(w, http.StatusUnprocessableEntity, "invalid log payload")
		default:
			s.logger.Printf(`{"level":"error","msg":"persist log batch failed","device_id":"%s","error":"%s"}`, req.DeviceID, err)
			writeError(w, http.StatusInternalServerError, "failed to persist log batch")
		}
		return
	}
	s.logger.Printf(`{"level":"info","msg":"log batch uploaded","device_id":"%s","entries":%d,"bytes":%d}`, req.DeviceID, req.EntryCount, len(payload))
	writeJSON(w, http.StatusOK, map[string]any{
		"status":    "ok",
		"device_id": saved.DeviceID,
		"log_batch": map[string]any{
			"stored_path": outPath,
			"entry_count": saved.LastLogUploadEntries,
			"bytes":       saved.LastLogUploadBytes,
			"sha256":      saved.LastLogUploadSHA256,
			"uploaded_at": saved.LastLogUploadAt,
		},
		"device_status": s.buildDeviceStatus(saved, now),
	})
}

func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.ensureSecureTransport(w, r) {
		return
	}
	if !s.requireAdminRead(w, r) {
		return
	}

	now := s.nowFn().UTC()
	items := s.store.list()
	statusFilter := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("status")))
	out := make([]deviceStatusView, 0, len(items))
	summary := map[string]int{
		"total":    0,
		"pending":  0,
		"online":   0,
		"degraded": 0,
		"offline":  0,
		"stale":    0,
		"retired":  0,
		"flagged":  0,
	}
	for _, rec := range items {
		view := s.buildDeviceStatus(rec, now)
		if statusFilter != "" && view.Status != statusFilter {
			continue
		}
		out = append(out, view)
		summary["total"]++
		if _, ok := summary[view.Status]; ok {
			summary[view.Status]++
		}
		if view.Flagged {
			summary["flagged"]++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"devices":  out,
		"summary":  summary,
		"filtered": statusFilter,
	})
}

func (s *Server) handleDevice(w http.ResponseWriter, r *http.Request) {
	deviceID, action, ok := parseDevicePath(r.URL.Path)
	if !ok {
		writeError(w, http.StatusBadRequest, "device_id is required in path")
		return
	}
	if !s.ensureSecureTransport(w, r) {
		return
	}
	if action == "retire" {
		if !s.requireAdminWrite(w, r) {
			return
		}
		s.handleRetireDevice(w, r, deviceID)
		return
	}
	if action == "revoke" {
		if !s.requireAdminWrite(w, r) {
			return
		}
		s.handleRevokeDeviceKey(w, r, deviceID)
		return
	}
	if action == "assign-policy" {
		if !s.requireAdminWrite(w, r) {
			return
		}
		s.handleAssignDesiredPolicy(w, r, deviceID)
		return
	}
	if action == "assign-release" {
		if !s.requireAdminWrite(w, r) {
			return
		}
		s.handleAssignDesiredRelease(w, r, deviceID)
		return
	}
	if action == "download-policy" {
		if !s.requireAdminRead(w, r) {
			return
		}
		s.handleDownloadDevicePolicy(w, r, deviceID)
		return
	}
	if !s.requireAdminRead(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	rec, ok := s.store.get(deviceID)
	if !ok {
		writeError(w, http.StatusNotFound, "device not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"device": s.buildDeviceStatus(rec, s.nowFn().UTC()),
	})
}

func (s *Server) handleRetireDevice(w http.ResponseWriter, r *http.Request, deviceID string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	req := retireRequest{}
	if r.Body != nil {
		dec := json.NewDecoder(r.Body)
		if err := dec.Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			writeError(w, http.StatusBadRequest, "invalid json payload")
			return
		}
	}
	req.Reason = strings.TrimSpace(req.Reason)
	if len(req.Reason) > 256 {
		writeError(w, http.StatusBadRequest, "reason must be 256 chars or less")
		return
	}

	now := s.nowFn().UTC()
	rec, err := s.store.retire(deviceID, now, req.Reason)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeError(w, http.StatusNotFound, "device not found")
			return
		}
		s.logger.Printf(`{"level":"error","msg":"persist retire failed","device_id":"%s","error":"%s"}`, deviceID, err)
		writeError(w, http.StatusInternalServerError, "failed to persist retire state")
		return
	}
	s.logger.Printf(`{"level":"info","msg":"device retired","device_id":"%s"}`, deviceID)
	writeJSON(w, http.StatusOK, map[string]any{
		"status":        "ok",
		"device_id":     rec.DeviceID,
		"retired_at":    rec.RetiredAt,
		"retire_reason": rec.RetireReason,
		"device_status": s.buildDeviceStatus(rec, now),
	})
}

func (s *Server) handleRevokeDeviceKey(w http.ResponseWriter, r *http.Request, deviceID string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	req := revokeKeyRequest{}
	if r.Body != nil {
		dec := json.NewDecoder(r.Body)
		if err := dec.Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			writeError(w, http.StatusBadRequest, "invalid json payload")
			return
		}
	}
	req.KeyID = strings.TrimSpace(req.KeyID)
	req.Reason = strings.TrimSpace(req.Reason)
	if req.KeyID != "" && !isValidKeyID(req.KeyID) {
		writeError(w, http.StatusBadRequest, "key_id is invalid")
		return
	}
	if len(req.Reason) > 256 {
		writeError(w, http.StatusBadRequest, "reason must be 256 chars or less")
		return
	}

	now := s.nowFn().UTC()
	rec, err := s.store.revokeKey(deviceID, req.KeyID, now, req.Reason)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeError(w, http.StatusNotFound, "device/key not found")
			return
		}
		s.logger.Printf(`{"level":"error","msg":"persist key revoke failed","device_id":"%s","error":"%s"}`, deviceID, err)
		writeError(w, http.StatusInternalServerError, "failed to persist key revoke state")
		return
	}
	s.logger.Printf(`{"level":"warn","msg":"device key revoked","device_id":"%s","revoked_key_id":"%s"}`, deviceID, req.KeyID)
	writeJSON(w, http.StatusOK, map[string]any{
		"status":        "ok",
		"device_id":     rec.DeviceID,
		"active_key_id": rec.KeyID,
		"device_status": s.buildDeviceStatus(rec, now),
		"revoked_keys":  rec.RevokedKeys,
	})
}

func (s *Server) handleAssignDesiredPolicy(w http.ResponseWriter, r *http.Request, deviceID string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req policyAssignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json payload")
		return
	}
	req.Version = normalizePolicyVersion(req.Version)
	if req.Version == "" {
		writeError(w, http.StatusBadRequest, "version is required")
		return
	}

	now := s.nowFn().UTC()
	saved, pol, err := s.store.assignDesiredPolicy(deviceID, req.Version, now)
	if err != nil {
		if errors.Is(err, errStoreInvalid) {
			writeError(w, http.StatusBadRequest, "version is invalid")
			return
		}
		if errors.Is(err, errStoreConflict) {
			writeError(w, http.StatusConflict, "policy must be approved before assignment")
			return
		}
		if errors.Is(err, os.ErrNotExist) {
			if _, exists := s.store.get(deviceID); !exists {
				writeError(w, http.StatusNotFound, "device not found")
				return
			}
			writeError(w, http.StatusNotFound, "policy not found")
			return
		}
		s.logger.Printf(`{"level":"error","msg":"persist policy assignment failed","device_id":"%s","version":"%s","error":"%s"}`, deviceID, req.Version, err)
		writeError(w, http.StatusInternalServerError, "failed to persist policy assignment")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":    "ok",
		"device_id": saved.DeviceID,
		"policy": map[string]any{
			"version":     pol.Version,
			"sha256":      pol.SHA256,
			"assigned_at": saved.DesiredPolicyAssignedAt,
		},
		"device_status": s.buildDeviceStatus(saved, now),
	})
}

func (s *Server) handleAssignDesiredRelease(w http.ResponseWriter, r *http.Request, deviceID string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req releaseAssignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json payload")
		return
	}
	req.Version = normalizePolicyVersion(req.Version)
	req.ApplyAt = strings.TrimSpace(req.ApplyAt)
	if req.Version == "" {
		writeError(w, http.StatusBadRequest, "version is required")
		return
	}
	var applyAt *time.Time
	if req.ApplyAt != "" {
		ts, ok := parseRFC3339Any(req.ApplyAt)
		if !ok {
			writeError(w, http.StatusBadRequest, "apply_at must be RFC3339")
			return
		}
		ts = ts.UTC()
		applyAt = &ts
	}

	now := s.nowFn().UTC()
	saved, rel, err := s.store.assignDesiredRelease(deviceID, req.Version, now, applyAt)
	if err != nil {
		if errors.Is(err, errStoreInvalid) {
			writeError(w, http.StatusBadRequest, "version is invalid")
			return
		}
		if errors.Is(err, errStoreConflict) {
			writeError(w, http.StatusConflict, "release must be approved before assignment")
			return
		}
		if errors.Is(err, os.ErrNotExist) {
			if _, exists := s.store.get(deviceID); !exists {
				writeError(w, http.StatusNotFound, "device not found")
				return
			}
			writeError(w, http.StatusNotFound, "release not found")
			return
		}
		s.logger.Printf(`{"level":"error","msg":"persist release assignment failed","device_id":"%s","version":"%s","error":"%s"}`, deviceID, req.Version, err)
		writeError(w, http.StatusInternalServerError, "failed to persist release assignment")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":    "ok",
		"device_id": saved.DeviceID,
		"release": map[string]any{
			"version":     rel.Version,
			"platform":    rel.Platform,
			"sha256":      rel.SHA256,
			"assigned_at": saved.DesiredReleaseAssignedAt,
			"apply_at":    saved.DesiredReleaseNotBeforeAt,
		},
		"device_status": s.buildDeviceStatus(saved, now),
	})
}

func (s *Server) handleDownloadDevicePolicy(w http.ResponseWriter, r *http.Request, deviceID string) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	state := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("state")))
	if state == "" {
		state = "desired"
	}
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "raw"
	}
	if state != "desired" && state != "current" {
		writeError(w, http.StatusBadRequest, "state must be desired|current")
		return
	}
	if format != "raw" && format != "json" {
		writeError(w, http.StatusBadRequest, "format must be raw|json")
		return
	}

	rec, ok := s.store.get(deviceID)
	if !ok {
		writeError(w, http.StatusNotFound, "device not found")
		return
	}

	version := rec.DesiredPolicyVersion
	assignedAt := rec.DesiredPolicyAssignedAt
	if state == "current" {
		version = rec.CurrentPolicyVersion
		assignedAt = rec.LastPolicySyncAt
	}
	if version == "" {
		if state == "current" {
			writeError(w, http.StatusConflict, "current policy is not set")
			return
		}
		writeError(w, http.StatusConflict, "desired policy is not assigned")
		return
	}

	pol, found := s.store.getPolicy(version)
	if !found {
		writeError(w, http.StatusConflict, "policy not found")
		return
	}

	if format == "json" {
		writeJSON(w, http.StatusOK, map[string]any{
			"device_id": deviceID,
			"state":     state,
			"policy": map[string]any{
				"version":        pol.Version,
				"sha256":         pol.SHA256,
				"waf_raw":        pol.WAFRaw,
				"bundle_tgz_b64": pol.BundleTGZB64,
				"bundle_sha256":  pol.BundleSHA256,
				"note":           pol.Note,
				"created_at":     pol.CreatedAt,
				"updated_at":     pol.UpdatedAt,
				"assigned_at":    rec.DesiredPolicyAssignedAt,
				"last_sync_at":   rec.LastPolicySyncAt,
			},
		})
		return
	}

	filename := fmt.Sprintf(
		"%s-%s-%s.waf",
		sanitizeDownloadName(deviceID),
		sanitizeDownloadName(pol.Version),
		state,
	)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	w.Header().Set("X-Policy-Version", pol.Version)
	w.Header().Set("X-Policy-SHA256", pol.SHA256)
	if pol.BundleSHA256 != "" {
		w.Header().Set("X-Policy-Bundle-SHA256", pol.BundleSHA256)
	}
	w.Header().Set("X-Policy-State", state)
	if assignedAt != "" {
		w.Header().Set("X-Policy-Assigned-At", assignedAt)
	}
	_, _ = w.Write([]byte(pol.WAFRaw))
}

func (s *Server) buildDeviceStatus(rec DeviceRecord, now time.Time) deviceStatusView {
	if strings.TrimSpace(rec.RetiredAt) != "" {
		lastSeenRef := strings.TrimSpace(rec.LastHeartbeatAt)
		if lastSeenRef == "" {
			lastSeenRef = rec.EnrolledAt
		}
		lastSeenTime, ok := parseRFC3339Any(lastSeenRef)
		if !ok {
			lastSeenTime = now
		}
		secondsSince := int64(now.Sub(lastSeenTime).Seconds())
		if secondsSince < 0 {
			secondsSince = 0
		}
		return deviceStatusView{
			DeviceRecord:         rec,
			Status:               "retired",
			Flagged:              true,
			HasHeartbeat:         strings.TrimSpace(rec.LastHeartbeatAt) != "",
			SecondsSinceLastSeen: secondsSince,
		}
	}

	lastSeenRef := strings.TrimSpace(rec.LastHeartbeatAt)
	hasHeartbeat := lastSeenRef != ""
	if !hasHeartbeat {
		lastSeenRef = rec.EnrolledAt
	}
	lastSeenTime, ok := parseRFC3339Any(lastSeenRef)
	if !ok {
		lastSeenTime = now
	}
	secondsSince := int64(now.Sub(lastSeenTime).Seconds())
	if secondsSince < 0 {
		secondsSince = 0
	}

	status, flagged := statusFromHeartbeatAge(
		hasHeartbeat,
		now.Sub(lastSeenTime),
		s.cfg.Heartbeat.ExpectedInterval.Duration,
		s.cfg.Heartbeat.MissedHeartbeatsForOffline,
		s.cfg.Heartbeat.StaleAfter.Duration,
	)
	return deviceStatusView{
		DeviceRecord:         rec,
		Status:               status,
		Flagged:              flagged,
		HasHeartbeat:         hasHeartbeat,
		SecondsSinceLastSeen: secondsSince,
	}
}

func statusFromHeartbeatAge(hasHeartbeat bool, age time.Duration, interval time.Duration, missedForOffline int, staleAfter time.Duration) (string, bool) {
	if age < 0 {
		age = 0
	}
	offlineAfter := interval * time.Duration(missedForOffline)

	if !hasHeartbeat {
		if age <= offlineAfter {
			return "pending", false
		}
		if age <= staleAfter {
			return "offline", true
		}
		return "stale", true
	}

	if age <= interval {
		return "online", false
	}
	if age <= offlineAfter {
		return "degraded", true
	}
	if age <= staleAfter {
		return "offline", true
	}
	return "stale", true
}

func (s *Server) authenticateSignedDeviceRequest(
	w http.ResponseWriter,
	scope string,
	deviceID string,
	keyID string,
	timestamp string,
	nonce string,
	bodyHash string,
	signatureB64 string,
	canonicalBody string,
) (DeviceRecord, time.Time, time.Time, bool) {
	if !isValidKeyID(keyID) {
		writeError(w, http.StatusBadRequest, "key_id is invalid")
		return DeviceRecord{}, time.Time{}, time.Time{}, false
	}
	rec, ok := s.store.get(deviceID)
	if !ok {
		writeError(w, http.StatusNotFound, "device is not enrolled")
		return DeviceRecord{}, time.Time{}, time.Time{}, false
	}
	if strings.TrimSpace(rec.RetiredAt) != "" {
		writeError(w, http.StatusGone, "device is retired")
		return DeviceRecord{}, time.Time{}, time.Time{}, false
	}
	if strings.TrimSpace(rec.KeyID) == "" || strings.TrimSpace(rec.PublicKeyPEMBase64) == "" {
		writeError(w, http.StatusGone, "device key is revoked")
		return DeviceRecord{}, time.Time{}, time.Time{}, false
	}
	if rec.KeyID != keyID {
		writeError(w, http.StatusUnauthorized, "key_id mismatch")
		return DeviceRecord{}, time.Time{}, time.Time{}, false
	}

	msgTS, ok := parseRFC3339Any(timestamp)
	if !ok {
		writeError(w, http.StatusBadRequest, "timestamp must be RFC3339")
		return DeviceRecord{}, time.Time{}, time.Time{}, false
	}
	now := s.nowFn().UTC()
	if !withinSkew(now, msgTS.UTC(), s.cfg.Heartbeat.MaxClockSkew.Duration) {
		writeError(w, http.StatusUnauthorized, "timestamp out of allowed skew")
		return DeviceRecord{}, time.Time{}, time.Time{}, false
	}
	if s.nonceCache.remember(scope, deviceID, nonce, now) {
		writeError(w, http.StatusConflict, "reused nonce")
		return DeviceRecord{}, time.Time{}, time.Time{}, false
	}
	if !secureTextEqual(bodyHash, hashStringHex(canonicalBody)) {
		writeError(w, http.StatusUnauthorized, "body_hash mismatch")
		return DeviceRecord{}, time.Time{}, time.Time{}, false
	}

	pub, err := parseEd25519PublicKeyFromBase64PEM(rec.PublicKeyPEMBase64)
	if err != nil {
		s.logger.Printf(`{"level":"error","msg":"stored public key decode failed","device_id":"%s","error":"%s"}`, deviceID, err)
		writeError(w, http.StatusInternalServerError, "stored key is invalid")
		return DeviceRecord{}, time.Time{}, time.Time{}, false
	}
	signature, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "signature_b64 is invalid base64")
		return DeviceRecord{}, time.Time{}, time.Time{}, false
	}
	message := signedEnvelopeMessage(deviceID, keyID, timestamp, nonce, bodyHash)
	if !ed25519.Verify(pub, []byte(message), signature) {
		writeError(w, http.StatusUnauthorized, "invalid signature")
		return DeviceRecord{}, time.Time{}, time.Time{}, false
	}
	return rec, msgTS.UTC(), now, true
}

func parseRFC3339Any(raw string) (time.Time, bool) {
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

func releaseScheduleReached(notBeforeRaw string, now time.Time) bool {
	notBeforeRaw = strings.TrimSpace(notBeforeRaw)
	if notBeforeRaw == "" {
		return true
	}
	ts, ok := parseRFC3339Any(notBeforeRaw)
	if !ok {
		// Keep update available if persisted value is malformed.
		return true
	}
	return !now.UTC().Before(ts.UTC())
}

func allowKeyRotation(raw string) bool {
	raw = strings.TrimSpace(strings.ToLower(raw))
	return raw == "1" || raw == "true" || raw == "yes"
}

func parseDevicePath(path string) (deviceID string, action string, ok bool) {
	deviceID = strings.TrimSpace(strings.TrimPrefix(path, "/v1/devices/"))
	if deviceID == "" {
		return "", "", false
	}
	if strings.Contains(deviceID, "/") {
		return "", "", false
	}
	if strings.HasSuffix(deviceID, ":retire") {
		deviceID = strings.TrimSpace(strings.TrimSuffix(deviceID, ":retire"))
		if deviceID == "" {
			return "", "", false
		}
		return deviceID, "retire", true
	}
	if strings.HasSuffix(deviceID, ":revoke") {
		deviceID = strings.TrimSpace(strings.TrimSuffix(deviceID, ":revoke"))
		if deviceID == "" {
			return "", "", false
		}
		return deviceID, "revoke", true
	}
	if strings.HasSuffix(deviceID, ":assign-policy") {
		deviceID = strings.TrimSpace(strings.TrimSuffix(deviceID, ":assign-policy"))
		if deviceID == "" {
			return "", "", false
		}
		return deviceID, "assign-policy", true
	}
	if strings.HasSuffix(deviceID, ":assign-release") {
		deviceID = strings.TrimSpace(strings.TrimSuffix(deviceID, ":assign-release"))
		if deviceID == "" {
			return "", "", false
		}
		return deviceID, "assign-release", true
	}
	if strings.HasSuffix(deviceID, ":download-policy") {
		deviceID = strings.TrimSpace(strings.TrimSuffix(deviceID, ":download-policy"))
		if deviceID == "" {
			return "", "", false
		}
		return deviceID, "download-policy", true
	}
	return deviceID, "", true
}

func heartbeatMessage(deviceID, timestamp, nonce, statusHash string) string {
	return deviceID + "\n" + timestamp + "\n" + nonce + "\n" + statusHash
}

func signedEnvelopeMessage(deviceID, keyID, timestamp, nonce, bodyHash string) string {
	return deviceID + "\n" + keyID + "\n" + timestamp + "\n" + nonce + "\n" + bodyHash
}

func enrollBodyCanonical(req enrollRequest) string {
	return req.DeviceID + "\n" + req.KeyID + "\n" + req.PublicKeyPEMBase64 + "\n" + req.PublicKeyFingerprintSHA256 + "\n" + req.Timestamp + "\n" + req.Nonce
}

func heartbeatBodyCanonical(req heartbeatRequest) string {
	return req.DeviceID + "\n" + req.KeyID + "\n" + req.Timestamp + "\n" + req.Nonce + "\n" + req.StatusHash + "\n" + req.CurrentPolicyVersion + "\n" + req.CurrentPolicySHA256
}

func policyPullBodyCanonical(req policyPullRequest) string {
	return req.DeviceID + "\n" + req.KeyID + "\n" + req.Timestamp + "\n" + req.Nonce + "\n" + req.CurrentPolicyVersion + "\n" + req.CurrentPolicySHA256
}

func policyAckBodyCanonical(req policyAckRequest) string {
	return req.DeviceID + "\n" + req.KeyID + "\n" + req.Timestamp + "\n" + req.Nonce + "\n" + req.PolicyVersion + "\n" + req.PolicySHA256 + "\n" + req.ResultStatus + "\n" + req.Message
}

func releasePullBodyCanonical(req releasePullRequest) string {
	return req.DeviceID + "\n" + req.KeyID + "\n" + req.Timestamp + "\n" + req.Nonce + "\n" + req.CurrentReleaseVersion + "\n" + req.CurrentReleaseSHA256
}

func releaseAckBodyCanonical(req releaseAckRequest) string {
	return req.DeviceID + "\n" + req.KeyID + "\n" + req.Timestamp + "\n" + req.Nonce + "\n" + req.ReleaseVersion + "\n" + req.ReleaseSHA256 + "\n" + req.ResultStatus + "\n" + req.Message
}

func logsPushBodyCanonical(req logsPushRequest) string {
	return req.DeviceID + "\n" + req.KeyID + "\n" + req.Timestamp + "\n" + req.Nonce + "\n" + strconv.Itoa(req.EntryCount) + "\n" + req.ContentSHA256 + "\n" + req.ContentEncoding
}

func parsePolicyVersionPath(path string) (version string, action string, ok bool) {
	version = strings.TrimSpace(strings.TrimPrefix(path, "/v1/policies/"))
	if version == "" || strings.Contains(version, "/") {
		return "", "", false
	}
	if strings.HasSuffix(version, ":approve") {
		version = normalizePolicyVersion(strings.TrimSuffix(version, ":approve"))
		if version == "" {
			return "", "", false
		}
		return version, "approve", true
	}
	version = normalizePolicyVersion(version)
	if version == "" {
		return "", "", false
	}
	return version, "", true
}

func parseReleaseVersionPath(path string) (version string, action string, ok bool) {
	version = strings.TrimSpace(strings.TrimPrefix(path, "/v1/releases/"))
	if version == "" || strings.Contains(version, "/") {
		return "", "", false
	}
	if strings.HasSuffix(version, ":approve") {
		version = normalizePolicyVersion(strings.TrimSuffix(version, ":approve"))
		if version == "" {
			return "", "", false
		}
		return version, "approve", true
	}
	version = normalizePolicyVersion(version)
	if version == "" {
		return "", "", false
	}
	return version, "", true
}

func resolvePolicyWAFRaw(raw string, template string, ruleFiles []string, bundleTGZB64 string, bundleSHA256 string) (string, error) {
	raw = strings.TrimSpace(raw)
	template = strings.ToLower(strings.TrimSpace(template))
	if raw != "" && template != "" {
		return "", fmt.Errorf("waf_raw and waf_raw_template are mutually exclusive")
	}
	if raw != "" {
		return raw, nil
	}
	if template == "" {
		return "", nil
	}
	switch template {
	case "bundle_default":
		confFiles, _, _, err := inspectBundle(bundleTGZB64, bundleSHA256)
		if err != nil {
			return "", err
		}
		selected, err := selectTemplateRuleFiles(confFiles, ruleFiles)
		if err != nil {
			return "", err
		}
		prefixed := make([]string, 0, len(selected))
		for _, f := range selected {
			prefixed = append(prefixed, "${MAMOTAMA_POLICY_ACTIVE}/"+f)
		}
		out, err := json.Marshal(map[string]any{
			"enabled":    true,
			"rule_files": prefixed,
		})
		if err != nil {
			return "", fmt.Errorf("marshal generated waf_raw: %w", err)
		}
		return string(out), nil
	default:
		return "", fmt.Errorf("unsupported waf_raw_template")
	}
}

func selectTemplateRuleFiles(bundleConfFiles []string, requested []string) ([]string, error) {
	if len(bundleConfFiles) == 0 {
		return nil, fmt.Errorf("bundle does not contain any .conf file")
	}
	available := make(map[string]struct{}, len(bundleConfFiles))
	for _, v := range bundleConfFiles {
		available[v] = struct{}{}
	}
	if len(requested) == 0 {
		return []string{recommendedBundleRuleFile(bundleConfFiles)}, nil
	}

	out := make([]string, 0, len(requested))
	seen := make(map[string]struct{}, len(requested))
	for _, raw := range requested {
		clean, ok := normalizeBundleEntryPath(raw)
		if !ok || !strings.HasSuffix(strings.ToLower(clean), ".conf") {
			return nil, fmt.Errorf("invalid waf_rule_files entry")
		}
		if _, ok := available[clean]; !ok {
			return nil, fmt.Errorf("waf_rule_files entry is not present in bundle")
		}
		if _, ok := seen[clean]; ok {
			continue
		}
		seen[clean] = struct{}{}
		out = append(out, clean)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("waf_rule_files must include at least one .conf path")
	}
	return out, nil
}

func inspectBundle(bundleTGZB64 string, expectedSHA256 string) ([]string, []string, string, error) {
	bundleTGZB64 = strings.TrimSpace(bundleTGZB64)
	if bundleTGZB64 == "" {
		return nil, nil, "", fmt.Errorf("bundle_tgz_b64 is required")
	}
	raw, err := base64.StdEncoding.DecodeString(bundleTGZB64)
	if err != nil {
		return nil, nil, "", fmt.Errorf("decode bundle_tgz_b64: %w", err)
	}
	if len(raw) == 0 {
		return nil, nil, "", fmt.Errorf("decoded bundle is empty")
	}
	sha := hashBytesHex(raw)
	expectedSHA256 = strings.ToLower(strings.TrimSpace(expectedSHA256))
	if expectedSHA256 != "" && sha != expectedSHA256 {
		return nil, nil, "", fmt.Errorf("bundle_sha256 mismatch")
	}

	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, nil, "", fmt.Errorf("open bundle gzip: %w", err)
	}
	defer zr.Close()

	tr := tar.NewReader(zr)
	confFiles := make([]string, 0, 8)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, "", fmt.Errorf("read bundle tar: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}
		name, ok := normalizeBundleEntryPath(hdr.Name)
		if !ok {
			continue
		}
		if strings.HasSuffix(strings.ToLower(name), ".conf") {
			confFiles = append(confFiles, name)
		}
	}
	if len(confFiles) == 0 {
		return nil, nil, "", fmt.Errorf("bundle does not contain any .conf file")
	}
	sort.Strings(confFiles)
	recommended := []string{recommendedBundleRuleFile(confFiles)}
	return confFiles, recommended, sha, nil
}

func recommendedBundleRuleFile(confFiles []string) string {
	for _, candidate := range confFiles {
		if candidate == "rules/mamotama.conf" {
			return candidate
		}
	}
	if len(confFiles) == 0 {
		return ""
	}
	return confFiles[0]
}

func normalizeBundleEntryPath(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	clean := path.Clean(strings.ReplaceAll(raw, "\\", "/"))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") {
		return "", false
	}
	local := filepath.Clean(filepath.FromSlash(clean))
	if local == "." || local == ".." || strings.HasPrefix(local, ".."+string(filepath.Separator)) {
		return "", false
	}
	return strings.TrimPrefix(filepath.ToSlash(local), "./"), true
}

func hashStringHex(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func secureTextEqual(a, b string) bool {
	a = strings.TrimSpace(a)
	b = strings.TrimSpace(b)
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func isValidKeyID(raw string) bool {
	raw = strings.TrimSpace(raw)
	if len(raw) < 8 || len(raw) > 128 {
		return false
	}
	for _, r := range raw {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.', r == ':':
		default:
			return false
		}
	}
	return true
}

func (s *Server) ensureSecureTransport(w http.ResponseWriter, r *http.Request) bool {
	if !s.cfg.Auth.RequireTLS {
		return true
	}
	if r.TLS != nil {
		return true
	}
	if s.cfg.Auth.TrustForwardedProto {
		parts := strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")
		if len(parts) > 0 && strings.EqualFold(strings.TrimSpace(parts[0]), "https") {
			return true
		}
	}
	writeError(w, http.StatusUpgradeRequired, "tls is required")
	return false
}

func newNonceReplayCache(ttl time.Duration, maxItems int) *nonceReplayCache {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	if maxItems <= 0 {
		maxItems = 256
	}
	return &nonceReplayCache{
		ttl:      ttl,
		maxItems: maxItems,
		byDevice: make(map[string]map[string]time.Time),
	}
}

func (c *nonceReplayCache) remember(scope string, deviceID string, nonce string, now time.Time) bool {
	scope = strings.TrimSpace(scope)
	deviceID = strings.TrimSpace(deviceID)
	nonce = strings.TrimSpace(nonce)
	if scope == "" || deviceID == "" || nonce == "" {
		return false
	}
	key := scope + ":" + deviceID

	c.mu.Lock()
	defer c.mu.Unlock()

	entries, ok := c.byDevice[key]
	if !ok {
		entries = make(map[string]time.Time, c.maxItems)
		c.byDevice[key] = entries
	}
	for n, expiresAt := range entries {
		if !expiresAt.After(now) {
			delete(entries, n)
		}
	}
	if expiresAt, exists := entries[nonce]; exists && expiresAt.After(now) {
		return true
	}
	if len(entries) >= c.maxItems {
		var oldestNonce string
		var oldest time.Time
		for n, expiresAt := range entries {
			if oldestNonce == "" || expiresAt.Before(oldest) {
				oldestNonce = n
				oldest = expiresAt
			}
		}
		if oldestNonce != "" {
			delete(entries, oldestNonce)
		}
	}
	entries[nonce] = now.Add(c.ttl)
	return false
}

func withinSkew(now, ts time.Time, skew time.Duration) bool {
	delta := now.Sub(ts)
	if delta < 0 {
		delta = -delta
	}
	return delta <= skew
}

func parseEd25519PublicKeyFromBase64PEM(b64 string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return nil, fmt.Errorf("decode base64 pem: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil || len(block.Bytes) == 0 {
		return nil, fmt.Errorf("decode pem")
	}
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	pub, ok := pubAny.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not ed25519")
	}
	return pub, nil
}

func validatePublicKeyPEMBase64(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return "", fmt.Errorf("decode base64 pem: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil || len(block.Bytes) == 0 {
		return "", fmt.Errorf("decode pem")
	}
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse public key: %w", err)
	}
	if _, ok := pubAny.(ed25519.PublicKey); !ok {
		return "", fmt.Errorf("public key is not ed25519")
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:]), nil
}

func (s *Server) hasValidLicense(got string) bool {
	got = strings.TrimSpace(got)
	if got == "" {
		return false
	}
	for _, key := range s.cfg.Auth.EnrollmentLicenseKeys {
		if subtle.ConstantTimeCompare([]byte(got), []byte(key)) == 1 {
			return true
		}
	}
	return false
}

func (s *Server) requireAdminRead(w http.ResponseWriter, r *http.Request) bool {
	if s.hasValidAdminReadAPIKey(r.Header.Get("X-API-Key")) {
		return true
	}
	writeError(w, http.StatusUnauthorized, "invalid admin api key")
	return false
}

func (s *Server) requireAdminWrite(w http.ResponseWriter, r *http.Request) bool {
	got := strings.TrimSpace(r.Header.Get("X-API-Key"))
	if s.hasValidAdminWriteAPIKey(got) {
		return true
	}
	if s.hasAnyAdminAPIKey(got) {
		writeError(w, http.StatusForbidden, "admin api key is read-only")
		return false
	}
	writeError(w, http.StatusUnauthorized, "invalid admin api key")
	return false
}

func (s *Server) hasValidAdminReadAPIKey(got string) bool {
	got = strings.TrimSpace(got)
	if got == "" {
		return false
	}
	if keyInListConstantTime(got, s.cfg.Auth.AdminReadAPIKeys) {
		return true
	}
	if keyInListConstantTime(got, s.cfg.Auth.AdminWriteAPIKeys) {
		return true
	}
	if keyInListConstantTime(got, s.cfg.Auth.AdminAPIKeys) {
		return true
	}
	return false
}

func (s *Server) hasValidAdminWriteAPIKey(got string) bool {
	got = strings.TrimSpace(got)
	if got == "" {
		return false
	}
	if keyInListConstantTime(got, s.cfg.Auth.AdminWriteAPIKeys) {
		return true
	}
	if keyInListConstantTime(got, s.cfg.Auth.AdminAPIKeys) {
		return true
	}
	return false
}

func (s *Server) hasAnyAdminAPIKey(got string) bool {
	got = strings.TrimSpace(got)
	if got == "" {
		return false
	}
	if keyInListConstantTime(got, s.cfg.Auth.AdminReadAPIKeys) {
		return true
	}
	if keyInListConstantTime(got, s.cfg.Auth.AdminWriteAPIKeys) {
		return true
	}
	if keyInListConstantTime(got, s.cfg.Auth.AdminAPIKeys) {
		return true
	}
	return false
}

func keyInListConstantTime(got string, keys []string) bool {
	for _, key := range keys {
		if subtle.ConstantTimeCompare([]byte(got), []byte(strings.TrimSpace(key))) == 1 {
			return true
		}
	}
	return false
}

func remoteAddressOnly(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return remote
	}
	return host
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, message string) {
	writeJSON(w, code, map[string]any{
		"status": "error",
		"error":  message,
		"code":   strconv.Itoa(code),
	})
}
