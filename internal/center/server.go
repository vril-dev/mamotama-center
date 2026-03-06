package center

import (
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
	"strconv"
	"strings"
	"sync"
	"time"
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
	Version string `json:"version"`
	SHA256  string `json:"sha256,omitempty"`
	WAFRaw  string `json:"waf_raw"`
	Note    string `json:"note,omitempty"`
}

type policyAssignRequest struct {
	Version string `json:"version"`
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
	store, err := loadDeviceStore(cfg.Storage.Path)
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
	s.mux.HandleFunc("/v1/enroll", s.handleEnroll)
	s.mux.HandleFunc("/v1/heartbeat", s.handleHeartbeat)
	s.mux.HandleFunc("/v1/policies", s.handlePolicies)
	s.mux.HandleFunc("/v1/policies/", s.handlePolicyByVersion)
	s.mux.HandleFunc("/v1/policy/pull", s.handlePolicyPull)
	s.mux.HandleFunc("/v1/policy/ack", s.handlePolicyAck)
	s.mux.HandleFunc("/v1/logs/push", s.handleLogsPush)
	s.mux.HandleFunc("/v1/devices", s.handleDevices)
	s.mux.HandleFunc("/v1/devices/", s.handleDevice)
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
	writeJSON(w, http.StatusOK, map[string]any{
		"status":            "ok",
		"device_id":         saved.DeviceID,
		"last_heartbeat_at": saved.LastHeartbeatAt,
		"device_status":     s.buildDeviceStatus(saved, now),
		"policy":            policy,
	})
}

func (s *Server) handlePolicies(w http.ResponseWriter, r *http.Request) {
	if !s.ensureSecureTransport(w, r) {
		return
	}
	switch r.Method {
	case http.MethodGet:
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
		if !s.hasValidLicense(r.Header.Get("X-License-Key")) {
			writeError(w, http.StatusUnauthorized, "invalid license key")
			return
		}
		var req policyUpsertRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json payload")
			return
		}
		now := s.nowFn().UTC()
		pol, err := s.store.upsertPolicy(PolicyRecord{
			Version: req.Version,
			SHA256:  req.SHA256,
			WAFRaw:  req.WAFRaw,
			Note:    req.Note,
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
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.ensureSecureTransport(w, r) {
		return
	}
	version, ok := parsePolicyVersionPath(r.URL.Path)
	if !ok {
		writeError(w, http.StatusBadRequest, "policy version is required in path")
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
	writeJSON(w, http.StatusOK, map[string]any{
		"status":          "ok",
		"device_id":       rec.DeviceID,
		"update_required": true,
		"policy": map[string]any{
			"version":      pol.Version,
			"sha256":       pol.SHA256,
			"waf_raw":      pol.WAFRaw,
			"note":         pol.Note,
			"created_at":   pol.CreatedAt,
			"updated_at":   pol.UpdatedAt,
			"assigned_at":  rec.DesiredPolicyAssignedAt,
			"current_seen": rec.CurrentPolicyVersion,
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
	if action == "retire" {
		s.handleRetireDevice(w, r, deviceID)
		return
	}
	if action == "revoke" {
		s.handleRevokeDeviceKey(w, r, deviceID)
		return
	}
	if action == "assign-policy" {
		s.handleAssignDesiredPolicy(w, r, deviceID)
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.ensureSecureTransport(w, r) {
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
	if !s.ensureSecureTransport(w, r) {
		return
	}
	if !s.hasValidLicense(r.Header.Get("X-License-Key")) {
		writeError(w, http.StatusUnauthorized, "invalid license key")
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
	if !s.ensureSecureTransport(w, r) {
		return
	}
	if !s.hasValidLicense(r.Header.Get("X-License-Key")) {
		writeError(w, http.StatusUnauthorized, "invalid license key")
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
	if !s.ensureSecureTransport(w, r) {
		return
	}
	if !s.hasValidLicense(r.Header.Get("X-License-Key")) {
		writeError(w, http.StatusUnauthorized, "invalid license key")
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

func logsPushBodyCanonical(req logsPushRequest) string {
	return req.DeviceID + "\n" + req.KeyID + "\n" + req.Timestamp + "\n" + req.Nonce + "\n" + strconv.Itoa(req.EntryCount) + "\n" + req.ContentSHA256 + "\n" + req.ContentEncoding
}

func parsePolicyVersionPath(path string) (string, bool) {
	version := strings.TrimSpace(strings.TrimPrefix(path, "/v1/policies/"))
	if version == "" || strings.Contains(version, "/") {
		return "", false
	}
	version = normalizePolicyVersion(version)
	if version == "" {
		return "", false
	}
	return version, true
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
