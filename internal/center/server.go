package center

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

type Server struct {
	cfg    Config
	logger *log.Logger
	store  *deviceStore
	nowFn  func() time.Time
	mux    *http.ServeMux
}

type enrollRequest struct {
	DeviceID                   string `json:"device_id"`
	PublicKeyPEMBase64         string `json:"public_key_pem_b64"`
	PublicKeyFingerprintSHA256 string `json:"public_key_fingerprint_sha256,omitempty"`
	Nonce                      string `json:"nonce,omitempty"`
	Timestamp                  string `json:"timestamp,omitempty"`
}

type heartbeatRequest struct {
	DeviceID     string `json:"device_id"`
	Timestamp    string `json:"timestamp"`
	Nonce        string `json:"nonce"`
	StatusHash   string `json:"status_hash,omitempty"`
	SignatureB64 string `json:"signature_b64"`
}

func NewServer(cfg Config, logger *log.Logger) (*Server, error) {
	store, err := loadDeviceStore(cfg.Storage.Path)
	if err != nil {
		return nil, fmt.Errorf("load device store: %w", err)
	}
	s := &Server{
		cfg:    cfg,
		logger: logger,
		store:  store,
		nowFn:  time.Now,
		mux:    http.NewServeMux(),
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
	req.PublicKeyPEMBase64 = strings.TrimSpace(req.PublicKeyPEMBase64)
	req.PublicKeyFingerprintSHA256 = strings.ToLower(strings.TrimSpace(req.PublicKeyFingerprintSHA256))
	if req.DeviceID == "" || req.PublicKeyPEMBase64 == "" {
		writeError(w, http.StatusBadRequest, "device_id and public_key_pem_b64 are required")
		return
	}

	fingerprint, err := validatePublicKeyPEMBase64(req.PublicKeyPEMBase64)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid public key")
		return
	}
	if req.PublicKeyFingerprintSHA256 != "" && req.PublicKeyFingerprintSHA256 != fingerprint {
		writeError(w, http.StatusUnprocessableEntity, "public key fingerprint mismatch")
		return
	}

	now := s.nowFn().UTC()
	addr := remoteAddressOnly(r.RemoteAddr)
	current, exists := s.store.get(req.DeviceID)
	if exists && current.PublicKeyPEMBase64 != req.PublicKeyPEMBase64 {
		s.logger.Printf(`{"level":"warn","msg":"public key rotated","device_id":"%s","remote_addr":"%s"}`, req.DeviceID, addr)
	}

	rec := DeviceRecord{
		DeviceID:                   req.DeviceID,
		PublicKeyPEMBase64:         req.PublicKeyPEMBase64,
		PublicKeyFingerprintSHA256: fingerprint,
		FirstSeenAt:                now.Format(time.RFC3339Nano),
		LastSeenAt:                 now.Format(time.RFC3339Nano),
		EnrolledAt:                 now.Format(time.RFC3339Nano),
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
		"enrolled_at":   saved.EnrolledAt,
		"fingerprint":   saved.PublicKeyFingerprintSHA256,
		"already_known": exists,
	})
}

func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req heartbeatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json payload")
		return
	}
	req.DeviceID = strings.TrimSpace(req.DeviceID)
	req.Timestamp = strings.TrimSpace(req.Timestamp)
	req.Nonce = strings.TrimSpace(req.Nonce)
	req.SignatureB64 = strings.TrimSpace(req.SignatureB64)
	req.StatusHash = strings.TrimSpace(req.StatusHash)
	if req.DeviceID == "" || req.Timestamp == "" || req.Nonce == "" || req.SignatureB64 == "" {
		writeError(w, http.StatusBadRequest, "device_id, timestamp, nonce, and signature_b64 are required")
		return
	}

	rec, ok := s.store.get(req.DeviceID)
	if !ok {
		writeError(w, http.StatusNotFound, "device is not enrolled")
		return
	}

	msgTS, err := time.Parse(time.RFC3339Nano, req.Timestamp)
	if err != nil {
		msgTS, err = time.Parse(time.RFC3339, req.Timestamp)
		if err != nil {
			writeError(w, http.StatusBadRequest, "timestamp must be RFC3339")
			return
		}
	}
	now := s.nowFn().UTC()
	if !withinSkew(now, msgTS.UTC(), s.cfg.Heartbeat.MaxClockSkew.Duration) {
		writeError(w, http.StatusUnauthorized, "timestamp out of allowed skew")
		return
	}

	if rec.LastHeartbeatMessageAt != "" {
		lastTS, err := time.Parse(time.RFC3339Nano, rec.LastHeartbeatMessageAt)
		if err == nil && !msgTS.UTC().After(lastTS.UTC()) {
			writeError(w, http.StatusConflict, "stale or replayed heartbeat")
			return
		}
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
	message := heartbeatMessage(req.DeviceID, req.Timestamp, req.Nonce, req.StatusHash)
	if !ed25519.Verify(pub, []byte(message), signature) {
		writeError(w, http.StatusUnauthorized, "invalid heartbeat signature")
		return
	}

	saved, err := s.store.updateHeartbeat(req.DeviceID, now, msgTS.UTC(), req.Nonce, req.StatusHash)
	if err != nil {
		s.logger.Printf(`{"level":"error","msg":"persist heartbeat failed","device_id":"%s","error":"%s"}`, req.DeviceID, err)
		writeError(w, http.StatusInternalServerError, "failed to persist heartbeat")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":            "ok",
		"device_id":         saved.DeviceID,
		"last_heartbeat_at": saved.LastHeartbeatAt,
	})
}

func heartbeatMessage(deviceID, timestamp, nonce, statusHash string) string {
	return deviceID + "\n" + timestamp + "\n" + nonce + "\n" + statusHash
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
	})
}
