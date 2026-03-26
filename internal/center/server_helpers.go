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
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

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

func reputationPullBodyCanonical(req reputationPullRequest) string {
	return req.DeviceID + "\n" + req.KeyID + "\n" + req.Timestamp + "\n" + req.Nonce
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
