package center

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	defaultReputationWindow    = 24 * time.Hour
	defaultReputationThreshold = 6
	defaultReputationMaxItems  = 1024
)

func (s *Server) handleReputationPull(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.ensureSecureTransport(w, r) {
		return
	}
	var req reputationPullRequest
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
	if req.DeviceID == "" || req.KeyID == "" || req.Timestamp == "" || req.Nonce == "" || req.BodyHash == "" || req.SignatureB64 == "" {
		writeError(w, http.StatusBadRequest, "device_id, key_id, timestamp, nonce, body_hash, and signature_b64 are required")
		return
	}

	_, _, now, ok := s.authenticateSignedDeviceRequest(
		w,
		"reputation_pull",
		req.DeviceID,
		req.KeyID,
		req.Timestamp,
		req.Nonce,
		req.BodyHash,
		req.SignatureB64,
		reputationPullBodyCanonical(req),
	)
	if !ok {
		return
	}

	snapshot, err := s.store.buildReputationFeed(now, defaultReputationWindow, defaultReputationThreshold, defaultReputationMaxItems)
	if err != nil {
		switch {
		case errors.Is(err, os.ErrNotExist):
			writeError(w, http.StatusNotFound, "device not found")
		default:
			s.logger.Printf(`{"level":"error","msg":"reputation pull failed","device_id":"%s","error":"%s"}`, req.DeviceID, err)
			writeError(w, http.StatusInternalServerError, "failed to build reputation feed")
		}
		return
	}
	writeJSON(w, http.StatusOK, snapshot)
}
