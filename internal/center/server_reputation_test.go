package center

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func signedReputationPullPayload(t *testing.T, deviceID string, key testDeviceKey, ts time.Time, nonce string) []byte {
	t.Helper()
	req := reputationPullRequest{
		DeviceID:  deviceID,
		KeyID:     key.KeyID,
		Timestamp: ts.UTC().Format(time.RFC3339Nano),
		Nonce:     nonce,
	}
	req.BodyHash = hashStringHex(reputationPullBodyCanonical(req))
	signature := ed25519.Sign(key.Private, []byte(signedEnvelopeMessage(req.DeviceID, req.KeyID, req.Timestamp, req.Nonce, req.BodyHash)))
	req.SignatureB64 = base64.StdEncoding.EncodeToString(signature)
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal reputation pull payload: %v", err)
	}
	return b
}

func TestReputationPullReturnsAggregatedBlocklist(t *testing.T) {
	t.Parallel()

	cfg := newSignedTestConfig(t)
	cfg.Heartbeat.MaxClockSkew.Duration = 10 * time.Minute
	srv, err := NewServer(cfg, log.New(bytes.NewBuffer(nil), "", 0))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	key := newTestDeviceKey(t)
	baseTS := time.Date(2026, 3, 26, 0, 0, 0, 0, time.UTC)
	srv.nowFn = func() time.Time { return baseTS }

	enrollReq := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(signedEnrollPayload(t, "device-reputation", key, baseTS, "reputation-enroll-1")))
	enrollReq.Header.Set("X-License-Key", "test-license-key-1234")
	enrollRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(enrollRes, enrollReq)
	if enrollRes.Code != http.StatusOK {
		t.Fatalf("enroll failed: %d body=%s", enrollRes.Code, enrollRes.Body.String())
	}

	logRaw := []byte(
		`{"timestamp":"2026-03-26T00:00:10Z","kind":"security","event":"waf_block","remote_ip":"203.0.113.10","status":403}` + "\n" +
			`{"timestamp":"2026-03-26T00:00:11Z","kind":"security","event":"waf_block","remote_ip":"203.0.113.10","status":403}` + "\n" +
			`{"timestamp":"2026-03-26T00:00:12Z","kind":"security","event":"semantic_anomaly","action":"challenge","remote_ip":"198.51.100.20","status":429}` + "\n",
	)
	payload := gzipBytes(t, logRaw)
	pushReq := httptest.NewRequest(http.MethodPost, "/v1/logs/push", bytes.NewReader(signedLogsPushPayload(t, "device-reputation", key, baseTS.Add(time.Second), "reputation-push-1", 3, payload)))
	pushRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(pushRes, pushReq)
	if pushRes.Code != http.StatusOK {
		t.Fatalf("logs push failed: %d body=%s", pushRes.Code, pushRes.Body.String())
	}

	pullReq := httptest.NewRequest(http.MethodPost, "/v1/reputation/pull", bytes.NewReader(signedReputationPullPayload(t, "device-reputation", key, baseTS.Add(2*time.Second), "reputation-pull-1")))
	pullRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(pullRes, pullReq)
	if pullRes.Code != http.StatusOK {
		t.Fatalf("reputation pull failed: %d body=%s", pullRes.Code, pullRes.Body.String())
	}
	if !strings.Contains(pullRes.Body.String(), `"203.0.113.10/32"`) {
		t.Fatalf("expected blocklist entry in response: %s", pullRes.Body.String())
	}
	if strings.Contains(pullRes.Body.String(), `"198.51.100.20/32"`) {
		t.Fatalf("did not expect low-score IP in blocklist: %s", pullRes.Body.String())
	}
}
