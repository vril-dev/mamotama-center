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

func TestReputationPullPromotesMultiDeviceSignals(t *testing.T) {
	t.Parallel()

	cfg := newSignedTestConfig(t)
	cfg.Heartbeat.MaxClockSkew.Duration = 10 * time.Minute
	srv, err := NewServer(cfg, log.New(bytes.NewBuffer(nil), "", 0))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	keyA := newTestDeviceKey(t)
	keyB := newTestDeviceKey(t)
	baseTS := time.Date(2026, 3, 26, 1, 0, 0, 0, time.UTC)
	srv.nowFn = func() time.Time { return baseTS }

	for _, enroll := range []struct {
		deviceID string
		key      testDeviceKey
		nonce    string
	}{
		{deviceID: "device-reputation-a", key: keyA, nonce: "reputation-enroll-a"},
		{deviceID: "device-reputation-b", key: keyB, nonce: "reputation-enroll-b"},
	} {
		req := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(signedEnrollPayload(t, enroll.deviceID, enroll.key, baseTS, enroll.nonce)))
		req.Header.Set("X-License-Key", "test-license-key-1234")
		res := httptest.NewRecorder()
		srv.Handler().ServeHTTP(res, req)
		if res.Code != http.StatusOK {
			t.Fatalf("enroll %s failed: %d body=%s", enroll.deviceID, res.Code, res.Body.String())
		}
	}

	for _, push := range []struct {
		deviceID string
		key      testDeviceKey
		nonce    string
		raw      string
	}{
		{
			deviceID: "device-reputation-a",
			key:      keyA,
			nonce:    "reputation-push-a",
			raw:      `{"timestamp":"2026-03-26T01:00:10Z","kind":"security","event":"bot_challenge","remote_ip":"192.0.2.44","status":429}` + "\n",
		},
		{
			deviceID: "device-reputation-b",
			key:      keyB,
			nonce:    "reputation-push-b",
			raw:      `{"timestamp":"2026-03-26T01:00:11Z","kind":"security","event":"bot_challenge","remote_ip":"192.0.2.44","status":429}` + "\n",
		},
	} {
		payload := gzipBytes(t, []byte(push.raw))
		req := httptest.NewRequest(http.MethodPost, "/v1/logs/push", bytes.NewReader(signedLogsPushPayload(t, push.deviceID, push.key, baseTS.Add(time.Second), push.nonce, 1, payload)))
		res := httptest.NewRecorder()
		srv.Handler().ServeHTTP(res, req)
		if res.Code != http.StatusOK {
			t.Fatalf("logs push %s failed: %d body=%s", push.deviceID, res.Code, res.Body.String())
		}
	}

	pullReq := httptest.NewRequest(http.MethodPost, "/v1/reputation/pull", bytes.NewReader(signedReputationPullPayload(t, "device-reputation-a", keyA, baseTS.Add(2*time.Second), "reputation-pull-multi-device")))
	pullRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(pullRes, pullReq)
	if pullRes.Code != http.StatusOK {
		t.Fatalf("reputation pull failed: %d body=%s", pullRes.Code, pullRes.Body.String())
	}
	if !strings.Contains(pullRes.Body.String(), `"192.0.2.44/32"`) {
		t.Fatalf("expected multi-device ip to be promoted into blocklist: %s", pullRes.Body.String())
	}
	if !strings.Contains(pullRes.Body.String(), `"multi_device_ips":1`) {
		t.Fatalf("expected multi-device summary in response: %s", pullRes.Body.String())
	}
}

func TestAdminMetricsIncludesReputationSignals(t *testing.T) {
	t.Parallel()

	cfg := newSignedTestConfig(t)
	srv, err := NewServer(cfg, log.New(bytes.NewBuffer(nil), "", 0))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/admin/metrics", nil)
	addAdminAPIKey(req)
	res := httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("metrics failed: %d body=%s", res.Code, res.Body.String())
	}
	body := res.Body.String()
	if !strings.Contains(body, "mamotama_center_reputation_blocked_ips") {
		t.Fatalf("missing blocked_ips gauge: %s", body)
	}
	if !strings.Contains(body, "mamotama_center_reputation_multi_device_ips") {
		t.Fatalf("missing multi_device_ips gauge: %s", body)
	}
}
