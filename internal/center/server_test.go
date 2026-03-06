package center

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type testDeviceKey struct {
	Public       ed25519.PublicKey
	Private      ed25519.PrivateKey
	PublicKeyB64 string
	Fingerprint  string
	KeyID        string
}

func newSignedTestConfig(t *testing.T) Config {
	t.Helper()
	cfg := defaultConfig()
	cfg.Auth.EnrollmentLicenseKeys = []string{"test-license-key-1234"}
	cfg.Auth.RequireTLS = false
	cfg.Storage.Path = filepath.Join(t.TempDir(), "devices.json")
	return cfg
}

func newTestDeviceKey(t *testing.T) testDeviceKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal pub key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	pubB64 := base64.StdEncoding.EncodeToString(pemBytes)
	fingerprint, err := validatePublicKeyPEMBase64(pubB64)
	if err != nil {
		t.Fatalf("validate pub key: %v", err)
	}
	return testDeviceKey{
		Public:       pub,
		Private:      priv,
		PublicKeyB64: pubB64,
		Fingerprint:  fingerprint,
		KeyID:        defaultKeyIDFromFingerprint(fingerprint),
	}
}

func signedEnrollPayload(t *testing.T, deviceID string, key testDeviceKey, ts time.Time, nonce string) []byte {
	t.Helper()
	req := enrollRequest{
		DeviceID:                   deviceID,
		KeyID:                      key.KeyID,
		PublicKeyPEMBase64:         key.PublicKeyB64,
		PublicKeyFingerprintSHA256: key.Fingerprint,
		Timestamp:                  ts.UTC().Format(time.RFC3339Nano),
		Nonce:                      nonce,
	}
	req.BodyHash = hashStringHex(enrollBodyCanonical(req))
	signature := ed25519.Sign(key.Private, []byte(signedEnvelopeMessage(req.DeviceID, req.KeyID, req.Timestamp, req.Nonce, req.BodyHash)))
	req.SignatureB64 = base64.StdEncoding.EncodeToString(signature)
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal enroll payload: %v", err)
	}
	return b
}

func signedHeartbeatPayload(t *testing.T, deviceID string, key testDeviceKey, ts time.Time, nonce string, statusHash string, policy ...string) []byte {
	t.Helper()
	req := heartbeatRequest{
		DeviceID:   deviceID,
		KeyID:      key.KeyID,
		Timestamp:  ts.UTC().Format(time.RFC3339Nano),
		Nonce:      nonce,
		StatusHash: statusHash,
	}
	if len(policy) > 0 {
		req.CurrentPolicyVersion = normalizePolicyVersion(policy[0])
	}
	if len(policy) > 1 {
		req.CurrentPolicySHA256 = policy[1]
	}
	req.BodyHash = hashStringHex(heartbeatBodyCanonical(req))
	signature := ed25519.Sign(key.Private, []byte(signedEnvelopeMessage(req.DeviceID, req.KeyID, req.Timestamp, req.Nonce, req.BodyHash)))
	req.SignatureB64 = base64.StdEncoding.EncodeToString(signature)
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal heartbeat payload: %v", err)
	}
	return b
}

func signedPolicyPullPayload(t *testing.T, deviceID string, key testDeviceKey, ts time.Time, nonce string, currentVersion string, currentSHA string) []byte {
	t.Helper()
	req := policyPullRequest{
		DeviceID:             deviceID,
		KeyID:                key.KeyID,
		Timestamp:            ts.UTC().Format(time.RFC3339Nano),
		Nonce:                nonce,
		CurrentPolicyVersion: normalizePolicyVersion(currentVersion),
		CurrentPolicySHA256:  currentSHA,
	}
	req.BodyHash = hashStringHex(policyPullBodyCanonical(req))
	signature := ed25519.Sign(key.Private, []byte(signedEnvelopeMessage(req.DeviceID, req.KeyID, req.Timestamp, req.Nonce, req.BodyHash)))
	req.SignatureB64 = base64.StdEncoding.EncodeToString(signature)
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal policy pull payload: %v", err)
	}
	return b
}

func signedPolicyAckPayload(t *testing.T, deviceID string, key testDeviceKey, ts time.Time, nonce string, version string, sha string, resultStatus string, message string) []byte {
	t.Helper()
	req := policyAckRequest{
		DeviceID:      deviceID,
		KeyID:         key.KeyID,
		Timestamp:     ts.UTC().Format(time.RFC3339Nano),
		Nonce:         nonce,
		PolicyVersion: normalizePolicyVersion(version),
		PolicySHA256:  sha,
		ResultStatus:  resultStatus,
		Message:       message,
	}
	req.BodyHash = hashStringHex(policyAckBodyCanonical(req))
	signature := ed25519.Sign(key.Private, []byte(signedEnvelopeMessage(req.DeviceID, req.KeyID, req.Timestamp, req.Nonce, req.BodyHash)))
	req.SignatureB64 = base64.StdEncoding.EncodeToString(signature)
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal policy ack payload: %v", err)
	}
	return b
}

func signedLogsPushPayload(t *testing.T, deviceID string, key testDeviceKey, ts time.Time, nonce string, entryCount int, payload []byte) []byte {
	t.Helper()
	req := logsPushRequest{
		DeviceID:        deviceID,
		KeyID:           key.KeyID,
		Timestamp:       ts.UTC().Format(time.RFC3339Nano),
		Nonce:           nonce,
		EntryCount:      entryCount,
		ContentSHA256:   hashBytesHex(payload),
		ContentEncoding: "gzip+base64",
		PayloadB64:      base64.StdEncoding.EncodeToString(payload),
	}
	req.BodyHash = hashStringHex(logsPushBodyCanonical(req))
	signature := ed25519.Sign(key.Private, []byte(signedEnvelopeMessage(req.DeviceID, req.KeyID, req.Timestamp, req.Nonce, req.BodyHash)))
	req.SignatureB64 = base64.StdEncoding.EncodeToString(signature)
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal logs push payload: %v", err)
	}
	return b
}

func gzipBytes(t *testing.T, raw []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(raw); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func TestEnrollAndHeartbeat(t *testing.T) {
	t.Parallel()

	cfg := newSignedTestConfig(t)

	srv, err := NewServer(cfg, log.New(bytes.NewBuffer(nil), "", 0))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	key := newTestDeviceKey(t)
	enrollReq := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(signedEnrollPayload(t, "device-001", key, time.Now().UTC(), "enroll-nonce-001")))
	enrollReq.Header.Set("X-License-Key", "test-license-key-1234")
	enrollRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(enrollRes, enrollReq)
	if enrollRes.Code != http.StatusOK {
		t.Fatalf("unexpected enroll status: %d body=%s", enrollRes.Code, enrollRes.Body.String())
	}

	heartbeatReq := httptest.NewRequest(http.MethodPost, "/v1/heartbeat", bytes.NewReader(signedHeartbeatPayload(t, "device-001", key, time.Now().UTC(), "nonce-001", "abc123")))
	heartbeatRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(heartbeatRes, heartbeatReq)
	if heartbeatRes.Code != http.StatusOK {
		t.Fatalf("unexpected heartbeat status: %d body=%s", heartbeatRes.Code, heartbeatRes.Body.String())
	}
}

func TestEnrollRejectsInvalidLicense(t *testing.T) {
	t.Parallel()

	cfg := newSignedTestConfig(t)
	srv, err := NewServer(cfg, log.New(bytes.NewBuffer(nil), "", 0))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("X-License-Key", "wrong")
	res := httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("unexpected status: %d", res.Code)
	}
}

func TestHeartbeatRejectsReplay(t *testing.T) {
	t.Parallel()

	cfg := newSignedTestConfig(t)
	cfg.Heartbeat.MaxClockSkew.Duration = 10 * time.Minute

	srv, err := NewServer(cfg, log.New(bytes.NewBuffer(nil), "", 0))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	key := newTestDeviceKey(t)

	enrollReq := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(signedEnrollPayload(t, "device-002", key, time.Now().UTC(), "enroll-nonce-002")))
	enrollReq.Header.Set("X-License-Key", "test-license-key-1234")
	enrollRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(enrollRes, enrollReq)
	if enrollRes.Code != http.StatusOK {
		t.Fatalf("unexpected enroll status: %d body=%s", enrollRes.Code, enrollRes.Body.String())
	}

	heartbeatBody := signedHeartbeatPayload(t, "device-002", key, time.Now().UTC(), "nonce-1", "")

	firstReq := httptest.NewRequest(http.MethodPost, "/v1/heartbeat", bytes.NewReader(heartbeatBody))
	firstRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(firstRes, firstReq)
	if firstRes.Code != http.StatusOK {
		t.Fatalf("unexpected first heartbeat status: %d body=%s", firstRes.Code, firstRes.Body.String())
	}

	secondReq := httptest.NewRequest(http.MethodPost, "/v1/heartbeat", bytes.NewReader(heartbeatBody))
	secondRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(secondRes, secondReq)
	if secondRes.Code != http.StatusConflict {
		t.Fatalf("unexpected replay heartbeat status: %d body=%s", secondRes.Code, secondRes.Body.String())
	}
}

func TestDevicesStatusFlagsOffline(t *testing.T) {
	t.Parallel()

	cfg := newSignedTestConfig(t)
	cfg.Heartbeat.ExpectedInterval.Duration = 10 * time.Second
	cfg.Heartbeat.MissedHeartbeatsForOffline = 3
	cfg.Heartbeat.StaleAfter.Duration = 2 * time.Minute

	baseNow := time.Date(2026, 3, 6, 10, 0, 0, 0, time.UTC)
	srv, err := NewServer(cfg, log.New(bytes.NewBuffer(nil), "", 0))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	srv.nowFn = func() time.Time { return baseNow }

	key := newTestDeviceKey(t)
	enrollReq := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(signedEnrollPayload(t, "device-offline", key, baseNow, "enroll-nonce-offline")))
	enrollReq.Header.Set("X-License-Key", "test-license-key-1234")
	enrollRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(enrollRes, enrollReq)
	if enrollRes.Code != http.StatusOK {
		t.Fatalf("unexpected enroll status: %d body=%s", enrollRes.Code, enrollRes.Body.String())
	}

	srv.nowFn = func() time.Time { return baseNow.Add(45 * time.Second) } // > 10*3 sec -> offline

	listReq := httptest.NewRequest(http.MethodGet, "/v1/devices", nil)
	listRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(listRes, listReq)
	if listRes.Code != http.StatusOK {
		t.Fatalf("unexpected list status: %d body=%s", listRes.Code, listRes.Body.String())
	}

	var body struct {
		Devices []struct {
			DeviceID string `json:"device_id"`
			Status   string `json:"status"`
			Flagged  bool   `json:"flagged"`
		} `json:"devices"`
		Summary map[string]int `json:"summary"`
	}
	if err := json.Unmarshal(listRes.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode list body: %v", err)
	}
	if len(body.Devices) != 1 {
		t.Fatalf("unexpected device count: %d", len(body.Devices))
	}
	if body.Devices[0].Status != "offline" {
		t.Fatalf("unexpected status: %s", body.Devices[0].Status)
	}
	if !body.Devices[0].Flagged {
		t.Fatal("expected flagged=true for offline device")
	}
	if body.Summary["offline"] != 1 {
		t.Fatalf("unexpected offline summary: %+v", body.Summary)
	}
}

func TestStatusFromHeartbeatAge(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name         string
		hasHeartbeat bool
		age          time.Duration
		wantStatus   string
		wantFlagged  bool
	}{
		{name: "pending", hasHeartbeat: false, age: 10 * time.Second, wantStatus: "pending", wantFlagged: false},
		{name: "pending to offline", hasHeartbeat: false, age: 40 * time.Second, wantStatus: "offline", wantFlagged: true},
		{name: "online", hasHeartbeat: true, age: 5 * time.Second, wantStatus: "online", wantFlagged: false},
		{name: "degraded", hasHeartbeat: true, age: 20 * time.Second, wantStatus: "degraded", wantFlagged: true},
		{name: "offline", hasHeartbeat: true, age: 40 * time.Second, wantStatus: "offline", wantFlagged: true},
		{name: "stale", hasHeartbeat: true, age: 2 * time.Minute, wantStatus: "stale", wantFlagged: true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gotStatus, gotFlagged := statusFromHeartbeatAge(tc.hasHeartbeat, tc.age, 10*time.Second, 3, 90*time.Second)
			if gotStatus != tc.wantStatus || gotFlagged != tc.wantFlagged {
				t.Fatalf("statusFromHeartbeatAge() = (%s, %v), want (%s, %v)", gotStatus, gotFlagged, tc.wantStatus, tc.wantFlagged)
			}
		})
	}
}

func TestEnrollRejectsPublicKeyMismatchWithoutRotationHeader(t *testing.T) {
	t.Parallel()

	cfg := newSignedTestConfig(t)
	srv, err := NewServer(cfg, log.New(bytes.NewBuffer(nil), "", 0))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	makeKey := func(t *testing.T) testDeviceKey {
		t.Helper()
		return newTestDeviceKey(t)
	}

	baseTS := time.Now().UTC()
	key1 := makeKey(t)
	firstReq := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(signedEnrollPayload(t, "device-rotate", key1, baseTS, "enroll-nonce-rotate-1")))
	firstReq.Header.Set("X-License-Key", "test-license-key-1234")
	firstRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(firstRes, firstReq)
	if firstRes.Code != http.StatusOK {
		t.Fatalf("unexpected first enroll status: %d body=%s", firstRes.Code, firstRes.Body.String())
	}

	key2 := makeKey(t)
	secondReq := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(signedEnrollPayload(t, "device-rotate", key2, baseTS.Add(time.Second), "enroll-nonce-rotate-2")))
	secondReq.Header.Set("X-License-Key", "test-license-key-1234")
	secondRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(secondRes, secondReq)
	if secondRes.Code != http.StatusConflict {
		t.Fatalf("expected conflict for key mismatch, got %d body=%s", secondRes.Code, secondRes.Body.String())
	}
}

func TestEnrollAllowsPublicKeyRotationWithHeader(t *testing.T) {
	t.Parallel()

	cfg := newSignedTestConfig(t)
	srv, err := NewServer(cfg, log.New(bytes.NewBuffer(nil), "", 0))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	makeKey := func(t *testing.T) testDeviceKey {
		t.Helper()
		return newTestDeviceKey(t)
	}

	baseTS := time.Now().UTC()
	key1 := makeKey(t)
	firstReq := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(signedEnrollPayload(t, "device-rotate-ok", key1, baseTS, "enroll-nonce-rotate-ok-1")))
	firstReq.Header.Set("X-License-Key", "test-license-key-1234")
	firstRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(firstRes, firstReq)
	if firstRes.Code != http.StatusOK {
		t.Fatalf("unexpected first enroll status: %d body=%s", firstRes.Code, firstRes.Body.String())
	}

	key2 := makeKey(t)
	secondReq := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(signedEnrollPayload(t, "device-rotate-ok", key2, baseTS.Add(time.Second), "enroll-nonce-rotate-ok-2")))
	secondReq.Header.Set("X-License-Key", "test-license-key-1234")
	secondReq.Header.Set("X-Allow-Key-Rotation", "true")
	secondRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(secondRes, secondReq)
	if secondRes.Code != http.StatusOK {
		t.Fatalf("expected key rotation success, got %d body=%s", secondRes.Code, secondRes.Body.String())
	}
}

func TestEnrollRejectsFingerprintReuseAcrossDeviceIDs(t *testing.T) {
	t.Parallel()

	cfg := newSignedTestConfig(t)
	srv, err := NewServer(cfg, log.New(bytes.NewBuffer(nil), "", 0))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	key := newTestDeviceKey(t)
	baseTS := time.Now().UTC()

	makeReq := func(deviceID string, ts time.Time, nonce string) *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(signedEnrollPayload(t, deviceID, key, ts, nonce)))
		req.Header.Set("X-License-Key", "test-license-key-1234")
		return req
	}

	firstRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(firstRes, makeReq("device-a", baseTS, "enroll-nonce-device-a"))
	if firstRes.Code != http.StatusOK {
		t.Fatalf("unexpected first enroll status: %d body=%s", firstRes.Code, firstRes.Body.String())
	}

	secondRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(secondRes, makeReq("device-b", baseTS.Add(time.Second), "enroll-nonce-device-b"))
	if secondRes.Code != http.StatusConflict {
		t.Fatalf("expected conflict for fingerprint reuse, got %d body=%s", secondRes.Code, secondRes.Body.String())
	}
}

func TestRetireDeviceBlocksHeartbeat(t *testing.T) {
	t.Parallel()

	cfg := newSignedTestConfig(t)
	cfg.Heartbeat.MaxClockSkew.Duration = 10 * time.Minute

	srv, err := NewServer(cfg, log.New(bytes.NewBuffer(nil), "", 0))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	key := newTestDeviceKey(t)
	enrollReq := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(signedEnrollPayload(t, "device-retire", key, time.Now().UTC(), "enroll-nonce-retire")))
	enrollReq.Header.Set("X-License-Key", "test-license-key-1234")
	enrollRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(enrollRes, enrollReq)
	if enrollRes.Code != http.StatusOK {
		t.Fatalf("unexpected enroll status: %d body=%s", enrollRes.Code, enrollRes.Body.String())
	}

	retireReqBody, _ := json.Marshal(map[string]any{"reason": "maintenance"})
	retireReq := httptest.NewRequest(http.MethodPost, "/v1/devices/device-retire:retire", bytes.NewReader(retireReqBody))
	retireReq.Header.Set("X-License-Key", "test-license-key-1234")
	retireRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(retireRes, retireReq)
	if retireRes.Code != http.StatusOK {
		t.Fatalf("unexpected retire status: %d body=%s", retireRes.Code, retireRes.Body.String())
	}

	var retireBody struct {
		DeviceStatus struct {
			Status  string `json:"status"`
			Flagged bool   `json:"flagged"`
		} `json:"device_status"`
	}
	if err := json.Unmarshal(retireRes.Body.Bytes(), &retireBody); err != nil {
		t.Fatalf("decode retire body: %v", err)
	}
	if retireBody.DeviceStatus.Status != "retired" || !retireBody.DeviceStatus.Flagged {
		t.Fatalf("unexpected retire status body: %s", retireRes.Body.String())
	}

	heartbeatReq := httptest.NewRequest(http.MethodPost, "/v1/heartbeat", bytes.NewReader(signedHeartbeatPayload(t, "device-retire", key, time.Now().UTC(), "nonce-after-retire", "")))
	heartbeatRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(heartbeatRes, heartbeatReq)
	if heartbeatRes.Code != http.StatusGone {
		t.Fatalf("expected retired heartbeat to be rejected, got %d body=%s", heartbeatRes.Code, heartbeatRes.Body.String())
	}
}

func TestRetireRequiresValidLicense(t *testing.T) {
	t.Parallel()

	cfg := newSignedTestConfig(t)
	srv, err := NewServer(cfg, log.New(bytes.NewBuffer(nil), "", 0))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	key := newTestDeviceKey(t)
	enrollReq := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(signedEnrollPayload(t, "device-retire-auth", key, time.Now().UTC(), "enroll-nonce-retire-auth")))
	enrollReq.Header.Set("X-License-Key", "test-license-key-1234")
	enrollRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(enrollRes, enrollReq)
	if enrollRes.Code != http.StatusOK {
		t.Fatalf("unexpected enroll status: %d body=%s", enrollRes.Code, enrollRes.Body.String())
	}

	retireReq := httptest.NewRequest(http.MethodPost, "/v1/devices/device-retire-auth:retire", bytes.NewReader([]byte(`{}`)))
	retireRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(retireRes, retireReq)
	if retireRes.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized, got %d body=%s", retireRes.Code, retireRes.Body.String())
	}
}

func TestReEnrollReactivatesRetiredDevice(t *testing.T) {
	t.Parallel()

	cfg := newSignedTestConfig(t)
	srv, err := NewServer(cfg, log.New(bytes.NewBuffer(nil), "", 0))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	key := newTestDeviceKey(t)
	baseTS := time.Now().UTC()
	enrollReqBody := signedEnrollPayload(t, "device-reactivate", key, baseTS, "enroll-nonce-reactivate-1")

	enrollReq := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(enrollReqBody))
	enrollReq.Header.Set("X-License-Key", "test-license-key-1234")
	enrollRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(enrollRes, enrollReq)
	if enrollRes.Code != http.StatusOK {
		t.Fatalf("unexpected first enroll status: %d body=%s", enrollRes.Code, enrollRes.Body.String())
	}

	retireReq := httptest.NewRequest(http.MethodPost, "/v1/devices/device-reactivate:retire", bytes.NewReader([]byte(`{"reason":"test"}`)))
	retireReq.Header.Set("X-License-Key", "test-license-key-1234")
	retireRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(retireRes, retireReq)
	if retireRes.Code != http.StatusOK {
		t.Fatalf("unexpected retire status: %d body=%s", retireRes.Code, retireRes.Body.String())
	}

	reenrollReq := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(signedEnrollPayload(t, "device-reactivate", key, baseTS.Add(time.Second), "enroll-nonce-reactivate-2")))
	reenrollReq.Header.Set("X-License-Key", "test-license-key-1234")
	reenrollRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(reenrollRes, reenrollReq)
	if reenrollRes.Code != http.StatusOK {
		t.Fatalf("unexpected re-enroll status: %d body=%s", reenrollRes.Code, reenrollRes.Body.String())
	}
	var reenrollBody struct {
		Reactivated bool `json:"reactivated"`
		DeviceState struct {
			Status string `json:"status"`
		} `json:"device_status"`
	}
	if err := json.Unmarshal(reenrollRes.Body.Bytes(), &reenrollBody); err != nil {
		t.Fatalf("decode re-enroll body: %v", err)
	}
	if !reenrollBody.Reactivated {
		t.Fatalf("expected reactivated=true, body=%s", reenrollRes.Body.String())
	}
	if reenrollBody.DeviceState.Status == "retired" {
		t.Fatalf("expected non-retired status after re-enroll, body=%s", reenrollRes.Body.String())
	}
}

func TestEnrollRequiresTLSWhenEnabled(t *testing.T) {
	t.Parallel()

	cfg := newSignedTestConfig(t)
	cfg.Auth.RequireTLS = true
	cfg.Auth.TrustForwardedProto = false
	srv, err := NewServer(cfg, log.New(bytes.NewBuffer(nil), "", 0))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	key := newTestDeviceKey(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(signedEnrollPayload(t, "device-tls", key, time.Now().UTC(), "enroll-nonce-tls")))
	req.Header.Set("X-License-Key", "test-license-key-1234")
	res := httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusUpgradeRequired {
		t.Fatalf("expected tls required, got %d body=%s", res.Code, res.Body.String())
	}
}

func TestRevokeKeyBlocksHeartbeatUntilReEnroll(t *testing.T) {
	t.Parallel()

	cfg := newSignedTestConfig(t)
	cfg.Heartbeat.MaxClockSkew.Duration = 10 * time.Minute
	srv, err := NewServer(cfg, log.New(bytes.NewBuffer(nil), "", 0))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	baseTS := time.Now().UTC()
	key1 := newTestDeviceKey(t)
	enrollReq := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(signedEnrollPayload(t, "device-revoke", key1, baseTS, "enroll-nonce-revoke-1")))
	enrollReq.Header.Set("X-License-Key", "test-license-key-1234")
	enrollRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(enrollRes, enrollReq)
	if enrollRes.Code != http.StatusOK {
		t.Fatalf("unexpected enroll status: %d body=%s", enrollRes.Code, enrollRes.Body.String())
	}

	revokeReq := httptest.NewRequest(http.MethodPost, "/v1/devices/device-revoke:revoke", bytes.NewReader([]byte(`{"reason":"compromised"}`)))
	revokeReq.Header.Set("X-License-Key", "test-license-key-1234")
	revokeRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(revokeRes, revokeReq)
	if revokeRes.Code != http.StatusOK {
		t.Fatalf("unexpected revoke status: %d body=%s", revokeRes.Code, revokeRes.Body.String())
	}

	heartbeatReq := httptest.NewRequest(http.MethodPost, "/v1/heartbeat", bytes.NewReader(signedHeartbeatPayload(t, "device-revoke", key1, baseTS.Add(time.Second), "hb-nonce-revoke-1", "")))
	heartbeatRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(heartbeatRes, heartbeatReq)
	if heartbeatRes.Code != http.StatusGone {
		t.Fatalf("expected heartbeat rejected after revoke, got %d body=%s", heartbeatRes.Code, heartbeatRes.Body.String())
	}

	key2 := newTestDeviceKey(t)
	reenrollReq := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(signedEnrollPayload(t, "device-revoke", key2, baseTS.Add(2*time.Second), "enroll-nonce-revoke-2")))
	reenrollReq.Header.Set("X-License-Key", "test-license-key-1234")
	reenrollReq.Header.Set("X-Allow-Key-Rotation", "true")
	reenrollRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(reenrollRes, reenrollReq)
	if reenrollRes.Code != http.StatusOK {
		t.Fatalf("unexpected re-enroll after revoke status: %d body=%s", reenrollRes.Code, reenrollRes.Body.String())
	}
}

func TestHeartbeatRejectsNonceReuse(t *testing.T) {
	t.Parallel()

	cfg := newSignedTestConfig(t)
	cfg.Heartbeat.MaxClockSkew.Duration = 10 * time.Minute
	srv, err := NewServer(cfg, log.New(bytes.NewBuffer(nil), "", 0))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	baseTS := time.Now().UTC()
	key := newTestDeviceKey(t)
	enrollReq := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(signedEnrollPayload(t, "device-nonce", key, baseTS, "enroll-nonce-nonce-1")))
	enrollReq.Header.Set("X-License-Key", "test-license-key-1234")
	enrollRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(enrollRes, enrollReq)
	if enrollRes.Code != http.StatusOK {
		t.Fatalf("unexpected enroll status: %d body=%s", enrollRes.Code, enrollRes.Body.String())
	}

	firstReq := httptest.NewRequest(http.MethodPost, "/v1/heartbeat", bytes.NewReader(signedHeartbeatPayload(t, "device-nonce", key, baseTS.Add(time.Second), "hb-nonce-1", "")))
	firstRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(firstRes, firstReq)
	if firstRes.Code != http.StatusOK {
		t.Fatalf("unexpected first heartbeat status: %d body=%s", firstRes.Code, firstRes.Body.String())
	}

	secondReq := httptest.NewRequest(http.MethodPost, "/v1/heartbeat", bytes.NewReader(signedHeartbeatPayload(t, "device-nonce", key, baseTS.Add(2*time.Second), "hb-nonce-1", "")))
	secondRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(secondRes, secondReq)
	if secondRes.Code != http.StatusConflict {
		t.Fatalf("expected heartbeat nonce reuse conflict, got %d body=%s", secondRes.Code, secondRes.Body.String())
	}
}

func TestHeartbeatAllowsNonceReuseAfterTTL(t *testing.T) {
	t.Parallel()

	cfg := newSignedTestConfig(t)
	cfg.Auth.NonceTTL.Duration = 2 * time.Second
	cfg.Heartbeat.MaxClockSkew.Duration = 10 * time.Minute
	srv, err := NewServer(cfg, log.New(bytes.NewBuffer(nil), "", 0))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	baseTS := time.Now().UTC()
	key := newTestDeviceKey(t)
	enrollReq := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(signedEnrollPayload(t, "device-nonce-ttl", key, baseTS, "enroll-nonce-ttl-1")))
	enrollReq.Header.Set("X-License-Key", "test-license-key-1234")
	enrollRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(enrollRes, enrollReq)
	if enrollRes.Code != http.StatusOK {
		t.Fatalf("unexpected enroll status: %d body=%s", enrollRes.Code, enrollRes.Body.String())
	}

	srv.nowFn = func() time.Time { return baseTS.Add(time.Second) }
	firstReq := httptest.NewRequest(http.MethodPost, "/v1/heartbeat", bytes.NewReader(signedHeartbeatPayload(t, "device-nonce-ttl", key, baseTS.Add(time.Second), "hb-nonce-ttl", "")))
	firstRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(firstRes, firstReq)
	if firstRes.Code != http.StatusOK {
		t.Fatalf("unexpected first heartbeat status: %d body=%s", firstRes.Code, firstRes.Body.String())
	}

	srv.nowFn = func() time.Time { return baseTS.Add(4 * time.Second) }
	secondReq := httptest.NewRequest(http.MethodPost, "/v1/heartbeat", bytes.NewReader(signedHeartbeatPayload(t, "device-nonce-ttl", key, baseTS.Add(4*time.Second), "hb-nonce-ttl", "")))
	secondRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(secondRes, secondReq)
	if secondRes.Code != http.StatusOK {
		t.Fatalf("expected heartbeat nonce reuse allowed after ttl, got %d body=%s", secondRes.Code, secondRes.Body.String())
	}
}

func TestEnrollRejectsNonceReuseWithinTTL(t *testing.T) {
	t.Parallel()

	cfg := newSignedTestConfig(t)
	cfg.Auth.NonceTTL.Duration = 10 * time.Minute
	cfg.Heartbeat.MaxClockSkew.Duration = 10 * time.Minute
	srv, err := NewServer(cfg, log.New(bytes.NewBuffer(nil), "", 0))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	baseTS := time.Now().UTC()
	key := newTestDeviceKey(t)

	firstReq := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(signedEnrollPayload(t, "device-enroll-nonce", key, baseTS, "enroll-nonce-reuse")))
	firstReq.Header.Set("X-License-Key", "test-license-key-1234")
	firstRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(firstRes, firstReq)
	if firstRes.Code != http.StatusOK {
		t.Fatalf("unexpected first enroll status: %d body=%s", firstRes.Code, firstRes.Body.String())
	}

	secondReq := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(signedEnrollPayload(t, "device-enroll-nonce", key, baseTS.Add(time.Second), "enroll-nonce-reuse")))
	secondReq.Header.Set("X-License-Key", "test-license-key-1234")
	secondRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(secondRes, secondReq)
	if secondRes.Code != http.StatusConflict {
		t.Fatalf("expected enroll nonce reuse conflict, got %d body=%s", secondRes.Code, secondRes.Body.String())
	}
}

func TestEndToEndEnrollHeartbeatRevokeReEnrollFlow(t *testing.T) {
	t.Parallel()

	cfg := newSignedTestConfig(t)
	cfg.Heartbeat.MaxClockSkew.Duration = 10 * time.Minute
	srv, err := NewServer(cfg, log.New(bytes.NewBuffer(nil), "", 0))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	baseTS := time.Now().UTC()
	key1 := newTestDeviceKey(t)
	key2 := newTestDeviceKey(t)

	enroll1Req := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(signedEnrollPayload(t, "device-e2e", key1, baseTS, "e2e-enroll-1")))
	enroll1Req.Header.Set("X-License-Key", "test-license-key-1234")
	enroll1Res := httptest.NewRecorder()
	srv.Handler().ServeHTTP(enroll1Res, enroll1Req)
	if enroll1Res.Code != http.StatusOK {
		t.Fatalf("enroll1 failed: %d body=%s", enroll1Res.Code, enroll1Res.Body.String())
	}

	hb1Req := httptest.NewRequest(http.MethodPost, "/v1/heartbeat", bytes.NewReader(signedHeartbeatPayload(t, "device-e2e", key1, baseTS.Add(time.Second), "e2e-hb-1", "")))
	hb1Res := httptest.NewRecorder()
	srv.Handler().ServeHTTP(hb1Res, hb1Req)
	if hb1Res.Code != http.StatusOK {
		t.Fatalf("heartbeat1 failed: %d body=%s", hb1Res.Code, hb1Res.Body.String())
	}

	revokeReq := httptest.NewRequest(http.MethodPost, "/v1/devices/device-e2e:revoke", bytes.NewReader([]byte(`{"reason":"test"}`)))
	revokeReq.Header.Set("X-License-Key", "test-license-key-1234")
	revokeRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(revokeRes, revokeReq)
	if revokeRes.Code != http.StatusOK {
		t.Fatalf("revoke failed: %d body=%s", revokeRes.Code, revokeRes.Body.String())
	}

	hbAfterRevokeReq := httptest.NewRequest(http.MethodPost, "/v1/heartbeat", bytes.NewReader(signedHeartbeatPayload(t, "device-e2e", key1, baseTS.Add(2*time.Second), "e2e-hb-2", "")))
	hbAfterRevokeRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(hbAfterRevokeRes, hbAfterRevokeReq)
	if hbAfterRevokeRes.Code != http.StatusGone {
		t.Fatalf("heartbeat after revoke should fail: %d body=%s", hbAfterRevokeRes.Code, hbAfterRevokeRes.Body.String())
	}

	enroll2Req := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(signedEnrollPayload(t, "device-e2e", key2, baseTS.Add(3*time.Second), "e2e-enroll-2")))
	enroll2Req.Header.Set("X-License-Key", "test-license-key-1234")
	enroll2Req.Header.Set("X-Allow-Key-Rotation", "true")
	enroll2Res := httptest.NewRecorder()
	srv.Handler().ServeHTTP(enroll2Res, enroll2Req)
	if enroll2Res.Code != http.StatusOK {
		t.Fatalf("re-enroll failed: %d body=%s", enroll2Res.Code, enroll2Res.Body.String())
	}

	hb2Req := httptest.NewRequest(http.MethodPost, "/v1/heartbeat", bytes.NewReader(signedHeartbeatPayload(t, "device-e2e", key2, baseTS.Add(4*time.Second), "e2e-hb-3", "")))
	hb2Res := httptest.NewRecorder()
	srv.Handler().ServeHTTP(hb2Res, hb2Req)
	if hb2Res.Code != http.StatusOK {
		t.Fatalf("heartbeat2 failed: %d body=%s", hb2Res.Code, hb2Res.Body.String())
	}
}

func TestPolicyAssignPullAckFlow(t *testing.T) {
	t.Parallel()

	cfg := newSignedTestConfig(t)
	cfg.Heartbeat.MaxClockSkew.Duration = 10 * time.Minute
	srv, err := NewServer(cfg, log.New(bytes.NewBuffer(nil), "", 0))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	key := newTestDeviceKey(t)
	baseTS := time.Now().UTC()

	enrollReq := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(signedEnrollPayload(t, "device-policy", key, baseTS, "policy-enroll-1")))
	enrollReq.Header.Set("X-License-Key", "test-license-key-1234")
	enrollRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(enrollRes, enrollReq)
	if enrollRes.Code != http.StatusOK {
		t.Fatalf("enroll failed: %d body=%s", enrollRes.Code, enrollRes.Body.String())
	}

	putPolicyReq := httptest.NewRequest(http.MethodPost, "/v1/policies", bytes.NewBufferString(`{"version":"waf-2026-03-06","waf_raw":"{\"enabled\":true,\"rule_files\":[\"./rules/mamotama.conf\"]}","note":"initial"}`))
	putPolicyReq.Header.Set("X-License-Key", "test-license-key-1234")
	putPolicyRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(putPolicyRes, putPolicyReq)
	if putPolicyRes.Code != http.StatusOK {
		t.Fatalf("policy upsert failed: %d body=%s", putPolicyRes.Code, putPolicyRes.Body.String())
	}
	var putBody struct {
		Policy PolicyRecord `json:"policy"`
	}
	if err := json.Unmarshal(putPolicyRes.Body.Bytes(), &putBody); err != nil {
		t.Fatalf("decode policy upsert body: %v", err)
	}
	if putBody.Policy.Version != "waf-2026-03-06" || putBody.Policy.SHA256 == "" {
		t.Fatalf("unexpected policy body: %s", putPolicyRes.Body.String())
	}

	assignReq := httptest.NewRequest(http.MethodPost, "/v1/devices/device-policy:assign-policy", bytes.NewBufferString(`{"version":"waf-2026-03-06"}`))
	assignReq.Header.Set("X-License-Key", "test-license-key-1234")
	assignRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(assignRes, assignReq)
	if assignRes.Code != http.StatusOK {
		t.Fatalf("assign policy failed: %d body=%s", assignRes.Code, assignRes.Body.String())
	}

	hbReq := httptest.NewRequest(http.MethodPost, "/v1/heartbeat", bytes.NewReader(signedHeartbeatPayload(t, "device-policy", key, baseTS.Add(time.Second), "policy-hb-1", "")))
	hbRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(hbRes, hbReq)
	if hbRes.Code != http.StatusOK {
		t.Fatalf("heartbeat failed: %d body=%s", hbRes.Code, hbRes.Body.String())
	}
	var hbBody map[string]any
	if err := json.Unmarshal(hbRes.Body.Bytes(), &hbBody); err != nil {
		t.Fatalf("decode heartbeat body: %v", err)
	}
	policyInfo, _ := hbBody["policy"].(map[string]any)
	if updateRequired, _ := policyInfo["update_required"].(bool); !updateRequired {
		t.Fatalf("expected update_required=true, body=%s", hbRes.Body.String())
	}

	pullReq := httptest.NewRequest(http.MethodPost, "/v1/policy/pull", bytes.NewReader(signedPolicyPullPayload(t, "device-policy", key, baseTS.Add(2*time.Second), "policy-pull-1", "", "")))
	pullRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(pullRes, pullReq)
	if pullRes.Code != http.StatusOK {
		t.Fatalf("policy pull failed: %d body=%s", pullRes.Code, pullRes.Body.String())
	}
	var pullBody struct {
		UpdateRequired bool `json:"update_required"`
		Policy         struct {
			Version string `json:"version"`
			SHA256  string `json:"sha256"`
		} `json:"policy"`
	}
	if err := json.Unmarshal(pullRes.Body.Bytes(), &pullBody); err != nil {
		t.Fatalf("decode pull body: %v", err)
	}
	if !pullBody.UpdateRequired {
		t.Fatalf("expected pull update_required=true, body=%s", pullRes.Body.String())
	}
	if pullBody.Policy.Version != "waf-2026-03-06" || pullBody.Policy.SHA256 == "" {
		t.Fatalf("unexpected pull policy: %s", pullRes.Body.String())
	}

	ackReq := httptest.NewRequest(http.MethodPost, "/v1/policy/ack", bytes.NewReader(signedPolicyAckPayload(t, "device-policy", key, baseTS.Add(3*time.Second), "policy-ack-1", pullBody.Policy.Version, pullBody.Policy.SHA256, "applied", "")))
	ackRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(ackRes, ackReq)
	if ackRes.Code != http.StatusOK {
		t.Fatalf("policy ack failed: %d body=%s", ackRes.Code, ackRes.Body.String())
	}

	hbReq2 := httptest.NewRequest(http.MethodPost, "/v1/heartbeat", bytes.NewReader(signedHeartbeatPayload(t, "device-policy", key, baseTS.Add(4*time.Second), "policy-hb-2", "", pullBody.Policy.Version, pullBody.Policy.SHA256)))
	hbRes2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(hbRes2, hbReq2)
	if hbRes2.Code != http.StatusOK {
		t.Fatalf("second heartbeat failed: %d body=%s", hbRes2.Code, hbRes2.Body.String())
	}
	if err := json.Unmarshal(hbRes2.Body.Bytes(), &hbBody); err != nil {
		t.Fatalf("decode second heartbeat body: %v", err)
	}
	policyInfo, _ = hbBody["policy"].(map[string]any)
	if updateRequired, _ := policyInfo["update_required"].(bool); updateRequired {
		t.Fatalf("expected update_required=false after applied ack, body=%s", hbRes2.Body.String())
	}
}

func TestLogsPushStoresCompressedBatch(t *testing.T) {
	t.Parallel()

	cfg := newSignedTestConfig(t)
	cfg.Heartbeat.MaxClockSkew.Duration = 10 * time.Minute
	srv, err := NewServer(cfg, log.New(bytes.NewBuffer(nil), "", 0))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	key := newTestDeviceKey(t)
	baseTS := time.Now().UTC()

	enrollReq := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(signedEnrollPayload(t, "device-logs", key, baseTS, "logs-enroll-1")))
	enrollReq.Header.Set("X-License-Key", "test-license-key-1234")
	enrollRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(enrollRes, enrollReq)
	if enrollRes.Code != http.StatusOK {
		t.Fatalf("enroll failed: %d body=%s", enrollRes.Code, enrollRes.Body.String())
	}

	payload := gzipBytes(t, []byte(`{"kind":"security","msg":"waf blocked","request_id":"r1"}`+"\n"+`{"kind":"access","msg":"proxy ok","request_id":"r2"}`+"\n"))
	pushReq := httptest.NewRequest(http.MethodPost, "/v1/logs/push", bytes.NewReader(signedLogsPushPayload(t, "device-logs", key, baseTS.Add(time.Second), "logs-push-1", 2, payload)))
	pushRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(pushRes, pushReq)
	if pushRes.Code != http.StatusOK {
		t.Fatalf("logs push failed: %d body=%s", pushRes.Code, pushRes.Body.String())
	}

	rec, ok := srv.store.get("device-logs")
	if !ok {
		t.Fatal("expected stored device")
	}
	if rec.LastLogUploadEntries != 2 || rec.LastLogUploadBytes <= 0 || rec.LastLogUploadSHA256 == "" || rec.LastLogUploadAt == "" {
		t.Fatalf("unexpected log upload metadata: %+v", rec)
	}

	logDir := filepath.Join(filepath.Dir(cfg.Storage.Path), "logs", "device-logs")
	entries, err := os.ReadDir(logDir)
	if err != nil {
		t.Fatalf("read log dir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected one stored log batch, got %d", len(entries))
	}
	if !entries[0].Type().IsRegular() {
		t.Fatalf("expected regular file, got %v", entries[0].Type())
	}
}
