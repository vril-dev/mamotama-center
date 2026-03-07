package center

import (
	"archive/tar"
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
	"sort"
	"strconv"
	"strings"
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

const (
	testAdminAPIKey      = "test-admin-api-key-1234"
	testAdminReadAPIKey  = "test-admin-read-api-key-1234"
	testAdminWriteAPIKey = "test-admin-write-api-key-1234"
)

func newSignedTestConfig(t *testing.T) Config {
	t.Helper()
	cfg := defaultConfig()
	cfg.Auth.EnrollmentLicenseKeys = []string{"test-license-key-1234"}
	cfg.Auth.AdminAPIKeys = []string{testAdminAPIKey}
	cfg.Auth.RequireTLS = false
	cfg.Storage.Path = filepath.Join(t.TempDir(), "devices.json")
	return cfg
}

func addAdminAPIKey(req *http.Request) {
	addAdminAPIKeyWithValue(req, testAdminAPIKey)
}

func addAdminAPIKeyWithValue(req *http.Request, key string) {
	req.Header.Set("X-API-Key", key)
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

func signedReleasePullPayload(t *testing.T, deviceID string, key testDeviceKey, ts time.Time, nonce string, currentVersion string, currentSHA string) []byte {
	t.Helper()
	req := releasePullRequest{
		DeviceID:              deviceID,
		KeyID:                 key.KeyID,
		Timestamp:             ts.UTC().Format(time.RFC3339Nano),
		Nonce:                 nonce,
		CurrentReleaseVersion: normalizePolicyVersion(currentVersion),
		CurrentReleaseSHA256:  currentSHA,
	}
	req.BodyHash = hashStringHex(releasePullBodyCanonical(req))
	signature := ed25519.Sign(key.Private, []byte(signedEnvelopeMessage(req.DeviceID, req.KeyID, req.Timestamp, req.Nonce, req.BodyHash)))
	req.SignatureB64 = base64.StdEncoding.EncodeToString(signature)
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal release pull payload: %v", err)
	}
	return b
}

func signedReleaseAckPayload(t *testing.T, deviceID string, key testDeviceKey, ts time.Time, nonce string, version string, sha string, resultStatus string, message string) []byte {
	t.Helper()
	req := releaseAckRequest{
		DeviceID:       deviceID,
		KeyID:          key.KeyID,
		Timestamp:      ts.UTC().Format(time.RFC3339Nano),
		Nonce:          nonce,
		ReleaseVersion: normalizePolicyVersion(version),
		ReleaseSHA256:  sha,
		ResultStatus:   resultStatus,
		Message:        message,
	}
	req.BodyHash = hashStringHex(releaseAckBodyCanonical(req))
	signature := ed25519.Sign(key.Private, []byte(signedEnvelopeMessage(req.DeviceID, req.KeyID, req.Timestamp, req.Nonce, req.BodyHash)))
	req.SignatureB64 = base64.StdEncoding.EncodeToString(signature)
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal release ack payload: %v", err)
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

func tgzBundleBase64(t *testing.T, files map[string]string) (string, string) {
	t.Helper()
	keys := make([]string, 0, len(files))
	for k := range files {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, name := range keys {
		body := []byte(files[name])
		hdr := &tar.Header{
			Name: name,
			Mode: 0o644,
			Size: int64(len(body)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar write header %q: %v", name, err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatalf("tar write body %q: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}

	payload := buf.Bytes()
	return base64.StdEncoding.EncodeToString(payload), hashBytesHex(payload)
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
	cfg.Heartbeat.MaxClockSkew.Duration = 24 * time.Hour

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
	addAdminAPIKey(listReq)
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
	addAdminAPIKey(retireReq)
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

func TestRetireRequiresAdminAPIKey(t *testing.T) {
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

	retireReqNoKey := httptest.NewRequest(http.MethodPost, "/v1/devices/device-retire-auth:retire", bytes.NewReader([]byte(`{}`)))
	retireResNoKey := httptest.NewRecorder()
	srv.Handler().ServeHTTP(retireResNoKey, retireReqNoKey)
	if retireResNoKey.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized without admin key, got %d body=%s", retireResNoKey.Code, retireResNoKey.Body.String())
	}

	retireReq := httptest.NewRequest(http.MethodPost, "/v1/devices/device-retire-auth:retire", bytes.NewReader([]byte(`{}`)))
	addAdminAPIKey(retireReq)
	retireRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(retireRes, retireReq)
	if retireRes.Code != http.StatusOK {
		t.Fatalf("expected success with admin key, got %d body=%s", retireRes.Code, retireRes.Body.String())
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
	addAdminAPIKey(retireReq)
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
	addAdminAPIKey(revokeReq)
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
	addAdminAPIKey(revokeReq)
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
	bundleB64, bundleSHA := tgzBundleBase64(t, map[string]string{
		"rules/mamotama.conf":                       "SecRuleEngine On\nInclude ./rules/crs/setup.conf\n",
		"rules/crs/REQUEST-901-INITIALIZATION.conf": "SecRule REQUEST_HEADERS:User-Agent \"@contains test\" \"id:901001,phase:1,pass\"",
	})

	enrollReq := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(signedEnrollPayload(t, "device-policy", key, baseTS, "policy-enroll-1")))
	enrollReq.Header.Set("X-License-Key", "test-license-key-1234")
	enrollRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(enrollRes, enrollReq)
	if enrollRes.Code != http.StatusOK {
		t.Fatalf("enroll failed: %d body=%s", enrollRes.Code, enrollRes.Body.String())
	}

	putPolicyBody, err := json.Marshal(map[string]any{
		"version":        "waf-2026-03-06",
		"waf_raw":        "{\"enabled\":true,\"rule_files\":[\"./rules/mamotama.conf\"]}",
		"note":           "initial",
		"bundle_tgz_b64": bundleB64,
		"bundle_sha256":  bundleSHA,
	})
	if err != nil {
		t.Fatalf("marshal policy upsert payload: %v", err)
	}
	putPolicyReq := httptest.NewRequest(http.MethodPost, "/v1/policies", bytes.NewReader(putPolicyBody))
	addAdminAPIKey(putPolicyReq)
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
	if putBody.Policy.BundleSHA256 != bundleSHA || putBody.Policy.BundleTGZB64 == "" {
		t.Fatalf("expected bundle in policy upsert response: %s", putPolicyRes.Body.String())
	}
	if putBody.Policy.Status != "draft" {
		t.Fatalf("expected draft policy after upsert, got status=%q", putBody.Policy.Status)
	}

	assignDraftReq := httptest.NewRequest(http.MethodPost, "/v1/devices/device-policy:assign-policy", bytes.NewBufferString(`{"version":"waf-2026-03-06"}`))
	addAdminAPIKey(assignDraftReq)
	assignDraftRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(assignDraftRes, assignDraftReq)
	if assignDraftRes.Code != http.StatusConflict {
		t.Fatalf("expected conflict while policy is draft, got %d body=%s", assignDraftRes.Code, assignDraftRes.Body.String())
	}

	approveReq := httptest.NewRequest(http.MethodPost, "/v1/policies/waf-2026-03-06:approve", nil)
	addAdminAPIKey(approveReq)
	approveRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(approveRes, approveReq)
	if approveRes.Code != http.StatusOK {
		t.Fatalf("approve policy failed: %d body=%s", approveRes.Code, approveRes.Body.String())
	}
	var approveBody struct {
		Policy PolicyRecord `json:"policy"`
	}
	if err := json.Unmarshal(approveRes.Body.Bytes(), &approveBody); err != nil {
		t.Fatalf("decode approve policy body: %v", err)
	}
	if approveBody.Policy.Status != "approved" {
		t.Fatalf("expected approved policy after approve endpoint, got status=%q", approveBody.Policy.Status)
	}

	assignReq := httptest.NewRequest(http.MethodPost, "/v1/devices/device-policy:assign-policy", bytes.NewBufferString(`{"version":"waf-2026-03-06"}`))
	addAdminAPIKey(assignReq)
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
			Version      string `json:"version"`
			SHA256       string `json:"sha256"`
			BundleTGZB64 string `json:"bundle_tgz_b64"`
			BundleSHA256 string `json:"bundle_sha256"`
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
	if pullBody.Policy.BundleSHA256 != bundleSHA || pullBody.Policy.BundleTGZB64 == "" {
		t.Fatalf("expected pull policy bundle fields: %s", pullRes.Body.String())
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

func TestReleaseAssignPullAckFlow(t *testing.T) {
	t.Parallel()

	cfg := newSignedTestConfig(t)
	cfg.Heartbeat.MaxClockSkew.Duration = 10 * time.Minute
	srv, err := NewServer(cfg, log.New(bytes.NewBuffer(nil), "", 0))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	key := newTestDeviceKey(t)
	baseTS := time.Now().UTC()
	releaseRaw := []byte("test-edge-binary-v0.5.0")
	releaseB64 := base64.StdEncoding.EncodeToString(releaseRaw)
	releaseSHA := hashBytesHex(releaseRaw)

	enrollReq := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(signedEnrollPayload(t, "device-release", key, baseTS, "release-enroll-1")))
	enrollReq.Header.Set("X-License-Key", "test-license-key-1234")
	enrollRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(enrollRes, enrollReq)
	if enrollRes.Code != http.StatusOK {
		t.Fatalf("enroll failed: %d body=%s", enrollRes.Code, enrollRes.Body.String())
	}

	putReleaseBody, err := json.Marshal(map[string]any{
		"version":    "edge-0.5.0",
		"platform":   "linux-amd64",
		"sha256":     releaseSHA,
		"binary_b64": releaseB64,
		"note":       "ota-test",
	})
	if err != nil {
		t.Fatalf("marshal release upsert payload: %v", err)
	}
	putReleaseReq := httptest.NewRequest(http.MethodPost, "/v1/releases", bytes.NewReader(putReleaseBody))
	addAdminAPIKey(putReleaseReq)
	putReleaseRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(putReleaseRes, putReleaseReq)
	if putReleaseRes.Code != http.StatusOK {
		t.Fatalf("release upsert failed: %d body=%s", putReleaseRes.Code, putReleaseRes.Body.String())
	}
	var putBody struct {
		Release ReleaseRecord `json:"release"`
	}
	if err := json.Unmarshal(putReleaseRes.Body.Bytes(), &putBody); err != nil {
		t.Fatalf("decode release upsert body: %v", err)
	}
	if putBody.Release.Status != "draft" {
		t.Fatalf("expected draft release after upsert, got status=%q", putBody.Release.Status)
	}

	assignDraftReq := httptest.NewRequest(http.MethodPost, "/v1/devices/device-release:assign-release", bytes.NewBufferString(`{"version":"edge-0.5.0"}`))
	addAdminAPIKey(assignDraftReq)
	assignDraftRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(assignDraftRes, assignDraftReq)
	if assignDraftRes.Code != http.StatusConflict {
		t.Fatalf("expected conflict while release is draft, got %d body=%s", assignDraftRes.Code, assignDraftRes.Body.String())
	}

	approveReq := httptest.NewRequest(http.MethodPost, "/v1/releases/edge-0.5.0:approve", nil)
	addAdminAPIKey(approveReq)
	approveRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(approveRes, approveReq)
	if approveRes.Code != http.StatusOK {
		t.Fatalf("approve release failed: %d body=%s", approveRes.Code, approveRes.Body.String())
	}

	assignReq := httptest.NewRequest(http.MethodPost, "/v1/devices/device-release:assign-release", bytes.NewBufferString(`{"version":"edge-0.5.0"}`))
	addAdminAPIKey(assignReq)
	assignRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(assignRes, assignReq)
	if assignRes.Code != http.StatusOK {
		t.Fatalf("assign release failed: %d body=%s", assignRes.Code, assignRes.Body.String())
	}

	hbReq := httptest.NewRequest(http.MethodPost, "/v1/heartbeat", bytes.NewReader(signedHeartbeatPayload(t, "device-release", key, baseTS.Add(time.Second), "release-hb-1", "")))
	hbRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(hbRes, hbReq)
	if hbRes.Code != http.StatusOK {
		t.Fatalf("heartbeat failed: %d body=%s", hbRes.Code, hbRes.Body.String())
	}
	var hbBody map[string]any
	if err := json.Unmarshal(hbRes.Body.Bytes(), &hbBody); err != nil {
		t.Fatalf("decode heartbeat body: %v", err)
	}
	releaseInfo, _ := hbBody["release"].(map[string]any)
	if updateRequired, _ := releaseInfo["update_required"].(bool); !updateRequired {
		t.Fatalf("expected release update_required=true, body=%s", hbRes.Body.String())
	}

	pullReq := httptest.NewRequest(http.MethodPost, "/v1/release/pull", bytes.NewReader(signedReleasePullPayload(t, "device-release", key, baseTS.Add(2*time.Second), "release-pull-1", "", "")))
	pullRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(pullRes, pullReq)
	if pullRes.Code != http.StatusOK {
		t.Fatalf("release pull failed: %d body=%s", pullRes.Code, pullRes.Body.String())
	}
	var pullBody struct {
		UpdateRequired bool `json:"update_required"`
		Release        struct {
			Version   string `json:"version"`
			Platform  string `json:"platform"`
			SHA256    string `json:"sha256"`
			BinaryB64 string `json:"binary_b64"`
		} `json:"release"`
	}
	if err := json.Unmarshal(pullRes.Body.Bytes(), &pullBody); err != nil {
		t.Fatalf("decode release pull body: %v", err)
	}
	if !pullBody.UpdateRequired {
		t.Fatalf("expected release pull update_required=true, body=%s", pullRes.Body.String())
	}
	if pullBody.Release.Version != "edge-0.5.0" || pullBody.Release.SHA256 != releaseSHA || pullBody.Release.BinaryB64 == "" {
		t.Fatalf("unexpected release pull body: %s", pullRes.Body.String())
	}

	ackReq := httptest.NewRequest(http.MethodPost, "/v1/release/ack", bytes.NewReader(signedReleaseAckPayload(t, "device-release", key, baseTS.Add(3*time.Second), "release-ack-1", pullBody.Release.Version, pullBody.Release.SHA256, "applied", "")))
	ackRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(ackRes, ackReq)
	if ackRes.Code != http.StatusOK {
		t.Fatalf("release ack failed: %d body=%s", ackRes.Code, ackRes.Body.String())
	}

	hbReq2 := httptest.NewRequest(http.MethodPost, "/v1/heartbeat", bytes.NewReader(signedHeartbeatPayload(t, "device-release", key, baseTS.Add(4*time.Second), "release-hb-2", "")))
	hbRes2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(hbRes2, hbReq2)
	if hbRes2.Code != http.StatusOK {
		t.Fatalf("second heartbeat failed: %d body=%s", hbRes2.Code, hbRes2.Body.String())
	}
	if err := json.Unmarshal(hbRes2.Body.Bytes(), &hbBody); err != nil {
		t.Fatalf("decode second heartbeat body: %v", err)
	}
	releaseInfo, _ = hbBody["release"].(map[string]any)
	if updateRequired, _ := releaseInfo["update_required"].(bool); updateRequired {
		t.Fatalf("expected release update_required=false after applied ack, body=%s", hbRes2.Body.String())
	}
}

func TestReleaseAssignWithApplyAtDelaysUpdate(t *testing.T) {
	t.Parallel()

	cfg := newSignedTestConfig(t)
	cfg.Heartbeat.MaxClockSkew.Duration = 10 * time.Minute
	srv, err := NewServer(cfg, log.New(bytes.NewBuffer(nil), "", 0))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	key := newTestDeviceKey(t)
	baseTS := time.Now().UTC()
	releaseRaw := []byte("test-edge-binary-v0.5.1")
	releaseB64 := base64.StdEncoding.EncodeToString(releaseRaw)
	releaseSHA := hashBytesHex(releaseRaw)
	applyAt := baseTS.Add(2 * time.Hour).UTC()

	enrollReq := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(signedEnrollPayload(t, "device-release-scheduled", key, baseTS, "release-enroll-scheduled-1")))
	enrollReq.Header.Set("X-License-Key", "test-license-key-1234")
	enrollRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(enrollRes, enrollReq)
	if enrollRes.Code != http.StatusOK {
		t.Fatalf("enroll failed: %d body=%s", enrollRes.Code, enrollRes.Body.String())
	}

	putReleaseBody, err := json.Marshal(map[string]any{
		"version":    "edge-0.5.1",
		"platform":   "linux-amd64",
		"sha256":     releaseSHA,
		"binary_b64": releaseB64,
		"note":       "ota-scheduled-test",
	})
	if err != nil {
		t.Fatalf("marshal release upsert payload: %v", err)
	}
	putReleaseReq := httptest.NewRequest(http.MethodPost, "/v1/releases", bytes.NewReader(putReleaseBody))
	addAdminAPIKey(putReleaseReq)
	putReleaseRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(putReleaseRes, putReleaseReq)
	if putReleaseRes.Code != http.StatusOK {
		t.Fatalf("release upsert failed: %d body=%s", putReleaseRes.Code, putReleaseRes.Body.String())
	}

	approveReq := httptest.NewRequest(http.MethodPost, "/v1/releases/edge-0.5.1:approve", nil)
	addAdminAPIKey(approveReq)
	approveRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(approveRes, approveReq)
	if approveRes.Code != http.StatusOK {
		t.Fatalf("approve release failed: %d body=%s", approveRes.Code, approveRes.Body.String())
	}

	assignBody, err := json.Marshal(map[string]any{
		"version":  "edge-0.5.1",
		"apply_at": applyAt.Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatalf("marshal assign body: %v", err)
	}
	assignReq := httptest.NewRequest(http.MethodPost, "/v1/devices/device-release-scheduled:assign-release", bytes.NewReader(assignBody))
	addAdminAPIKey(assignReq)
	assignRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(assignRes, assignReq)
	if assignRes.Code != http.StatusOK {
		t.Fatalf("assign release failed: %d body=%s", assignRes.Code, assignRes.Body.String())
	}
	var assignResp struct {
		Release struct {
			ApplyAt string `json:"apply_at"`
		} `json:"release"`
	}
	if err := json.Unmarshal(assignRes.Body.Bytes(), &assignResp); err != nil {
		t.Fatalf("decode assign response: %v", err)
	}
	if assignResp.Release.ApplyAt == "" {
		t.Fatalf("expected apply_at in assign response: %s", assignRes.Body.String())
	}

	srv.nowFn = func() time.Time { return baseTS.Add(1 * time.Minute) }
	hbReq := httptest.NewRequest(http.MethodPost, "/v1/heartbeat", bytes.NewReader(signedHeartbeatPayload(t, "device-release-scheduled", key, baseTS.Add(1*time.Minute), "release-hb-scheduled-1", "")))
	hbRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(hbRes, hbReq)
	if hbRes.Code != http.StatusOK {
		t.Fatalf("heartbeat before apply_at failed: %d body=%s", hbRes.Code, hbRes.Body.String())
	}
	var hbBody map[string]any
	if err := json.Unmarshal(hbRes.Body.Bytes(), &hbBody); err != nil {
		t.Fatalf("decode heartbeat body: %v", err)
	}
	releaseInfo, _ := hbBody["release"].(map[string]any)
	if updateRequired, _ := releaseInfo["update_required"].(bool); updateRequired {
		t.Fatalf("expected update_required=false before apply_at, body=%s", hbRes.Body.String())
	}
	if ready, _ := releaseInfo["update_ready"].(bool); ready {
		t.Fatalf("expected update_ready=false before apply_at, body=%s", hbRes.Body.String())
	}

	pullReq := httptest.NewRequest(http.MethodPost, "/v1/release/pull", bytes.NewReader(signedReleasePullPayload(t, "device-release-scheduled", key, baseTS.Add(2*time.Minute), "release-pull-scheduled-1", "", "")))
	pullRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(pullRes, pullReq)
	if pullRes.Code != http.StatusOK {
		t.Fatalf("release pull before apply_at failed: %d body=%s", pullRes.Code, pullRes.Body.String())
	}
	var pullBody struct {
		UpdateRequired bool `json:"update_required"`
	}
	if err := json.Unmarshal(pullRes.Body.Bytes(), &pullBody); err != nil {
		t.Fatalf("decode release pull body before apply_at: %v", err)
	}
	if pullBody.UpdateRequired {
		t.Fatalf("expected release pull update_required=false before apply_at, body=%s", pullRes.Body.String())
	}

	srv.nowFn = func() time.Time { return applyAt.Add(1 * time.Minute) }
	hbReq2 := httptest.NewRequest(http.MethodPost, "/v1/heartbeat", bytes.NewReader(signedHeartbeatPayload(t, "device-release-scheduled", key, applyAt.Add(time.Minute), "release-hb-scheduled-2", "")))
	hbRes2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(hbRes2, hbReq2)
	if hbRes2.Code != http.StatusOK {
		t.Fatalf("heartbeat after apply_at failed: %d body=%s", hbRes2.Code, hbRes2.Body.String())
	}
	if err := json.Unmarshal(hbRes2.Body.Bytes(), &hbBody); err != nil {
		t.Fatalf("decode heartbeat body after apply_at: %v", err)
	}
	releaseInfo, _ = hbBody["release"].(map[string]any)
	if updateRequired, _ := releaseInfo["update_required"].(bool); !updateRequired {
		t.Fatalf("expected update_required=true after apply_at, body=%s", hbRes2.Body.String())
	}

	pullReq2 := httptest.NewRequest(http.MethodPost, "/v1/release/pull", bytes.NewReader(signedReleasePullPayload(t, "device-release-scheduled", key, applyAt.Add(2*time.Minute), "release-pull-scheduled-2", "", "")))
	pullRes2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(pullRes2, pullReq2)
	if pullRes2.Code != http.StatusOK {
		t.Fatalf("release pull after apply_at failed: %d body=%s", pullRes2.Code, pullRes2.Body.String())
	}
	var pullBody2 struct {
		UpdateRequired bool `json:"update_required"`
		Release        struct {
			Version string `json:"version"`
		} `json:"release"`
	}
	if err := json.Unmarshal(pullRes2.Body.Bytes(), &pullBody2); err != nil {
		t.Fatalf("decode release pull body after apply_at: %v", err)
	}
	if !pullBody2.UpdateRequired {
		t.Fatalf("expected release pull update_required=true after apply_at, body=%s", pullRes2.Body.String())
	}
	if pullBody2.Release.Version != "edge-0.5.1" {
		t.Fatalf("unexpected release version after apply_at: %s", pullRes2.Body.String())
	}
}

func TestPolicyUpsertWithBundleTemplate(t *testing.T) {
	t.Parallel()

	cfg := newSignedTestConfig(t)
	srv, err := NewServer(cfg, log.New(bytes.NewBuffer(nil), "", 0))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	bundleB64, bundleSHA := tgzBundleBase64(t, map[string]string{
		"rules/mamotama.conf": "SecRuleEngine On\n",
		"rules/z-last.conf":   "SecRule REQUEST_URI \"@contains admin\" \"id:12345,phase:1,deny\"\n",
	})
	reqBody, err := json.Marshal(map[string]any{
		"version":          "waf-template-v1",
		"waf_raw_template": "bundle_default",
		"bundle_tgz_b64":   bundleB64,
		"bundle_sha256":    bundleSHA,
		"note":             "template-generated",
	})
	if err != nil {
		t.Fatalf("marshal request body: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/policies", bytes.NewReader(reqBody))
	addAdminAPIKey(req)
	res := httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("policy upsert with template failed: %d body=%s", res.Code, res.Body.String())
	}

	var body struct {
		Policy PolicyRecord `json:"policy"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	if body.Policy.WAFRaw == "" {
		t.Fatalf("expected generated waf_raw, body=%s", res.Body.String())
	}
	if body.Policy.SHA256 != hashStringHex(body.Policy.WAFRaw) {
		t.Fatalf("expected sha256 to match generated waf_raw: %s", res.Body.String())
	}
	var waf map[string]any
	if err := json.Unmarshal([]byte(body.Policy.WAFRaw), &waf); err != nil {
		t.Fatalf("decode generated waf_raw: %v", err)
	}
	files, _ := waf["rule_files"].([]any)
	if len(files) != 1 || files[0] != "${MAMOTAMA_POLICY_ACTIVE}/rules/mamotama.conf" {
		t.Fatalf("unexpected generated rule_files: %#v", waf["rule_files"])
	}
}

func TestPolicyPutTemplateUsesExistingBundle(t *testing.T) {
	t.Parallel()

	cfg := newSignedTestConfig(t)
	srv, err := NewServer(cfg, log.New(bytes.NewBuffer(nil), "", 0))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	bundleB64, bundleSHA := tgzBundleBase64(t, map[string]string{
		"rules/main.conf": "SecRuleEngine On\n",
	})
	createReq := httptest.NewRequest(http.MethodPost, "/v1/policies", bytes.NewBufferString(`{"version":"waf-template-put-v1","waf_raw":"{\"enabled\":true,\"rule_files\":[\"./rules/main.conf\"]}","bundle_tgz_b64":"`+bundleB64+`","bundle_sha256":"`+bundleSHA+`"}`))
	addAdminAPIKey(createReq)
	createRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(createRes, createReq)
	if createRes.Code != http.StatusOK {
		t.Fatalf("create policy failed: %d body=%s", createRes.Code, createRes.Body.String())
	}

	putReq := httptest.NewRequest(http.MethodPut, "/v1/policies/waf-template-put-v1", bytes.NewBufferString(`{"waf_raw_template":"bundle_default"}`))
	addAdminAPIKey(putReq)
	putRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(putRes, putReq)
	if putRes.Code != http.StatusOK {
		t.Fatalf("put policy with template failed: %d body=%s", putRes.Code, putRes.Body.String())
	}
	var putBody struct {
		Policy PolicyRecord `json:"policy"`
	}
	if err := json.Unmarshal(putRes.Body.Bytes(), &putBody); err != nil {
		t.Fatalf("decode put response body: %v", err)
	}
	if !strings.Contains(putBody.Policy.WAFRaw, "${MAMOTAMA_POLICY_ACTIVE}/rules/main.conf") {
		t.Fatalf("expected template-generated rule file from existing bundle, body=%s", putRes.Body.String())
	}
}

func TestPolicyUpsertRejectsRawAndTemplateTogether(t *testing.T) {
	t.Parallel()

	cfg := newSignedTestConfig(t)
	srv, err := NewServer(cfg, log.New(bytes.NewBuffer(nil), "", 0))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/policies", bytes.NewBufferString(`{"version":"waf-template-invalid","waf_raw":"{\"enabled\":true,\"rule_files\":[\"./rules/a.conf\"]}","waf_raw_template":"bundle_default"}`))
	addAdminAPIKey(req)
	res := httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("expected bad request, got %d body=%s", res.Code, res.Body.String())
	}
}

func TestPolicyUpsertTemplateWithSelectedRuleFiles(t *testing.T) {
	t.Parallel()

	cfg := newSignedTestConfig(t)
	srv, err := NewServer(cfg, log.New(bytes.NewBuffer(nil), "", 0))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	bundleB64, bundleSHA := tgzBundleBase64(t, map[string]string{
		"rules/a.conf": "SecRuleEngine On\n",
		"rules/b.conf": "SecRule ARGS:test \"@contains bad\" \"id:1001,phase:2,deny\"\n",
	})
	reqBody, err := json.Marshal(map[string]any{
		"version":          "waf-template-select-v1",
		"waf_raw_template": "bundle_default",
		"waf_rule_files":   []string{"rules/b.conf", "rules/a.conf"},
		"bundle_tgz_b64":   bundleB64,
		"bundle_sha256":    bundleSHA,
	})
	if err != nil {
		t.Fatalf("marshal request body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/policies", bytes.NewReader(reqBody))
	addAdminAPIKey(req)
	res := httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("policy upsert with selected template files failed: %d body=%s", res.Code, res.Body.String())
	}

	var body struct {
		Policy PolicyRecord `json:"policy"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	var waf struct {
		RuleFiles []string `json:"rule_files"`
	}
	if err := json.Unmarshal([]byte(body.Policy.WAFRaw), &waf); err != nil {
		t.Fatalf("decode generated waf_raw: %v", err)
	}
	if len(waf.RuleFiles) != 2 {
		t.Fatalf("unexpected generated rule files: %#v", waf.RuleFiles)
	}
	if waf.RuleFiles[0] != "${MAMOTAMA_POLICY_ACTIVE}/rules/b.conf" || waf.RuleFiles[1] != "${MAMOTAMA_POLICY_ACTIVE}/rules/a.conf" {
		t.Fatalf("unexpected selected order: %#v", waf.RuleFiles)
	}
}

func TestInspectBundleEndpoint(t *testing.T) {
	t.Parallel()

	cfg := newSignedTestConfig(t)
	srv, err := NewServer(cfg, log.New(bytes.NewBuffer(nil), "", 0))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	bundleB64, bundleSHA := tgzBundleBase64(t, map[string]string{
		"rules/mamotama.conf": "SecRuleEngine On\n",
		"rules/z.conf":        "SecRule REQUEST_URI \"@contains x\" \"id:2001,phase:1,deny\"\n",
		"README.txt":          "not-a-rule",
	})
	reqBody, err := json.Marshal(map[string]any{
		"bundle_tgz_b64": bundleB64,
		"bundle_sha256":  bundleSHA,
	})
	if err != nil {
		t.Fatalf("marshal request body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/policies:inspect-bundle", bytes.NewReader(reqBody))
	addAdminAPIKey(req)
	res := httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("inspect bundle failed: %d body=%s", res.Code, res.Body.String())
	}
	var body struct {
		Bundle struct {
			SHA256               string   `json:"sha256"`
			ConfFiles            []string `json:"conf_files"`
			RecommendedRuleFiles []string `json:"recommended_rule_files"`
		} `json:"bundle"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode inspect response: %v", err)
	}
	if body.Bundle.SHA256 != bundleSHA {
		t.Fatalf("unexpected bundle sha: got=%s want=%s", body.Bundle.SHA256, bundleSHA)
	}
	if len(body.Bundle.ConfFiles) != 2 {
		t.Fatalf("unexpected conf files: %#v", body.Bundle.ConfFiles)
	}
	if len(body.Bundle.RecommendedRuleFiles) != 1 || body.Bundle.RecommendedRuleFiles[0] != "rules/mamotama.conf" {
		t.Fatalf("unexpected recommended files: %#v", body.Bundle.RecommendedRuleFiles)
	}
}

func TestDevicePolicyDownload(t *testing.T) {
	t.Parallel()

	cfg := newSignedTestConfig(t)
	cfg.Heartbeat.MaxClockSkew.Duration = 10 * time.Minute
	srv, err := NewServer(cfg, log.New(bytes.NewBuffer(nil), "", 0))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	key := newTestDeviceKey(t)
	baseTS := time.Now().UTC()
	srv.nowFn = func() time.Time { return baseTS }
	srv.nowFn = func() time.Time { return baseTS }

	enrollReq := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(signedEnrollPayload(t, "device-policy-download", key, baseTS, "policy-download-enroll-1")))
	enrollReq.Header.Set("X-License-Key", "test-license-key-1234")
	enrollRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(enrollRes, enrollReq)
	if enrollRes.Code != http.StatusOK {
		t.Fatalf("enroll failed: %d body=%s", enrollRes.Code, enrollRes.Body.String())
	}

	putPolicyReq := httptest.NewRequest(http.MethodPost, "/v1/policies", bytes.NewBufferString(`{"version":"waf-2026-03-06","waf_raw":"SecRuleEngine On\nSecRule ARGS:test \"@contains bad\" \"id:1001,phase:2,deny\"","note":"download-test"}`))
	addAdminAPIKey(putPolicyReq)
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

	approveReq := httptest.NewRequest(http.MethodPost, "/v1/policies/waf-2026-03-06:approve", nil)
	addAdminAPIKey(approveReq)
	approveRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(approveRes, approveReq)
	if approveRes.Code != http.StatusOK {
		t.Fatalf("approve policy failed: %d body=%s", approveRes.Code, approveRes.Body.String())
	}

	assignReq := httptest.NewRequest(http.MethodPost, "/v1/devices/device-policy-download:assign-policy", bytes.NewBufferString(`{"version":"waf-2026-03-06"}`))
	addAdminAPIKey(assignReq)
	assignRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(assignRes, assignReq)
	if assignRes.Code != http.StatusOK {
		t.Fatalf("assign policy failed: %d body=%s", assignRes.Code, assignRes.Body.String())
	}

	desiredReq := httptest.NewRequest(http.MethodGet, "/v1/devices/device-policy-download:download-policy?state=desired", nil)
	addAdminAPIKey(desiredReq)
	desiredRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(desiredRes, desiredReq)
	if desiredRes.Code != http.StatusOK {
		t.Fatalf("desired policy download failed: %d body=%s", desiredRes.Code, desiredRes.Body.String())
	}
	if got := strings.ToLower(desiredRes.Header().Get("Content-Type")); !strings.Contains(got, "text/plain") {
		t.Fatalf("unexpected content-type: %s", got)
	}
	if !strings.Contains(desiredRes.Body.String(), "SecRuleEngine On") {
		t.Fatalf("unexpected desired policy body: %s", desiredRes.Body.String())
	}

	noCurrentReq := httptest.NewRequest(http.MethodGet, "/v1/devices/device-policy-download:download-policy?state=current", nil)
	addAdminAPIKey(noCurrentReq)
	noCurrentRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(noCurrentRes, noCurrentReq)
	if noCurrentRes.Code != http.StatusConflict {
		t.Fatalf("expected current policy conflict before heartbeat, got %d body=%s", noCurrentRes.Code, noCurrentRes.Body.String())
	}

	hbReq := httptest.NewRequest(http.MethodPost, "/v1/heartbeat", bytes.NewReader(signedHeartbeatPayload(
		t,
		"device-policy-download",
		key,
		baseTS.Add(time.Second),
		"policy-download-hb-1",
		"",
		putBody.Policy.Version,
		putBody.Policy.SHA256,
	)))
	hbRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(hbRes, hbReq)
	if hbRes.Code != http.StatusOK {
		t.Fatalf("heartbeat failed: %d body=%s", hbRes.Code, hbRes.Body.String())
	}

	currentJSONReq := httptest.NewRequest(http.MethodGet, "/v1/devices/device-policy-download:download-policy?state=current&format=json", nil)
	addAdminAPIKey(currentJSONReq)
	currentJSONRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(currentJSONRes, currentJSONReq)
	if currentJSONRes.Code != http.StatusOK {
		t.Fatalf("current policy json download failed: %d body=%s", currentJSONRes.Code, currentJSONRes.Body.String())
	}
	var currentJSONBody struct {
		State  string `json:"state"`
		Policy struct {
			Version string `json:"version"`
			WAFRaw  string `json:"waf_raw"`
		} `json:"policy"`
	}
	if err := json.Unmarshal(currentJSONRes.Body.Bytes(), &currentJSONBody); err != nil {
		t.Fatalf("decode current policy json body: %v", err)
	}
	if currentJSONBody.State != "current" || currentJSONBody.Policy.Version != putBody.Policy.Version {
		t.Fatalf("unexpected current policy json body: %s", currentJSONRes.Body.String())
	}
	if !strings.Contains(currentJSONBody.Policy.WAFRaw, "SecRule ARGS:test") {
		t.Fatalf("unexpected current policy raw in json body: %s", currentJSONRes.Body.String())
	}
}

func TestPolicyOverwriteAndDeleteUnused(t *testing.T) {
	t.Parallel()

	cfg := newSignedTestConfig(t)
	cfg.Heartbeat.MaxClockSkew.Duration = 10 * time.Minute
	srv, err := NewServer(cfg, log.New(bytes.NewBuffer(nil), "", 0))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	key := newTestDeviceKey(t)
	baseTS := time.Now().UTC()
	srv.nowFn = func() time.Time { return baseTS }

	enrollReq := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(signedEnrollPayload(t, "device-policy-mutate", key, baseTS, "policy-mutate-enroll-1")))
	enrollReq.Header.Set("X-License-Key", "test-license-key-1234")
	enrollRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(enrollRes, enrollReq)
	if enrollRes.Code != http.StatusOK {
		t.Fatalf("enroll failed: %d body=%s", enrollRes.Code, enrollRes.Body.String())
	}

	createV1Req := httptest.NewRequest(http.MethodPost, "/v1/policies", bytes.NewBufferString(`{"version":"waf-inuse-v1","waf_raw":"SecRuleEngine On","note":"inuse"}`))
	addAdminAPIKey(createV1Req)
	createV1Res := httptest.NewRecorder()
	srv.Handler().ServeHTTP(createV1Res, createV1Req)
	if createV1Res.Code != http.StatusOK {
		t.Fatalf("create v1 failed: %d body=%s", createV1Res.Code, createV1Res.Body.String())
	}

	approveV1Req := httptest.NewRequest(http.MethodPost, "/v1/policies/waf-inuse-v1:approve", nil)
	addAdminAPIKey(approveV1Req)
	approveV1Res := httptest.NewRecorder()
	srv.Handler().ServeHTTP(approveV1Res, approveV1Req)
	if approveV1Res.Code != http.StatusOK {
		t.Fatalf("approve v1 failed: %d body=%s", approveV1Res.Code, approveV1Res.Body.String())
	}

	assignV1Req := httptest.NewRequest(http.MethodPost, "/v1/devices/device-policy-mutate:assign-policy", bytes.NewBufferString(`{"version":"waf-inuse-v1"}`))
	addAdminAPIKey(assignV1Req)
	assignV1Res := httptest.NewRecorder()
	srv.Handler().ServeHTTP(assignV1Res, assignV1Req)
	if assignV1Res.Code != http.StatusOK {
		t.Fatalf("assign v1 failed: %d body=%s", assignV1Res.Code, assignV1Res.Body.String())
	}

	overwriteInUseReq := httptest.NewRequest(http.MethodPut, "/v1/policies/waf-inuse-v1", bytes.NewBufferString(`{"version":"waf-inuse-v1","waf_raw":"SecRuleEngine DetectionOnly","note":"overwrite"}`))
	addAdminAPIKey(overwriteInUseReq)
	overwriteInUseRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(overwriteInUseRes, overwriteInUseReq)
	if overwriteInUseRes.Code != http.StatusConflict {
		t.Fatalf("expected conflict when overwriting in-use policy, got %d body=%s", overwriteInUseRes.Code, overwriteInUseRes.Body.String())
	}

	deleteInUseReq := httptest.NewRequest(http.MethodDelete, "/v1/policies/waf-inuse-v1", nil)
	addAdminAPIKey(deleteInUseReq)
	deleteInUseRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(deleteInUseRes, deleteInUseReq)
	if deleteInUseRes.Code != http.StatusConflict {
		t.Fatalf("expected conflict when deleting in-use policy, got %d body=%s", deleteInUseRes.Code, deleteInUseRes.Body.String())
	}

	createV2Req := httptest.NewRequest(http.MethodPost, "/v1/policies", bytes.NewBufferString(`{"version":"waf-unused-v1","waf_raw":"SecRuleEngine On","note":"unused"}`))
	addAdminAPIKey(createV2Req)
	createV2Res := httptest.NewRecorder()
	srv.Handler().ServeHTTP(createV2Res, createV2Req)
	if createV2Res.Code != http.StatusOK {
		t.Fatalf("create v2 failed: %d body=%s", createV2Res.Code, createV2Res.Body.String())
	}

	overwriteV2Req := httptest.NewRequest(http.MethodPut, "/v1/policies/waf-unused-v1", bytes.NewBufferString(`{"version":"waf-unused-v1","waf_raw":"SecRuleEngine DetectionOnly","note":"updated"}`))
	addAdminAPIKey(overwriteV2Req)
	overwriteV2Res := httptest.NewRecorder()
	srv.Handler().ServeHTTP(overwriteV2Res, overwriteV2Req)
	if overwriteV2Res.Code != http.StatusOK {
		t.Fatalf("overwrite v2 failed: %d body=%s", overwriteV2Res.Code, overwriteV2Res.Body.String())
	}
	var overwriteBody struct {
		Policy PolicyRecord `json:"policy"`
	}
	if err := json.Unmarshal(overwriteV2Res.Body.Bytes(), &overwriteBody); err != nil {
		t.Fatalf("decode overwrite v2 body: %v", err)
	}
	if overwriteBody.Policy.Status != "draft" {
		t.Fatalf("expected draft after overwrite, got status=%q", overwriteBody.Policy.Status)
	}
	if !strings.Contains(overwriteBody.Policy.WAFRaw, "DetectionOnly") {
		t.Fatalf("unexpected overwrite waf_raw: %s", overwriteBody.Policy.WAFRaw)
	}

	deleteV2Req := httptest.NewRequest(http.MethodDelete, "/v1/policies/waf-unused-v1", nil)
	addAdminAPIKey(deleteV2Req)
	deleteV2Res := httptest.NewRecorder()
	srv.Handler().ServeHTTP(deleteV2Res, deleteV2Req)
	if deleteV2Res.Code != http.StatusOK {
		t.Fatalf("delete v2 failed: %d body=%s", deleteV2Res.Code, deleteV2Res.Body.String())
	}

	getDeletedReq := httptest.NewRequest(http.MethodGet, "/v1/policies/waf-unused-v1", nil)
	addAdminAPIKey(getDeletedReq)
	getDeletedRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(getDeletedRes, getDeletedReq)
	if getDeletedRes.Code != http.StatusNotFound {
		t.Fatalf("expected not found for deleted policy, got %d body=%s", getDeletedRes.Code, getDeletedRes.Body.String())
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

func TestAdminLogsEndpointsRequireAPIKey(t *testing.T) {
	t.Parallel()

	cfg := newSignedTestConfig(t)
	srv, err := NewServer(cfg, log.New(bytes.NewBuffer(nil), "", 0))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/admin/logs/devices", nil)
	res := httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized without api key, got %d body=%s", res.Code, res.Body.String())
	}

	reqSummary := httptest.NewRequest(http.MethodGet, "/v1/admin/logs/summary", nil)
	resSummary := httptest.NewRecorder()
	srv.Handler().ServeHTTP(resSummary, reqSummary)
	if resSummary.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized summary without api key, got %d body=%s", resSummary.Code, resSummary.Body.String())
	}
}

func TestAdminLogsSummaryValidation(t *testing.T) {
	t.Parallel()

	cfg := newSignedTestConfig(t)
	srv, err := NewServer(cfg, log.New(bytes.NewBuffer(nil), "", 0))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	invalidReq := httptest.NewRequest(http.MethodGet, "/v1/admin/logs/summary?kind=invalid", nil)
	addAdminAPIKey(invalidReq)
	invalidRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(invalidRes, invalidReq)
	if invalidRes.Code != http.StatusBadRequest {
		t.Fatalf("expected bad request for invalid kind, got %d body=%s", invalidRes.Code, invalidRes.Body.String())
	}

	notFoundReq := httptest.NewRequest(http.MethodGet, "/v1/admin/logs/summary?device_id=not-found-device", nil)
	addAdminAPIKey(notFoundReq)
	notFoundRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(notFoundRes, notFoundReq)
	if notFoundRes.Code != http.StatusNotFound {
		t.Fatalf("expected not found for unknown device, got %d body=%s", notFoundRes.Code, notFoundRes.Body.String())
	}
}

func TestAdminAPIKeyScopes(t *testing.T) {
	t.Parallel()

	cfg := newSignedTestConfig(t)
	cfg.Auth.AdminAPIKeys = nil
	cfg.Auth.AdminReadAPIKeys = []string{testAdminReadAPIKey}
	cfg.Auth.AdminWriteAPIKeys = []string{testAdminWriteAPIKey}
	srv, err := NewServer(cfg, log.New(bytes.NewBuffer(nil), "", 0))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	listReadReq := httptest.NewRequest(http.MethodGet, "/v1/policies", nil)
	addAdminAPIKeyWithValue(listReadReq, testAdminReadAPIKey)
	listReadRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(listReadRes, listReadReq)
	if listReadRes.Code != http.StatusOK {
		t.Fatalf("read key should access GET /v1/policies, got %d body=%s", listReadRes.Code, listReadRes.Body.String())
	}

	putReadReq := httptest.NewRequest(http.MethodPost, "/v1/policies", bytes.NewBufferString(`{"version":"scope-test-v1","waf_raw":"SecRuleEngine On"}`))
	addAdminAPIKeyWithValue(putReadReq, testAdminReadAPIKey)
	putReadRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(putReadRes, putReadReq)
	if putReadRes.Code != http.StatusForbidden {
		t.Fatalf("read key should be forbidden for write endpoint, got %d body=%s", putReadRes.Code, putReadRes.Body.String())
	}

	putWriteReq := httptest.NewRequest(http.MethodPost, "/v1/policies", bytes.NewBufferString(`{"version":"scope-test-v1","waf_raw":"SecRuleEngine On"}`))
	addAdminAPIKeyWithValue(putWriteReq, testAdminWriteAPIKey)
	putWriteRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(putWriteRes, putWriteReq)
	if putWriteRes.Code != http.StatusOK {
		t.Fatalf("write key should access write endpoint, got %d body=%s", putWriteRes.Code, putWriteRes.Body.String())
	}
}

func TestAdminLogsListAndDownload(t *testing.T) {
	t.Parallel()

	cfg := newSignedTestConfig(t)
	cfg.Heartbeat.MaxClockSkew.Duration = 10 * time.Minute
	srv, err := NewServer(cfg, log.New(bytes.NewBuffer(nil), "", 0))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	key := newTestDeviceKey(t)
	baseTS := time.Date(2026, 3, 6, 12, 0, 0, 0, time.UTC)
	srv.nowFn = func() time.Time { return baseTS }

	enrollReq := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(signedEnrollPayload(t, "device-admin-logs", key, baseTS, "admin-logs-enroll-1")))
	enrollReq.Header.Set("X-License-Key", "test-license-key-1234")
	enrollRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(enrollRes, enrollReq)
	if enrollRes.Code != http.StatusOK {
		t.Fatalf("enroll failed: %d body=%s", enrollRes.Code, enrollRes.Body.String())
	}

	logRaw := []byte(`{"timestamp":"2026-03-06T12:00:01Z","kind":"security","level":"warn","msg":"waf blocked","request_id":"r1"}` + "\n" +
		`{"timestamp":"2026-03-06T12:00:02Z","kind":"access","level":"info","msg":"proxy ok","request_id":"r2"}` + "\n")
	payload := gzipBytes(t, logRaw)
	pushReq := httptest.NewRequest(http.MethodPost, "/v1/logs/push", bytes.NewReader(signedLogsPushPayload(t, "device-admin-logs", key, baseTS.Add(time.Second), "admin-logs-push-1", 2, payload)))
	pushRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(pushRes, pushReq)
	if pushRes.Code != http.StatusOK {
		t.Fatalf("logs push failed: %d body=%s", pushRes.Code, pushRes.Body.String())
	}

	devicesReq := httptest.NewRequest(http.MethodGet, "/v1/admin/logs/devices", nil)
	addAdminAPIKey(devicesReq)
	devicesRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(devicesRes, devicesReq)
	if devicesRes.Code != http.StatusOK {
		t.Fatalf("log devices failed: %d body=%s", devicesRes.Code, devicesRes.Body.String())
	}

	listReq := httptest.NewRequest(http.MethodGet, "/v1/admin/logs?device_id=device-admin-logs&limit=1", nil)
	addAdminAPIKey(listReq)
	listRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(listRes, listReq)
	if listRes.Code != http.StatusOK {
		t.Fatalf("log list failed: %d body=%s", listRes.Code, listRes.Body.String())
	}
	var listBody struct {
		Count      int               `json:"count"`
		NextCursor string            `json:"next_cursor"`
		Entries    []json.RawMessage `json:"entries"`
	}
	if err := json.Unmarshal(listRes.Body.Bytes(), &listBody); err != nil {
		t.Fatalf("decode log list body: %v", err)
	}
	if listBody.Count != 1 || len(listBody.Entries) != 1 || listBody.NextCursor == "" {
		t.Fatalf("unexpected log list body: %s", listRes.Body.String())
	}

	summaryReq := httptest.NewRequest(http.MethodGet, "/v1/admin/logs/summary?device_id=device-admin-logs", nil)
	addAdminAPIKey(summaryReq)
	summaryRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(summaryRes, summaryReq)
	if summaryRes.Code != http.StatusOK {
		t.Fatalf("log summary failed: %d body=%s", summaryRes.Code, summaryRes.Body.String())
	}
	var summaryBody struct {
		Summary struct {
			TotalEntries int64            `json:"total_entries"`
			ByKind       map[string]int64 `json:"by_kind"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(summaryRes.Body.Bytes(), &summaryBody); err != nil {
		t.Fatalf("decode summary body: %v", err)
	}
	if summaryBody.Summary.TotalEntries != 2 {
		t.Fatalf("unexpected summary total_entries: %d body=%s", summaryBody.Summary.TotalEntries, summaryRes.Body.String())
	}
	if summaryBody.Summary.ByKind["security"] != 1 || summaryBody.Summary.ByKind["access"] != 1 {
		t.Fatalf("unexpected by_kind summary: %+v", summaryBody.Summary.ByKind)
	}

	downloadReq := httptest.NewRequest(http.MethodGet, "/v1/admin/logs/download?device_id=device-admin-logs&limit=10&kind=security", nil)
	addAdminAPIKey(downloadReq)
	downloadRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(downloadRes, downloadReq)
	if downloadRes.Code != http.StatusOK {
		t.Fatalf("log download failed: %d body=%s", downloadRes.Code, downloadRes.Body.String())
	}
	downloadBody := strings.TrimSpace(downloadRes.Body.String())
	if !strings.Contains(downloadBody, `"kind":"security"`) || strings.Contains(downloadBody, `"kind":"access"`) {
		t.Fatalf("unexpected download body: %s", downloadBody)
	}

	uiReq := httptest.NewRequest(http.MethodGet, "/admin/logs", nil)
	uiRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(uiRes, uiReq)
	if uiRes.Code != http.StatusOK {
		t.Fatalf("admin logs ui failed: %d body=%s", uiRes.Code, uiRes.Body.String())
	}
	if got := uiRes.Header().Get("Content-Type"); !strings.Contains(strings.ToLower(got), "text/html") {
		t.Fatalf("unexpected admin logs ui content-type: %s", got)
	}
	if !strings.Contains(uiRes.Body.String(), "/admin/logs/assets/admin_logs.js") {
		t.Fatalf("unexpected admin logs ui body: missing logs assets reference")
	}

	logAssetReq := httptest.NewRequest(http.MethodGet, "/admin/logs/assets/admin_logs.js", nil)
	logAssetRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(logAssetRes, logAssetReq)
	if logAssetRes.Code != http.StatusOK {
		t.Fatalf("admin logs ui asset failed: %d body=%s", logAssetRes.Code, logAssetRes.Body.String())
	}
	if got := logAssetRes.Header().Get("Content-Type"); !strings.Contains(strings.ToLower(got), "javascript") {
		t.Fatalf("unexpected admin logs ui asset content-type: %s", got)
	}

	deviceUIReq := httptest.NewRequest(http.MethodGet, "/admin/devices", nil)
	deviceUIRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(deviceUIRes, deviceUIReq)
	if deviceUIRes.Code != http.StatusOK {
		t.Fatalf("admin devices ui failed: %d body=%s", deviceUIRes.Code, deviceUIRes.Body.String())
	}
	if got := deviceUIRes.Header().Get("Content-Type"); !strings.Contains(strings.ToLower(got), "text/html") {
		t.Fatalf("unexpected admin devices ui content-type: %s", got)
	}
	if !strings.Contains(deviceUIRes.Body.String(), "/admin/devices/assets/admin_devices.js") {
		t.Fatalf("unexpected admin devices ui body: missing devices assets reference")
	}

	deviceAssetReq := httptest.NewRequest(http.MethodGet, "/admin/devices/assets/admin_devices.js", nil)
	deviceAssetRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(deviceAssetRes, deviceAssetReq)
	if deviceAssetRes.Code != http.StatusOK {
		t.Fatalf("admin devices ui asset failed: %d body=%s", deviceAssetRes.Code, deviceAssetRes.Body.String())
	}
	if got := deviceAssetRes.Header().Get("Content-Type"); !strings.Contains(strings.ToLower(got), "javascript") {
		t.Fatalf("unexpected admin devices ui asset content-type: %s", got)
	}
}

func TestLogsPushPrunesExpiredBatchesByRetention(t *testing.T) {
	t.Parallel()

	cfg := newSignedTestConfig(t)
	cfg.Heartbeat.MaxClockSkew.Duration = 10 * time.Minute
	cfg.Storage.LogRetention.Duration = 1 * time.Hour
	cfg.Storage.LogMaxBytes = 1024 * 1024 * 1024
	srv, err := NewServer(cfg, log.New(bytes.NewBuffer(nil), "", 0))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	key := newTestDeviceKey(t)
	baseTS := time.Now().UTC()

	enrollReq := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(signedEnrollPayload(t, "device-prune-retention", key, baseTS, "prune-retention-enroll-1")))
	enrollReq.Header.Set("X-License-Key", "test-license-key-1234")
	enrollRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(enrollRes, enrollReq)
	if enrollRes.Code != http.StatusOK {
		t.Fatalf("enroll failed: %d body=%s", enrollRes.Code, enrollRes.Body.String())
	}

	payload1 := gzipBytes(t, []byte(`{"timestamp":"2026-03-06T12:00:01Z","kind":"security","msg":"old-batch"}`+"\n"))
	pushReq1 := httptest.NewRequest(http.MethodPost, "/v1/logs/push", bytes.NewReader(signedLogsPushPayload(t, "device-prune-retention", key, baseTS.Add(time.Second), "prune-retention-push-1", 1, payload1)))
	pushRes1 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(pushRes1, pushReq1)
	if pushRes1.Code != http.StatusOK {
		t.Fatalf("first logs push failed: %d body=%s", pushRes1.Code, pushRes1.Body.String())
	}
	var body1 struct {
		LogBatch struct {
			StoredPath string `json:"stored_path"`
		} `json:"log_batch"`
	}
	if err := json.Unmarshal(pushRes1.Body.Bytes(), &body1); err != nil {
		t.Fatalf("decode first logs push body: %v", err)
	}
	if body1.LogBatch.StoredPath == "" {
		t.Fatalf("missing stored_path in first logs push body: %s", pushRes1.Body.String())
	}
	oldTS := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(body1.LogBatch.StoredPath, oldTS, oldTS); err != nil {
		t.Fatalf("set old mtime: %v", err)
	}

	payload2 := gzipBytes(t, []byte(`{"timestamp":"2026-03-06T12:00:02Z","kind":"security","msg":"new-batch"}`+"\n"))
	pushReq2 := httptest.NewRequest(http.MethodPost, "/v1/logs/push", bytes.NewReader(signedLogsPushPayload(t, "device-prune-retention", key, baseTS.Add(2*time.Second), "prune-retention-push-2", 1, payload2)))
	pushRes2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(pushRes2, pushReq2)
	if pushRes2.Code != http.StatusOK {
		t.Fatalf("second logs push failed: %d body=%s", pushRes2.Code, pushRes2.Body.String())
	}
	var body2 struct {
		LogBatch struct {
			StoredPath string `json:"stored_path"`
		} `json:"log_batch"`
	}
	if err := json.Unmarshal(pushRes2.Body.Bytes(), &body2); err != nil {
		t.Fatalf("decode second logs push body: %v", err)
	}
	if body2.LogBatch.StoredPath == "" {
		t.Fatalf("missing stored_path in second logs push body: %s", pushRes2.Body.String())
	}

	if _, err := os.Stat(body1.LogBatch.StoredPath); !os.IsNotExist(err) {
		t.Fatalf("expected old batch removed by retention, stat err=%v", err)
	}
	if _, err := os.Stat(body2.LogBatch.StoredPath); err != nil {
		t.Fatalf("expected new batch to remain, stat err=%v", err)
	}
}

func TestLogsPushPrunesOldestBatchesByCapacity(t *testing.T) {
	t.Parallel()

	cfg := newSignedTestConfig(t)
	cfg.Heartbeat.MaxClockSkew.Duration = 10 * time.Minute
	cfg.Storage.LogRetention.Duration = 30 * 24 * time.Hour
	cfg.Storage.LogMaxBytes = 1
	srv, err := NewServer(cfg, log.New(bytes.NewBuffer(nil), "", 0))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	key := newTestDeviceKey(t)
	baseTS := time.Now().UTC()

	enrollReq := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(signedEnrollPayload(t, "device-prune-capacity", key, baseTS, "prune-capacity-enroll-1")))
	enrollReq.Header.Set("X-License-Key", "test-license-key-1234")
	enrollRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(enrollRes, enrollReq)
	if enrollRes.Code != http.StatusOK {
		t.Fatalf("enroll failed: %d body=%s", enrollRes.Code, enrollRes.Body.String())
	}

	push := func(idx int) string {
		payload := gzipBytes(t, []byte(`{"timestamp":"2026-03-06T12:00:0`+strconv.Itoa(idx)+`Z","kind":"security","msg":"batch-`+strconv.Itoa(idx)+`"}`+"\n"))
		req := httptest.NewRequest(http.MethodPost, "/v1/logs/push", bytes.NewReader(signedLogsPushPayload(t, "device-prune-capacity", key, baseTS.Add(time.Duration(idx)*time.Second), "prune-capacity-push-"+strconv.Itoa(idx), 1, payload)))
		res := httptest.NewRecorder()
		srv.Handler().ServeHTTP(res, req)
		if res.Code != http.StatusOK {
			t.Fatalf("logs push #%d failed: %d body=%s", idx, res.Code, res.Body.String())
		}
		var body struct {
			LogBatch struct {
				StoredPath string `json:"stored_path"`
			} `json:"log_batch"`
		}
		if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode logs push #%d body: %v", idx, err)
		}
		if body.LogBatch.StoredPath == "" {
			t.Fatalf("missing stored_path for push #%d", idx)
		}
		return body.LogBatch.StoredPath
	}

	path1 := push(1)
	path2 := push(2)
	path3 := push(3)

	if _, err := os.Stat(path1); !os.IsNotExist(err) {
		t.Fatalf("expected oldest batch removed, stat err=%v", err)
	}
	if _, err := os.Stat(path2); !os.IsNotExist(err) {
		t.Fatalf("expected middle batch removed due capacity cap, stat err=%v", err)
	}
	if _, err := os.Stat(path3); err != nil {
		t.Fatalf("expected latest batch to remain, stat err=%v", err)
	}
}
