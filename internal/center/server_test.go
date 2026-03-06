package center

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestEnrollAndHeartbeat(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	cfg.Auth.EnrollmentLicenseKeys = []string{"test-license-key-1234"}
	cfg.Storage.Path = filepath.Join(t.TempDir(), "devices.json")

	srv, err := NewServer(cfg, log.New(bytes.NewBuffer(nil), "", 0))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

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

	enrollBody := map[string]any{
		"device_id":                     "device-001",
		"public_key_pem_b64":            pubB64,
		"public_key_fingerprint_sha256": fingerprint,
	}
	enrollReqBody, _ := json.Marshal(enrollBody)
	enrollReq := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(enrollReqBody))
	enrollReq.Header.Set("X-License-Key", "test-license-key-1234")
	enrollRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(enrollRes, enrollReq)
	if enrollRes.Code != http.StatusOK {
		t.Fatalf("unexpected enroll status: %d body=%s", enrollRes.Code, enrollRes.Body.String())
	}

	ts := time.Now().UTC().Format(time.RFC3339Nano)
	nonce := "nonce-001"
	statusHash := "abc123"
	message := heartbeatMessage("device-001", ts, nonce, statusHash)
	signature := ed25519.Sign(priv, []byte(message))
	heartbeatBody := map[string]any{
		"device_id":     "device-001",
		"timestamp":     ts,
		"nonce":         nonce,
		"status_hash":   statusHash,
		"signature_b64": base64.StdEncoding.EncodeToString(signature),
	}
	heartbeatReqBody, _ := json.Marshal(heartbeatBody)
	heartbeatReq := httptest.NewRequest(http.MethodPost, "/v1/heartbeat", bytes.NewReader(heartbeatReqBody))
	heartbeatRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(heartbeatRes, heartbeatReq)
	if heartbeatRes.Code != http.StatusOK {
		t.Fatalf("unexpected heartbeat status: %d body=%s", heartbeatRes.Code, heartbeatRes.Body.String())
	}
}

func TestEnrollRejectsInvalidLicense(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	cfg.Auth.EnrollmentLicenseKeys = []string{"test-license-key-1234"}
	cfg.Storage.Path = filepath.Join(t.TempDir(), "devices.json")
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

	cfg := defaultConfig()
	cfg.Auth.EnrollmentLicenseKeys = []string{"test-license-key-1234"}
	cfg.Storage.Path = filepath.Join(t.TempDir(), "devices.json")
	cfg.Heartbeat.MaxClockSkew.Duration = 10 * time.Minute

	srv, err := NewServer(cfg, log.New(bytes.NewBuffer(nil), "", 0))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

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

	enrollReqBody, _ := json.Marshal(map[string]any{
		"device_id":                     "device-002",
		"public_key_pem_b64":            pubB64,
		"public_key_fingerprint_sha256": fingerprint,
	})
	enrollReq := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(enrollReqBody))
	enrollReq.Header.Set("X-License-Key", "test-license-key-1234")
	enrollRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(enrollRes, enrollReq)
	if enrollRes.Code != http.StatusOK {
		t.Fatalf("unexpected enroll status: %d body=%s", enrollRes.Code, enrollRes.Body.String())
	}

	ts := time.Now().UTC().Format(time.RFC3339Nano)
	msg := heartbeatMessage("device-002", ts, "nonce-1", "")
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(msg)))
	heartbeatPayload := map[string]any{
		"device_id":     "device-002",
		"timestamp":     ts,
		"nonce":         "nonce-1",
		"signature_b64": sig,
	}
	heartbeatBody, _ := json.Marshal(heartbeatPayload)

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

	cfg := defaultConfig()
	cfg.Auth.EnrollmentLicenseKeys = []string{"test-license-key-1234"}
	cfg.Storage.Path = filepath.Join(t.TempDir(), "devices.json")
	cfg.Heartbeat.ExpectedInterval.Duration = 10 * time.Second
	cfg.Heartbeat.MissedHeartbeatsForOffline = 3
	cfg.Heartbeat.StaleAfter.Duration = 2 * time.Minute

	baseNow := time.Date(2026, 3, 6, 10, 0, 0, 0, time.UTC)
	srv, err := NewServer(cfg, log.New(bytes.NewBuffer(nil), "", 0))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	srv.nowFn = func() time.Time { return baseNow }

	pub, _, err := ed25519.GenerateKey(rand.Reader)
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

	enrollReqBody, _ := json.Marshal(map[string]any{
		"device_id":                     "device-offline",
		"public_key_pem_b64":            pubB64,
		"public_key_fingerprint_sha256": fingerprint,
	})
	enrollReq := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(enrollReqBody))
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

	cfg := defaultConfig()
	cfg.Auth.EnrollmentLicenseKeys = []string{"test-license-key-1234"}
	cfg.Storage.Path = filepath.Join(t.TempDir(), "devices.json")
	srv, err := NewServer(cfg, log.New(bytes.NewBuffer(nil), "", 0))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	makePayload := func(pubB64, fingerprint string) []byte {
		b, _ := json.Marshal(map[string]any{
			"device_id":                     "device-rotate",
			"public_key_pem_b64":            pubB64,
			"public_key_fingerprint_sha256": fingerprint,
		})
		return b
	}

	makeKey := func(t *testing.T) (string, string) {
		t.Helper()
		pub, _, err := ed25519.GenerateKey(rand.Reader)
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
		return pubB64, fingerprint
	}

	pub1, fp1 := makeKey(t)
	firstReq := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(makePayload(pub1, fp1)))
	firstReq.Header.Set("X-License-Key", "test-license-key-1234")
	firstRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(firstRes, firstReq)
	if firstRes.Code != http.StatusOK {
		t.Fatalf("unexpected first enroll status: %d body=%s", firstRes.Code, firstRes.Body.String())
	}

	pub2, fp2 := makeKey(t)
	secondReq := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(makePayload(pub2, fp2)))
	secondReq.Header.Set("X-License-Key", "test-license-key-1234")
	secondRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(secondRes, secondReq)
	if secondRes.Code != http.StatusConflict {
		t.Fatalf("expected conflict for key mismatch, got %d body=%s", secondRes.Code, secondRes.Body.String())
	}
}

func TestEnrollAllowsPublicKeyRotationWithHeader(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	cfg.Auth.EnrollmentLicenseKeys = []string{"test-license-key-1234"}
	cfg.Storage.Path = filepath.Join(t.TempDir(), "devices.json")
	srv, err := NewServer(cfg, log.New(bytes.NewBuffer(nil), "", 0))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	makePayload := func(pubB64, fingerprint string) []byte {
		b, _ := json.Marshal(map[string]any{
			"device_id":                     "device-rotate-ok",
			"public_key_pem_b64":            pubB64,
			"public_key_fingerprint_sha256": fingerprint,
		})
		return b
	}

	makeKey := func(t *testing.T) (string, string) {
		t.Helper()
		pub, _, err := ed25519.GenerateKey(rand.Reader)
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
		return pubB64, fingerprint
	}

	pub1, fp1 := makeKey(t)
	firstReq := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(makePayload(pub1, fp1)))
	firstReq.Header.Set("X-License-Key", "test-license-key-1234")
	firstRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(firstRes, firstReq)
	if firstRes.Code != http.StatusOK {
		t.Fatalf("unexpected first enroll status: %d body=%s", firstRes.Code, firstRes.Body.String())
	}

	pub2, fp2 := makeKey(t)
	secondReq := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(makePayload(pub2, fp2)))
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

	cfg := defaultConfig()
	cfg.Auth.EnrollmentLicenseKeys = []string{"test-license-key-1234"}
	cfg.Storage.Path = filepath.Join(t.TempDir(), "devices.json")
	srv, err := NewServer(cfg, log.New(bytes.NewBuffer(nil), "", 0))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	pub, _, err := ed25519.GenerateKey(rand.Reader)
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

	makeReq := func(deviceID string) *http.Request {
		body, _ := json.Marshal(map[string]any{
			"device_id":                     deviceID,
			"public_key_pem_b64":            pubB64,
			"public_key_fingerprint_sha256": fingerprint,
		})
		req := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(body))
		req.Header.Set("X-License-Key", "test-license-key-1234")
		return req
	}

	firstRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(firstRes, makeReq("device-a"))
	if firstRes.Code != http.StatusOK {
		t.Fatalf("unexpected first enroll status: %d body=%s", firstRes.Code, firstRes.Body.String())
	}

	secondRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(secondRes, makeReq("device-b"))
	if secondRes.Code != http.StatusConflict {
		t.Fatalf("expected conflict for fingerprint reuse, got %d body=%s", secondRes.Code, secondRes.Body.String())
	}
}

func TestRetireDeviceBlocksHeartbeat(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	cfg.Auth.EnrollmentLicenseKeys = []string{"test-license-key-1234"}
	cfg.Storage.Path = filepath.Join(t.TempDir(), "devices.json")
	cfg.Heartbeat.MaxClockSkew.Duration = 10 * time.Minute

	srv, err := NewServer(cfg, log.New(bytes.NewBuffer(nil), "", 0))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

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

	enrollReqBody, _ := json.Marshal(map[string]any{
		"device_id":                     "device-retire",
		"public_key_pem_b64":            pubB64,
		"public_key_fingerprint_sha256": fingerprint,
	})
	enrollReq := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(enrollReqBody))
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

	ts := time.Now().UTC().Format(time.RFC3339Nano)
	nonce := "nonce-after-retire"
	message := heartbeatMessage("device-retire", ts, nonce, "")
	signature := ed25519.Sign(priv, []byte(message))
	heartbeatBody, _ := json.Marshal(map[string]any{
		"device_id":     "device-retire",
		"timestamp":     ts,
		"nonce":         nonce,
		"signature_b64": base64.StdEncoding.EncodeToString(signature),
	})
	heartbeatReq := httptest.NewRequest(http.MethodPost, "/v1/heartbeat", bytes.NewReader(heartbeatBody))
	heartbeatRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(heartbeatRes, heartbeatReq)
	if heartbeatRes.Code != http.StatusGone {
		t.Fatalf("expected retired heartbeat to be rejected, got %d body=%s", heartbeatRes.Code, heartbeatRes.Body.String())
	}
}

func TestRetireRequiresValidLicense(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	cfg.Auth.EnrollmentLicenseKeys = []string{"test-license-key-1234"}
	cfg.Storage.Path = filepath.Join(t.TempDir(), "devices.json")
	srv, err := NewServer(cfg, log.New(bytes.NewBuffer(nil), "", 0))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	pub, _, err := ed25519.GenerateKey(rand.Reader)
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

	enrollReqBody, _ := json.Marshal(map[string]any{
		"device_id":                     "device-retire-auth",
		"public_key_pem_b64":            pubB64,
		"public_key_fingerprint_sha256": fingerprint,
	})
	enrollReq := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(enrollReqBody))
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

	cfg := defaultConfig()
	cfg.Auth.EnrollmentLicenseKeys = []string{"test-license-key-1234"}
	cfg.Storage.Path = filepath.Join(t.TempDir(), "devices.json")
	srv, err := NewServer(cfg, log.New(bytes.NewBuffer(nil), "", 0))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	pub, _, err := ed25519.GenerateKey(rand.Reader)
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

	enrollPayload := map[string]any{
		"device_id":                     "device-reactivate",
		"public_key_pem_b64":            pubB64,
		"public_key_fingerprint_sha256": fingerprint,
	}
	enrollReqBody, _ := json.Marshal(enrollPayload)

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

	reenrollReq := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(enrollReqBody))
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
