package center

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestExtractLatestUpstreamHealthSnapshot(t *testing.T) {
	t.Parallel()

	raw := []byte(
		`{"timestamp":"2026-03-19T00:00:01Z","kind":"system","policy":"proxy","level":"warn","msg":"upstream health degraded endpoint=https://api.example.local/healthz failures=2","error":"dial timeout"}` + "\n" +
			`{"timestamp":"2026-03-19T00:00:03Z","kind":"system","policy":"proxy","level":"info","msg":"upstream health recovered endpoint=https://api.example.local/healthz latency_ms=12"}` + "\n",
	)
	payload := gzipBytes(t, raw)

	snap, ok, err := extractLatestUpstreamHealthSnapshot(payload)
	if err != nil {
		t.Fatalf("extract snapshot failed: %v", err)
	}
	if !ok {
		t.Fatal("expected upstream health snapshot")
	}
	if snap.Status != "healthy" {
		t.Fatalf("expected healthy, got %q", snap.Status)
	}
	if snap.Endpoint != "https://api.example.local/healthz" {
		t.Fatalf("unexpected endpoint: %q", snap.Endpoint)
	}
	if snap.ConsecutiveFailures != 0 {
		t.Fatalf("expected 0 failures on healthy status, got %d", snap.ConsecutiveFailures)
	}
	if snap.LastChangedAt.IsZero() {
		t.Fatal("expected non-zero changed_at")
	}
}

func TestLogsPushUpdatesUpstreamHealth(t *testing.T) {
	t.Parallel()

	cfg := newSignedTestConfig(t)
	cfg.Heartbeat.MaxClockSkew.Duration = 10 * time.Minute
	srv, err := NewServer(cfg, log.New(bytes.NewBuffer(nil), "", 0))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	key := newTestDeviceKey(t)
	baseTS := time.Date(2026, 3, 19, 0, 0, 0, 0, time.UTC)
	srv.nowFn = func() time.Time { return baseTS }

	enrollReq := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(signedEnrollPayload(t, "device-upstream-health", key, baseTS, "enroll-1")))
	enrollReq.Header.Set("X-License-Key", "test-license-key-1234")
	enrollRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(enrollRes, enrollReq)
	if enrollRes.Code != http.StatusOK {
		t.Fatalf("enroll failed: %d body=%s", enrollRes.Code, enrollRes.Body.String())
	}

	degradedRaw := []byte(`{"timestamp":"2026-03-19T00:00:10Z","kind":"system","policy":"proxy","level":"warn","msg":"upstream health degraded endpoint=https://api.example.local/healthz failures=3","error":"dial timeout"}` + "\n")
	degradedPayload := gzipBytes(t, degradedRaw)
	push1Req := httptest.NewRequest(http.MethodPost, "/v1/logs/push", bytes.NewReader(signedLogsPushPayload(t, "device-upstream-health", key, baseTS.Add(10*time.Second), "push-1", 1, degradedPayload)))
	push1Res := httptest.NewRecorder()
	srv.Handler().ServeHTTP(push1Res, push1Req)
	if push1Res.Code != http.StatusOK {
		t.Fatalf("logs push (degraded) failed: %d body=%s", push1Res.Code, push1Res.Body.String())
	}

	rec, ok := srv.store.get("device-upstream-health")
	if !ok {
		t.Fatal("expected stored device")
	}
	if rec.UpstreamHealthStatus != "unhealthy" {
		t.Fatalf("expected unhealthy, got %q", rec.UpstreamHealthStatus)
	}
	if rec.UpstreamHealthEndpoint != "https://api.example.local/healthz" {
		t.Fatalf("unexpected endpoint: %q", rec.UpstreamHealthEndpoint)
	}
	if rec.UpstreamHealthConsecutiveFailures != 3 {
		t.Fatalf("expected failures=3, got %d", rec.UpstreamHealthConsecutiveFailures)
	}
	if rec.UpstreamHealthLastError != "dial timeout" {
		t.Fatalf("unexpected last error: %q", rec.UpstreamHealthLastError)
	}
	if rec.UpstreamHealthLastChangedAt == "" {
		t.Fatal("expected upstream health last changed at")
	}

	recoveredRaw := []byte(`{"timestamp":"2026-03-19T00:00:20Z","kind":"system","policy":"proxy","level":"info","msg":"upstream health recovered endpoint=https://api.example.local/healthz latency_ms=7"}` + "\n")
	recoveredPayload := gzipBytes(t, recoveredRaw)
	push2Req := httptest.NewRequest(http.MethodPost, "/v1/logs/push", bytes.NewReader(signedLogsPushPayload(t, "device-upstream-health", key, baseTS.Add(20*time.Second), "push-2", 1, recoveredPayload)))
	push2Res := httptest.NewRecorder()
	srv.Handler().ServeHTTP(push2Res, push2Req)
	if push2Res.Code != http.StatusOK {
		t.Fatalf("logs push (recovered) failed: %d body=%s", push2Res.Code, push2Res.Body.String())
	}

	rec, ok = srv.store.get("device-upstream-health")
	if !ok {
		t.Fatal("expected stored device")
	}
	if rec.UpstreamHealthStatus != "healthy" {
		t.Fatalf("expected healthy, got %q", rec.UpstreamHealthStatus)
	}
	if rec.UpstreamHealthConsecutiveFailures != 0 {
		t.Fatalf("expected failures reset to 0, got %d", rec.UpstreamHealthConsecutiveFailures)
	}
	if rec.UpstreamHealthLastError != "" {
		t.Fatalf("expected last error cleared, got %q", rec.UpstreamHealthLastError)
	}
}
