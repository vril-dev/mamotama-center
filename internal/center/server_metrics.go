package center

import (
	"fmt"
	"net/http"
	"strings"
)

func (s *Server) handleAdminMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.ensureSecureTransport(w, r) {
		return
	}
	if !s.requireAdminRead(w, r) {
		return
	}

	devices := s.store.list()
	policies := s.store.listPolicies()
	releases := s.store.listReleases()
	reputation, _ := s.store.buildReputationFeed(s.nowFn().UTC(), defaultReputationWindow, defaultReputationThreshold, defaultReputationMaxItems)
	logDevices, _ := s.store.listLogDevices()

	var b strings.Builder
	writePromGauge(&b, "mamotama_center_devices", len(devices))
	writePromGauge(&b, "mamotama_center_policies", len(policies))
	writePromGauge(&b, "mamotama_center_releases", len(releases))
	writePromGauge(&b, "mamotama_center_log_devices", len(logDevices))
	writePromGauge(&b, "mamotama_center_reputation_blocked_ips", reputation.Summary.BlockedIPs)
	writePromGauge(&b, "mamotama_center_reputation_multi_device_ips", reputation.Summary.MultiDeviceIPs)
	writePromGauge(&b, "mamotama_center_reputation_window_seconds", reputation.WindowSeconds)

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(b.String()))
}

func writePromGauge(b *strings.Builder, name string, value int) {
	fmt.Fprintf(b, "# TYPE %s gauge\n%s %d\n", name, name, value)
}
