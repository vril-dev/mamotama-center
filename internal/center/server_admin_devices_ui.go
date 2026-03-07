package center

import (
	"net/http"
	"strings"
)

func (s *Server) handleAdminDevicesUI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.ensureSecureTransport(w, r) {
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(adminDevicesPageHTML))
}

func (s *Server) handleAdminDevicesUIAssets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.ensureSecureTransport(w, r) {
		return
	}
	assetPath := strings.TrimPrefix(r.URL.Path, "/admin/devices/assets/")
	switch assetPath {
	case "admin_devices.css":
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		_, _ = w.Write(adminDevicesPageCSS)
		return
	case "admin_devices.js":
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		_, _ = w.Write(adminDevicesPageJS)
		return
	default:
		writeError(w, http.StatusNotFound, "not found")
		return
	}
}
