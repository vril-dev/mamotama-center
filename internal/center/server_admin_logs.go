package center

import (
	"compress/gzip"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
)

func (s *Server) handleAdminLogDevices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.ensureSecureTransport(w, r) {
		return
	}
	if !s.hasValidAdminAPIKey(r.Header.Get("X-API-Key")) {
		writeError(w, http.StatusUnauthorized, "invalid admin api key")
		return
	}
	items, err := s.store.listLogDevices()
	if err != nil {
		s.logger.Printf(`{"level":"error","msg":"list log devices failed","error":"%s"}`, err)
		writeError(w, http.StatusInternalServerError, "failed to list log devices")
		return
	}
	prefix := strings.TrimSpace(r.URL.Query().Get("device_id_prefix"))
	if prefix != "" {
		filtered := make([]LogDeviceRecord, 0, len(items))
		for _, item := range items {
			if strings.HasPrefix(item.DeviceID, prefix) {
				filtered = append(filtered, item)
			}
		}
		items = filtered
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"devices": items,
		"count":   len(items),
	})
}

func (s *Server) handleAdminLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.ensureSecureTransport(w, r) {
		return
	}
	if !s.hasValidAdminAPIKey(r.Header.Get("X-API-Key")) {
		writeError(w, http.StatusUnauthorized, "invalid admin api key")
		return
	}
	deviceID, opts, err := parseAdminLogQuery(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	result, err := s.store.queryLogs(deviceID, opts)
	if err != nil {
		switch {
		case errors.Is(err, os.ErrNotExist):
			writeError(w, http.StatusNotFound, "device not found")
		case errors.Is(err, errStoreInvalid):
			writeError(w, http.StatusBadRequest, "invalid query")
		default:
			s.logger.Printf(`{"level":"error","msg":"query logs failed","device_id":"%s","error":"%s"}`, deviceID, err)
			writeError(w, http.StatusInternalServerError, "failed to query logs")
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"device_id":   deviceID,
		"count":       len(result.Entries),
		"next_cursor": result.NextCursor,
		"entries":     result.Entries,
	})
}

func (s *Server) handleAdminLogsDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.ensureSecureTransport(w, r) {
		return
	}
	if !s.hasValidAdminAPIKey(r.Header.Get("X-API-Key")) {
		writeError(w, http.StatusUnauthorized, "invalid admin api key")
		return
	}
	deviceID, opts, err := parseAdminLogQuery(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	result, err := s.store.queryLogs(deviceID, opts)
	if err != nil {
		switch {
		case errors.Is(err, os.ErrNotExist):
			writeError(w, http.StatusNotFound, "device not found")
		case errors.Is(err, errStoreInvalid):
			writeError(w, http.StatusBadRequest, "invalid query")
		default:
			s.logger.Printf(`{"level":"error","msg":"download logs failed","device_id":"%s","error":"%s"}`, deviceID, err)
			writeError(w, http.StatusInternalServerError, "failed to download logs")
		}
		return
	}

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s-logs.ndjson\"", sanitizeDownloadName(deviceID)))

	useGzip := strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("gzip")), "1") || strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("gzip")), "true")
	if useGzip {
		w.Header().Set("Content-Encoding", "gzip")
		zw := gzip.NewWriter(w)
		defer zw.Close()
		for _, entry := range result.Entries {
			if _, err := zw.Write(entry); err != nil {
				return
			}
			if _, err := zw.Write([]byte("\n")); err != nil {
				return
			}
		}
		return
	}

	for _, entry := range result.Entries {
		if _, err := w.Write(entry); err != nil {
			return
		}
		if _, err := w.Write([]byte("\n")); err != nil {
			return
		}
	}
}

func parseAdminLogQuery(r *http.Request) (string, LogQueryOptions, error) {
	if r == nil {
		return "", LogQueryOptions{}, fmt.Errorf("request is required")
	}
	q := r.URL.Query()
	deviceID := strings.TrimSpace(q.Get("device_id"))
	if deviceID == "" {
		return "", LogQueryOptions{}, fmt.Errorf("device_id is required")
	}

	opts := LogQueryOptions{}
	if raw := strings.TrimSpace(q.Get("from")); raw != "" {
		ts, ok := parseRFC3339Any(raw)
		if !ok {
			return "", LogQueryOptions{}, fmt.Errorf("from must be RFC3339")
		}
		opts.From = ts
		opts.HasFrom = true
	}
	if raw := strings.TrimSpace(q.Get("to")); raw != "" {
		ts, ok := parseRFC3339Any(raw)
		if !ok {
			return "", LogQueryOptions{}, fmt.Errorf("to must be RFC3339")
		}
		opts.To = ts
		opts.HasTo = true
	}
	if raw := strings.TrimSpace(q.Get("cursor")); raw != "" {
		ts, ok := parseRFC3339Any(raw)
		if !ok {
			return "", LogQueryOptions{}, fmt.Errorf("cursor must be RFC3339")
		}
		opts.Before = ts
		opts.HasBefore = true
	}
	if raw := strings.TrimSpace(q.Get("limit")); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil || v <= 0 {
			return "", LogQueryOptions{}, fmt.Errorf("limit must be a positive integer")
		}
		opts.Limit = v
	}
	opts.Kind = strings.ToLower(strings.TrimSpace(q.Get("kind")))
	opts.Level = strings.ToLower(strings.TrimSpace(q.Get("level")))

	switch opts.Kind {
	case "", "access", "security", "system":
	default:
		return "", LogQueryOptions{}, fmt.Errorf("kind must be one of access|security|system")
	}
	switch opts.Level {
	case "", "info", "warn", "error":
	default:
		return "", LogQueryOptions{}, fmt.Errorf("level must be one of info|warn|error")
	}
	if opts.HasFrom && opts.HasTo && opts.From.After(opts.To) {
		return "", LogQueryOptions{}, fmt.Errorf("from must be <= to")
	}
	return deviceID, opts, nil
}

func sanitizeDownloadName(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "device"
	}
	b := strings.Builder{}
	for _, r := range raw {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "device"
	}
	return b.String()
}
