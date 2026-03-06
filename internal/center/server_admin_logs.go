package center

import (
	"compress/gzip"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
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

func (s *Server) handleAdminLogsSummary(w http.ResponseWriter, r *http.Request) {
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
	opts, err := parseAdminLogSummaryQuery(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	summary, err := s.store.summarizeLogs(opts)
	if err != nil {
		switch {
		case errors.Is(err, os.ErrNotExist):
			writeError(w, http.StatusNotFound, "device not found")
		case errors.Is(err, errStoreInvalid):
			writeError(w, http.StatusBadRequest, "invalid query")
		default:
			s.logger.Printf(`{"level":"error","msg":"summarize logs failed","error":"%s"}`, err)
			writeError(w, http.StatusInternalServerError, "failed to summarize logs")
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"summary": summary,
		"filters": map[string]any{
			"device_id": opts.DeviceID,
			"from":      formatTimeOrEmpty(opts.From, opts.HasFrom),
			"to":        formatTimeOrEmpty(opts.To, opts.HasTo),
			"kind":      opts.Kind,
			"level":     opts.Level,
		},
		"storage_policy": map[string]any{
			"log_retention": s.cfg.Storage.LogRetention.Duration.String(),
			"log_max_bytes": s.cfg.Storage.LogMaxBytes,
		},
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

func (s *Server) handleAdminLogsUI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.ensureSecureTransport(w, r) {
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(adminLogsPageHTML))
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

func parseAdminLogSummaryQuery(r *http.Request) (LogSummaryOptions, error) {
	if r == nil {
		return LogSummaryOptions{}, fmt.Errorf("request is required")
	}
	q := r.URL.Query()
	opts := LogSummaryOptions{
		DeviceID: strings.TrimSpace(q.Get("device_id")),
		Kind:     strings.ToLower(strings.TrimSpace(q.Get("kind"))),
		Level:    strings.ToLower(strings.TrimSpace(q.Get("level"))),
	}
	if raw := strings.TrimSpace(q.Get("from")); raw != "" {
		ts, ok := parseRFC3339Any(raw)
		if !ok {
			return LogSummaryOptions{}, fmt.Errorf("from must be RFC3339")
		}
		opts.From = ts
		opts.HasFrom = true
	}
	if raw := strings.TrimSpace(q.Get("to")); raw != "" {
		ts, ok := parseRFC3339Any(raw)
		if !ok {
			return LogSummaryOptions{}, fmt.Errorf("to must be RFC3339")
		}
		opts.To = ts
		opts.HasTo = true
	}
	switch opts.Kind {
	case "", "access", "security", "system":
	default:
		return LogSummaryOptions{}, fmt.Errorf("kind must be one of access|security|system")
	}
	switch opts.Level {
	case "", "info", "warn", "error":
	default:
		return LogSummaryOptions{}, fmt.Errorf("level must be one of info|warn|error")
	}
	if opts.HasFrom && opts.HasTo && opts.From.After(opts.To) {
		return LogSummaryOptions{}, fmt.Errorf("from must be <= to")
	}
	return opts, nil
}

func formatTimeOrEmpty(ts time.Time, ok bool) string {
	if !ok {
		return ""
	}
	return ts.UTC().Format(time.RFC3339Nano)
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

const adminLogsPageHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>mamotama-center logs</title>
  <style>
    :root { --bg:#f6f7fb; --panel:#ffffff; --ink:#16202a; --muted:#5b6773; --line:#d7dee6; --brand:#0f766e; --alert:#9f1239; }
    body { margin:0; font-family: ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background:linear-gradient(180deg,#eef2ff 0%,var(--bg) 40%); color:var(--ink); }
    .wrap { max-width:1120px; margin:0 auto; padding:20px 16px 40px; }
    h1 { margin:0 0 14px; font-size:28px; }
    .grid { display:grid; grid-template-columns: repeat(auto-fit,minmax(320px,1fr)); gap:12px; }
    .panel { background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:14px; box-shadow:0 2px 8px rgba(22,32,42,.05); }
    .row { display:flex; gap:8px; align-items:center; margin-bottom:8px; flex-wrap:wrap; }
    label { font-size:12px; color:var(--muted); display:block; margin-bottom:4px; }
    input, select, button, textarea { font:inherit; }
    input, select { border:1px solid var(--line); border-radius:8px; padding:8px; min-height:36px; background:#fff; }
    textarea { width:100%; min-height:220px; border:1px solid var(--line); border-radius:10px; padding:10px; background:#f8fafc; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size:12px; }
    button { border:0; border-radius:8px; padding:8px 12px; background:var(--brand); color:#fff; cursor:pointer; }
    button.secondary { background:#334155; }
    .muted { color:var(--muted); font-size:12px; }
    .error { color:var(--alert); font-size:12px; white-space:pre-wrap; }
  </style>
</head>
<body>
  <div class="wrap">
    <h1>Center Admin Logs</h1>
    <div class="grid">
      <div class="panel">
        <div class="row">
          <div style="flex:1; min-width:260px;">
            <label>Admin API Key</label>
            <input id="apiKey" type="password" placeholder="X-API-Key">
          </div>
          <button id="saveKey" class="secondary">Save Key</button>
        </div>
        <div class="row">
          <div>
            <label>Device Prefix</label>
            <input id="prefix" placeholder="device-">
          </div>
          <button id="loadDevices">Load Devices</button>
        </div>
        <div class="row">
          <label style="margin:0;">Device</label>
          <select id="deviceSelect" style="min-width:220px;"></select>
        </div>
        <div class="row">
          <div><label>From (RFC3339)</label><input id="from" placeholder="2026-03-06T00:00:00Z"></div>
          <div><label>To (RFC3339)</label><input id="to" placeholder="2026-03-07T00:00:00Z"></div>
          <div><label>Kind</label><select id="kind"><option value="">all</option><option>access</option><option>security</option><option>system</option></select></div>
          <div><label>Level</label><select id="level"><option value="">all</option><option>info</option><option>warn</option><option>error</option></select></div>
        </div>
        <div class="row">
          <button id="loadSummary">Load Summary</button>
          <button id="loadLogs">Load Logs</button>
          <button id="downloadLogs" class="secondary">Download NDJSON</button>
        </div>
        <div id="err" class="error"></div>
        <div class="muted">API: <code>/v1/admin/logs/devices</code>, <code>/v1/admin/logs/summary</code>, <code>/v1/admin/logs</code>, <code>/v1/admin/logs/download</code></div>
      </div>
      <div class="panel">
        <label>Summary</label>
        <textarea id="summaryOut" readonly></textarea>
      </div>
      <div class="panel">
        <label>Logs</label>
        <textarea id="logsOut" readonly></textarea>
      </div>
    </div>
  </div>
  <script>
    const byId = (id) => document.getElementById(id);
    const keyStorageKey = "center_admin_api_key";
    byId("apiKey").value = localStorage.getItem(keyStorageKey) || "";
    byId("saveKey").onclick = () => { localStorage.setItem(keyStorageKey, byId("apiKey").value); };

    async function api(path) {
      const key = byId("apiKey").value.trim();
      const res = await fetch(path, { headers: { "X-API-Key": key } });
      const text = await res.text();
      if (!res.ok) throw new Error(text || ("HTTP " + res.status));
      try { return JSON.parse(text); } catch { return text; }
    }
    function qBase() {
      const p = new URLSearchParams();
      const device = byId("deviceSelect").value.trim();
      if (device) p.set("device_id", device);
      const from = byId("from").value.trim(); if (from) p.set("from", from);
      const to = byId("to").value.trim(); if (to) p.set("to", to);
      const kind = byId("kind").value.trim(); if (kind) p.set("kind", kind);
      const level = byId("level").value.trim(); if (level) p.set("level", level);
      return p;
    }
    function setErr(msg) { byId("err").textContent = msg || ""; }
    function setText(id, data) { byId(id).value = typeof data === "string" ? data : JSON.stringify(data, null, 2); }

    byId("loadDevices").onclick = async () => {
      try {
        setErr("");
        const p = new URLSearchParams();
        const prefix = byId("prefix").value.trim();
        if (prefix) p.set("device_id_prefix", prefix);
        const body = await api("/v1/admin/logs/devices?" + p.toString());
        const sel = byId("deviceSelect");
        sel.innerHTML = "";
        for (const d of (body.devices || [])) {
          const opt = document.createElement("option");
          opt.value = d.device_id;
          opt.textContent = d.device_id + " (" + (d.batch_files || 0) + ")";
          sel.appendChild(opt);
        }
        setText("summaryOut", body);
      } catch (e) { setErr(String(e.message || e)); }
    };

    byId("loadSummary").onclick = async () => {
      try {
        setErr("");
        const p = qBase();
        const body = await api("/v1/admin/logs/summary?" + p.toString());
        setText("summaryOut", body);
      } catch (e) { setErr(String(e.message || e)); }
    };

    byId("loadLogs").onclick = async () => {
      try {
        setErr("");
        const p = qBase();
        p.set("limit", "200");
        const body = await api("/v1/admin/logs?" + p.toString());
        setText("logsOut", body);
      } catch (e) { setErr(String(e.message || e)); }
    };

    byId("downloadLogs").onclick = () => {
      const p = qBase();
      p.set("limit", "1000");
      const url = "/v1/admin/logs/download?" + p.toString();
      fetch(url, { headers: { "X-API-Key": byId("apiKey").value.trim() } })
        .then(r => { if (!r.ok) return r.text().then(t => Promise.reject(new Error(t || ("HTTP " + r.status)))); return r.blob(); })
        .then(blob => {
          const a = document.createElement("a");
          a.href = URL.createObjectURL(blob);
          a.download = "center-logs.ndjson";
          a.click();
          URL.revokeObjectURL(a.href);
        })
        .catch(e => setErr(String(e.message || e)));
    };
  </script>
</body>
</html>`
