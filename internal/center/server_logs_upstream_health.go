package center

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

type upstreamHealthSnapshot struct {
	Status              string
	Endpoint            string
	LastChangedAt       time.Time
	LastError           string
	ConsecutiveFailures int
}

type upstreamHealthLogEntry struct {
	Timestamp string `json:"timestamp"`
	Kind      string `json:"kind"`
	Policy    string `json:"policy"`
	Msg       string `json:"msg"`
	Error     string `json:"error"`
}

func extractLatestUpstreamHealthSnapshot(payloadGzip []byte) (upstreamHealthSnapshot, bool, error) {
	if len(payloadGzip) == 0 {
		return upstreamHealthSnapshot{}, false, nil
	}
	zr, err := gzip.NewReader(bytes.NewReader(payloadGzip))
	if err != nil {
		return upstreamHealthSnapshot{}, false, err
	}
	defer zr.Close()

	scanner := bufio.NewScanner(zr)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)

	var latest upstreamHealthSnapshot
	found := false
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var entry upstreamHealthLogEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			continue
		}
		snap, ok := parseUpstreamHealthSnapshotEntry(entry)
		if !ok {
			continue
		}
		latest = snap
		found = true
	}
	if err := scanner.Err(); err != nil {
		return upstreamHealthSnapshot{}, false, err
	}
	return latest, found, nil
}

func parseUpstreamHealthSnapshotEntry(entry upstreamHealthLogEntry) (upstreamHealthSnapshot, bool) {
	policy := strings.TrimSpace(strings.ToLower(entry.Policy))
	if policy != "" && policy != "proxy" {
		return upstreamHealthSnapshot{}, false
	}
	kind := strings.TrimSpace(strings.ToLower(entry.Kind))
	if kind != "" && kind != "system" {
		return upstreamHealthSnapshot{}, false
	}
	msg := strings.TrimSpace(entry.Msg)
	if msg == "" {
		return upstreamHealthSnapshot{}, false
	}
	msgLower := strings.ToLower(msg)

	snap := upstreamHealthSnapshot{}
	switch {
	case strings.HasPrefix(msgLower, "upstream health recovered"):
		snap.Status = "healthy"
	case strings.HasPrefix(msgLower, "upstream health degraded"):
		snap.Status = "unhealthy"
	default:
		return upstreamHealthSnapshot{}, false
	}

	kv := parseInlineLogTokens(msg)
	snap.Endpoint = strings.TrimSpace(kv["endpoint"])
	if snap.Status == "unhealthy" {
		snap.LastError = strings.TrimSpace(entry.Error)
		if rawFailures := strings.TrimSpace(kv["failures"]); rawFailures != "" {
			if parsed, err := strconv.Atoi(rawFailures); err == nil && parsed > 0 {
				snap.ConsecutiveFailures = parsed
			}
		}
	}

	if ts, ok := parseStoreRFC3339Any(entry.Timestamp); ok {
		snap.LastChangedAt = ts
	}
	return snap, true
}

func parseInlineLogTokens(msg string) map[string]string {
	out := map[string]string{}
	for _, token := range strings.Fields(msg) {
		key, val, ok := strings.Cut(token, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(strings.ToLower(key))
		val = strings.TrimSpace(strings.Trim(val, `"'`))
		if key == "" || val == "" {
			continue
		}
		out[key] = val
	}
	return out
}
