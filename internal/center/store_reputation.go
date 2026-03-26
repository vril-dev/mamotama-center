package center

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type ReputationFeed struct {
	GeneratedAt   string                `json:"generated_at"`
	WindowSeconds int                   `json:"window_seconds"`
	Allowlist     []string              `json:"allowlist,omitempty"`
	Blocklist     []string              `json:"blocklist,omitempty"`
	Summary       ReputationFeedSummary `json:"summary"`
}

type ReputationFeedSummary struct {
	ScannedEntries int64 `json:"scanned_entries"`
	CandidateIPs   int   `json:"candidate_ips"`
	BlockedIPs     int   `json:"blocked_ips"`
	MultiDeviceIPs int   `json:"multi_device_ips,omitempty"`
}

type scoredAddr struct {
	addr        netip.Addr
	score       int
	deviceCount int
}

type reputationAggregate struct {
	rawScore int
	devices  map[string]struct{}
}

func (s *deviceStore) buildReputationFeed(now time.Time, window time.Duration, threshold int, maxItems int) (ReputationFeed, error) {
	if window <= 0 {
		window = 24 * time.Hour
	}
	if threshold <= 0 {
		threshold = 6
	}
	if maxItems <= 0 {
		maxItems = 1024
	}

	s.mu.RLock()
	deviceIDs := make([]string, 0, len(s.devices))
	for deviceID := range s.devices {
		deviceIDs = append(deviceIDs, deviceID)
	}
	storePath := s.path
	s.mu.RUnlock()
	sort.Strings(deviceIDs)

	cutoff := now.UTC().Add(-window)
	logsRoot := filepath.Join(filepath.Dir(storePath), "logs")
	aggregates := make(map[netip.Addr]*reputationAggregate, 1024)
	var scanned int64

	for _, deviceID := range deviceIDs {
		deviceDir := filepath.Join(logsRoot, safePathComponent(deviceID))
		entries, err := os.ReadDir(deviceDir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return ReputationFeed{}, fmt.Errorf("read log dir: %w", err)
		}

		files := make([]string, 0, len(entries))
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			if strings.HasSuffix(strings.ToLower(entry.Name()), ".ndjson.gz") {
				files = append(files, filepath.Join(deviceDir, entry.Name()))
			}
		}
		sort.Strings(files)
		for _, filePath := range files {
			if err := accumulateReputationFile(filePath, deviceID, cutoff, aggregates, &scanned); err != nil {
				return ReputationFeed{}, err
			}
		}
	}

	candidates := make([]scoredAddr, 0, len(aggregates))
	multiDeviceIPs := 0
	for addr, aggregate := range aggregates {
		deviceCount := len(aggregate.devices)
		if deviceCount > 1 {
			multiDeviceIPs++
		}
		score := reputationEffectiveScore(aggregate.rawScore, deviceCount)
		if score >= threshold {
			candidates = append(candidates, scoredAddr{
				addr:        addr,
				score:       score,
				deviceCount: deviceCount,
			})
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].score == candidates[j].score {
			if candidates[i].deviceCount == candidates[j].deviceCount {
				return candidates[i].addr.String() < candidates[j].addr.String()
			}
			return candidates[i].deviceCount > candidates[j].deviceCount
		}
		return candidates[i].score > candidates[j].score
	})
	if len(candidates) > maxItems {
		candidates = candidates[:maxItems]
	}

	blocklist := make([]string, 0, len(candidates))
	for _, item := range candidates {
		blocklist = append(blocklist, netip.PrefixFrom(item.addr, item.addr.BitLen()).String())
	}

	return ReputationFeed{
		GeneratedAt:   now.UTC().Format(time.RFC3339Nano),
		WindowSeconds: int(window / time.Second),
		Blocklist:     blocklist,
		Summary: ReputationFeedSummary{
			ScannedEntries: scanned,
			CandidateIPs:   len(aggregates),
			BlockedIPs:     len(blocklist),
			MultiDeviceIPs: multiDeviceIPs,
		},
	}, nil
}

func accumulateReputationFile(filePath, deviceID string, cutoff time.Time, aggregates map[netip.Addr]*reputationAggregate, scanned *int64) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("open log batch: %w", err)
	}
	defer f.Close()

	zr, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("open gzip log batch: %w", err)
	}
	defer zr.Close()

	sc := bufio.NewScanner(zr)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var meta struct {
			Timestamp string `json:"timestamp"`
			Kind      string `json:"kind"`
			RemoteIP  string `json:"remote_ip"`
			IP        string `json:"ip"`
			Policy    string `json:"policy"`
			Event     string `json:"event"`
			Action    string `json:"action"`
			Status    int    `json:"status"`
		}
		if err := json.Unmarshal([]byte(line), &meta); err != nil {
			continue
		}
		*scanned = *scanned + 1
		if strings.ToLower(strings.TrimSpace(meta.Kind)) != "security" {
			continue
		}
		ts, ok := parseStoreRFC3339Any(meta.Timestamp)
		if !ok || ts.Before(cutoff) {
			continue
		}
		event := strings.ToLower(strings.TrimSpace(meta.Event))
		policy := strings.ToLower(strings.TrimSpace(meta.Policy))
		if event == "ip_reputation" || policy == "ip_reputation" {
			continue
		}
		ipStr := strings.TrimSpace(meta.RemoteIP)
		if ipStr == "" {
			ipStr = strings.TrimSpace(meta.IP)
		}
		addr, err := netip.ParseAddr(ipStr)
		if err != nil {
			continue
		}
		weight := reputationWeight(event, strings.ToLower(strings.TrimSpace(meta.Action)), meta.Status)
		if weight <= 0 {
			continue
		}
		aggregate := aggregates[addr]
		if aggregate == nil {
			aggregate = &reputationAggregate{devices: make(map[string]struct{}, 2)}
			aggregates[addr] = aggregate
		}
		aggregate.rawScore += weight
		if deviceID != "" {
			aggregate.devices[deviceID] = struct{}{}
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("scan log batch: %w", err)
	}
	return nil
}

func reputationEffectiveScore(rawScore, deviceCount int) int {
	return rawScore + reputationDeviceBonus(deviceCount)
}

func reputationDeviceBonus(deviceCount int) int {
	if deviceCount <= 1 {
		return 0
	}
	bonus := (deviceCount - 1) * 4
	if bonus > 12 {
		return 12
	}
	return bonus
}

func reputationWeight(event, action string, status int) int {
	switch event {
	case "waf_block":
		return 3
	case "semantic_anomaly":
		switch action {
		case "block":
			return 3
		case "challenge":
			return 2
		default:
			if status >= 400 {
				return 1
			}
		}
	case "rate_limited":
		return 1
	case "bot_challenge":
		return 1
	}
	if status >= 500 {
		return 0
	}
	if status >= 400 {
		return 1
	}
	return 0
}
