package edge

import "net/http"

type Handlers struct {
	Enroll      http.HandlerFunc
	Heartbeat   http.HandlerFunc
	PolicyPull  http.HandlerFunc
	PolicyAck   http.HandlerFunc
	ReleasePull http.HandlerFunc
	ReleaseAck  http.HandlerFunc
	LogsPush    http.HandlerFunc
}

func Register(mux *http.ServeMux, h Handlers) {
	if mux == nil {
		return
	}
	if h.Enroll != nil {
		mux.HandleFunc("/v1/enroll", h.Enroll)
	}
	if h.Heartbeat != nil {
		mux.HandleFunc("/v1/heartbeat", h.Heartbeat)
	}
	if h.PolicyPull != nil {
		mux.HandleFunc("/v1/policy/pull", h.PolicyPull)
	}
	if h.PolicyAck != nil {
		mux.HandleFunc("/v1/policy/ack", h.PolicyAck)
	}
	if h.ReleasePull != nil {
		mux.HandleFunc("/v1/release/pull", h.ReleasePull)
	}
	if h.ReleaseAck != nil {
		mux.HandleFunc("/v1/release/ack", h.ReleaseAck)
	}
	if h.LogsPush != nil {
		mux.HandleFunc("/v1/logs/push", h.LogsPush)
	}
}
