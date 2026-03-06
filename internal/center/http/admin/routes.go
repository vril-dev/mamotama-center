package admin

import "net/http"

type Handlers struct {
	Policies    http.HandlerFunc
	PolicyTools http.HandlerFunc
	PolicyByID  http.HandlerFunc
	Devices     http.HandlerFunc
	DeviceByID  http.HandlerFunc
	LogDevices  http.HandlerFunc
	LogEntries  http.HandlerFunc
	LogSummary  http.HandlerFunc
	LogDownload http.HandlerFunc
	LogUI       http.HandlerFunc
	DeviceUI    http.HandlerFunc
}

func Register(mux *http.ServeMux, h Handlers) {
	if mux == nil {
		return
	}
	if h.Policies != nil {
		mux.HandleFunc("/v1/policies", h.Policies)
	}
	if h.PolicyTools != nil {
		mux.HandleFunc("/v1/policies:inspect-bundle", h.PolicyTools)
	}
	if h.PolicyByID != nil {
		mux.HandleFunc("/v1/policies/", h.PolicyByID)
	}
	if h.Devices != nil {
		mux.HandleFunc("/v1/devices", h.Devices)
	}
	if h.DeviceByID != nil {
		mux.HandleFunc("/v1/devices/", h.DeviceByID)
	}
	if h.LogDevices != nil {
		mux.HandleFunc("/v1/admin/logs/devices", h.LogDevices)
	}
	if h.LogEntries != nil {
		mux.HandleFunc("/v1/admin/logs", h.LogEntries)
	}
	if h.LogSummary != nil {
		mux.HandleFunc("/v1/admin/logs/summary", h.LogSummary)
	}
	if h.LogDownload != nil {
		mux.HandleFunc("/v1/admin/logs/download", h.LogDownload)
	}
	if h.LogUI != nil {
		mux.HandleFunc("/admin/logs", h.LogUI)
	}
	if h.DeviceUI != nil {
		mux.HandleFunc("/admin/devices", h.DeviceUI)
	}
}
