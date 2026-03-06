package admin

import "net/http"

type Handlers struct {
	Policies    http.HandlerFunc
	PolicyByID  http.HandlerFunc
	Devices     http.HandlerFunc
	DeviceByID  http.HandlerFunc
	LogDevices  http.HandlerFunc
	LogEntries  http.HandlerFunc
	LogDownload http.HandlerFunc
}

func Register(mux *http.ServeMux, h Handlers) {
	if mux == nil {
		return
	}
	if h.Policies != nil {
		mux.HandleFunc("/v1/policies", h.Policies)
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
	if h.LogDownload != nil {
		mux.HandleFunc("/v1/admin/logs/download", h.LogDownload)
	}
}
