package center

import _ "embed"

//go:embed assets/admin_devices.html
var adminDevicesPageHTML string

//go:embed assets/admin_devices.css
var adminDevicesPageCSS []byte

//go:embed assets/admin_devices.js
var adminDevicesPageJS []byte

//go:embed assets/admin_logs.html
var adminLogsPageHTML string

//go:embed assets/admin_logs.css
var adminLogsPageCSS []byte

//go:embed assets/admin_logs.js
var adminLogsPageJS []byte
