package center

import "net/http"

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

const adminDevicesPageHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>mamotama-center devices</title>
  <style>
    :root { --bg:#f5f7fb; --panel:#fff; --ink:#17212b; --muted:#586270; --line:#d8dee7; --brand:#0f766e; --warn:#b45309; --err:#9f1239; }
    body { margin:0; font-family: ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; background:linear-gradient(180deg,#eef2ff 0%,#f5f7fb 42%); color:var(--ink); }
    .wrap { max-width:1280px; margin:0 auto; padding:18px 14px 32px; }
    .grid { display:grid; gap:12px; grid-template-columns:repeat(auto-fit,minmax(380px,1fr)); }
    .panel { background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:12px; box-shadow:0 2px 8px rgba(16,24,40,.04); }
    h1 { margin:0 0 10px; font-size:28px; }
    h2 { margin:0 0 8px; font-size:16px; }
    .row { display:flex; gap:8px; align-items:center; flex-wrap:wrap; margin-bottom:8px; }
    label { font-size:12px; color:var(--muted); display:block; margin-bottom:3px; }
    input, textarea, button, select { font:inherit; }
    input, textarea, select { border:1px solid var(--line); border-radius:8px; padding:8px; background:#fff; }
    textarea { width:100%; min-height:220px; font-family: ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12px; }
    button { border:0; border-radius:8px; padding:8px 12px; background:var(--brand); color:#fff; cursor:pointer; }
    button.warn { background:var(--warn); }
    button.err { background:var(--err); }
    table { width:100%; border-collapse:collapse; font-size:13px; }
    th, td { border-bottom:1px solid var(--line); padding:6px 4px; text-align:left; }
    tr.selected { background:#e9f5f4; }
    .muted { color:var(--muted); font-size:12px; }
    .error { color:var(--err); font-size:12px; white-space:pre-wrap; }
    .ok { color:#166534; font-size:12px; white-space:pre-wrap; }
    .mono { font-family: ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12px; }
    pre.box { margin:0; padding:8px; border:1px solid var(--line); border-radius:8px; background:#fbfcff; min-height:120px; overflow:auto; font-family: ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12px; }
  </style>
</head>
<body>
  <div class="wrap">
    <h1>Center Admin Devices & Policies</h1>
    <div class="panel">
      <div class="row">
        <div style="flex:1; min-width:280px;">
          <label>Admin API Key (write key for mutate actions)</label>
          <input id="apiKey" type="password" placeholder="X-API-Key">
        </div>
        <button id="saveKey">Save Key</button>
        <button id="refreshAll">Refresh All</button>
      </div>
      <div class="muted">Read APIs: devices/policies/list/download. Write APIs: policy create/overwrite/approve/delete, device assign.</div>
      <div id="err" class="error"></div>
      <div id="ok" class="ok"></div>
    </div>

    <div class="grid">
      <div class="panel">
        <h2>Devices</h2>
        <div class="row">
          <button id="reloadDevices">Reload Devices</button>
          <span class="muted">Selected device: <span id="selectedDevice" class="mono">-</span></span>
        </div>
        <table id="devicesTable">
          <thead>
            <tr>
              <th>device_id</th><th>status</th><th>desired</th><th>current</th><th>flagged</th>
            </tr>
          </thead>
          <tbody></tbody>
        </table>
      </div>

      <div class="panel">
        <h2>Policies</h2>
        <div class="row">
          <button id="reloadPolicies">Reload Policies</button>
          <span class="muted">Selected policy: <span id="selectedPolicy" class="mono">-</span></span>
        </div>
        <table id="policiesTable">
          <thead>
            <tr>
              <th>version</th><th>status</th><th>assigned</th><th>applied</th><th>updated_at</th>
            </tr>
          </thead>
          <tbody></tbody>
        </table>
      </div>
    </div>

    <div class="panel" style="margin-top:12px;">
      <h2>Policy Editor / Actions</h2>
      <div class="row">
        <div style="min-width:320px; flex:1;">
          <label>Policy Version</label>
          <input id="version" placeholder="waf-2026-03-06">
        </div>
        <div style="min-width:320px; flex:1;">
          <label>Note</label>
          <input id="note" placeholder="optional note">
        </div>
      </div>
      <div class="row">
        <div style="min-width:320px; flex:1;">
          <label>Bundle (.tar.gz, optional)</label>
          <input id="bundleFile" type="file" accept=".tar.gz,.tgz,application/gzip,application/x-gzip">
        </div>
        <div style="min-width:320px; flex:1;">
          <label>Bundle SHA256 (auto)</label>
          <input id="bundleSHA" readonly>
        </div>
        <div style="min-width:260px; flex:1;">
          <label>WAF Raw Template (optional)</label>
          <select id="wafTemplate">
            <option value="">(none)</option>
            <option value="bundle_default">bundle_default</option>
          </select>
        </div>
      </div>
      <div class="row">
        <div style="min-width:420px; flex:1;">
          <label>Bundle .conf Files (for template)</label>
          <select id="bundleRuleFiles" multiple size="6" style="width:100%;"></select>
        </div>
      </div>
      <div>
        <label>WAF Raw</label>
        <textarea id="wafRaw" placeholder='{"enabled":true,"rule_files":["${MAMOTAMA_POLICY_ACTIVE}/rules/mamotama.conf"]}'></textarea>
      </div>
      <div class="row" style="margin-top:8px;">
        <button id="loadPolicy">Load Policy</button>
        <button id="createPolicy">Upload New (POST draft)</button>
        <button id="overwritePolicy" class="warn">Overwrite (PUT draft)</button>
        <button id="approvePolicy">Approve</button>
        <button id="deletePolicy" class="err">Delete Unused</button>
      </div>
      <div class="row">
        <button id="assignPolicy">Assign To Selected Device</button>
        <button id="downloadDesired">Download Desired Rule</button>
        <button id="downloadCurrent">Download Current Rule</button>
      </div>
      <div id="actionOut" class="mono"></div>
    </div>

    <div class="panel" style="margin-top:12px;">
      <h2>Rule Files Diff (Selected Device)</h2>
      <div class="row">
        <span class="muted">current: <span id="rfCurrentVersion" class="mono">-</span></span>
        <span class="muted">desired: <span id="rfDesiredVersion" class="mono">-</span></span>
        <span class="muted">target(edit): <span id="rfTargetVersion" class="mono">-</span></span>
      </div>
      <div class="row">
        <div style="min-width:420px; flex:1;">
          <label>Policy Active Base (preview expand)</label>
          <input id="rfActiveBase" value="/var/lib/mamotama-edge/policy-active" placeholder="/var/lib/mamotama-edge/policy-active">
          <div class="muted">Saved per device in browser localStorage.</div>
        </div>
        <div style="min-width:280px;">
          <label>Base Map Backup</label>
          <div class="row">
            <button id="rfExportBaseMap">Export JSON</button>
            <button id="rfImportBaseMap" class="warn">Import JSON</button>
          </div>
          <input id="rfImportFile" type="file" accept="application/json,.json" style="display:none;">
        </div>
      </div>
      <div class="grid">
        <div>
          <label>Current rule_files</label>
          <pre id="rfCurrent" class="box"></pre>
        </div>
        <div>
          <label>Desired rule_files</label>
          <pre id="rfDesired" class="box"></pre>
        </div>
        <div>
          <label>Target(edit) rule_files</label>
          <pre id="rfTarget" class="box"></pre>
        </div>
      </div>
      <div class="grid" style="margin-top:8px;">
        <div>
          <label>Current expanded (preview)</label>
          <pre id="rfCurrentExpanded" class="box"></pre>
        </div>
        <div>
          <label>Desired expanded (preview)</label>
          <pre id="rfDesiredExpanded" class="box"></pre>
        </div>
        <div>
          <label>Target expanded (preview)</label>
          <pre id="rfTargetExpanded" class="box"></pre>
        </div>
      </div>
      <div style="margin-top:8px;">
        <label>Diff Summary</label>
        <pre id="rfDiffSummary" class="box"></pre>
      </div>
    </div>
  </div>

  <script>
    const byId = (id) => document.getElementById(id);
    const keyStore = "center_admin_api_key";
    const rfBaseStore = "center_policy_active_base_by_device";
    const rfBaseDefault = "/var/lib/mamotama-edge/policy-active";
    let selectedDevice = "";
    let selectedPolicy = "";
    let devicesCache = [];
    let policiesCache = [];
    let assignedBy = {};
    let appliedBy = {};
    let bundleB64 = "";
    let bundleSHA = "";
    let activeBaseByDevice = {};

    byId("apiKey").value = localStorage.getItem(keyStore) || "";
    byId("saveKey").onclick = () => localStorage.setItem(keyStore, byId("apiKey").value);
    byId("rfActiveBase").value = rfBaseDefault;
    try {
      activeBaseByDevice = sanitizeActiveBaseMap(JSON.parse(localStorage.getItem(rfBaseStore) || "{}") || {});
    } catch {
      activeBaseByDevice = {};
    }

    function activeBaseKeyForDevice(deviceID) {
      const id = String(deviceID || "").trim();
      return id || "__default__";
    }

    function loadActiveBaseForSelection() {
      const key = activeBaseKeyForDevice(selectedDevice);
      const fallback = String(activeBaseByDevice["__default__"] || rfBaseDefault).trim() || rfBaseDefault;
      const value = String(activeBaseByDevice[key] || fallback).trim() || fallback;
      byId("rfActiveBase").value = value;
    }

    function saveActiveBaseForSelection() {
      const key = activeBaseKeyForDevice(selectedDevice);
      const value = byId("rfActiveBase").value.trim();
      if (value) activeBaseByDevice[key] = value;
      else delete activeBaseByDevice[key];
      localStorage.setItem(rfBaseStore, JSON.stringify(activeBaseByDevice));
    }

    function sanitizeActiveBaseMap(input) {
      const out = {};
      const src = (input && typeof input === "object") ? input : {};
      for (const [k, v] of Object.entries(src)) {
        const key = String(k || "").trim();
        const val = String(v || "").trim();
        if (!key || !val) continue;
        out[key] = val;
      }
      return out;
    }

    function exportActiveBaseMap() {
      const payload = {
        format: "center_policy_active_base_map/v1",
        exported_at: new Date().toISOString(),
        active_base_by_device: sanitizeActiveBaseMap(activeBaseByDevice),
      };
      const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
      const a = document.createElement("a");
      const stamp = new Date().toISOString().replace(/[:.]/g, "-");
      a.href = URL.createObjectURL(blob);
      a.download = "center-policy-active-base-map-" + stamp + ".json";
      a.click();
      URL.revokeObjectURL(a.href);
    }

    async function importActiveBaseMapFile(file) {
      if (!file) return;
      const text = await file.text();
      const parsed = JSON.parse(text);
      let map = {};
      if (parsed && typeof parsed === "object" && parsed.active_base_by_device && typeof parsed.active_base_by_device === "object") {
        map = parsed.active_base_by_device;
      } else {
        map = parsed;
      }
      activeBaseByDevice = sanitizeActiveBaseMap(map);
      localStorage.setItem(rfBaseStore, JSON.stringify(activeBaseByDevice));
      loadActiveBaseForSelection();
      renderRuleFilesDiff();
      setOk("imported policy active base map entries: " + Object.keys(activeBaseByDevice).length);
    }

    function setErr(msg) { byId("err").textContent = msg || ""; }
    function setOk(msg) { byId("ok").textContent = msg || ""; }
    function setActionOut(v) { byId("actionOut").textContent = typeof v === "string" ? v : JSON.stringify(v, null, 2); }
    function toHex(u8) { return Array.from(u8).map(b => b.toString(16).padStart(2, "0")).join(""); }
    function bytesToBase64(bytes) {
      const chunk = 0x8000;
      let out = "";
      for (let i = 0; i < bytes.length; i += chunk) {
        out += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
      }
      return btoa(out);
    }

    async function api(method, path, body) {
      const key = byId("apiKey").value.trim();
      const opts = { method, headers: { "X-API-Key": key } };
      if (body !== undefined) {
        opts.headers["Content-Type"] = "application/json";
        opts.body = JSON.stringify(body);
      }
      const res = await fetch(path, opts);
      const text = await res.text();
      let json = null;
      try { json = text ? JSON.parse(text) : null; } catch {}
      if (!res.ok) throw new Error((json && json.error) ? json.error : (text || ("HTTP " + res.status)));
      return json;
    }

    function renderDevices() {
      const tbody = byId("devicesTable").querySelector("tbody");
      tbody.innerHTML = "";
      for (const d of devicesCache) {
        const tr = document.createElement("tr");
        if (d.device_id === selectedDevice) tr.className = "selected";
        tr.innerHTML = "<td>"+(d.device_id||"")+"</td><td>"+(d.status||"")+"</td><td>"+(d.desired_policy_version||"")+"</td><td>"+(d.current_policy_version||"")+"</td><td>"+String(!!d.flagged)+"</td>";
        tr.onclick = () => {
          selectedDevice = d.device_id || "";
          byId("selectedDevice").textContent = selectedDevice || "-";
          renderDevices();
          loadActiveBaseForSelection();
          renderRuleFilesDiff();
        };
        tbody.appendChild(tr);
      }
    }

    function renderPolicies() {
      const tbody = byId("policiesTable").querySelector("tbody");
      tbody.innerHTML = "";
      for (const p of policiesCache) {
        const tr = document.createElement("tr");
        if (p.version === selectedPolicy) tr.className = "selected";
        const a = assignedBy[p.version] || 0;
        const c = appliedBy[p.version] || 0;
        tr.innerHTML = "<td>"+(p.version||"")+"</td><td>"+(p.status||"")+"</td><td>"+a+"</td><td>"+c+"</td><td>"+(p.updated_at||"")+"</td>";
        tr.onclick = () => {
          selectedPolicy = p.version || "";
          byId("selectedPolicy").textContent = selectedPolicy || "-";
          byId("version").value = selectedPolicy;
          renderPolicies();
          renderRuleFilesDiff();
        };
        tbody.appendChild(tr);
      }
    }

    async function loadDevices() {
      const body = await api("GET", "/v1/devices");
      devicesCache = body.devices || [];
      if (!selectedDevice && devicesCache.length > 0) {
        selectedDevice = devicesCache[0].device_id || "";
        byId("selectedDevice").textContent = selectedDevice || "-";
      }
      renderDevices();
      loadActiveBaseForSelection();
      renderRuleFilesDiff();
      setActionOut(body);
    }

    async function loadPolicies() {
      const body = await api("GET", "/v1/policies");
      policiesCache = body.policies || [];
      assignedBy = (body.summary && body.summary.assigned_by_version) || {};
      appliedBy = (body.summary && body.summary.applied_by_version) || {};
      if (!selectedPolicy && policiesCache.length > 0) {
        selectedPolicy = policiesCache[0].version || "";
        byId("selectedPolicy").textContent = selectedPolicy || "-";
        byId("version").value = selectedPolicy;
      }
      renderPolicies();
      renderRuleFilesDiff();
      setActionOut(body);
    }

    async function refreshAll() {
      setErr(""); setOk("");
      await Promise.all([loadDevices(), loadPolicies()]);
    }

    function currentVersion() {
      const v = byId("version").value.trim();
      if (!v) throw new Error("policy version is required");
      return v;
    }

    function currentDraftBody(version) {
      const raw = byId("wafRaw").value.trim();
      const template = byId("wafTemplate").value.trim();
      if (!raw && !template) throw new Error("waf_raw or waf_raw_template is required");
      if (raw && template) throw new Error("set either waf_raw or waf_raw_template, not both");
      const body = { version, note: byId("note").value.trim() };
      if (raw) body.waf_raw = raw;
      if (template) {
        body.waf_raw_template = template;
        const selected = Array.from(byId("bundleRuleFiles").selectedOptions || []).map(o => o.value).filter(Boolean);
        if (selected.length > 0) body.waf_rule_files = selected;
      }
      if (bundleB64 && bundleSHA) {
        body.bundle_tgz_b64 = bundleB64;
        body.bundle_sha256 = bundleSHA;
      }
      return body;
    }

    function renderBundleRuleFiles(files, recommended) {
      const sel = byId("bundleRuleFiles");
      sel.innerHTML = "";
      const recommendSet = new Set((recommended || []).filter(Boolean));
      for (const f of (files || [])) {
        const opt = document.createElement("option");
        opt.value = f;
        opt.textContent = f;
        if (recommendSet.has(f)) opt.selected = true;
        sel.appendChild(opt);
      }
    }

    function uniq(arr) {
      const seen = new Set();
      const out = [];
      for (const v of arr || []) {
        const s = String(v || "").trim();
        if (!s || seen.has(s)) continue;
        seen.add(s);
        out.push(s);
      }
      return out;
    }

    function parsePolicyRuleFiles(policy) {
      if (!policy || !policy.waf_raw) return { files: [], error: "" };
      try {
        const obj = JSON.parse(String(policy.waf_raw));
        if (!obj || !Array.isArray(obj.rule_files)) return { files: [], error: "" };
        return { files: uniq(obj.rule_files), error: "" };
      } catch {
        return { files: [], error: "waf_raw is not JSON" };
      }
    }

    function findPolicy(version) {
      const v = String(version || "").trim();
      if (!v) return null;
      return (policiesCache || []).find(p => (p.version || "") === v) || null;
    }

    function selectedDeviceRecord() {
      const id = String(selectedDevice || "").trim();
      if (!id) return null;
      return (devicesCache || []).find(d => (d.device_id || "") === id) || null;
    }

    function diffRuleFiles(base, next) {
      const baseSet = new Set(base || []);
      const nextSet = new Set(next || []);
      const added = [];
      const removed = [];
      for (const v of nextSet) if (!baseSet.has(v)) added.push(v);
      for (const v of baseSet) if (!nextSet.has(v)) removed.push(v);
      return { added, removed };
    }

    function fmtRuleFiles(files, parseError) {
      const rows = [];
      if (parseError) rows.push("# " + parseError);
      if (!files || files.length === 0) rows.push("(none)");
      else rows.push(...files);
      return rows.join("\n");
    }

    function isAbsPath(p) {
      return /^([a-zA-Z]:[\\/]|\/)/.test(String(p || ""));
    }

    function trimSlash(v) {
      return String(v || "").replace(/[\\/]+$/, "");
    }

    function joinPath(base, rel) {
      const b = trimSlash(base);
      const r = String(rel || "").replace(/^[./\\]+/, "");
      if (!b) return r;
      if (!r) return b;
      return b + "/" + r;
    }

    function expandRuleFilesPreview(files, activeBase) {
      const base = String(activeBase || "").trim();
      return (files || []).map((raw) => {
        let v = String(raw || "").trim();
        if (!v) return v;
        v = v.replaceAll("${MAMOTAMA_POLICY_ACTIVE}", base);
        v = v.replaceAll("${POLICY_ACTIVE_LINK}", base);
        if (!isAbsPath(v)) v = joinPath(base, v);
        return v;
      });
    }

    function renderRuleFilesDiff() {
      const dev = selectedDeviceRecord();
      const currentVersion = (dev && dev.current_policy_version) || "";
      const desiredVersion = (dev && dev.desired_policy_version) || "";
      const targetVersion = byId("version").value.trim() || selectedPolicy || "";

      const currentPolicy = findPolicy(currentVersion);
      const desiredPolicy = findPolicy(desiredVersion);
      const targetPolicy = findPolicy(targetVersion);

      const currentParsed = parsePolicyRuleFiles(currentPolicy);
      const desiredParsed = parsePolicyRuleFiles(desiredPolicy);
      const targetParsed = parsePolicyRuleFiles(targetPolicy);

      byId("rfCurrentVersion").textContent = currentVersion || "-";
      byId("rfDesiredVersion").textContent = desiredVersion || "-";
      byId("rfTargetVersion").textContent = targetVersion || "-";
      byId("rfCurrent").textContent = fmtRuleFiles(currentParsed.files, currentParsed.error);
      byId("rfDesired").textContent = fmtRuleFiles(desiredParsed.files, desiredParsed.error);
      byId("rfTarget").textContent = fmtRuleFiles(targetParsed.files, targetParsed.error);

      const activeBase = byId("rfActiveBase").value.trim();
      const currentExpanded = expandRuleFilesPreview(currentParsed.files, activeBase);
      const desiredExpanded = expandRuleFilesPreview(desiredParsed.files, activeBase);
      const targetExpanded = expandRuleFilesPreview(targetParsed.files, activeBase);
      byId("rfCurrentExpanded").textContent = fmtRuleFiles(currentExpanded, currentParsed.error);
      byId("rfDesiredExpanded").textContent = fmtRuleFiles(desiredExpanded, desiredParsed.error);
      byId("rfTargetExpanded").textContent = fmtRuleFiles(targetExpanded, targetParsed.error);

      const d1 = diffRuleFiles(currentParsed.files, desiredParsed.files);
      const d2 = diffRuleFiles(currentParsed.files, targetParsed.files);
      const d1x = diffRuleFiles(currentExpanded, desiredExpanded);
      const d2x = diffRuleFiles(currentExpanded, targetExpanded);
      const lines = [];
      lines.push("[current -> desired]");
      lines.push("add: " + (d1.added.length ? d1.added.join(", ") : "(none)"));
      lines.push("remove: " + (d1.removed.length ? d1.removed.join(", ") : "(none)"));
      lines.push("");
      lines.push("[current -> target(edit)]");
      lines.push("add: " + (d2.added.length ? d2.added.join(", ") : "(none)"));
      lines.push("remove: " + (d2.removed.length ? d2.removed.join(", ") : "(none)"));
      lines.push("");
      lines.push("[expanded current -> expanded desired]");
      lines.push("add: " + (d1x.added.length ? d1x.added.join(", ") : "(none)"));
      lines.push("remove: " + (d1x.removed.length ? d1x.removed.join(", ") : "(none)"));
      lines.push("");
      lines.push("[expanded current -> expanded target(edit)]");
      lines.push("add: " + (d2x.added.length ? d2x.added.join(", ") : "(none)"));
      lines.push("remove: " + (d2x.removed.length ? d2x.removed.join(", ") : "(none)"));
      byId("rfDiffSummary").textContent = lines.join("\n");
    }

    function triggerDownload(url, fileName) {
      return fetch(url, { headers: { "X-API-Key": byId("apiKey").value.trim() } })
        .then(r => { if (!r.ok) return r.text().then(t => Promise.reject(new Error(t || ("HTTP " + r.status)))); return r.blob(); })
        .then(blob => {
          const a = document.createElement("a");
          a.href = URL.createObjectURL(blob);
          a.download = fileName;
          a.click();
          URL.revokeObjectURL(a.href);
        });
    }

    byId("refreshAll").onclick = () => refreshAll().catch(e => setErr(String(e.message || e)));
    byId("reloadDevices").onclick = () => loadDevices().catch(e => setErr(String(e.message || e)));
    byId("reloadPolicies").onclick = () => loadPolicies().catch(e => setErr(String(e.message || e)));

    byId("loadPolicy").onclick = async () => {
      try {
        setErr(""); setOk("");
        const version = currentVersion();
        const body = await api("GET", "/v1/policies/" + encodeURIComponent(version));
        const p = body.policy || {};
        byId("note").value = p.note || "";
        byId("wafRaw").value = p.waf_raw || "";
        byId("wafTemplate").value = "";
        byId("bundleSHA").value = p.bundle_sha256 || "";
        renderBundleRuleFiles([], []);
        bundleB64 = "";
        bundleSHA = "";
        byId("bundleFile").value = "";
        selectedPolicy = p.version || version;
        byId("selectedPolicy").textContent = selectedPolicy;
        renderPolicies();
        renderRuleFilesDiff();
        setActionOut(body);
      } catch (e) { setErr(String(e.message || e)); }
    };

    byId("createPolicy").onclick = async () => {
      try {
        setErr(""); setOk("");
        const version = currentVersion();
        const body = await api("POST", "/v1/policies", currentDraftBody(version));
        setOk("created/updated draft: " + version);
        setActionOut(body);
        await loadPolicies();
        renderRuleFilesDiff();
      } catch (e) { setErr(String(e.message || e)); }
    };

    byId("overwritePolicy").onclick = async () => {
      try {
        setErr(""); setOk("");
        const version = currentVersion();
        const body = await api("PUT", "/v1/policies/" + encodeURIComponent(version), currentDraftBody(version));
        setOk("overwritten as draft: " + version);
        setActionOut(body);
        await loadPolicies();
        renderRuleFilesDiff();
      } catch (e) { setErr(String(e.message || e)); }
    };

    byId("approvePolicy").onclick = async () => {
      try {
        setErr(""); setOk("");
        const version = currentVersion();
        const body = await api("POST", "/v1/policies/" + encodeURIComponent(version) + ":approve");
        setOk("approved: " + version);
        setActionOut(body);
        await loadPolicies();
        renderRuleFilesDiff();
      } catch (e) { setErr(String(e.message || e)); }
    };

    byId("deletePolicy").onclick = async () => {
      try {
        setErr(""); setOk("");
        const version = currentVersion();
        const body = await api("DELETE", "/v1/policies/" + encodeURIComponent(version));
        setOk("deleted: " + version);
        setActionOut(body);
        if (selectedPolicy === version) {
          selectedPolicy = "";
          byId("selectedPolicy").textContent = "-";
        }
        await loadPolicies();
        renderRuleFilesDiff();
      } catch (e) { setErr(String(e.message || e)); }
    };

    byId("assignPolicy").onclick = async () => {
      try {
        setErr(""); setOk("");
        const version = currentVersion();
        const device = selectedDevice || "";
        if (!device) throw new Error("select device first");
        const body = await api("POST", "/v1/devices/" + encodeURIComponent(device) + ":assign-policy", { version });
        setOk("assigned policy " + version + " to " + device);
        setActionOut(body);
        await loadDevices();
        renderRuleFilesDiff();
      } catch (e) { setErr(String(e.message || e)); }
    };

    byId("downloadDesired").onclick = async () => {
      try {
        setErr(""); setOk("");
        const device = selectedDevice || "";
        if (!device) throw new Error("select device first");
        await triggerDownload("/v1/devices/" + encodeURIComponent(device) + ":download-policy?state=desired", device + "-desired.waf");
      } catch (e) { setErr(String(e.message || e)); }
    };

    byId("downloadCurrent").onclick = async () => {
      try {
        setErr(""); setOk("");
        const device = selectedDevice || "";
        if (!device) throw new Error("select device first");
        await triggerDownload("/v1/devices/" + encodeURIComponent(device) + ":download-policy?state=current", device + "-current.waf");
      } catch (e) { setErr(String(e.message || e)); }
    };

    byId("rfExportBaseMap").onclick = () => {
      try {
        setErr(""); setOk("");
        exportActiveBaseMap();
        setOk("exported policy active base map");
      } catch (e) { setErr(String(e.message || e)); }
    };

    byId("rfImportBaseMap").onclick = () => {
      byId("rfImportFile").click();
    };

    byId("rfImportFile").onchange = async (ev) => {
      try {
        setErr(""); setOk("");
        const f = (ev.target.files || [])[0];
        await importActiveBaseMapFile(f);
      } catch (e) { setErr(String(e.message || e)); }
      finally { byId("rfImportFile").value = ""; }
    };

    byId("bundleFile").onchange = async (ev) => {
      try {
        setErr(""); setOk("");
        const f = (ev.target.files || [])[0];
        if (!f) {
          bundleB64 = "";
          bundleSHA = "";
          byId("bundleSHA").value = "";
          renderBundleRuleFiles([], []);
          return;
        }
        const buf = await f.arrayBuffer();
        const bytes = new Uint8Array(buf);
        const digest = await crypto.subtle.digest("SHA-256", bytes);
        bundleSHA = toHex(new Uint8Array(digest));
        bundleB64 = bytesToBase64(bytes);
        byId("bundleSHA").value = bundleSHA;
        const inspect = await api("POST", "/v1/policies:inspect-bundle", { bundle_tgz_b64: bundleB64, bundle_sha256: bundleSHA });
        const bundle = (inspect && inspect.bundle) || {};
        renderBundleRuleFiles(bundle.conf_files || [], bundle.recommended_rule_files || []);
        if (!byId("wafRaw").value.trim() && !byId("wafTemplate").value) {
          byId("wafTemplate").value = "bundle_default";
        }
        setOk("bundle loaded: " + f.name + " (" + bytes.length + " bytes, conf=" + ((bundle.conf_count|0)) + ")");
      } catch (e) { setErr(String(e.message || e)); }
    };

    byId("version").oninput = () => renderRuleFilesDiff();
    byId("rfActiveBase").oninput = () => {
      saveActiveBaseForSelection();
      renderRuleFilesDiff();
    };

    refreshAll().catch(e => setErr(String(e.message || e)));
  </script>
</body>
</html>`
