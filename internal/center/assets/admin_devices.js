    const byId = (id) => document.getElementById(id);
    const keyStore = "center_admin_api_key";
    const rfBaseStore = "center_policy_active_base_by_device";
    const rfProfileStore = "center_policy_active_base_profiles_v1";
    const rfDefaultProfile = "default";
    const rfBaseDefault = "/var/lib/mamotama-edge/policy-active";
    let selectedDevice = "";
    let selectedPolicy = "";
    let selectedRelease = "";
    let devicesCache = [];
    let policiesCache = [];
    let releasesCache = [];
    let assignedBy = {};
    let appliedBy = {};
    let releaseAssignedBy = {};
    let releaseAppliedBy = {};
    let bundleB64 = "";
    let bundleSHA = "";
    let releaseBinaryB64 = "";
    let releaseSHA = "";
    let activeBaseByDevice = {};
    let activeBaseProfiles = {};
    let currentBaseProfile = rfDefaultProfile;

    byId("apiKey").value = localStorage.getItem(keyStore) || "";
    byId("saveKey").onclick = () => localStorage.setItem(keyStore, byId("apiKey").value);
    hydrateActiveBaseState();
    renderProfileControls();
    byId("rfActiveBase").value = rfBaseDefault;

    function activeBaseKeyForDevice(deviceID) {
      const id = String(deviceID || "").trim();
      return id || "__default__";
    }

    function sanitizeProfileName(raw) {
      const base = String(raw || "").trim().replace(/\s+/g, "-");
      const safe = base.replace(/[^a-zA-Z0-9._-]/g, "");
      return safe;
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
      persistActiveBaseState();
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

    function sanitizeActiveBaseProfiles(input) {
      const out = {};
      const src = (input && typeof input === "object") ? input : {};
      for (const [name, map] of Object.entries(src)) {
        const safeName = sanitizeProfileName(name);
        if (!safeName) continue;
        out[safeName] = sanitizeActiveBaseMap(map);
      }
      return out;
    }

    function persistActiveBaseState() {
      activeBaseByDevice = sanitizeActiveBaseMap(activeBaseByDevice);
      activeBaseProfiles[currentBaseProfile] = activeBaseByDevice;
      const payload = {
        format: "center_policy_active_base_profiles/v1",
        current_profile: currentBaseProfile,
        profiles: sanitizeActiveBaseProfiles(activeBaseProfiles),
      };
      localStorage.setItem(rfProfileStore, JSON.stringify(payload));
      localStorage.setItem(rfBaseStore, JSON.stringify(activeBaseByDevice));
    }

    function hydrateActiveBaseState() {
      activeBaseProfiles = {};
      currentBaseProfile = rfDefaultProfile;
      try {
        const parsed = JSON.parse(localStorage.getItem(rfProfileStore) || "{}") || {};
        const profiles = sanitizeActiveBaseProfiles(parsed.profiles || {});
        if (Object.keys(profiles).length > 0) {
          activeBaseProfiles = profiles;
          const preferred = sanitizeProfileName(parsed.current_profile || "");
          if (preferred && activeBaseProfiles[preferred]) currentBaseProfile = preferred;
          else currentBaseProfile = Object.keys(activeBaseProfiles).sort()[0];
        }
      } catch {}

      if (Object.keys(activeBaseProfiles).length === 0) {
        let legacy = {};
        try { legacy = sanitizeActiveBaseMap(JSON.parse(localStorage.getItem(rfBaseStore) || "{}") || {}); } catch {}
        activeBaseProfiles[rfDefaultProfile] = legacy;
        currentBaseProfile = rfDefaultProfile;
      }
      activeBaseByDevice = sanitizeActiveBaseMap(activeBaseProfiles[currentBaseProfile] || {});
      activeBaseProfiles[currentBaseProfile] = activeBaseByDevice;
      persistActiveBaseState();
    }

    function renderProfileControls() {
      const names = Object.keys(activeBaseProfiles).sort();
      const sel = byId("rfProfileSelect");
      sel.innerHTML = "";
      for (const name of names) {
        const opt = document.createElement("option");
        opt.value = name;
        opt.textContent = name;
        if (name === currentBaseProfile) opt.selected = true;
        sel.appendChild(opt);
      }
      byId("rfProfileName").value = currentBaseProfile;

      const compareSel = byId("rfProfileCompare");
      const prevCompare = String(compareSel.value || "").trim();
      compareSel.innerHTML = "";
      const noneOpt = document.createElement("option");
      noneOpt.value = "";
      noneOpt.textContent = "(none)";
      compareSel.appendChild(noneOpt);
      for (const name of names) {
        if (name === currentBaseProfile) continue;
        const opt = document.createElement("option");
        opt.value = name;
        opt.textContent = name;
        compareSel.appendChild(opt);
      }
      let nextCompare = prevCompare;
      if (!nextCompare || nextCompare === currentBaseProfile || !activeBaseProfiles[nextCompare]) {
        nextCompare = names.find((v) => v !== currentBaseProfile) || "";
      }
      compareSel.value = nextCompare;
      renderProfileMapDiff();
    }

    function profileDiffType(currentVal, compareVal) {
      const currentMissing = currentVal === "";
      const compareMissing = compareVal === "";
      if (currentMissing && !compareMissing) return "missing_current";
      if (!currentMissing && compareMissing) return "missing_compare";
      return "changed";
    }

    function includeProfileDiffType(diffType, filter) {
      if (filter === "changed") return diffType === "changed";
      if (filter === "missing_current") return diffType === "missing_current";
      if (filter === "missing_compare") return diffType === "missing_compare";
      return true;
    }

    function sortProfileDiffRows(rows, mode) {
      rows.sort((a, b) => {
        if (mode === "key_desc") {
          return b.key.localeCompare(a.key);
        }
        if (mode === "type_key") {
          const order = { changed: 0, missing_current: 1, missing_compare: 2 };
          const ao = order[a.type] ?? 99;
          const bo = order[b.type] ?? 99;
          if (ao !== bo) return ao - bo;
          return a.key.localeCompare(b.key);
        }
        return a.key.localeCompare(b.key);
      });
      return rows;
    }

    function renderProfileMapDiff() {
      const compareProfile = String(byId("rfProfileCompare").value || "").trim();
      const diffFilter = String(byId("rfProfileDiffFilter").value || "all").trim();
      const search = String(byId("rfProfileDiffSearch").value || "").trim().toLowerCase();
      const sortMode = String(byId("rfProfileDiffSort").value || "key_asc").trim();
      const currentMap = sanitizeActiveBaseMap(activeBaseProfiles[currentBaseProfile] || {});
      const compareMap = compareProfile ? sanitizeActiveBaseMap(activeBaseProfiles[compareProfile] || {}) : {};
      const tbody = byId("rfProfileDiffTableBody");
      tbody.innerHTML = "";

      if (!compareProfile) {
        byId("rfProfileDiffSummary").textContent = "select compare profile";
        return;
      }
      const keys = Array.from(new Set([...Object.keys(currentMap), ...Object.keys(compareMap)])).sort();
      const lines = [];
      lines.push("[profile map diff]");
      lines.push("current=" + currentBaseProfile + " compare=" + compareProfile);
      lines.push("filter=" + diffFilter);
      lines.push("sort=" + sortMode);
      lines.push("search=" + (search || "(none)"));
      lines.push("");
      let shown = 0;
      let missingCurrent = 0;
      let missingCompare = 0;
      let valueChanged = 0;
      let totalDiff = 0;
      const rows = [];
      for (const key of keys) {
        const currentVal = String(currentMap[key] || "");
        const compareVal = String(compareMap[key] || "");
        if (currentVal === compareVal) continue;
        totalDiff++;
        const diffType = profileDiffType(currentVal, compareVal);
        if (diffType === "missing_current") missingCurrent++;
        else if (diffType === "missing_compare") missingCompare++;
        else valueChanged++;

        if (!includeProfileDiffType(diffType, diffFilter)) continue;
        if (search) {
          const hay = (key + "\n" + currentVal + "\n" + compareVal + "\n" + diffType).toLowerCase();
          if (!hay.includes(search)) continue;
        }
        rows.push({ key, type: diffType, current: currentVal, compare: compareVal });
      }
      sortProfileDiffRows(rows, sortMode);
      for (const row of rows) {
        shown++;
        const tr = document.createElement("tr");
        const tdKey = document.createElement("td");
        tdKey.textContent = row.key;
        const tdType = document.createElement("td");
        tdType.textContent = row.type;
        const tdCurrent = document.createElement("td");
        tdCurrent.textContent = row.current || "(none)";
        const tdCompare = document.createElement("td");
        tdCompare.textContent = row.compare || "(none)";
        tr.appendChild(tdKey);
        tr.appendChild(tdType);
        tr.appendChild(tdCurrent);
        tr.appendChild(tdCompare);
        tbody.appendChild(tr);
      }
      if (shown === 0) {
        lines.push("(no entries matched filter)");
      } else {
        lines.push("");
        lines.push("shown_entries=" + shown);
      }
      lines.push("summary: total_diff=" + totalDiff + ", value_changed=" + valueChanged + ", missing_current=" + missingCurrent + ", missing_compare=" + missingCompare);
      byId("rfProfileDiffSummary").textContent = lines.join("\n");
    }

    function switchActiveBaseProfile(name) {
      const safe = sanitizeProfileName(name);
      if (!safe || !activeBaseProfiles[safe]) return;
      currentBaseProfile = safe;
      activeBaseByDevice = sanitizeActiveBaseMap(activeBaseProfiles[safe] || {});
      activeBaseProfiles[safe] = activeBaseByDevice;
      persistActiveBaseState();
      renderProfileControls();
      loadActiveBaseForSelection();
      renderRuleFilesDiff();
    }

    function saveAsActiveBaseProfile(name) {
      const safe = sanitizeProfileName(name);
      if (!safe) throw new Error("profile name is required");
      activeBaseProfiles[safe] = sanitizeActiveBaseMap(activeBaseByDevice);
      currentBaseProfile = safe;
      activeBaseByDevice = sanitizeActiveBaseMap(activeBaseProfiles[safe]);
      persistActiveBaseState();
      renderProfileControls();
      loadActiveBaseForSelection();
      renderRuleFilesDiff();
    }

    function deleteCurrentActiveBaseProfile() {
      const names = Object.keys(activeBaseProfiles);
      if (names.length <= 1) throw new Error("at least one profile is required");
      delete activeBaseProfiles[currentBaseProfile];
      const next = Object.keys(activeBaseProfiles).sort()[0] || rfDefaultProfile;
      currentBaseProfile = next;
      activeBaseByDevice = sanitizeActiveBaseMap(activeBaseProfiles[next] || {});
      activeBaseProfiles[next] = activeBaseByDevice;
      persistActiveBaseState();
      renderProfileControls();
      loadActiveBaseForSelection();
      renderRuleFilesDiff();
    }

    function exportActiveBaseMap() {
      const payload = {
        format: "center_policy_active_base_profiles/v1",
        exported_at: new Date().toISOString(),
        current_profile: currentBaseProfile,
        profiles: sanitizeActiveBaseProfiles(activeBaseProfiles),
        active_base_by_device: sanitizeActiveBaseMap(activeBaseByDevice), // legacy field
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
      if (parsed && typeof parsed === "object" && parsed.profiles && typeof parsed.profiles === "object") {
        activeBaseProfiles = sanitizeActiveBaseProfiles(parsed.profiles);
        if (Object.keys(activeBaseProfiles).length === 0) {
          throw new Error("imported profiles are empty");
        }
        const preferred = sanitizeProfileName(parsed.current_profile || "");
        currentBaseProfile = preferred && activeBaseProfiles[preferred] ? preferred : Object.keys(activeBaseProfiles).sort()[0];
      } else {
        let map = {};
        if (parsed && typeof parsed === "object" && parsed.active_base_by_device && typeof parsed.active_base_by_device === "object") {
          map = parsed.active_base_by_device;
        } else {
          map = parsed;
        }
        activeBaseProfiles = {};
        activeBaseProfiles[rfDefaultProfile] = sanitizeActiveBaseMap(map);
        currentBaseProfile = rfDefaultProfile;
      }
      activeBaseByDevice = sanitizeActiveBaseMap(activeBaseProfiles[currentBaseProfile] || {});
      activeBaseProfiles[currentBaseProfile] = activeBaseByDevice;
      persistActiveBaseState();
      renderProfileControls();
      loadActiveBaseForSelection();
      renderRuleFilesDiff();
      setOk("imported profile(s): " + Object.keys(activeBaseProfiles).length + ", current=" + currentBaseProfile);
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
        const policyPair = (d.desired_policy_version || "-") + " / " + (d.current_policy_version || "-");
        const releasePair = (d.desired_release_version || "-") + " / " + (d.current_release_version || "-");
        tr.innerHTML = "<td>"+(d.device_id||"")+"</td><td>"+(d.status||"")+"</td><td>"+policyPair+"</td><td>"+releasePair+"</td><td>"+(d.desired_release_not_before_at||"-")+"</td><td>"+String(!!d.flagged)+"</td>";
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

    function renderReleases() {
      const tbody = byId("releasesTable").querySelector("tbody");
      tbody.innerHTML = "";
      for (const rel of releasesCache) {
        const tr = document.createElement("tr");
        if (rel.version === selectedRelease) tr.className = "selected";
        const assigned = releaseAssignedBy[rel.version] || 0;
        const applied = releaseAppliedBy[rel.version] || 0;
        tr.innerHTML = "<td>"+(rel.version||"")+"</td><td>"+(rel.platform||"")+"</td><td>"+(rel.status||"")+"</td><td>"+assigned+"</td><td>"+applied+"</td><td>"+(rel.updated_at||"")+"</td>";
        tr.onclick = () => {
          selectedRelease = rel.version || "";
          byId("selectedRelease").textContent = selectedRelease || "-";
          byId("releaseVersion").value = selectedRelease;
          if (rel.platform) byId("releasePlatform").value = rel.platform;
          renderReleases();
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

    async function loadReleases() {
      const body = await api("GET", "/v1/releases");
      releasesCache = body.releases || [];
      releaseAssignedBy = (body.summary && body.summary.assigned_by_version) || {};
      releaseAppliedBy = (body.summary && body.summary.applied_by_version) || {};
      if (!selectedRelease && releasesCache.length > 0) {
        selectedRelease = releasesCache[0].version || "";
        byId("selectedRelease").textContent = selectedRelease || "-";
        byId("releaseVersion").value = selectedRelease;
      }
      renderReleases();
      setActionOut(body);
    }

    async function refreshAll() {
      setErr(""); setOk("");
      await Promise.all([loadDevices(), loadPolicies(), loadReleases()]);
    }

    function currentVersion() {
      const v = byId("version").value.trim();
      if (!v) throw new Error("policy version is required");
      return v;
    }

    function currentReleaseVersion() {
      const v = byId("releaseVersion").value.trim();
      if (!v) throw new Error("release version is required");
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

    function currentReleaseDraftBody(version) {
      const platform = byId("releasePlatform").value.trim();
      if (!platform) throw new Error("release platform is required");
      if (!releaseBinaryB64 || !releaseSHA) throw new Error("release binary file is required");
      return {
        version,
        platform,
        sha256: releaseSHA,
        binary_b64: releaseBinaryB64,
        note: byId("releaseNote").value.trim(),
      };
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
    byId("reloadReleases").onclick = () => loadReleases().catch(e => setErr(String(e.message || e)));
    byId("rfProfileSelect").onchange = (ev) => {
      try {
        setErr(""); setOk("");
        switchActiveBaseProfile(ev.target.value);
        setOk("switched profile: " + currentBaseProfile);
      } catch (e) { setErr(String(e.message || e)); }
    };
    byId("rfProfileCompare").onchange = () => {
      try {
        setErr(""); setOk("");
        renderProfileMapDiff();
      } catch (e) { setErr(String(e.message || e)); }
    };
    byId("rfProfileDiffFilter").onchange = () => {
      try {
        setErr(""); setOk("");
        renderProfileMapDiff();
      } catch (e) { setErr(String(e.message || e)); }
    };
    byId("rfProfileDiffSort").onchange = () => {
      try {
        setErr(""); setOk("");
        renderProfileMapDiff();
      } catch (e) { setErr(String(e.message || e)); }
    };
    byId("rfProfileDiffSearch").oninput = () => {
      try {
        setErr(""); setOk("");
        renderProfileMapDiff();
      } catch (e) { setErr(String(e.message || e)); }
    };
    byId("rfProfileSave").onclick = () => {
      try {
        setErr(""); setOk("");
        saveAsActiveBaseProfile(byId("rfProfileName").value);
        setOk("saved profile: " + currentBaseProfile);
      } catch (e) { setErr(String(e.message || e)); }
    };
    byId("rfProfileDelete").onclick = () => {
      try {
        setErr(""); setOk("");
        const deleting = currentBaseProfile;
        deleteCurrentActiveBaseProfile();
        setOk("deleted profile: " + deleting + " -> current=" + currentBaseProfile);
      } catch (e) { setErr(String(e.message || e)); }
    };

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

    byId("loadRelease").onclick = async () => {
      try {
        setErr(""); setOk("");
        const version = currentReleaseVersion();
        const body = await api("GET", "/v1/releases/" + encodeURIComponent(version));
        const rel = body.release || {};
        selectedRelease = rel.version || version;
        byId("selectedRelease").textContent = selectedRelease || "-";
        byId("releaseVersion").value = selectedRelease;
        byId("releasePlatform").value = rel.platform || "";
        byId("releaseNote").value = rel.note || "";
        byId("releaseSHA").value = rel.sha256 || "";
        releaseSHA = rel.sha256 || "";
        releaseBinaryB64 = "";
        byId("releaseBinaryFile").value = "";
        renderReleases();
        byId("releaseActionOut").textContent = JSON.stringify(body, null, 2);
      } catch (e) { setErr(String(e.message || e)); }
    };

    byId("createRelease").onclick = async () => {
      try {
        setErr(""); setOk("");
        const version = currentReleaseVersion();
        const body = await api("POST", "/v1/releases", currentReleaseDraftBody(version));
        setOk("created/updated release draft: " + version);
        byId("releaseActionOut").textContent = JSON.stringify(body, null, 2);
        await loadReleases();
        await loadDevices();
      } catch (e) { setErr(String(e.message || e)); }
    };

    byId("overwriteRelease").onclick = async () => {
      try {
        setErr(""); setOk("");
        const version = currentReleaseVersion();
        const body = await api("PUT", "/v1/releases/" + encodeURIComponent(version), currentReleaseDraftBody(version));
        setOk("overwritten release draft: " + version);
        byId("releaseActionOut").textContent = JSON.stringify(body, null, 2);
        await loadReleases();
        await loadDevices();
      } catch (e) { setErr(String(e.message || e)); }
    };

    byId("approveRelease").onclick = async () => {
      try {
        setErr(""); setOk("");
        const version = currentReleaseVersion();
        const body = await api("POST", "/v1/releases/" + encodeURIComponent(version) + ":approve");
        setOk("approved release: " + version);
        byId("releaseActionOut").textContent = JSON.stringify(body, null, 2);
        await loadReleases();
      } catch (e) { setErr(String(e.message || e)); }
    };

    byId("deleteRelease").onclick = async () => {
      try {
        setErr(""); setOk("");
        const version = currentReleaseVersion();
        const body = await api("DELETE", "/v1/releases/" + encodeURIComponent(version));
        setOk("deleted release: " + version);
        byId("releaseActionOut").textContent = JSON.stringify(body, null, 2);
        if (selectedRelease === version) {
          selectedRelease = "";
          byId("selectedRelease").textContent = "-";
        }
        await loadReleases();
        await loadDevices();
      } catch (e) { setErr(String(e.message || e)); }
    };

    byId("assignRelease").onclick = async () => {
      try {
        setErr(""); setOk("");
        const version = currentReleaseVersion();
        const device = selectedDevice || "";
        if (!device) throw new Error("select device first");
        const applyAt = byId("releaseApplyAt").value.trim();
        const payload = { version };
        if (applyAt) payload.apply_at = applyAt;
        const body = await api("POST", "/v1/devices/" + encodeURIComponent(device) + ":assign-release", payload);
        setOk("assigned release " + version + " to " + device + (applyAt ? (" apply_at=" + applyAt) : ""));
        byId("releaseActionOut").textContent = JSON.stringify(body, null, 2);
        await loadDevices();
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

    byId("releaseBinaryFile").onchange = async (ev) => {
      try {
        setErr(""); setOk("");
        const f = (ev.target.files || [])[0];
        if (!f) {
          releaseBinaryB64 = "";
          releaseSHA = "";
          byId("releaseSHA").value = "";
          return;
        }
        const buf = await f.arrayBuffer();
        const bytes = new Uint8Array(buf);
        const digest = await crypto.subtle.digest("SHA-256", bytes);
        releaseSHA = toHex(new Uint8Array(digest));
        releaseBinaryB64 = bytesToBase64(bytes);
        byId("releaseSHA").value = releaseSHA;
        setOk("release binary loaded: " + f.name + " (" + bytes.length + " bytes)");
      } catch (e) { setErr(String(e.message || e)); }
    };

    byId("version").oninput = () => renderRuleFilesDiff();
    byId("releaseVersion").oninput = () => {
      selectedRelease = byId("releaseVersion").value.trim();
      byId("selectedRelease").textContent = selectedRelease || "-";
      renderReleases();
    };
    byId("rfActiveBase").oninput = () => {
      saveActiveBaseForSelection();
      renderRuleFilesDiff();
      renderProfileMapDiff();
    };

    refreshAll().catch(e => setErr(String(e.message || e)));
