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

    byId("downloadRule").onclick = () => {
      const device = byId("deviceSelect").value.trim();
      if (!device) {
        setErr("device is required");
        return;
      }
      const state = byId("policyState").value.trim() || "desired";
      const url = "/v1/devices/" + encodeURIComponent(device) + ":download-policy?state=" + encodeURIComponent(state);
      fetch(url, { headers: { "X-API-Key": byId("apiKey").value.trim() } })
        .then(r => { if (!r.ok) return r.text().then(t => Promise.reject(new Error(t || ("HTTP " + r.status)))); return r.blob(); })
        .then(blob => {
          const a = document.createElement("a");
          a.href = URL.createObjectURL(blob);
          a.download = device + "-" + state + ".waf";
          a.click();
          URL.revokeObjectURL(a.href);
        })
        .catch(e => setErr(String(e.message || e)));
    };
