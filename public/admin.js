// admin dashboard — tools.shiftsad.dev
(() => {
  const $ = (s) => document.querySelector(s);
  const TOKEN_KEY = "vp_admin_token";
  const state = { tab: "reports", token: localStorage.getItem(TOKEN_KEY) || "" };

  // ── api ──────────────────────────────────────────────────────────
  async function api(path, opts = {}) {
    const headers = { ...(opts.headers || {}) };
    if (state.token) headers.Authorization = `Bearer ${state.token}`;
    if (opts.body && !(opts.body instanceof FormData) && !headers["Content-Type"]) {
      headers["Content-Type"] = "application/json";
    }
    const res = await fetch(`/api/admin${path}`, { ...opts, headers });
    if (res.status === 401) {
      state.token = "";
      localStorage.removeItem(TOKEN_KEY);
      showLogin();
      throw new Error("sessão expirou");
    }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `erro ${res.status}`);
    return data;
  }

  function toast(msg, isErr = false) {
    const el = $("#toast");
    el.textContent = msg;
    el.classList.toggle("is-err", isErr);
    el.classList.add("is-shown");
    clearTimeout(toast._t);
    toast._t = setTimeout(() => el.classList.remove("is-shown"), 2400);
  }

  function escapeHtml(s) {
    return String(s ?? "").replace(/[&<>"']/g, (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
    );
  }

  function fmtDate(ms) {
    if (!ms) return "—";
    return new Date(ms).toLocaleString("pt-BR", { dateStyle: "short", timeStyle: "short" });
  }
  function fmtSize(n) {
    if (n == null) return "—";
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / 1024 / 1024).toFixed(2)} MB`;
  }
  function shortHash(h) {
    if (!h) return "";
    return `${h.slice(0, 10)}…${h.slice(-6)}`;
  }
  function statusPill(g) {
    if (g.in_allowed_list) return `<span class="pill is-ok">permitido</span>`;
    if (g.current_match) return `<span class="pill is-bad" title="${escapeHtml(g.current_match.pattern || "")}">vírus · ${escapeHtml(g.current_match.reason)}</span>`;
    return `<span class="pill">limpo</span>`;
  }
  function matchExplain(m, in_allowed) {
    if (in_allowed) return `<span>na allowlist — admin marcou como confiável</span>`;
    if (!m) return `<span class="dim">sem match nas blocklists atuais</span>`;
    const reasonText = {
      hash: "hash bate com a blocklist",
      package: `pacote bate com <strong>${escapeHtml(m.pattern)}</strong>`,
      url: `URL bate com <strong>${escapeHtml(m.pattern)}</strong>`,
    }[m.reason] || m.reason;
    const lbl = m.label ? ` · label <strong>${escapeHtml(m.label)}</strong>` : "";
    return `${reasonText}${lbl}`;
  }

  // ── auth ─────────────────────────────────────────────────────────
  function showLogin() {
    $("#dashboard").hidden = true;
    $("#login").hidden = false;
    setTimeout(() => $("#password")?.focus(), 0);
  }
  function showDashboard() {
    $("#login").hidden = true;
    $("#dashboard").hidden = false;
    refresh();
  }

  $("#login-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const password = $("#password").value;
    $("#login-err").textContent = "";
    try {
      const data = await fetch("/api/admin/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password }),
      }).then(async (r) => {
        const j = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(j.error || `erro ${r.status}`);
        return j;
      });
      state.token = data.token;
      localStorage.setItem(TOKEN_KEY, data.token);
      $("#password").value = "";
      showDashboard();
    } catch (err) {
      $("#login-err").textContent = err.message || "falha";
    }
  });

  $("#logout").addEventListener("click", () => {
    state.token = "";
    localStorage.removeItem(TOKEN_KEY);
    showLogin();
  });
  $("#refresh").addEventListener("click", () => refresh());

  $("#tabs").addEventListener("click", (e) => {
    const b = e.target.closest("button[data-tab]");
    if (!b) return;
    state.tab = b.dataset.tab;
    document.querySelectorAll("#tabs button").forEach((x) => x.classList.toggle("is-active", x === b));
    refresh();
  });

  // ── refresh dispatch ─────────────────────────────────────────────
  async function refresh() {
    try {
      const sum = await api("/summary");
      renderSummary(sum);
      if (state.tab === "reports") await loadReports();
      else if (state.tab === "hashes") await loadList("hashes");
      else if (state.tab === "packages") await loadList("packages");
      else if (state.tab === "urls") await loadList("urls");
      else if (state.tab === "allowed") await loadList("allowed");
      $("#last-loaded").textContent = `atualizado ${new Date().toLocaleTimeString("pt-BR")}`;
    } catch (err) {
      if (err.message !== "sessão expirou") toast(err.message, true);
    }
  }

  function renderSummary(s) {
    const r = s.reports || {};
    const b = s.blocklists || {};
    $("#summary").innerHTML = `
      <div class="summary__cell"><div class="summary__num is-bad">${r.infected_groups || 0}</div><div class="summary__label">grupos infectados</div></div>
      <div class="summary__cell"><div class="summary__num">${r.clean_groups || 0}</div><div class="summary__label">grupos limpos</div></div>
      <div class="summary__cell"><div class="summary__num is-ok">${r.allowed_groups || 0}</div><div class="summary__label">grupos permitidos</div></div>
      <div class="summary__cell"><div class="summary__num">${r.unique_hashes || 0}</div><div class="summary__label">hashes únicos</div></div>
      <div class="summary__cell"><div class="summary__num">${r.total || 0}</div><div class="summary__label">total de envios</div></div>
      <div class="summary__cell"><div class="summary__num">${b.hashes || 0}</div><div class="summary__label">blocklist hash</div></div>
      <div class="summary__cell"><div class="summary__num">${b.packages || 0}</div><div class="summary__label">blocklist pkg</div></div>
      <div class="summary__cell"><div class="summary__num">${b.urls || 0}</div><div class="summary__label">blocklist url</div></div>
      <div class="summary__cell"><div class="summary__num">${b.allowed || 0}</div><div class="summary__label">allowlist</div></div>
    `;
  }

  // ── reports tab ──────────────────────────────────────────────────
  async function loadReports() {
    const { groups } = await api("/reports/groups");
    if (!groups.length) {
      $("#panel").innerHTML = `<div class="empty">nenhum report ainda</div>`;
      return;
    }
    $("#panel").innerHTML = `
      <table class="table">
        <thead><tr>
          <th>Hash</th><th>Envios</th><th>Tamanho</th><th>Último</th><th>Status atual</th><th>Motivo</th><th></th>
        </tr></thead>
        <tbody>
          ${groups.map(g => `
            <tr data-hash="${escapeHtml(g.hash)}">
              <td class="hash" title="${escapeHtml(g.hash)}">${shortHash(g.hash)}</td>
              <td class="mono">${g.count}</td>
              <td class="mono">${fmtSize(g.file_size)}</td>
              <td class="dim">${fmtDate(g.last_seen)}</td>
              <td>${statusPill(g)}</td>
              <td class="dim" style="font-size:12px">${matchExplain(g.current_match, g.in_allowed_list)}</td>
              <td>
                <div class="row-actions">
                  <button class="js-detail">detalhes</button>
                  ${g.in_hash_list
                    ? `<button class="js-unblock">tirar da blocklist</button>`
                    : `<button class="js-block">marcar vírus</button>`}
                  ${g.in_allowed_list
                    ? `<button class="js-unallow">tirar da allowlist</button>`
                    : `<button class="js-allow">marcar limpo</button>`}
                  <button class="js-delete is-danger">apagar</button>
                </div>
              </td>
            </tr>
            <tr class="detail-row" hidden><td colspan="7" class="detail-cell"></td></tr>
          `).join("")}
        </tbody>
      </table>
    `;

    $("#panel").querySelectorAll(".js-detail").forEach((b) =>
      b.addEventListener("click", (e) => toggleDetail(e.target.closest("tr")))
    );
    $("#panel").querySelectorAll(".js-block").forEach((b) =>
      b.addEventListener("click", (e) => groupAction(e.target.closest("tr").dataset.hash, "mark-virus", "hash marcado como vírus"))
    );
    $("#panel").querySelectorAll(".js-unblock").forEach((b) =>
      b.addEventListener("click", (e) => removeFromList(e.target.closest("tr").dataset.hash, "hashes", "tirado da blocklist"))
    );
    $("#panel").querySelectorAll(".js-allow").forEach((b) =>
      b.addEventListener("click", (e) => groupAction(e.target.closest("tr").dataset.hash, "mark-clean", "hash marcado como permitido"))
    );
    $("#panel").querySelectorAll(".js-unallow").forEach((b) =>
      b.addEventListener("click", (e) => removeFromList(e.target.closest("tr").dataset.hash, "allowed", "tirado da allowlist"))
    );
    $("#panel").querySelectorAll(".js-delete").forEach((b) =>
      b.addEventListener("click", (e) => deleteGroup(e.target.closest("tr").dataset.hash))
    );
  }

  async function toggleDetail(row) {
    const detail = row.nextElementSibling;
    if (!detail.hidden) { detail.hidden = true; return; }
    const hash = row.dataset.hash;
    const cell = detail.querySelector(".detail-cell");
    cell.innerHTML = `<div class="dim mono" style="padding:12px 0">carregando…</div>`;
    detail.hidden = false;
    try {
      const { reports } = await api(`/reports?hash=${encodeURIComponent(hash)}&limit=50`);
      cell.innerHTML = reports.map(r => `
        <details class="report">
          <summary>
            <span class="name">#${r.id} · ${escapeHtml(r.filename)}</span>
            ${statusPill(r)}
            <span class="dim mono">${fmtDate(r.created_at)}</span>
          </summary>
          <div class="body">
            <dl>
              <dt>e-mail</dt>      <dd>${escapeHtml(r.email || "—")}</dd>
              <dt>ip</dt>          <dd>${escapeHtml(r.ip || "—")}</dd>
              <dt>tamanho</dt>     <dd>${fmtSize(r.file_size)}</dd>
              <dt>match atual</dt> <dd>${matchExplain(r.current_match, r.in_allowed_list)}</dd>
              <dt>na hora do scan</dt> <dd>${r.at_scan_match ? matchExplain(r.at_scan_match, false) : '<span class="dim">não bateu nada na hora</span>'}</dd>
            </dl>
            <div class="row-actions" style="justify-content:flex-start">
              ${r.has_file ? `<button class="js-download" data-id="${r.id}">baixar .jar</button>` : `<span class="dim mono">arquivo não armazenado</span>`}
              <button class="js-detail-full" data-id="${r.id}">ver análise completa</button>
            </div>
            <div class="full" hidden></div>
          </div>
        </details>
      `).join("");
      cell.querySelectorAll(".js-download").forEach((b) =>
        b.addEventListener("click", () => downloadFile(`/api/admin/reports/${b.dataset.id}/file`))
      );
      cell.querySelectorAll(".js-detail-full").forEach((b) =>
        b.addEventListener("click", () => loadFullDetail(+b.dataset.id, b.closest(".body").querySelector(".full")))
      );
    } catch (err) {
      cell.innerHTML = `<div class="dim mono" style="padding:12px 0">${escapeHtml(err.message)}</div>`;
    }
  }

  async function loadFullDetail(id, container) {
    if (!container.hidden) { container.hidden = true; return; }
    container.hidden = false;
    container.innerHTML = `<div class="dim mono">carregando…</div>`;
    try {
      const { report } = await api(`/reports/${id}`);
      container.innerHTML = `
        <dl>
          <dt>packages (${report.packages.length})</dt>
          <dd>${report.packages.length ? report.packages.map(escapeHtml).join("<br>") : "—"}</dd>
          <dt>urls (${report.urls.length})</dt>
          <dd>${report.urls.length ? report.urls.map(escapeHtml).join("<br>") : "—"}</dd>
        </dl>
      `;
    } catch (err) {
      container.innerHTML = `<div class="dim mono">${escapeHtml(err.message)}</div>`;
    }
  }

  async function downloadFile(url) {
    try {
      const res = await fetch(url, { headers: { Authorization: `Bearer ${state.token}` } });
      if (!res.ok) throw new Error(`erro ${res.status}`);
      const blob = await res.blob();
      const cd = res.headers.get("Content-Disposition") || "";
      const m = /filename="?([^"]+)"?/.exec(cd);
      const name = (m && m[1]) || "plugin.jar";
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = name;
      a.click();
      URL.revokeObjectURL(a.href);
    } catch (err) {
      toast(err.message, true);
    }
  }

  async function groupAction(hash, action, msg) {
    try {
      await api(`/groups/${hash}/${action}`, { method: "POST", body: JSON.stringify({ label: "" }) });
      toast(msg);
      await refresh();
    } catch (err) {
      toast(err.message, true);
    }
  }

  async function removeFromList(hash, kind, msg) {
    if (!confirm(`remover ${shortHash(hash)} da lista?`)) return;
    try {
      await api(`/${kind}/${encodeURIComponent(hash)}`, { method: "DELETE" });
      toast(msg);
      await refresh();
    } catch (err) {
      toast(err.message, true);
    }
  }

  async function deleteGroup(hash) {
    if (!confirm(`apagar todos os reports e o arquivo armazenado de ${shortHash(hash)}?`)) return;
    try {
      await api(`/groups/${encodeURIComponent(hash)}`, { method: "DELETE" });
      toast("reports apagados");
      await refresh();
    } catch (err) {
      toast(err.message, true);
    }
  }

  // ── blocklist tabs ───────────────────────────────────────────────
  const TAB_CONFIG = {
    hashes:   { keyField: "hash",    placeholder: "sha256 (64 hex chars)" },
    packages: { keyField: "pattern", placeholder: "ex: me.monkey ou me.monkey.*" },
    urls:     { keyField: "pattern", placeholder: "ex: evil.example.com" },
    allowed:  { keyField: "hash",    placeholder: "sha256 (64 hex chars) — hash de arquivo confiável" },
  };

  async function loadList(kind) {
    const cfg = TAB_CONFIG[kind];
    const { items } = await api(`/${kind}`);
    $("#panel").innerHTML = `
      <form class="add-form" id="add-form">
        <input class="input" name="key" placeholder="${cfg.placeholder}" required />
        <input class="input" name="label" placeholder="label público (opcional)" />
        <button class="btn" type="submit">adicionar</button>
      </form>
      ${items.length ? `
        <table class="table">
          <thead><tr>
            <th>${cfg.keyField === "hash" ? "Hash" : "Pattern"}</th>
            <th>Label</th>
            <th>Origem</th>
            <th>Adicionado</th>
            <th></th>
          </tr></thead>
          <tbody>
            ${items.map(it => `
              <tr>
                <td class="${cfg.keyField === "hash" ? "hash" : "mono"}" title="${escapeHtml(it[cfg.keyField])}">${escapeHtml(cfg.keyField === "hash" ? shortHash(it[cfg.keyField]) : it[cfg.keyField])}</td>
                <td>${escapeHtml(it.label || "—")}</td>
                <td class="dim" style="font-size:11.5px">${escapeHtml(it.source || "—")}</td>
                <td class="dim">${fmtDate(it.added_at)}</td>
                <td>
                  <div class="row-actions">
                    <button class="js-del is-danger" data-key="${escapeHtml(it[cfg.keyField])}">remover</button>
                  </div>
                </td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      ` : `<div class="empty">nada na lista</div>`}
    `;
    $("#add-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      const fd = new FormData(e.target);
      const key = String(fd.get("key") || "").trim();
      const label = String(fd.get("label") || "").trim();
      if (!key) return;
      const body = { label };
      body[cfg.keyField] = key;
      try {
        await api(`/${kind}`, { method: "POST", body: JSON.stringify(body) });
        toast("adicionado");
        await refresh();
      } catch (err) {
        toast(err.message, true);
      }
    });
    $("#panel").querySelectorAll(".js-del").forEach((b) =>
      b.addEventListener("click", async () => {
        const key = b.dataset.key;
        if (!confirm(`remover ${cfg.keyField === "hash" ? shortHash(key) : key}?`)) return;
        try {
          await api(`/${kind}/${encodeURIComponent(key)}`, { method: "DELETE" });
          toast("removido");
          await refresh();
        } catch (err) {
          toast(err.message, true);
        }
      })
    );
  }

  // ── boot ─────────────────────────────────────────────────────────
  (async () => {
    if (!state.token) { showLogin(); return; }
    try {
      await api("/me");
      showDashboard();
    } catch {
      showLogin();
    }
  })();
})();
