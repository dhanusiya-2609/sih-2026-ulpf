/* App shell shared by every authenticated page: renders the sidebar and
   topbar, enforces the auth guard, and exposes small formatting/toast
   helpers used across pages. */

const NAV_ITEMS = [
  { group: "Overview", items: [
    { href: "dashboard.html", label: "Dashboard", icon: "bi-grid-1x2" },
  ]},
  { group: "Data", items: [
    { href: "events.html", label: "Event Explorer", icon: "bi-search" },
    { href: "ingest.html", label: "Ingestion", icon: "bi-cloud-arrow-up" },
    { href: "export.html", label: "Export", icon: "bi-box-arrow-up-right" },
  ]},
  { group: "Configuration", items: [
    { href: "sources.html", label: "Sources", icon: "bi-hdd-network" },
    { href: "parsers.html", label: "Parsers", icon: "bi-braces" },
    { href: "training.html", label: "Onboarding", icon: "bi-magic" },
    { href: "alerts.html", label: "Alerts", icon: "bi-bell" },
  ]},
  { group: "System", items: [
    { href: "settings.html", label: "Settings", icon: "bi-gear" },
    { href: "audit.html", label: "Audit Log", icon: "bi-journal-text" },
  ]},
];

const PAGE_META = {
  "dashboard.html": { title: "Dashboard", desc: "Ingestion volume, normalization confidence, and listener health across all registered sources." },
  "events.html": { title: "Event Explorer", desc: "Server-side filtered search over normalized events, with full raw/normalized detail on demand." },
  "ingest.html": { title: "Ingestion", desc: "Upload log files for one-time or bulk processing." },
  "export.html": { title: "Export", desc: "Download normalized events for downstream SIEM or data-lake ingestion." },
  "sources.html": { title: "Sources", desc: "Registered devices and log sources." },
  "parsers.html": { title: "Parsers", desc: "Built-in format parsers and approved field mappings." },
  "training.html": { title: "Parser Onboarding", desc: "Offline, human-approved field-mapping suggestions for unrecognized formats." },
  "alerts.html": { title: "Alerts", desc: "Simple rule-based matching against normalized event fields." },
  "settings.html": { title: "Settings", desc: "Effective server configuration and integrations for this deployment." },
  "audit.html": { title: "Audit Log", desc: "Record of configuration-changing actions." },
};

function requireAuth() {
  if (!API.token()) {
    location.href = "/login.html";
    return false;
  }
  return true;
}

function renderShell(activePage) {
  const root = document.getElementById("app-shell-root");
  if (!root) return;
  const meta = PAGE_META[activePage] || { title: "", desc: "" };

  const groups = NAV_ITEMS.map(g => `
    <div class="nav-section-label">${g.group}</div>
    ${g.items.map(it => `
      <a class="nav-link ${it.href === activePage ? "active" : ""}" href="${it.href}">
        <i class="bi ${it.icon}"></i><span>${it.label}</span>
      </a>`).join("")}
  `).join("");

  root.innerHTML = `
    <div class="app-shell">
      <aside class="app-sidebar">
        <div class="app-brand">
          <div class="d-flex align-items-center gap-2">
            <span class="mark">U</span>
            <div>
              <div class="name">ULPF Console</div>
              <div class="sub">Universal Log Pre-processing</div>
            </div>
          </div>
        </div>
        <nav class="app-nav">${groups}</nav>
        <div class="app-sidebar-footer">
          <div class="pill-live mb-2" style="color:#9FB2CE;"><span class="led"></span>backend reachable</div>
          <div class="user-line">
            <span id="shell-username">&mdash;</span>
            <button class="btn-link-muted" onclick="doLogout()">Log out</button>
          </div>
        </div>
      </aside>
      <div class="app-main">
        <div class="app-topbar">
          <div>
            <h1 class="page-title">${meta.title}</h1>
            <div class="page-desc">${meta.desc}</div>
          </div>
          <div class="d-flex align-items-center gap-2">
            <button class="theme-toggle" onclick="toggleTheme()" title="Toggle light/dark theme">
              <i class="bi bi-moon-stars" id="theme-toggle-icon"></i>
            </button>
          </div>
        </div>
        <div class="app-content" id="page-content"></div>
      </div>
    </div>
    <div class="toast-region" id="toast-region"></div>
  `;

  initThemeToggleIcon();

  API.get("/api/auth/me").then(u => {
    document.getElementById("shell-username").textContent = `${u.username} · ${u.role}`;
  }).catch(() => {});
}

function doLogout() {
  API.clearToken();
  location.href = "/login.html";
}

function toast(message, kind = "default") {
  const region = document.getElementById("toast-region");
  if (!region) { console.log(message); return; }
  const kindClass = kind === "error" ? "text-bg-danger" : kind === "success" ? "text-bg-success" : "text-bg-dark";
  const el = document.createElement("div");
  el.className = `toast align-items-center ${kindClass} border-0 show`;
  el.setAttribute("role", "alert");
  el.innerHTML = `<div class="d-flex"><div class="toast-body">${escapeHtml(message)}</div>
    <button type="button" class="btn-close btn-close-white me-2 m-auto" onclick="this.closest('.toast').remove()"></button></div>`;
  region.appendChild(el);
  setTimeout(() => el.remove(), 5000);
}

function fmtTime(iso) {
  if (!iso) return "—";
  try {
    const d = new Date(iso);
    return d.toISOString().replace("T", " ").slice(0, 19) + " UTC";
  } catch { return iso; }
}

function fmtRelative(iso) {
  if (!iso) return "—";
  const diffMs = Date.now() - new Date(iso).getTime();
  const s = Math.round(diffMs / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

function statusBadgeClass(status) {
  return { success: "ok", partial: "warn", failed: "danger", unrecognized: "unknown" }[status] || "unknown";
}

function severityBadgeClass(sev) {
  if (!sev) return "unknown";
  const s = String(sev).toLowerCase();
  if (["critical", "emergency", "alert", "high"].includes(s)) return "danger";
  if (["error", "warning", "medium"].includes(s)) return "warn";
  if (["informational", "notice", "debug", "low"].includes(s)) return "ok";
  return "unknown";
}

function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

/* Shared Chart.js palette so every chart on every page matches the brand
   theme and adapts automatically when the user switches light/dark. */
function chartPalette() {
  const css = getComputedStyle(document.documentElement);
  return {
    text: css.getPropertyValue("--app-text-muted").trim() || "#64748B",
    grid: css.getPropertyValue("--app-border").trim() || "#E2E8F0",
    primary: css.getPropertyValue("--brand-primary").trim() || "#1E3A5F",
    accent: css.getPropertyValue("--brand-accent").trim() || "#0F8B8D",
    ok: css.getPropertyValue("--status-ok").trim() || "#0F9D58",
    warn: css.getPropertyValue("--status-warn").trim() || "#B7791F",
    danger: css.getPropertyValue("--status-danger").trim() || "#C0362C",
    unknown: css.getPropertyValue("--status-unknown").trim() || "#64748B",
    series: document.documentElement.getAttribute("data-bs-theme") === "dark"
      ? ["#5C8AC7", "#34C6C4", "#8FB4E8", "#F0B429", "#94A3B8", "#7BE0DE", "#C9A24A", "#7FA0CC"]
      : ["#1E3A5F", "#0F8B8D", "#5C8AC7", "#B7791F", "#7C8AA8", "#34C6C4", "#8C6D31", "#4C6A92"],
  };
}
