/* EcoShield AI - shared UI: nav, auth guards, formatting helpers. */
const UI = (() => {
  const USER_LINKS = [
    ["dashboard.html", "Dashboard", "dashboard"],
    ["calculator.html", "Calculator", "calculator"],
    ["recommendations.html", "AI Advice", "recommendations"],
    ["assistant.html", "Eco Assistant", "assistant"],
    ["history.html", "History", "history"],
    ["security.html", "Security", "security"],
    ["profile.html", "Profile", "profile"],
  ];
  const STAFF_LINKS = [
    ["admin.html", "Admin", "admin"],
  ];

  function renderNav(active) {
    const host = document.getElementById("nav");
    if (!host) return;
    const role = API.getRole();
    let links = USER_LINKS.slice();
    if (role === "ADMIN" || role === "SECURITY_ADMIN") links = links.concat(STAFF_LINKS);
    const linkHtml = links
      .map(([href, label, key]) =>
        `<a href="${href}" class="${key === active ? "active" : ""}">${label}</a>`)
      .join("");
    host.innerHTML = `
      <div class="container nav-inner">
        <a class="brand" href="dashboard.html"><span class="logo">🛡️</span><span>EcoShield <span class="grad-text">AI</span></span></a>
        <nav class="nav-links">${linkHtml}<a href="#" id="logoutBtn" class="">Logout</a></nav>
      </div>`;
    const btn = document.getElementById("logoutBtn");
    if (btn) btn.addEventListener("click", async (e) => { e.preventDefault(); await doLogout(); });
  }

  async function doLogout() {
    try { await API.logout(); } catch (_) {}
    API.clearToken();
    location.href = "login.html";
  }

  function requireAuth() {
    if (!API.getToken()) { location.href = "login.html"; return false; }
    return true;
  }

  function requireStaff() {
    if (!requireAuth()) return false;
    const role = API.getRole();
    if (role !== "ADMIN" && role !== "SECURITY_ADMIN") {
      alert("You do not have permission to view this page.");
      location.href = "dashboard.html";
      return false;
    }
    return true;
  }

  function kg(v) { return `${Number(v || 0).toFixed(1)} kg`; }
  function tons(v) { return `${(Number(v || 0) / 1000).toFixed(2)} t`; }
  function pct(v) { return `${Number(v || 0).toFixed(1)}%`; }
  function date(v) { return v ? new Date(v).toLocaleString() : "—"; }

  function alertBox(container, type, message) {
    const el = document.createElement("div");
    el.className = `alert alert-${type === "error" ? "error" : "ok"}`;
    el.textContent = message;
    container.prepend(el);
    setTimeout(() => el.remove(), 6000);
  }

  function severityBadge(sev) {
    const s = (sev || "LOW").toUpperCase();
    const cls = { LOW: "ok", MEDIUM: "info", HIGH: "warn", CRITICAL: "danger" }[s] || "info";
    return `<span class="badge ${cls}"><span class="dot"></span>${s}</span>`;
  }

  return { renderNav, doLogout, requireAuth, requireStaff, kg, tons, pct, date, alertBox, severityBadge };
})();
