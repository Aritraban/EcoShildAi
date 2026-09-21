/* EcoShield AI - API client (same-origin, Bearer + CSRF double-submit). */
const API = (() => {
  const PREFIX = "/api";
  const TOKEN_KEY = "ecoshield_access";
  const ROLE_KEY = "ecoshield_role";
  let csrfToken = "";

  function getToken() { return sessionStorage.getItem(TOKEN_KEY) || ""; }
  function setToken(t, role) {
    if (t) sessionStorage.setItem(TOKEN_KEY, t);
    if (role) sessionStorage.setItem(ROLE_KEY, role);
  }
  function clearToken() { sessionStorage.removeItem(TOKEN_KEY); sessionStorage.removeItem(ROLE_KEY); }
  function getRole() { return sessionStorage.getItem(ROLE_KEY) || ""; }

  function readCsrfCookie() {
    const m = document.cookie.match(/(?:^|;\s*)ecoshield_csrf=([^;]+)/);
    return m ? decodeURIComponent(m[1]) : "";
  }

  async function ensureCsrf() {
    csrfToken = readCsrfCookie();
    if (csrfToken) return csrfToken;
    try {
      const r = await fetch(`${PREFIX}/csrf-token`, { credentials: "include" });
      const data = await r.json();
      csrfToken = data.csrf_token || readCsrfCookie();
    } catch (_) { /* ignore */ }
    return csrfToken;
  }

  async function request(method, path, { body, auth = true } = {}) {
    const headers = { "Accept": "application/json" };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (auth && getToken()) headers["Authorization"] = `Bearer ${getToken()}`;
    if (["POST", "PUT", "PATCH", "DELETE"].includes(method)) {
      const token = await ensureCsrf();
      if (token) headers["X-CSRF-Token"] = token;
    }
    const res = await fetch(`${PREFIX}${path}`, {
      method,
      headers,
      credentials: "include",
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });

    if (res.status === 401 && auth && getToken()) {
      // Session expired -> try refresh once, else bounce to login.
      const ok = await tryRefresh();
      if (ok) return request(method, path, { body, auth });
      clearToken();
      if (!location.pathname.endsWith("login.html")) location.href = "login.html";
      throw new Error("Session expired");
    }
    if (res.status === 204) return null;

    let data = null;
    const text = await res.text();
    if (text) { try { data = JSON.parse(text); } catch (_) { data = { detail: text }; } }
    if (!res.ok) {
      const msg = (data && (data.detail || data.message)) || `Request failed (${res.status})`;
      const err = new Error(typeof msg === "string" ? msg : JSON.stringify(msg));
      err.status = res.status; err.data = data;
      throw err;
    }
    return data;
  }

  async function tryRefresh() {
    try {
      await ensureCsrf();
      const r = await fetch(`${PREFIX}/auth/refresh`, {
        method: "POST", credentials: "include",
        headers: { "X-CSRF-Token": csrfToken || "" },
      });
      if (!r.ok) return false;
      const data = await r.json();
      setToken(data.access_token, data.role);
      return true;
    } catch (_) { return false; }
  }

  return {
    get: (p, o) => request("GET", p, o),
    post: (p, body, o) => request("POST", p, { ...o, body }),
    put: (p, body, o) => request("PUT", p, { ...o, body }),
    patch: (p, body, o) => request("PATCH", p, { ...o, body }),
    del: (p, o) => request("DELETE", p, o),
    getToken, setToken, clearToken, getRole, ensureCsrf,
    login: (email, password) => request("POST", "/auth/login", { body: { email, password }, auth: false }),
    register: (data) => request("POST", "/auth/register", { body: data, auth: false }),
    logout: () => request("POST", "/auth/logout"),
  };
})();
