/* Thin fetch wrapper: attaches the bearer token, handles JSON, and
   redirects to login on 401 so every page doesn't repeat this logic. */
const API = {
  base: "",

  token() {
    return localStorage.getItem("ulpf_token");
  },

  setToken(t) {
    localStorage.setItem("ulpf_token", t);
  },

  clearToken() {
    localStorage.removeItem("ulpf_token");
  },

  async request(path, { method = "GET", body, isForm = false, query } = {}) {
    let url = this.base + path;
    if (query) {
      const qs = new URLSearchParams(
        Object.entries(query).filter(([, v]) => v !== undefined && v !== null && v !== "")
      ).toString();
      if (qs) url += (url.includes("?") ? "&" : "?") + qs;
    }
    const headers = {};
    const tok = this.token();
    if (tok) headers["Authorization"] = "Bearer " + tok;
    let payload = body;
    if (body && !isForm) {
      headers["Content-Type"] = "application/json";
      payload = JSON.stringify(body);
    }
    const resp = await fetch(url, { method, headers, body: payload });
    if (resp.status === 401) {
      this.clearToken();
      if (!location.pathname.endsWith("login.html")) {
        location.href = "/login.html";
      }
      throw new Error("Not authenticated");
    }
    const contentType = resp.headers.get("content-type") || "";
    let data = null;
    if (contentType.includes("application/json")) {
      data = await resp.json();
    } else {
      data = await resp.text();
    }
    if (!resp.ok) {
      const detail = (data && data.detail) ? data.detail : (typeof data === "string" ? data : resp.statusText);
      throw new Error(detail || `Request failed (${resp.status})`);
    }
    return data;
  },

  get(path, query) { return this.request(path, { method: "GET", query }); },
  post(path, body) { return this.request(path, { method: "POST", body }); },
  put(path, body) { return this.request(path, { method: "PUT", body }); },
  del(path) { return this.request(path, { method: "DELETE" }); },
  postForm(path, formData, query) { return this.request(path, { method: "POST", body: formData, isForm: true, query }); },
};
