const state = {
  api: localStorage.getItem("netguard.api") || "http://127.0.0.1:5000",
  key: localStorage.getItem("netguard.key") || "",
};

const $ = (id) => document.getElementById(id);
const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, (c) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;",
}[c]));
const apiUrl = (path) => `${state.api.replace(/\/+$/, "")}${path}`;

async function request(path, options = {}) {
  const headers = {};
  if (state.key) headers["X-API-Key"] = state.key;
  const response = await fetch(apiUrl(path), { ...options, headers: { ...headers, ...(options.headers || {}) } });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.message || body.error || `HTTP ${response.status}`);
  return body;
}

async function simulate() {
  const button = $("simulate");
  button.disabled = true;
  button.textContent = "Simulyatsiya bajarilmoqda...";
  try {
    const result = await request("/api/v1/simulate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ minutes: 10, seed: 7 }),
    });
    showMessage(`Simulyatsiya tugadi: ${result.alerts} ta ogohlantirish, ${result.incidents} ta insident`, false);
    await refresh();
  } catch (error) {
    showMessage(error.message, true);
  } finally {
    button.disabled = false;
    button.textContent = "▶ Sinov hujumlarini simulyatsiya qilish";
  }
}

function showMessage(text, error = false) {
  $("message").textContent = text;
  $("message").className = `message ${error ? "error" : "ok"}`;
  $("message").hidden = false;
}

function level(value) {
  return `<span class="level ${escapeHtml(value)}">${escapeHtml(value || "—")}</span>`;
}

function renderStats(stats, health) {
  const cards = [
    ["Ulanishlar", stats.conns],
    ["Ogohlantirishlar", stats.alerts],
    ["Ochiq insidentlar", stats.incidents_open],
    ["To‘xtatilgan", stats.dropped],
    ["Rejim", health.mode],
  ];
  $("kpis").innerHTML = cards.map(([name, value]) =>
    `<article class="kpi"><span>${escapeHtml(name)}</span><strong>${escapeHtml(value)}</strong></article>`).join("");
}

function renderTables(incidents, alerts, blocklist) {
  $("incident-count").textContent = `${incidents.length} ta`;
  $("incidents").innerHTML = incidents.length ? incidents.map((item) =>
    `<tr><td>#${item.id}</td><td>${escapeHtml(item.title)}</td><td>${level(item.level)}</td>` +
    `<td>${Number(item.risk || 0).toFixed(2)}</td><td>${escapeHtml(item.status)}</td></tr>`).join("") :
    `<tr><td colspan="5" class="empty">Ochiq insident yo‘q</td></tr>`;

  $("block-count").textContent = `${blocklist.length} ta`;
  $("blocklist").innerHTML = blocklist.length ? blocklist.map((item) =>
    `<tr><td>${escapeHtml(item.ip)}</td><td>${escapeHtml(item.action)}</td>` +
    `<td>${item.timeout ? `${Math.ceil(item.timeout / 3600)} soat` : "cheksiz"}</td></tr>`).join("") :
    `<tr><td colspan="3" class="empty">Faol chora yo‘q</td></tr>`;

  $("alert-count").textContent = `${alerts.length} ta`;
  $("alerts").innerHTML = alerts.length ? alerts.slice(0, 20).map((item) =>
    `<tr><td>${escapeHtml(item.src)}</td><td>${escapeHtml(item.name)}</td><td>${level(item.level)}</td>` +
    `<td>${Number(item.risk || 0).toFixed(2)}</td><td>${new Date(Number(item.last_ts) * 1000).toLocaleString()}</td></tr>`).join("") :
    `<tr><td colspan="5" class="empty">Ogohlantirish yo‘q</td></tr>`;
}

async function refresh() {
  $("status").textContent = "Ma’lumotlar yuklanmoqda...";
  try {
    const [health, stats, incidents, alerts, blocklist] = await Promise.all([
      request("/api/v1/health"),
      request("/api/v1/stats"),
      request("/api/v1/incidents?status=open"),
      request("/api/v1/alerts?limit=20"),
      request("/api/v1/blocklist"),
    ]);
    renderStats(stats, health);
    renderTables(incidents.items || [], alerts.items || [], blocklist.items || []);
    $("status").textContent = `Backend ulandi · ${health.version} · ${health.mode.toUpperCase()}`;
    $("message").hidden = true;
  } catch (error) {
    $("status").textContent = "Backend bilan ulanish amalga oshmadi";
    const message = error instanceof TypeError && error.message === "Failed to fetch"
      ? "Backendga ulanib bo‘lmadi. Backend ishlayotganini va API URL to‘g‘ri ekanini tekshiring."
      : error.message;
    showMessage(message, true);
  }
}

$("api-url").value = state.api;
$("api-key").value = state.key;
$("settings").addEventListener("submit", (event) => {
  event.preventDefault();
  state.api = $("api-url").value.trim();
  state.key = $("api-key").value.trim();
  localStorage.setItem("netguard.api", state.api);
  localStorage.setItem("netguard.key", state.key);
  refresh();
});
$("refresh").addEventListener("click", refresh);
$("simulate").addEventListener("click", simulate);
refresh();
