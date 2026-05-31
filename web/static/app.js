"use strict";

const $ = (id) => document.getElementById(id);

const inputText   = $("inputText");
const outputText  = $("outputText");
const inputCount  = $("inputCount");
const outputCount = $("outputCount");
const statsBar    = $("statsBar");
const statsPanel  = $("statsPanel");
const statsGrid   = $("statsGrid");
const btnSanitize = $("btnSanitize");
const btnCopy     = $("btnCopy");
const btnDownload = $("btnDownload");
const btnPaste    = $("btnPaste");
const btnClearInput = $("btnClearInput");
const toast       = $("toast");

let toastTimer = null;

function showToast(msg, duration = 2200) {
  toast.textContent = msg;
  toast.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { toast.hidden = true; }, duration);
}

function fmtCount(n) {
  return n.toLocaleString() + " char" + (n !== 1 ? "s" : "");
}

inputText.addEventListener("input", () => {
  inputCount.textContent = fmtCount(inputText.value.length);
});

async function sanitize() {
  const text = inputText.value;
  if (!text.trim()) { showToast("Paste a log first."); return; }

  btnSanitize.disabled = true;
  btnSanitize.textContent = "Working…";

  const options = {
    strip_ips:        $("opt_ips").checked,
    strip_emails:     $("opt_emails").checked,
    strip_macs:       $("opt_macs").checked,
    strip_hostnames:  $("opt_hostnames").checked,
    strip_users:      $("opt_users").checked,
    strip_uuids:      $("opt_uuids").checked,
    strip_auth_tokens: $("opt_auth").checked,
    strip_url_creds:  $("opt_url_creds").checked,
    strip_phones:     $("opt_phones").checked,
    domains:          $("opt_domains").value,
  };

  try {
    const resp = await fetch("/api/sanitize", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text, options }),
    });

    const data = await resp.json();
    if (!resp.ok) { showToast("Error: " + (data.error || resp.status), 4000); return; }

    outputText.value = data.sanitized;
    outputCount.textContent = fmtCount(data.sanitized.length);

    const total = data.total ?? 0;
    statsBar.textContent = total
      ? `${total} item${total !== 1 ? "s" : ""} replaced`
      : "Nothing to replace";

    renderStats(data.stats);

    btnCopy.disabled     = false;
    btnDownload.disabled = false;

    if (total === 0) showToast("No sensitive values detected.");

  } catch (err) {
    showToast("Request failed: " + err.message, 4000);
  } finally {
    btnSanitize.disabled = false;
    btnSanitize.textContent = "Sanitize →";
  }
}

function renderStats(stats) {
  statsGrid.innerHTML = "";
  const entries = Object.entries(stats).sort((a, b) => b[1] - a[1]);
  if (!entries.length) { statsPanel.hidden = true; return; }

  const LABELS = {
    IPV4:        "IPv4",
    IPV6:        "IPv6",
    EMAIL:       "Email",
    USER:        "Username",
    MAC:         "MAC address",
    PHONE:       "Phone",
    AUTH_TOKEN:  "Auth Token",
    URL_CREDS:   "URL Credentials",
    UUID:        "UUID",
    HOSTNAME:    "Hostname",
  };

  entries.forEach(([type, count]) => {
    const badge = document.createElement("span");
    badge.className = "stat-badge";
    badge.dataset.type = type;
    badge.innerHTML = `${LABELS[type] || type} <span class="stat-count">${count}</span>`;
    statsGrid.appendChild(badge);
  });

  statsPanel.hidden = false;
}

btnSanitize.addEventListener("click", sanitize);

inputText.addEventListener("keydown", (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === "Enter") sanitize();
});

btnCopy.addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(outputText.value);
    showToast("Copied to clipboard!");
  } catch {
    outputText.select();
    document.execCommand("copy");
    showToast("Copied!");
  }
});

btnDownload.addEventListener("click", () => {
  const blob = new Blob([outputText.value], { type: "text/plain" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "sanitized-log.txt";
  a.click();
  URL.revokeObjectURL(a.href);
});

btnPaste.addEventListener("click", async () => {
  try {
    const text = await navigator.clipboard.readText();
    inputText.value = text;
    inputCount.textContent = fmtCount(text.length);
  } catch {
    showToast("Clipboard access denied — paste manually.", 3000);
  }
});

btnClearInput.addEventListener("click", () => {
  inputText.value = "";
  inputCount.textContent = fmtCount(0);
});
