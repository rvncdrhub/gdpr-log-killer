"use strict";

const $ = (id) => document.getElementById(id);

// ── State ─────────────────────────────────────────────────────────────────────
let versions = [];          // [{id, timestamp, label, notes, rule_count, diff_summary}]
let activeVersionId = null;

// ── Helpers ───────────────────────────────────────────────────────────────────
function esc(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function fmtTs(iso) {
  const d = new Date(iso);
  return d.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" })
    + " " + d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
}

function versionDisplayName(v) {
  return v.label || `Version ${v.id}`;
}

let toastTimer = null;
function showToast(msg, ms = 2400) {
  const t = $("toast");
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, ms);
}

// ── API ───────────────────────────────────────────────────────────────────────
async function apiFetch(url, opts = {}) {
  const resp = await fetch(url, opts);
  const ct = resp.headers.get("content-type") || "";
  const body = ct.includes("json") ? await resp.json() : await resp.text();
  if (!resp.ok) throw new Error((body && body.error) || `HTTP ${resp.status}`);
  return body;
}

async function loadVersions() {
  versions = await apiFetch("/api/versions");
  renderSidebar();
}

async function submitVersion() {
  const xml   = $("inputXml").value.trim();
  const label = $("inputLabel").value.trim();
  const notes = $("inputNotes").value.trim();

  if (!xml) { showToast("Paste your rule file XML first."); return; }

  const btn = $("btnSubmit");
  btn.disabled = true;
  btn.textContent = "Saving…";
  $("uploadError").hidden = true;

  try {
    const v = await apiFetch("/api/versions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ xml, label, notes }),
    });
    $("inputXml").value = "";
    $("inputLabel").value = "";
    $("inputNotes").value = "";
    $("xmlCount").textContent = "0 chars";
    await loadVersions();
    showView("upload");
    // Auto-select the just-added version
    selectVersion(v.id);
  } catch (err) {
    $("uploadError").textContent = "Error: " + err.message;
    $("uploadError").hidden = false;
  } finally {
    btn.disabled = false;
    btn.textContent = "Save Version";
  }
}

async function loadDiff(fromId, toId) {
  return apiFetch(`/api/diff/${fromId}/${toId}`);
}

async function deleteVersion(id) {
  await apiFetch(`/api/versions/${id}`, { method: "DELETE" });
  if (activeVersionId === id) {
    activeVersionId = null;
    showView("upload");
  }
  await loadVersions();
}

// ── Sidebar rendering ─────────────────────────────────────────────────────────
function renderSidebar() {
  const list = $("versionList");
  if (!versions.length) {
    list.innerHTML = '<div class="empty-state small">No versions yet.</div>';
    return;
  }

  list.innerHTML = versions.map((v, i) => {
    const name = versionDisplayName(v);
    const ts   = fmtTs(v.timestamp);
    const badges = renderVersionBadges(v, i);
    const isActive = v.id === activeVersionId;
    return `
      <div class="version-item ${isActive ? "active" : ""}" data-id="${v.id}">
        <div class="version-num">v${v.id} &mdash; ${v.rule_count} rule${v.rule_count !== 1 ? "s" : ""}</div>
        <div class="version-label" title="${esc(name)}">${esc(name)}</div>
        <div class="version-ts">${ts}</div>
        <div class="version-badges">${badges}</div>
        <button class="del-btn" data-del-id="${v.id}" title="Delete version">&#x2715;</button>
      </div>`;
  }).join("");

  list.querySelectorAll(".version-item").forEach(el => {
    el.addEventListener("click", (e) => {
      if (e.target.closest(".del-btn")) return;
      selectVersion(parseInt(el.dataset.id, 10));
    });
  });
  list.querySelectorAll(".del-btn").forEach(btn => {
    btn.addEventListener("click", async (e) => {
      e.stopPropagation();
      const id = parseInt(btn.dataset.delId, 10);
      const v = versions.find(x => x.id === id);
      if (!confirm(`Delete "${versionDisplayName(v)}"?`)) return;
      await deleteVersion(id);
      showToast("Version deleted.");
    });
  });
}

function renderVersionBadges(v, idx) {
  if (idx === 0) return '<span class="v-badge baseline">Baseline</span>';
  const s = v.diff_summary;
  if (!s || s.total === 0) return '<span class="v-badge unchanged">No changes</span>';
  let out = "";
  if (s.added)    out += `<span class="v-badge added">+${s.added}</span>`;
  if (s.removed)  out += `<span class="v-badge removed">-${s.removed}</span>`;
  if (s.modified) out += `<span class="v-badge modified">~${s.modified}</span>`;
  return out;
}

// ── View switching ────────────────────────────────────────────────────────────
function showView(which) {
  $("uploadForm").hidden   = (which !== "upload");
  $("diffView").hidden     = (which !== "diff");
  $("baselineView").hidden = (which !== "baseline");
}

async function selectVersion(id) {
  activeVersionId = id;
  renderSidebar();

  const idx = versions.findIndex(v => v.id === id);
  if (idx < 0) return;

  if (idx === 0) {
    await showBaselineView(versions[0]);
  } else {
    await showDiffView(versions[idx - 1].id, versions[idx].id);
  }
}

async function showBaselineView(v) {
  showView("baseline");
  $("baselineVersionLabel").textContent = `${versionDisplayName(v)} — ${fmtTs(v.timestamp)}`;
  $("baselineMeta").textContent = `${v.rule_count} rule${v.rule_count !== 1 ? "s" : ""}${v.notes ? " · " + v.notes : ""}`;

  const rules = await apiFetch(`/api/diff/0/0`).catch(() => null);
  // Render all rules as "baseline" cards by fetching raw
  const raw = await apiFetch(`/api/versions/${v.id}/raw`).catch(() => "");
  // Just show all parsed rules as individual baseline cards
  // We get them by diffing nothing against this version using a trick:
  // actually let's just display from the diff endpoint vs a virtual "empty"
  // We'll do a simple raw XML display for the baseline
  const content = $("baselineContent");
  content.innerHTML = `
    <div class="diff-section-header">All rules (${v.rule_count})</div>
    <div class="xml-block">${esc(raw)}</div>`;
}

async function showDiffView(fromId, toId) {
  showView("diff");
  try {
    const data = await loadDiff(fromId, toId);
    renderDiff(data);
    // store toId for "view raw" button
    $("btnViewRaw").dataset.toId = toId;
  } catch (err) {
    $("diffContent").innerHTML = `<div class="empty-state">Failed to load diff: ${esc(err.message)}</div>`;
  }
}

// ── Diff rendering ────────────────────────────────────────────────────────────
function renderDiff(data) {
  const { from_version: fv, to_version: tv, summary: s, changes } = data;

  $("diffFromLabel").textContent = `${versionDisplayName(fv)} (v${fv.id})`;
  $("diffToLabel").textContent   = `${versionDisplayName(tv)} (v${tv.id})`;

  // Summary badges
  const badges = $("diffSummaryBadges");
  if (s.total === 0) {
    badges.innerHTML = '<span class="summary-badge nochange">No changes between these versions</span>';
  } else {
    let html = "";
    if (s.added)    html += `<span class="summary-badge added">+${s.added} added</span>`;
    if (s.removed)  html += `<span class="summary-badge removed">-${s.removed} removed</span>`;
    if (s.modified) html += `<span class="summary-badge modified">~${s.modified} modified</span>`;
    badges.innerHTML = html;
  }

  if (from_version && tv.notes) {
    // no-op here, notes shown in header
  }

  const content = $("diffContent");
  if (!changes.length) { content.innerHTML = ""; return; }

  const added    = changes.filter(c => c.change_type === "added");
  const removed  = changes.filter(c => c.change_type === "removed");
  const modified = changes.filter(c => c.change_type === "modified");

  let html = "";
  if (added.length) {
    html += `<div class="diff-section-header">&#x2795; Added rules (${added.length})</div>`;
    html += added.map(c => renderRuleCard(c)).join("");
  }
  if (removed.length) {
    html += `<div class="diff-section-header">&#x2796; Removed rules (${removed.length})</div>`;
    html += removed.map(c => renderRuleCard(c)).join("");
  }
  if (modified.length) {
    html += `<div class="diff-section-header">&#x270F;&#xFE0F; Modified rules (${modified.length})</div>`;
    html += modified.map(c => renderRuleCard(c)).join("");
  }

  content.innerHTML = html;

  // Wire up expand toggles
  content.querySelectorAll(".rule-card-header").forEach(hdr => {
    hdr.addEventListener("click", () => {
      hdr.closest(".rule-card").classList.toggle("expanded");
    });
  });
  content.querySelectorAll(".expand-xml-btn").forEach(btn => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      const block = btn.nextElementSibling;
      const hidden = block.style.display === "none" || !block.style.display;
      block.style.display = hidden ? "block" : "none";
      btn.textContent = hidden ? "Hide XML" : "Show raw XML";
    });
  });
}

function renderRuleCard(change) {
  const rule = change.new_rule || change.old_rule;
  const desc = getChildValue(rule, "description") || "(no description)";
  const level = rule.level;
  const type  = change.change_type;

  let bodyHtml = "";

  if (type === "modified") {
    bodyHtml += `<table class="field-changes">
      <thead><tr>
        <th>Field</th><th>Before</th><th>After</th>
      </tr></thead>
      <tbody>
      ${change.field_changes.map(fc => `
        <tr>
          <td class="field-name">${esc(fc.field)}</td>
          <td class="${fc.old == null ? "field-null" : "field-old"}">${fc.old == null ? "—" : esc(Array.isArray(fc.old) ? fc.old.join(", ") : fc.old)}</td>
          <td class="${fc.new == null ? "field-null" : "field-new"}">${fc.new == null ? "—" : esc(Array.isArray(fc.new) ? fc.new.join(", ") : fc.new)}</td>
        </tr>`).join("")}
      </tbody>
    </table>`;
  } else {
    // Show key fields for added / removed
    bodyHtml += renderRuleFields(rule);
  }

  // Raw XML toggle (shown for added/removed)
  if (type !== "modified") {
    const xml = ruleToXml(rule);
    bodyHtml += `<button class="expand-xml-btn">Show raw XML</button>
      <div class="xml-block" style="display:none">${esc(xml)}</div>`;
  }

  return `
    <div class="rule-card ${type}">
      <div class="rule-card-header">
        <span class="rule-id-badge">ID ${rule.rule_id}</span>
        <span class="rule-level">Level ${level}</span>
        <span class="rule-desc" title="${esc(desc)}">${esc(desc)}</span>
        <span class="rule-expand-icon">&#x25B6;</span>
      </div>
      <div class="rule-card-body">${bodyHtml}</div>
    </div>`;
}

function renderRuleFields(rule) {
  const LABELS = {
    description: "Description",
    match: "Match",
    regex: "Regex",
    decoded_as: "Decoded as",
    group: "Group",
    if_sid: "If SID",
    if_matched_sid: "If matched SID",
    if_group: "If group",
    if_matched_group: "If matched group",
    frequency: "Frequency",
    timeframe: "Timeframe",
    same_source_ip: "Same source IP",
    same_id: "Same ID",
    same_user: "Same user",
    options: "Options",
    info: "Info",
    mitre: "MITRE",
  };

  let rows = `<div class="rule-fields">
    <div class="rule-field-row">
      <span class="rule-field-key">level</span>
      <span class="rule-field-val">${esc(String(rule.level))}</span>
    </div>`;

  for (const [tag, values] of Object.entries(rule.children || {})) {
    const label = LABELS[tag] || tag;
    rows += `<div class="rule-field-row">
      <span class="rule-field-key">${esc(label)}</span>
      <span class="rule-field-val">${esc(values.join(", "))}</span>
    </div>`;
  }

  for (const [k, v] of Object.entries(rule.attributes || {})) {
    rows += `<div class="rule-field-row">
      <span class="rule-field-key">@${esc(k)}</span>
      <span class="rule-field-val">${esc(v)}</span>
    </div>`;
  }

  rows += "</div>";
  return rows;
}

function getChildValue(rule, tag) {
  return (rule?.children?.[tag] ?? [])[0] ?? null;
}

function ruleToXml(rule) {
  if (!rule) return "";
  let attrs = `id="${rule.rule_id}" level="${rule.level}"`;
  for (const [k, v] of Object.entries(rule.attributes || {})) {
    attrs += ` ${k}="${v}"`;
  }
  let children = "";
  for (const [tag, values] of Object.entries(rule.children || {})) {
    for (const val of values) {
      children += `\n  <${tag}>${val}</${tag}>`;
    }
  }
  return `<rule ${attrs}>${children}\n</rule>`;
}

// ── Compare modal ─────────────────────────────────────────────────────────────
function openCompareModal() {
  if (versions.length < 2) { showToast("Need at least 2 versions to compare."); return; }

  const fromSel = $("compareFrom");
  const toSel   = $("compareTo");

  const opts = versions.map(v =>
    `<option value="${v.id}">${versionDisplayName(v)} (v${v.id})</option>`
  ).join("");
  fromSel.innerHTML = opts;
  toSel.innerHTML   = opts;

  // Default: last two versions
  fromSel.value = String(versions[versions.length - 2].id);
  toSel.value   = String(versions[versions.length - 1].id);

  $("compareModal").hidden = false;
}

function closeCompareModal() { $("compareModal").hidden = true; }

async function runCompare() {
  const fromId = parseInt($("compareFrom").value, 10);
  const toId   = parseInt($("compareTo").value,   10);
  if (fromId === toId) { showToast("Select two different versions."); return; }
  closeCompareModal();
  activeVersionId = toId;
  renderSidebar();
  await showDiffView(fromId, toId);
}

// ── Event wiring ──────────────────────────────────────────────────────────────
$("btnSubmit").addEventListener("click", submitVersion);
$("inputXml").addEventListener("keydown", (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === "Enter") submitVersion();
});
$("inputXml").addEventListener("input", () => {
  $("xmlCount").textContent = $("inputXml").value.length.toLocaleString() + " chars";
});

$("btnPasteXml").addEventListener("click", async () => {
  try {
    const t = await navigator.clipboard.readText();
    $("inputXml").value = t;
    $("xmlCount").textContent = t.length.toLocaleString() + " chars";
  } catch { showToast("Clipboard access denied — paste manually."); }
});
$("btnClearXml").addEventListener("click", () => {
  $("inputXml").value = "";
  $("xmlCount").textContent = "0 chars";
});

$("btnAddVersion").addEventListener("click", () => {
  activeVersionId = null;
  renderSidebar();
  showView("upload");
});
$("btnBackToUpload").addEventListener("click", () => { activeVersionId = null; renderSidebar(); showView("upload"); });
$("btnBaselineNewVersion").addEventListener("click", () => { activeVersionId = null; renderSidebar(); showView("upload"); });

$("btnViewRaw").addEventListener("click", async () => {
  const id = parseInt($("btnViewRaw").dataset.toId || "0", 10);
  if (!id) return;
  window.open(`/api/versions/${id}/raw`, "_blank");
});
$("btnBaselineRaw").addEventListener("click", () => {
  const v = versions.find(x => x.id === activeVersionId);
  if (v) window.open(`/api/versions/${v.id}/raw`, "_blank");
});

$("btnCompare").addEventListener("click", openCompareModal);
$("btnModalClose").addEventListener("click", closeCompareModal);
$("btnModalCancel").addEventListener("click", closeCompareModal);
$("btnModalCompare").addEventListener("click", runCompare);
$("compareModal").addEventListener("click", (e) => { if (e.target === $("compareModal")) closeCompareModal(); });

// ── Boot ──────────────────────────────────────────────────────────────────────
(async () => {
  try {
    await loadVersions();
    if (versions.length > 0) {
      // Auto-select the latest version on load
      selectVersion(versions[versions.length - 1].id);
    }
  } catch (err) {
    showToast("Could not load versions: " + err.message, 5000);
  }
})();
