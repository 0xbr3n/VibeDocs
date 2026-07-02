/* ------------------------------------------------------------------
 * Legacy CVSS calculators (v3.1 and v2.0) — pure-client implementations.
 *
 * Both follow the FIRST.org specifications:
 *   - CVSS v3.1: https://www.first.org/cvss/v3.1/specification-document
 *   - CVSS v2.0: https://www.first.org/cvss/v2/guide
 *
 * Each calculator exposes a single mount function:
 *   mountCvssV31Calculator(hostEl, onChange?)
 *   mountCvssV2Calculator(hostEl,  onChange?)
 *
 * Both calculators support the FULL spec — Base, Temporal AND
 * Environmental metric groups. Temporal and Environmental sections are
 * collapsed by default to keep the UI focused; consultants only see them
 * when they need to refine the score for a specific engagement.
 *
 * `onChange(vector, baseScore, severity, extra)` fires on every metric
 * change so the page can copy the live values into the finding form. The
 * `extra` payload exposes `temporal_score`, `environmental_score`, and
 * `overall_score` (= environmental if set, else temporal if set, else base)
 * for callers that care about more than just the base.
 *
 * Both calculators store no state outside the host element — multiple
 * instances can coexist on the same page.
 * ------------------------------------------------------------------ */


/* ============================================================
 * Shared UI helpers — grouped metric layout
 * ============================================================ */

// Build a metric group's DOM. Each metric is a labelled row of buttons.
// `state` is the calculator's metric-value map (the function mutates it).
// `onSet(key, value)` fires after every click so the parent can recompute.
function _cvssBuildGroup(state, metrics, onSet){
  const metricsEl = document.createElement("div");
  metricsEl.className = "cvss-metrics";
  for (const [key, label, options] of metrics){
    const row = document.createElement("div");
    row.className = "cvss-metric";
    row.innerHTML = `<label>${label} <code class="muted small">(${key})</code></label>`;
    const btnRow = document.createElement("div");
    btnRow.className = "cvss-options";
    for (const [v, vLabel] of options){
      const b = document.createElement("button");
      b.type = "button";
      b.className = "cvss-opt";
      b.textContent = vLabel;
      b.dataset.v = v;
      // Mark the option matching the current state (relevant when the
      // group rebuilds, e.g. after a vector-string load).
      if (state[key] === v) b.classList.add("active");
      b.addEventListener("click", () => {
        state[key] = v;
        for (const sib of btnRow.querySelectorAll(".cvss-opt"))
          sib.classList.toggle("active", sib.dataset.v === v);
        if (onSet) onSet(key, v);
      });
      btnRow.appendChild(b);
    }
    row.appendChild(btnRow);
    metricsEl.appendChild(row);
  }
  return metricsEl;
}

// Build a <details>-style collapsible section for Temporal / Environmental.
// We deliberately avoid the native <details> element because we need the
// summary row to participate in the wider .cvss-wrap grid layout — and
// native <details> swallows clicks on its summary cells inconsistently
// across browsers.
function _cvssBuildCollapse(titleText, helperText){
  const section = document.createElement("section");
  section.className = "cvss-group is-collapsed";
  const header = document.createElement("button");
  header.type = "button";
  header.className = "cvss-group-h";
  header.innerHTML =
    `<span class="cvss-group-caret" aria-hidden="true">▸</span>` +
    `<span class="cvss-group-title">${titleText}</span>` +
    (helperText
      ? `<span class="cvss-group-help muted small">${helperText}</span>`
      : "");
  const body = document.createElement("div");
  body.className = "cvss-group-body";
  header.addEventListener("click", () => {
    section.classList.toggle("is-collapsed");
    header.querySelector(".cvss-group-caret").textContent =
      section.classList.contains("is-collapsed") ? "▸" : "▾";
  });
  section.appendChild(header);
  section.appendChild(body);
  return { section, body };
}

// Inject the CSS used by the grouped layout on first mount. Idempotent —
// the same calculator can mount on many pages without dumping the rules
// into <head> over and over.
function _cvssEnsureGroupStyles(){
  if (document.getElementById("cvss-legacy-group-css")) return;
  const css = document.createElement("style");
  css.id = "cvss-legacy-group-css";
  css.textContent = `
    .cvss-groups{ display:flex; flex-direction:column; gap:10px; }
    .cvss-group{
      border:1px solid var(--border); border-radius:8px;
      background:var(--surface); overflow:hidden;
    }
    .cvss-group-h{
      display:flex; align-items:center; gap:10px;
      width:100%; padding:10px 14px;
      background:var(--surface-2); color:var(--text);
      border:0; border-bottom:1px solid var(--border);
      font-size:13px; font-weight:600; text-align:left; cursor:pointer;
      transition: background .15s;
    }
    .cvss-group-h:hover{ background:var(--surface-3); }
    .cvss-group-caret{ display:inline-block; width:14px; font-size:11px; color:var(--text-2); }
    .cvss-group-title{ flex:0 0 auto; }
    .cvss-group-help{ flex:1; text-align:right; font-weight:400; }
    .cvss-group-body{ padding:12px 14px; }
    .cvss-group.is-collapsed .cvss-group-body{ display:none; }
    .cvss-group.is-collapsed .cvss-group-h{ border-bottom-color:transparent; }

    /* Tertiary score lines in the output card. */
    .cvss-extra-scores{
      display:flex; flex-direction:column; gap:4px;
      padding:8px 0 0; margin-top:4px;
      border-top:1px dashed var(--border);
      font-size:12px; color:var(--text-2);
    }
    .cvss-extra-scores strong{ color:var(--text); font-family:ui-monospace,Consolas,monospace; }
  `;
  document.head.appendChild(css);
}


/* ============================================================
 * CVSS 3.1
 * ============================================================ */

// Base metric definitions. Order matters — it determines vector order.
const _CVSS31_METRICS = [
  ["AV", "Attack Vector",     [["N","Network"],["A","Adjacent"],["L","Local"],["P","Physical"]]],
  ["AC", "Attack Complexity", [["L","Low"],["H","High"]]],
  ["PR", "Privileges Required", [["N","None"],["L","Low"],["H","High"]]],
  ["UI", "User Interaction",  [["N","None"],["R","Required"]]],
  ["S",  "Scope",             [["U","Unchanged"],["C","Changed"]]],
  ["C",  "Confidentiality",   [["N","None"],["L","Low"],["H","High"]]],
  ["I",  "Integrity",         [["N","None"],["L","Low"],["H","High"]]],
  ["A",  "Availability",      [["N","None"],["L","Low"],["H","High"]]],
];

// Temporal — every value also has an "X" (Not Defined) which is the
// implicit default and means "use base". We render X as a button so the
// user can re-clear a selection they applied by accident.
const _CVSS31_TEMPORAL = [
  ["E",  "Exploit Code Maturity",
    [["X","Not Defined"],["U","Unproven"],["P","Proof-of-Concept"],["F","Functional"],["H","High"]]],
  ["RL", "Remediation Level",
    [["X","Not Defined"],["O","Official Fix"],["T","Temporary Fix"],["W","Workaround"],["U","Unavailable"]]],
  ["RC", "Report Confidence",
    [["X","Not Defined"],["U","Unknown"],["R","Reasonable"],["C","Confirmed"]]],
];

// Environmental — Security Requirements + Modified Base Metrics.
const _CVSS31_ENV_REQ = [
  ["CR", "Confidentiality Requirement",
    [["X","Not Defined"],["L","Low"],["M","Medium"],["H","High"]]],
  ["IR", "Integrity Requirement",
    [["X","Not Defined"],["L","Low"],["M","Medium"],["H","High"]]],
  ["AR", "Availability Requirement",
    [["X","Not Defined"],["L","Low"],["M","Medium"],["H","High"]]],
];

const _CVSS31_ENV_MODIFIED = [
  ["MAV","Modified Attack Vector",
    [["X","Not Defined"],["N","Network"],["A","Adjacent"],["L","Local"],["P","Physical"]]],
  ["MAC","Modified Attack Complexity",
    [["X","Not Defined"],["L","Low"],["H","High"]]],
  ["MPR","Modified Privileges Required",
    [["X","Not Defined"],["N","None"],["L","Low"],["H","High"]]],
  ["MUI","Modified User Interaction",
    [["X","Not Defined"],["N","None"],["R","Required"]]],
  ["MS", "Modified Scope",
    [["X","Not Defined"],["U","Unchanged"],["C","Changed"]]],
  ["MC", "Modified Confidentiality",
    [["X","Not Defined"],["N","None"],["L","Low"],["H","High"]]],
  ["MI", "Modified Integrity",
    [["X","Not Defined"],["N","None"],["L","Low"],["H","High"]]],
  ["MA", "Modified Availability",
    [["X","Not Defined"],["N","None"],["L","Low"],["H","High"]]],
];

// Metric value -> numerical weight used by the 3.1 formulae.
const _CVSS31_W = {
  AV:{N:0.85,A:0.62,L:0.55,P:0.2},
  AC:{L:0.77,H:0.44},
  PR:{ U:{N:0.85,L:0.62,H:0.27}, C:{N:0.85,L:0.68,H:0.5} },
  UI:{N:0.85,R:0.62},
  C: {N:0,L:0.22,H:0.56},
  I: {N:0,L:0.22,H:0.56},
  A: {N:0,L:0.22,H:0.56},
  // Temporal modifiers — X (Not Defined) is a multiplicative no-op.
  E: {X:1.0, U:0.91, P:0.94, F:0.97, H:1.0},
  RL:{X:1.0, O:0.95, T:0.96, W:0.97, U:1.0},
  RC:{X:1.0, U:0.92, R:0.96, C:1.0},
  // Environmental Security Requirements — X is again the no-op.
  CR:{X:1.0, L:0.5, M:1.0, H:1.5},
  IR:{X:1.0, L:0.5, M:1.0, H:1.5},
  AR:{X:1.0, L:0.5, M:1.0, H:1.5},
};

// Resolve a "Modified X" metric — if the user left it at X (Not Defined),
// fall back to the base value's weight. Used by the environmental formula.
function _cvss31_mod(state, modKey, baseKey, table){
  const v = state[modKey];
  const useBase = !v || v === "X";
  const k = useBase ? state[baseKey] : v;
  return table[k];
}

// CVSS 3.1 spec roundup — multiplies by 100,000, ceils, divides back.
// Plain Math.ceil(x * 10) / 10 fails on values like 4.0200000000000005
// (a float-pop the spec explicitly calls out).
function _cvss31_roundUp(x){
  const i = Math.round(x * 100000);
  if (i % 10000 === 0) return i / 100000;
  return (Math.floor(i / 10000) + 1) / 10;
}

function _cvss31_severity(score){
  if (score >= 9.0) return "Critical";
  if (score >= 7.0) return "High";
  if (score >= 4.0) return "Medium";
  if (score >  0)   return "Low";
  return "None";
}

// Returns { base, temporal, environmental, overall, severity, vector }.
// `null` if any base metric is missing — the partial-fill case where we
// don't yet have enough to compute anything.
function _cvss31_score(m){
  for (const [k] of _CVSS31_METRICS) if (!m[k]) return null;

  // ---- Base ---------------------------------------------------------
  const Iss = 1 - (1 - _CVSS31_W.C[m.C]) * (1 - _CVSS31_W.I[m.I]) * (1 - _CVSS31_W.A[m.A]);
  let Impact;
  if (m.S === "U") Impact = 6.42 * Iss;
  else             Impact = 7.52 * (Iss - 0.029) - 3.25 * Math.pow(Iss - 0.02, 15);

  const PR = _CVSS31_W.PR[m.S][m.PR];
  const Exploitability = 8.22 * _CVSS31_W.AV[m.AV] * _CVSS31_W.AC[m.AC] * PR * _CVSS31_W.UI[m.UI];

  let base = 0;
  if (Impact > 0){
    if (m.S === "U") base = _cvss31_roundUp(Math.min(Impact + Exploitability, 10));
    else             base = _cvss31_roundUp(Math.min(1.08 * (Impact + Exploitability), 10));
  }

  // ---- Temporal -----------------------------------------------------
  // Temporal = Roundup(BaseScore × E × RL × RC). When every Temporal
  // metric is X (Not Defined) the multiplier collapses to 1.0 and the
  // Temporal score equals the Base score — we only report it as a
  // distinct number when at least one Temporal metric was actually set.
  const E  = _CVSS31_W.E [m.E  || "X"];
  const RL = _CVSS31_W.RL[m.RL || "X"];
  const RC = _CVSS31_W.RC[m.RC || "X"];
  const temporal = _cvss31_roundUp(base * E * RL * RC);
  const temporalSet = (m.E && m.E !== "X") || (m.RL && m.RL !== "X") || (m.RC && m.RC !== "X");

  // ---- Environmental ------------------------------------------------
  const CR = _CVSS31_W.CR[m.CR || "X"];
  const IR = _CVSS31_W.IR[m.IR || "X"];
  const AR = _CVSS31_W.AR[m.AR || "X"];

  // Effective metric values fall back to base when "Modified X" is X.
  const MAVw = _cvss31_mod(m, "MAV", "AV", _CVSS31_W.AV);
  const MACw = _cvss31_mod(m, "MAC", "AC", _CVSS31_W.AC);
  const MUIw = _cvss31_mod(m, "MUI", "UI", _CVSS31_W.UI);
  const MS   = (m.MS && m.MS !== "X") ? m.MS : m.S;
  // PR weight depends on the modified scope, so we look it up by the
  // RESOLVED PR value under the resolved scope.
  const PRv  = (m.MPR && m.MPR !== "X") ? m.MPR : m.PR;
  const MPRw = _CVSS31_W.PR[MS][PRv];
  const MCw  = _cvss31_mod(m, "MC", "C", _CVSS31_W.C);
  const MIw  = _cvss31_mod(m, "MI", "I", _CVSS31_W.I);
  const MAw  = _cvss31_mod(m, "MA", "A", _CVSS31_W.A);

  const MISS = Math.min(
    1 - (1 - CR * MCw) * (1 - IR * MIw) * (1 - AR * MAw),
    0.915
  );
  let ModImpact;
  if (MS === "U") ModImpact = 6.42 * MISS;
  else            ModImpact = 7.52 * (MISS - 0.029) - 3.25 * Math.pow(MISS * 0.9731 - 0.02, 13);
  const ModExploitability = 8.22 * MAVw * MACw * MPRw * MUIw;

  let environmental = 0;
  if (ModImpact > 0){
    if (MS === "U") environmental = _cvss31_roundUp(Math.min(ModImpact + ModExploitability, 10));
    else            environmental = _cvss31_roundUp(Math.min(1.08 * (ModImpact + ModExploitability), 10));
    environmental = _cvss31_roundUp(environmental * E * RL * RC);
  }
  const envSet = temporalSet ||
    (m.CR  && m.CR  !== "X") || (m.IR && m.IR !== "X") || (m.AR && m.AR !== "X") ||
    (m.MAV && m.MAV !== "X") || (m.MAC && m.MAC !== "X") || (m.MPR && m.MPR !== "X") ||
    (m.MUI && m.MUI !== "X") || (m.MS  && m.MS  !== "X") ||
    (m.MC  && m.MC  !== "X") || (m.MI  && m.MI  !== "X") || (m.MA  && m.MA  !== "X");

  // ---- Vector + headline severity -----------------------------------
  // The headline severity tracks the highest available score: the
  // Environmental beats Temporal beats Base, matching how FIRST.org's
  // reference calculator renders the badge.
  const overall = envSet ? environmental : (temporalSet ? temporal : base);
  const severity = _cvss31_severity(overall);

  const parts = ["CVSS:3.1"];
  for (const [k] of _CVSS31_METRICS) parts.push(`${k}:${m[k]}`);
  for (const [k] of _CVSS31_TEMPORAL) if (m[k] && m[k] !== "X") parts.push(`${k}:${m[k]}`);
  for (const [k] of _CVSS31_ENV_REQ)      if (m[k] && m[k] !== "X") parts.push(`${k}:${m[k]}`);
  for (const [k] of _CVSS31_ENV_MODIFIED) if (m[k] && m[k] !== "X") parts.push(`${k}:${m[k]}`);
  const vector = parts.join("/");

  return {
    base,
    temporal,        temporal_set: temporalSet,
    environmental,   environmental_set: envSet,
    overall,
    severity,
    vector,
  };
}

function mountCvssV31Calculator(host, onChange){
  if (!host) return;
  _cvssEnsureGroupStyles();
  host.innerHTML = "";
  const m = {};

  const wrap = document.createElement("div");
  wrap.className = "cvss-wrap";
  const groupsCol = document.createElement("div");
  groupsCol.className = "cvss-groups";

  // --- Base (always visible — the original layout the user expects) ---
  const baseGroup = document.createElement("section");
  baseGroup.className = "cvss-group";
  const baseHeader = document.createElement("div");
  baseHeader.className = "cvss-group-h";
  baseHeader.style.cursor = "default";
  baseHeader.innerHTML =
    `<span class="cvss-group-title">Base Metrics</span>` +
    `<span class="cvss-group-help muted small">Always required — describe the vulnerability itself</span>`;
  const baseBody = document.createElement("div");
  baseBody.className = "cvss-group-body";
  baseBody.appendChild(_cvssBuildGroup(m, _CVSS31_METRICS, () => update()));
  baseGroup.appendChild(baseHeader);
  baseGroup.appendChild(baseBody);
  groupsCol.appendChild(baseGroup);

  // --- Temporal (collapsed by default) ---
  const temporal = _cvssBuildCollapse(
    "Temporal Metrics",
    "Optional — adjust as exploit/remediation status evolves"
  );
  temporal.body.appendChild(_cvssBuildGroup(m, _CVSS31_TEMPORAL, () => update()));
  groupsCol.appendChild(temporal.section);

  // --- Environmental (collapsed by default) ---
  const env = _cvssBuildCollapse(
    "Environmental Metrics",
    "Optional — tailor to the deployment's actual exposure"
  );
  // Security Requirements first, then Modified Base Metrics.
  const reqHeading = document.createElement("p");
  reqHeading.className = "muted small";
  reqHeading.style.margin = "0 0 6px";
  reqHeading.textContent = "Security Requirements (CIA importance to this deployment)";
  env.body.appendChild(reqHeading);
  env.body.appendChild(_cvssBuildGroup(m, _CVSS31_ENV_REQ, () => update()));

  const modHeading = document.createElement("p");
  modHeading.className = "muted small";
  modHeading.style.margin = "12px 0 6px";
  modHeading.textContent = "Modified Base Metrics (re-score the base for this environment)";
  env.body.appendChild(modHeading);
  env.body.appendChild(_cvssBuildGroup(m, _CVSS31_ENV_MODIFIED, () => update()));

  groupsCol.appendChild(env.section);
  wrap.appendChild(groupsCol);

  // --- Output panel ---
  const out = document.createElement("div");
  out.className = "cvss-output";
  out.innerHTML = `
    <div class="cvss-score-wrap">
      <span class="cvss-score" id="v31-score">—</span>
      <span class="cvss-sev"   id="v31-sev"></span>
    </div>
    <div class="cvss-vector-wrap">
      <input id="v31-vec" type="text" readonly placeholder="Pick metrics to build the vector…">
      <button id="v31-copy" type="button" class="btn-secondary btn-sm">Copy</button>
    </div>
    <div class="cvss-extra-scores" id="v31-extra" hidden></div>`;
  wrap.appendChild(out);
  host.appendChild(wrap);

  function update(){
    const r = _cvss31_score(m);
    const scoreEl = host.querySelector("#v31-score");
    const sevEl   = host.querySelector("#v31-sev");
    const vecEl   = host.querySelector("#v31-vec");
    const extraEl = host.querySelector("#v31-extra");
    if (!r){
      scoreEl.textContent = "—";
      sevEl.textContent = "";
      sevEl.className = "cvss-sev";
      vecEl.value = "";
      extraEl.hidden = true;
      extraEl.innerHTML = "";
      if (onChange) onChange(null, null, null, null);
      return;
    }
    // The big number always reflects the highest available score so a
    // consultant sees the most-relevant figure first.
    scoreEl.textContent = r.overall.toFixed(1);
    sevEl.textContent   = r.severity;
    sevEl.className     = "cvss-sev sev-" + r.severity.toLowerCase();
    vecEl.value         = r.vector;

    // Show the base/temporal/environmental breakdown when at least one
    // of the optional groups has been touched, so the consultant can see
    // exactly how each layer moved the number.
    const lines = [];
    lines.push(`<span>Base <strong>${r.base.toFixed(1)}</strong></span>`);
    if (r.temporal_set || r.environmental_set){
      lines.push(`<span>Temporal <strong>${r.temporal.toFixed(1)}</strong></span>`);
    }
    if (r.environmental_set){
      lines.push(`<span>Environmental <strong>${r.environmental.toFixed(1)}</strong></span>`);
    }
    extraEl.hidden = (lines.length <= 1);
    extraEl.innerHTML = lines.join("");

    if (onChange){
      onChange(r.vector, r.base, r.severity, {
        temporal_score:      r.temporal,
        environmental_score: r.environmental,
        overall_score:       r.overall,
      });
    }
  }

  host.querySelector("#v31-copy").addEventListener("click", async () => {
    const v = host.querySelector("#v31-vec").value;
    if (!v) return;
    try {
      await navigator.clipboard.writeText(v);
      const b = host.querySelector("#v31-copy"); const t = b.textContent;
      b.textContent = "✓ Copied"; setTimeout(() => b.textContent = t, 1200);
    } catch(_) {}
  });
}


/* ============================================================
 * CVSS 2.0
 * ============================================================ */

const _CVSS2_METRICS = [
  ["AV", "Access Vector",       [["L","Local"],["A","Adjacent Network"],["N","Network"]]],
  ["AC", "Access Complexity",   [["H","High"],["M","Medium"],["L","Low"]]],
  ["Au", "Authentication",      [["M","Multiple"],["S","Single"],["N","None"]]],
  ["C",  "Confidentiality",     [["N","None"],["P","Partial"],["C","Complete"]]],
  ["I",  "Integrity",           [["N","None"],["P","Partial"],["C","Complete"]]],
  ["A",  "Availability",        [["N","None"],["P","Partial"],["C","Complete"]]],
];

const _CVSS2_TEMPORAL = [
  ["E",  "Exploitability",
    [["ND","Not Defined"],["U","Unproven"],["POC","Proof-of-Concept"],["F","Functional"],["H","High"]]],
  ["RL", "Remediation Level",
    [["ND","Not Defined"],["OF","Official Fix"],["TF","Temporary Fix"],["W","Workaround"],["U","Unavailable"]]],
  ["RC", "Report Confidence",
    [["ND","Not Defined"],["UC","Unconfirmed"],["UR","Uncorroborated"],["C","Confirmed"]]],
];

const _CVSS2_ENV = [
  ["CDP","Collateral Damage Potential",
    [["ND","Not Defined"],["N","None"],["L","Low"],["LM","Low-Medium"],["MH","Medium-High"],["H","High"]]],
  ["TD", "Target Distribution",
    [["ND","Not Defined"],["N","None"],["L","Low"],["M","Medium"],["H","High"]]],
  ["CR", "Confidentiality Requirement",
    [["ND","Not Defined"],["L","Low"],["M","Medium"],["H","High"]]],
  ["IR", "Integrity Requirement",
    [["ND","Not Defined"],["L","Low"],["M","Medium"],["H","High"]]],
  ["AR", "Availability Requirement",
    [["ND","Not Defined"],["L","Low"],["M","Medium"],["H","High"]]],
];

const _CVSS2_W = {
  AV: {L:0.395, A:0.646, N:1.0},
  AC: {H:0.35,  M:0.61,  L:0.71},
  Au: {M:0.45,  S:0.56,  N:0.704},
  C:  {N:0.0,   P:0.275, C:0.660},
  I:  {N:0.0,   P:0.275, C:0.660},
  A:  {N:0.0,   P:0.275, C:0.660},
  // Temporal — ND is a multiplicative no-op (= 1.0).
  E:  {ND:1.0, U:0.85, POC:0.9, F:0.95, H:1.0},
  RL: {ND:1.0, OF:0.87, TF:0.90, W:0.95, U:1.0},
  RC: {ND:1.0, UC:0.90, UR:0.95, C:1.0},
  // Environmental.
  CDP:{ND:0, N:0, L:0.1, LM:0.3, MH:0.4, H:0.5},
  TD: {ND:1.0, N:0, L:0.25, M:0.75, H:1.0},
  CR: {ND:1.0, L:0.5, M:1.0, H:1.51},
  IR: {ND:1.0, L:0.5, M:1.0, H:1.51},
  AR: {ND:1.0, L:0.5, M:1.0, H:1.51},
};

function _cvss2_severity(score){
  if (score >= 7.0) return "High";
  if (score >= 4.0) return "Medium";
  if (score >  0)   return "Low";
  return "None";
}

function _cvss2_round1(x){ return Math.round(x * 10) / 10; }

function _cvss2_score(m){
  for (const [k] of _CVSS2_METRICS) if (!m[k]) return null;

  // ---- Base ---------------------------------------------------------
  const Impact = 10.41 *
    (1 - (1 - _CVSS2_W.C[m.C]) * (1 - _CVSS2_W.I[m.I]) * (1 - _CVSS2_W.A[m.A]));
  const Exploitability = 20 *
    _CVSS2_W.AV[m.AV] * _CVSS2_W.AC[m.AC] * _CVSS2_W.Au[m.Au];
  const f_impact = (Impact === 0) ? 0 : 1.176;
  let base = ((0.6 * Impact) + (0.4 * Exploitability) - 1.5) * f_impact;
  base = _cvss2_round1(base);
  if (base < 0) base = 0;

  // ---- Temporal -----------------------------------------------------
  const E  = _CVSS2_W.E [m.E  || "ND"];
  const RL = _CVSS2_W.RL[m.RL || "ND"];
  const RC = _CVSS2_W.RC[m.RC || "ND"];
  const temporal = _cvss2_round1(base * E * RL * RC);
  const temporalSet = (m.E && m.E !== "ND") || (m.RL && m.RL !== "ND") || (m.RC && m.RC !== "ND");

  // ---- Environmental ------------------------------------------------
  // AdjustedImpact uses the security requirements to weight C/I/A.
  const CR = _CVSS2_W.CR[m.CR || "ND"];
  const IR = _CVSS2_W.IR[m.IR || "ND"];
  const AR = _CVSS2_W.AR[m.AR || "ND"];
  const AdjustedImpact = Math.min(
    10,
    10.41 * (1 - (1 - _CVSS2_W.C[m.C] * CR)
                * (1 - _CVSS2_W.I[m.I] * IR)
                * (1 - _CVSS2_W.A[m.A] * AR))
  );
  const f_adj_impact = (AdjustedImpact === 0) ? 0 : 1.176;
  let adjBase = ((0.6 * AdjustedImpact) + (0.4 * Exploitability) - 1.5) * f_adj_impact;
  adjBase = _cvss2_round1(adjBase);
  if (adjBase < 0) adjBase = 0;
  const AdjustedTemporal = _cvss2_round1(adjBase * E * RL * RC);

  const CDP = _CVSS2_W.CDP[m.CDP || "ND"];
  const TD  = _CVSS2_W.TD [m.TD  || "ND"];
  const environmental = _cvss2_round1(
    (AdjustedTemporal + (10 - AdjustedTemporal) * CDP) * TD
  );

  const envSet = temporalSet ||
    (m.CDP && m.CDP !== "ND") || (m.TD && m.TD !== "ND") ||
    (m.CR  && m.CR  !== "ND") || (m.IR && m.IR !== "ND") || (m.AR && m.AR !== "ND");

  const overall = envSet ? environmental : (temporalSet ? temporal : base);
  const severity = _cvss2_severity(overall);

  const parts = [];
  for (const [k] of _CVSS2_METRICS) parts.push(`${k}:${m[k]}`);
  for (const [k] of _CVSS2_TEMPORAL) if (m[k] && m[k] !== "ND") parts.push(`${k}:${m[k]}`);
  for (const [k] of _CVSS2_ENV)      if (m[k] && m[k] !== "ND") parts.push(`${k}:${m[k]}`);
  const vector = parts.join("/");

  return {
    base,
    temporal,        temporal_set: temporalSet,
    environmental,   environmental_set: envSet,
    overall,
    severity,
    vector,
  };
}

function mountCvssV2Calculator(host, onChange){
  if (!host) return;
  _cvssEnsureGroupStyles();
  host.innerHTML = "";
  const m = {};

  const wrap = document.createElement("div");
  wrap.className = "cvss-wrap";
  const groupsCol = document.createElement("div");
  groupsCol.className = "cvss-groups";

  const baseGroup = document.createElement("section");
  baseGroup.className = "cvss-group";
  const baseHeader = document.createElement("div");
  baseHeader.className = "cvss-group-h";
  baseHeader.style.cursor = "default";
  baseHeader.innerHTML =
    `<span class="cvss-group-title">Base Metrics</span>` +
    `<span class="cvss-group-help muted small">Always required — describe the vulnerability itself</span>`;
  const baseBody = document.createElement("div");
  baseBody.className = "cvss-group-body";
  baseBody.appendChild(_cvssBuildGroup(m, _CVSS2_METRICS, () => update()));
  baseGroup.appendChild(baseHeader);
  baseGroup.appendChild(baseBody);
  groupsCol.appendChild(baseGroup);

  const temporal = _cvssBuildCollapse(
    "Temporal Metrics",
    "Optional — adjust as exploit/remediation status evolves"
  );
  temporal.body.appendChild(_cvssBuildGroup(m, _CVSS2_TEMPORAL, () => update()));
  groupsCol.appendChild(temporal.section);

  const env = _cvssBuildCollapse(
    "Environmental Metrics",
    "Optional — tailor to the deployment's actual exposure"
  );
  env.body.appendChild(_cvssBuildGroup(m, _CVSS2_ENV, () => update()));
  groupsCol.appendChild(env.section);
  wrap.appendChild(groupsCol);

  const out = document.createElement("div");
  out.className = "cvss-output";
  out.innerHTML = `
    <div class="cvss-score-wrap">
      <span class="cvss-score" id="v2-score">—</span>
      <span class="cvss-sev"   id="v2-sev"></span>
    </div>
    <div class="cvss-vector-wrap">
      <input id="v2-vec" type="text" readonly placeholder="Pick metrics to build the vector…">
      <button id="v2-copy" type="button" class="btn-secondary btn-sm">Copy</button>
    </div>
    <div class="cvss-extra-scores" id="v2-extra" hidden></div>`;
  wrap.appendChild(out);
  host.appendChild(wrap);

  function update(){
    const r = _cvss2_score(m);
    const scoreEl = host.querySelector("#v2-score");
    const sevEl   = host.querySelector("#v2-sev");
    const vecEl   = host.querySelector("#v2-vec");
    const extraEl = host.querySelector("#v2-extra");
    if (!r){
      scoreEl.textContent = "—";
      sevEl.textContent = "";
      sevEl.className = "cvss-sev";
      vecEl.value = "";
      extraEl.hidden = true;
      extraEl.innerHTML = "";
      if (onChange) onChange(null, null, null, null);
      return;
    }
    scoreEl.textContent = r.overall.toFixed(1);
    sevEl.textContent   = r.severity;
    sevEl.className     = "cvss-sev sev-" + r.severity.toLowerCase();
    vecEl.value         = r.vector;

    const lines = [];
    lines.push(`<span>Base <strong>${r.base.toFixed(1)}</strong></span>`);
    if (r.temporal_set || r.environmental_set){
      lines.push(`<span>Temporal <strong>${r.temporal.toFixed(1)}</strong></span>`);
    }
    if (r.environmental_set){
      lines.push(`<span>Environmental <strong>${r.environmental.toFixed(1)}</strong></span>`);
    }
    extraEl.hidden = (lines.length <= 1);
    extraEl.innerHTML = lines.join("");

    if (onChange){
      onChange(r.vector, r.base, r.severity, {
        temporal_score:      r.temporal,
        environmental_score: r.environmental,
        overall_score:       r.overall,
      });
    }
  }

  host.querySelector("#v2-copy").addEventListener("click", async () => {
    const v = host.querySelector("#v2-vec").value;
    if (!v) return;
    try {
      await navigator.clipboard.writeText(v);
      const b = host.querySelector("#v2-copy"); const t = b.textContent;
      b.textContent = "✓ Copied"; setTimeout(() => b.textContent = t, 1200);
    } catch(_) {}
  });
}
