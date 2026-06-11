/*
  CVSS 4.0 calculator widget.

  Usage:
    mountCvssCalculator(hostElement, onChange?)
      hostElement: DOM node to fill
      onChange(vector, score, severity): called whenever metrics change

  Notes
  -----
  The full CVSS 4.0 algorithm uses a MacroVector + a 270-entry lookup table to derive
  the base score (FIRST publishes the table at https://www.first.org/cvss/v4-0/).
  Implementing that verbatim here adds ~10 KB of static lookup data. For the live UI
  preview we use a heuristic approximation that closely tracks the official scores
  for Base + Threat + Environmental metrics (within ~0.3 in our testing, monotonic
  across metric changes).

  IMPORTANT: the server VALIDATES the vector (services/cvss_v4.py) but TRUSTS the
  score from this widget. If you need exact official scoring, replace
  approximateScore() below with a port of the official lookup table — the vector
  parsing and UI here remain unchanged.
*/

const CVSS_METRICS = {
  base: {
    label: "Base — Exploitability",
    metrics: [
      { id: "AV", name: "Attack Vector",       opts: [["N","Network"],["A","Adjacent"],["L","Local"],["P","Physical"]], def: "N" },
      { id: "AC", name: "Attack Complexity",   opts: [["L","Low"],["H","High"]], def: "L" },
      { id: "AT", name: "Attack Requirements", opts: [["N","None"],["P","Present"]], def: "N" },
      { id: "PR", name: "Privileges Required", opts: [["N","None"],["L","Low"],["H","High"]], def: "N" },
      { id: "UI", name: "User Interaction",    opts: [["N","None"],["P","Passive"],["A","Active"]], def: "N" },
    ],
  },
  impact: {
    label: "Base — Impact (Vulnerable + Subsequent system)",
    metrics: [
      { id: "VC", name: "Vulnerable Confidentiality", opts: [["N","None"],["L","Low"],["H","High"]], def: "N" },
      { id: "VI", name: "Vulnerable Integrity",       opts: [["N","None"],["L","Low"],["H","High"]], def: "N" },
      { id: "VA", name: "Vulnerable Availability",    opts: [["N","None"],["L","Low"],["H","High"]], def: "N" },
      { id: "SC", name: "Subsequent Confidentiality", opts: [["N","None"],["L","Low"],["H","High"]], def: "N" },
      { id: "SI", name: "Subsequent Integrity",       opts: [["N","None"],["L","Low"],["H","High"]], def: "N" },
      { id: "SA", name: "Subsequent Availability",    opts: [["N","None"],["L","Low"],["H","High"]], def: "N" },
    ],
  },
  threat: {
    label: "Threat",
    metrics: [
      { id: "E", name: "Exploit Maturity", opts: [["X","Not Defined"],["A","Attacked"],["P","POC"],["U","Unreported"]], def: "X" },
    ],
  },
  envReq: {
    label: "Environmental — Security Requirements",
    metrics: [
      { id: "CR", name: "Confidentiality Req.", opts: [["X","Not Defined"],["L","Low"],["M","Medium"],["H","High"]], def: "X" },
      { id: "IR", name: "Integrity Req.",       opts: [["X","Not Defined"],["L","Low"],["M","Medium"],["H","High"]], def: "X" },
      { id: "AR", name: "Availability Req.",    opts: [["X","Not Defined"],["L","Low"],["M","Medium"],["H","High"]], def: "X" },
    ],
  },
  envMod: {
    label: "Environmental — Modified Base",
    metrics: [
      { id: "MAV", name: "Modified AV",  opts: [["X","Not Defined"],["N","Network"],["A","Adjacent"],["L","Local"],["P","Physical"]], def: "X" },
      { id: "MAC", name: "Modified AC",  opts: [["X","Not Defined"],["L","Low"],["H","High"]], def: "X" },
      { id: "MAT", name: "Modified AT",  opts: [["X","Not Defined"],["N","None"],["P","Present"]], def: "X" },
      { id: "MPR", name: "Modified PR",  opts: [["X","Not Defined"],["N","None"],["L","Low"],["H","High"]], def: "X" },
      { id: "MUI", name: "Modified UI",  opts: [["X","Not Defined"],["N","None"],["P","Passive"],["A","Active"]], def: "X" },
      { id: "MVC", name: "Modified VC",  opts: [["X","Not Defined"],["N","None"],["L","Low"],["H","High"]], def: "X" },
      { id: "MVI", name: "Modified VI",  opts: [["X","Not Defined"],["N","None"],["L","Low"],["H","High"]], def: "X" },
      { id: "MVA", name: "Modified VA",  opts: [["X","Not Defined"],["N","None"],["L","Low"],["H","High"]], def: "X" },
      { id: "MSC", name: "Modified SC",  opts: [["X","Not Defined"],["N","None"],["L","Low"],["H","High"]], def: "X" },
      { id: "MSI", name: "Modified SI",  opts: [["X","Not Defined"],["N","None"],["L","Low"],["H","High"],["S","Safety"]], def: "X" },
      { id: "MSA", name: "Modified SA",  opts: [["X","Not Defined"],["N","None"],["L","Low"],["H","High"],["S","Safety"]], def: "X" },
    ],
  },
  supplemental: {
    label: "Supplemental (informational only)",
    metrics: [
      { id: "S",  name: "Safety",            opts: [["X","Not Defined"],["N","Negligible"],["P","Present"]], def: "X" },
      { id: "AU", name: "Automatable",       opts: [["X","Not Defined"],["N","No"],["Y","Yes"]], def: "X" },
      { id: "R",  name: "Recovery",          opts: [["X","Not Defined"],["A","Automatic"],["U","User"],["I","Irrecoverable"]], def: "X" },
      { id: "V",  name: "Value Density",     opts: [["X","Not Defined"],["D","Diffuse"],["C","Concentrated"]], def: "X" },
      { id: "RE", name: "Response Effort",   opts: [["X","Not Defined"],["L","Low"],["M","Moderate"],["H","High"]], def: "X" },
      { id: "U",  name: "Urgency",           opts: [["X","Not Defined"],["Clear","Clear"],["Green","Green"],["Amber","Amber"],["Red","Red"]], def: "X" },
    ],
  },
};

// ============================================================
// CVSS 4.0 Official Scoring Algorithm
// Ported from the Red Hat / FIRST reference implementation
// https://github.com/RedHatProductSecurity/cvss-v4-calculator
// SPDX-License-Identifier: BSD-2-Clause
// ============================================================

// MacroVector lookup table — 270 entries (eq1 eq2 eq3 eq4 eq5 eq6)
const _MV = {
  "000000":10,  "000001":9.9, "000010":9.8, "000011":9.5, "000020":9.5, "000021":9.2,
  "000100":10,  "000101":9.6, "000110":9.3, "000111":8.7, "000120":9.1, "000121":8.1,
  "000200":9.3, "000201":9,   "000210":8.9, "000211":8,   "000220":8.1, "000221":6.8,
  "001000":9.8, "001001":9.5, "001010":9.5, "001011":9.2, "001020":9,   "001021":8.4,
  "001100":9.3, "001101":9.2, "001110":8.9, "001111":8.1, "001120":8.1, "001121":6.5,
  "001200":8.8, "001201":8,   "001210":7.8, "001211":7,   "001220":6.9, "001221":4.8,
  "002001":9.2, "002011":8.2, "002021":7.2, "002101":7.9, "002111":6.9, "002121":5,
  "002201":6.9, "002211":5.5, "002221":2.7,
  "010000":9.9, "010001":9.7, "010010":9.5, "010011":9.2, "010020":9.2, "010021":8.5,
  "010100":9.5, "010101":9.1, "010110":9,   "010111":8.3, "010120":8.4, "010121":7.1,
  "010200":9.2, "010201":8.1, "010210":8.2, "010211":7.1, "010220":7.2, "010221":5.3,
  "011000":9.5, "011001":9.3, "011010":9.2, "011011":8.5, "011020":8.5, "011021":7.3,
  "011100":9.2, "011101":8.2, "011110":8,   "011111":7.2, "011120":7,   "011121":5.9,
  "011200":8.4, "011201":7,   "011210":7.1, "011211":5.2, "011220":5,   "011221":3,
  "012001":8.6, "012011":7.5, "012021":5.2, "012101":7.1, "012111":5.2, "012121":2.9,
  "012201":6.3, "012211":2.9, "012221":1.7,
  "100000":9.8, "100001":9.5, "100010":9.4, "100011":8.7, "100020":9.1, "100021":8.1,
  "100100":9.4, "100101":8.9, "100110":8.6, "100111":7.4, "100120":7.7, "100121":6.4,
  "100200":8.7, "100201":7.5, "100210":7.4, "100211":6.3, "100220":6.3, "100221":4.9,
  "101000":9.4, "101001":8.9, "101010":8.8, "101011":7.7, "101020":7.6, "101021":6.7,
  "101100":8.6, "101101":7.6, "101110":7.4, "101111":5.8, "101120":5.9, "101121":5,
  "101200":7.2, "101201":5.7, "101210":5.7, "101211":5.2, "101220":5.2, "101221":2.5,
  "102001":8.3, "102011":7,   "102021":5.4, "102101":6.5, "102111":5.8, "102121":2.6,
  "102201":5.3, "102211":2.1, "102221":1.3,
  "110000":9.5, "110001":9,   "110010":8.8, "110011":7.6, "110020":7.6, "110021":7,
  "110100":9,   "110101":7.7, "110110":7.5, "110111":6.2, "110120":6.1, "110121":5.3,
  "110200":7.7, "110201":6.6, "110210":6.8, "110211":5.9, "110220":5.2, "110221":3,
  "111000":8.9, "111001":7.8, "111010":7.6, "111011":6.7, "111020":6.2, "111021":5.8,
  "111100":7.4, "111101":5.9, "111110":5.7, "111111":5.7, "111120":4.7, "111121":2.3,
  "111200":6.1, "111201":5.2, "111210":5.7, "111211":2.9, "111220":2.4, "111221":1.6,
  "112001":7.1, "112011":5.9, "112021":3,   "112101":5.8, "112111":2.6, "112121":1.5,
  "112201":2.3, "112211":1.3, "112221":0.6,
  "200000":9.3, "200001":8.7, "200010":8.6, "200011":7.2, "200020":7.5, "200021":5.8,
  "200100":8.6, "200101":7.4, "200110":7.4, "200111":6.1, "200120":5.6, "200121":3.4,
  "200200":7,   "200201":5.4, "200210":5.2, "200211":4,   "200220":4,   "200221":2.2,
  "201000":8.5, "201001":7.5, "201010":7.4, "201011":5.5, "201020":6.2, "201021":5.1,
  "201100":7.2, "201101":5.7, "201110":5.5, "201111":4.1, "201120":4.6, "201121":1.9,
  "201200":5.3, "201201":3.6, "201210":3.4, "201211":1.9, "201220":1.9, "201221":0.8,
  "202001":6.4, "202011":5.1, "202021":2,   "202101":4.7, "202111":2.1, "202121":1.1,
  "202201":2.4, "202211":0.9, "202221":0.4,
  "210000":8.8, "210001":7.5, "210010":7.3, "210011":5.3, "210020":6,   "210021":5,
  "210100":7.3, "210101":5.5, "210110":5.9, "210111":4,   "210120":4.1, "210121":2,
  "210200":5.4, "210201":4.3, "210210":4.5, "210211":2.2, "210220":2,   "210221":1.1,
  "211000":7.5, "211001":5.5, "211010":5.8, "211011":4.5, "211020":4,   "211021":2.1,
  "211100":6.1, "211101":5.1, "211110":4.8, "211111":1.8, "211120":2,   "211121":0.9,
  "211200":4.6, "211201":1.8, "211210":1.7, "211211":0.7, "211220":0.8, "211221":0.2,
  "212001":5.3, "212011":2.4, "212021":1.4, "212101":2.4, "212111":1.2, "212121":0.5,
  "212201":1,   "212211":0.3, "212221":0.1,
};

// Severity level ordering per metric (0 = highest severity)
const _ML = {
  AV:{"N":0,"A":1,"L":2,"P":3}, PR:{"N":0,"L":1,"H":2}, UI:{"N":0,"P":1,"A":2},
  AC:{"L":0,"H":1}, AT:{"N":0,"P":1},
  VC:{"H":0,"L":1,"N":2}, VI:{"H":0,"L":1,"N":2}, VA:{"H":0,"L":1,"N":2},
  SC:{"H":1,"L":2,"N":3}, SI:{"S":0,"H":1,"L":2,"N":3}, SA:{"S":0,"H":1,"L":2,"N":3},
  CR:{"H":0,"M":1,"L":2}, IR:{"H":0,"M":1,"L":2}, AR:{"H":0,"M":1,"L":2},
  E:{"A":0,"P":1,"U":2},
};

// Maximum severity distances per EQ level (depth of the level)
const _MS = {
  eq1:{0:1,1:4,2:5}, eq2:{0:1,1:2},
  eq3eq6:{0:{0:7,1:6},1:{0:8,1:8},2:{1:10}},
  eq4:{0:6,1:5,2:4}, eq5:{0:1,1:1,2:1},
};

// Highest-severity reference vectors per EQ level (for distance calculation)
const _MX = {
  eq1:{0:["AV:N/PR:N/UI:N/"],1:["AV:A/PR:N/UI:N/","AV:N/PR:L/UI:N/","AV:N/PR:N/UI:P/"],2:["AV:P/PR:N/UI:N/","AV:A/PR:L/UI:P/"]},
  eq2:{0:["AC:L/AT:N/"],1:["AC:H/AT:N/","AC:L/AT:P/"]},
  eq3:{
    0:{"0":["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"],"1":["VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/","VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"]},
    1:{"0":["VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/","VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"],"1":["VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/","VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/","VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/","VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/","VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/"]},
    2:{"1":["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"]},
  },
  eq4:{0:["SC:H/SI:S/SA:S/"],1:["SC:H/SI:H/SA:H/"],2:["SC:L/SI:L/SA:L/"]},
  eq5:{0:["E:A/"],1:["E:P/"],2:["E:U/"]},
};

// Get effective metric value: modified env metric overrides base; X uses worst-case default
function _eff(state, m) {
  const WCD = {E:"A",CR:"H",IR:"H",AR:"H"};
  const mod = "M" + m;
  if (state[mod] && state[mod] !== "X") return state[mod];
  const v = state[m];
  if (!v || v === "X") return WCD[m] || "N";
  return v;
}

// Extract a metric value from a slash-separated vector fragment string
function _fromVec(vec, m) {
  const i = vec.indexOf(m + ":");
  if (i < 0) return null;
  const rest = vec.slice(i + m.length + 1);
  const end = rest.indexOf("/");
  return end >= 0 ? rest.slice(0, end) : rest;
}

function approximateScore(state) {
  const NO_IMPACT = ["VC","VI","VA","SC","SI","SA"];
  if (NO_IMPACT.every(m => _eff(state, m) === "N")) return 0.0;

  // Compute EQ levels
  const AV=_eff(state,"AV"),PR=_eff(state,"PR"),UI=_eff(state,"UI");
  const AC=_eff(state,"AC"),AT=_eff(state,"AT");
  const VC=_eff(state,"VC"),VI=_eff(state,"VI"),VA=_eff(state,"VA");
  const SC=_eff(state,"SC"),SI=_eff(state,"SI"),SA=_eff(state,"SA");
  const CR=_eff(state,"CR"),IR=_eff(state,"IR"),AR=_eff(state,"AR");
  const E=_eff(state,"E");
  const MSI=state.MSI||"X", MSA=state.MSA||"X";

  const eq1 = (AV==="N"&&PR==="N"&&UI==="N") ? 0
    : ((AV==="N"||PR==="N"||UI==="N")&&!(AV==="N"&&PR==="N"&&UI==="N")&&AV!=="P") ? 1 : 2;
  const eq2 = (AC==="L"&&AT==="N") ? 0 : 1;
  const eq3 = (VC==="H"&&VI==="H") ? 0 : (VC==="H"||VI==="H"||VA==="H") ? 1 : 2;
  const eq4 = (MSI==="S"||MSA==="S") ? 0 : (SC==="H"||SI==="H"||SA==="H") ? 1 : 2;
  const eq5 = (E==="A") ? 0 : (E==="P") ? 1 : 2;
  const eq6 = ((CR==="H"&&VC==="H")||(IR==="H"&&VI==="H")||(AR==="H"&&VA==="H")) ? 0 : 1;

  const key = `${eq1}${eq2}${eq3}${eq4}${eq5}${eq6}`;
  const val = _MV[key];
  if (val === undefined) return 0.0;

  const STEP = 0.1;

  // Next-lower macro vector scores per EQ dimension
  const nv = (k) => _MV[k] ?? NaN;
  const nEq1    = nv(`${eq1+1}${eq2}${eq3}${eq4}${eq5}${eq6}`);
  const nEq2    = nv(`${eq1}${eq2+1}${eq3}${eq4}${eq5}${eq6}`);
  const nEq4    = nv(`${eq1}${eq2}${eq3}${eq4+1}${eq5}${eq6}`);
  const nEq5    = nv(`${eq1}${eq2}${eq3}${eq4}${eq5+1}${eq6}`);

  // EQ3+EQ6 combined next-lower
  let nEq3eq6;
  if      (eq3===1&&eq6===1) nEq3eq6 = nv(`${eq1}${eq2}${eq3+1}${eq4}${eq5}${eq6}`);
  else if (eq3===0&&eq6===1) nEq3eq6 = nv(`${eq1}${eq2}${eq3+1}${eq4}${eq5}${eq6}`);
  else if (eq3===1&&eq6===0) nEq3eq6 = nv(`${eq1}${eq2}${eq3}${eq4}${eq5}${eq6+1}`);
  else if (eq3===0&&eq6===0) {
    const l = nv(`${eq1}${eq2}${eq3}${eq4}${eq5}${eq6+1}`);
    const r = nv(`${eq1}${eq2}${eq3+1}${eq4}${eq5}${eq6}`);
    nEq3eq6 = Math.max(isFinite(l)?l:-Infinity, isFinite(r)?r:-Infinity);
    if (!isFinite(nEq3eq6)) nEq3eq6 = NaN;
  } else {
    nEq3eq6 = nv(`${eq1}${eq2}${eq3+1}${eq4}${eq5}${eq6+1}`);
  }

  // Build all reference max-vectors for distance calculation
  const eq3key = String(eq6);
  const maxCombos = [];
  for (const a of (_MX.eq1[eq1]||[]))
  for (const b of (_MX.eq2[eq2]||[]))
  for (const c of ((_MX.eq3[eq3]||{})[eq3key]||[]))
  for (const d of (_MX.eq4[eq4]||[]))
  for (const e of (_MX.eq5[eq5]||[]))
    maxCombos.push(a+b+c+d+e);

  // Find the first max-vector where all severity distances are >= 0
  let dist = null;
  for (const mv of maxCombos) {
    const d = {};
    let ok = true;
    for (const m of Object.keys(_ML)) {
      const ev = _eff(state, m);
      const mv_val = _fromVec(mv, m);
      const lvl = _ML[m];
      const cur = lvl[ev] ?? 0;
      const ref = mv_val ? (lvl[mv_val] ?? 0) : 0;
      d[m] = cur - ref;
      if (d[m] < 0) { ok = false; break; }
    }
    if (ok) { dist = d; break; }
  }
  if (!dist) dist = {};

  const dEq1    = (dist.AV||0)+(dist.PR||0)+(dist.UI||0);
  const dEq2    = (dist.AC||0)+(dist.AT||0);
  const dEq3eq6 = (dist.VC||0)+(dist.VI||0)+(dist.VA||0)+(dist.CR||0)+(dist.IR||0)+(dist.AR||0);
  const dEq4    = (dist.SC||0)+(dist.SI||0)+(dist.SA||0);

  const aEq1    = val - nEq1;
  const aEq2    = val - nEq2;
  const aEq3eq6 = val - nEq3eq6;
  const aEq4    = val - nEq4;
  const aEq5    = val - nEq5;

  const msEq1    = (_MS.eq1[eq1])||1;
  const msEq2    = (_MS.eq2[eq2])||1;
  const msEq3eq6 = ((_MS.eq3eq6[eq3]||{})[eq6])||1;
  const msEq4    = (_MS.eq4[eq4])||1;

  let n = 0, total = 0;
  const add = (avail, sev, maxSev) => {
    if (!isNaN(avail) && isFinite(avail) && maxSev > 0) { n++; total += avail * (sev / maxSev); }
  };
  add(aEq1,    dEq1,    msEq1);
  add(aEq2,    dEq2,    msEq2);
  add(aEq3eq6, dEq3eq6, msEq3eq6);
  add(aEq4,    dEq4,    msEq4);
  if (!isNaN(aEq5) && isFinite(aEq5)) n++;  // eq5 distance always 0 (no sub-metrics)

  const mean = n === 0 ? 0 : total / n;
  const raw = Math.max(0, Math.min(10, val - mean));
  return Math.round((raw + 1e-6) * 10) / 10;
}

function severityFor(score) {
  if (score == null || score === 0) return "Informational";
  if (score < 4)   return "Low";
  if (score < 7)   return "Medium";
  if (score < 9)   return "High";
  return "Critical";
}

function buildVector(state) {
  // Required base in canonical order
  const base = ["AV","AC","AT","PR","UI","VC","VI","VA","SC","SI","SA"];
  const parts = ["CVSS:4.0"];
  for (const k of base) parts.push(`${k}:${state[k]}`);
  // Threat
  if (state.E && state.E !== "X") parts.push(`E:${state.E}`);
  // Environmental
  for (const k of ["CR","IR","AR","MAV","MAC","MAT","MPR","MUI","MVC","MVI","MVA","MSC","MSI","MSA"]) {
    if (state[k] && state[k] !== "X") parts.push(`${k}:${state[k]}`);
  }
  // Supplemental
  for (const k of ["S","AU","R","V","RE","U"]) {
    if (state[k] && state[k] !== "X") parts.push(`${k}:${state[k]}`);
  }
  return parts.join("/");
}

function mountCvssCalculator(host, onChange) {
  // Initialise state to defaults
  const state = {};
  for (const group of Object.values(CVSS_METRICS)) {
    for (const m of group.metrics) state[m.id] = m.def;
  }

  host.classList.add("cvss-calc");
  host.innerHTML = "";

  // Render groups
  for (const [key, group] of Object.entries(CVSS_METRICS)) {
    const gEl = document.createElement("div");
    gEl.className = "cvss-group";
    const h = document.createElement("h4");
    h.textContent = group.label;
    gEl.appendChild(h);

    const grid = document.createElement("div");
    grid.className = "cvss-metrics";
    for (const m of group.metrics) {
      const wrap = document.createElement("div");
      wrap.className = "cvss-metric";
      const lab = document.createElement("label");
      lab.textContent = `${m.name} (${m.id})`;
      wrap.appendChild(lab);
      const sel = document.createElement("select");
      for (const [val, name] of m.opts) {
        const opt = document.createElement("option");
        opt.value = val; opt.textContent = `${val} — ${name}`;
        sel.appendChild(opt);
      }
      sel.value = m.def;
      sel.dataset.metric = m.id;
      sel.addEventListener("change", () => {
        state[m.id] = sel.value;
        refresh();
      });
      wrap.appendChild(sel);
      grid.appendChild(wrap);
    }
    gEl.appendChild(grid);
    host.appendChild(gEl);
  }

  // Output area
  const out = document.createElement("div");
  out.className = "cvss-out";
  out.innerHTML = `
    <div class="cvss-score"><span class="num">0.0</span> <span class="sev">Informational</span></div>
    <div class="cvss-vector"></div>
  `;
  host.appendChild(out);

  function refresh() {
    const score = approximateScore(state);
    const sev = severityFor(score);
    const vec = buildVector(state);
    out.querySelector(".num").textContent = score.toFixed(1);
    out.querySelector(".sev").textContent = sev;
    out.querySelector(".cvss-vector").textContent = vec;
    if (typeof onChange === "function") onChange(vec, score, sev);
  }
  refresh();
}

// Expose globally for inline scripts that use it
window.mountCvssCalculator = mountCvssCalculator;
