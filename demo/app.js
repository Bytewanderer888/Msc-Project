/* SafeSOC validation workbench.
 *
 * The two validation paths are kept apart here exactly as they are on the server:
 *   validate()  -> POST /api/validate   package + output + policy      (deployable)
 *   research()  -> GET  /api/research   adds frozen ground truth, A4   (offline only)
 * Model outputs are replayed from disk; nothing in this file calls a model provider.
 */
'use strict';

const S = {
  snap: null, researchSnap: null, cases: [],
  filters: {tier:new Set(), condition:new Set(), split:new Set()},
  search: '', caseId: null, pkg: null, available: {},
  // Gemini / A2 / round 1 is the state the tool exists to show: on ACCT-001 it passes the runtime
  // policy with zero findings yet fails A4 — the limit of a ground-truth-free layer. Landing on
  // whichever model key happened to sort first buried that.
  model: 'gemini-2.5-flash', arm: 'A2_evidence_prompt', round: 1,
  output: null, profile: null, runtime: null, tab: 'workbench', activePreset: null,
  dashboardView: 'performance',
  // Last offline A4 result, plus the exact selection it describes. Keyed so that switching model,
  // arm or round cannot leave ground-truth-derived badges attached to a different output.
  research: null, researchKey: null,
};

const selectionKey = () => `${S.caseId}|${S.model}|${S.arm}|${S.round}`;
const researchGrounding = () => {
  const fresh = S.research && S.researchKey === selectionKey();
  const g = fresh ? (S.research.grounding || {}) : {};
  const up = (a) => new Set((a || []).map(x => String(x).toUpperCase()));
  return {supporting: up(g.supporting_evidence), counter: up(g.counter_evidence), fresh: !!fresh};
};

const $ = (id) => document.getElementById(id);
const el = (h) => { const t = document.createElement('template'); t.innerHTML = h.trim(); return t.content.firstChild; };
const esc = (s) => String(s ?? '').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
// Canonical ladders, mirrored from eval/validator_v1_1.py (SEVERITIES / VERDICTS / ACTIONS).
// They are the axes of the decision-band scales; if the evaluator's ladders ever change, these
// must change with them.
const LADDER = {
  verdict: ['benign', 'suspicious', 'malicious'],
  severity: ['informational', 'low', 'medium', 'high', 'critical'],
  action: ['close_benign', 'monitor', 'investigate', 'escalate', 'isolate'],
};
const STEP_LABEL = (s) => s.replace(/_/g, ' ').replace(/^./, c => c.toUpperCase());

const CLS = {malicious:'c-crit',critical:'c-crit',high:'c-crit',isolate:'c-crit',escalate:'c-crit',
  suspicious:'c-mid',medium:'c-mid',low:'c-mid',investigate:'c-mid',monitor:'c-mid',
  benign:'c-good',informational:'c-good',close_benign:'c-good'};
const chip = (t) => `<span class="chip ${CLS[t]||''}">${esc(t)}</span>`;
const ARM_LABEL = {A1_basic_prompt:'A1 basic', A2_evidence_prompt:'A2 evidence'};
const MODEL_LABEL = {'gemini-2.5-flash':'Gemini 2.5 Flash', 'claude-sonnet-4-6':'Claude Sonnet 4.6'};

async function api(path, opts) {
  const r = await fetch(path, opts);
  const body = await r.json();
  if (!r.ok) throw new Error(body.error || `HTTP ${r.status}`);
  return body;
}
function toast(msg) {
  const t = el(`<div class="toast">${esc(msg)}</div>`);
  document.body.appendChild(t); setTimeout(() => t.remove(), 4200);
}

/* ---------------- boot ---------------- */
(async function init() {
  try { S.snap = await api('/api/snapshot'); }
  catch (e) { document.body.innerHTML = `<div class="empty">Cannot load snapshot: ${esc(e.message)}<br>
    Run <code>python3 demo/build_snapshot.py</code>, then restart the server.</div>`; return; }
  S.cases = S.snap.cases;
  S.profile = S.snap.runtime.default_profile;
  buildFilters(); buildProfileSelect(); renderCaseList();
  wireChrome();
  if (S.cases.length) selectCase(S.cases[0].case_id);
})();

function wireChrome() {
  $('caseSearch').addEventListener('input', e => { S.search = e.target.value.toLowerCase(); renderCaseList(); });
  $('validateBtn').addEventListener('click', runValidation);
  $('profileSel').addEventListener('change', e => {
    S.profile = e.target.value;
    if (S.runtime) { renderRuntimeSummary(); renderRuntimeDetail(); }
  });
  $('runtimeSummary').addEventListener('click', showRuntimeDetail);
  $('runtimeBack').addEventListener('click', showTriageView);
  // Any control carrying data-goto jumps to that evidence item, wherever it lives.
  document.addEventListener('click', e => {
    const g = e.target.closest('[data-goto]');
    if (!g) return;
    const ids = g.dataset.goto.split(',').map(s => s.trim()).filter(Boolean);
    const run = () => {
      const r = focusEvidence(ids);
      if (!r.found) toast(`${ids.join(', ')} is not present in this alert package.`);
    };
    if (S.tab === 'workbench') { run(); return; }
    // Coming from another page: switchTab is synchronous on the workbench path, but the pane still
    // holds the layout it had while that page was active, and scrolling then lands on a stale
    // offset (verified: 365px instead of 1503px). Force a reflow so the scroll is computed
    // against the real geometry. Deliberately not requestAnimationFrame — its callbacks are not
    // guaranteed to run (verified: the handler never executed at all via that path).
    switchTab('workbench');
    void $('evidencePane').offsetHeight;
    run();
  });
  $('presentBtn').addEventListener('click', () => presentSet($('presentBar').hidden));
  $('presentPrev').addEventListener('click', () => presentGo(presentIx - 1));
  $('presentNext').addEventListener('click', () => presentGo(presentIx + 1));
  $('presentExit').addEventListener('click', () => presentSet(false));
  $('presetSel').addEventListener('change', e => e.target.value && applyPreset(e.target.value));
  $('presetLoad').addEventListener('click', loadResearchPresets);
  $('scenarioResearch').addEventListener('click', () => switchTab('research'));
  $('scenarioDismiss').addEventListener('click', clearPresetContext);
  $('tabs').addEventListener('click', e => { const b = e.target.closest('.tab'); if (b) switchTab(b.dataset.tab); });
  $('researchClose').addEventListener('click', () => switchTab('workbench'));
  $('dashClose').addEventListener('click', () => switchTab('workbench'));
  document.querySelectorAll('[data-sheet-tab]').forEach(b =>
    b.addEventListener('click', () => switchTab(b.dataset.sheetTab)));
  $('themeBtn').addEventListener('click', () => {
    const dark = getComputedStyle(document.documentElement).getPropertyValue('--ground').trim().startsWith('#0');
    document.documentElement.setAttribute('data-theme', dark ? 'light' : 'dark');
  });
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && S.tab !== 'workbench') switchTab('workbench');
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'SELECT') return;
    // Projector focus: collapse the case queue and give the two working panels the width.
    if (e.key === 'f' || e.key === 'F') { document.body.classList.toggle('focusmode'); return; }
    if (!$('presentBar').hidden) {
      if (e.key === 'ArrowRight') { presentGo(presentIx + 1); return; }
      if (e.key === 'ArrowLeft') { presentGo(presentIx - 1); return; }
    }
    if (e.key === 'v' && !$('validateBtn').disabled) runValidation();
  });
}

/* ---------------- left panel ---------------- */
function buildFilters() {
  const groups = [
    {key:'tier', label:'Tier', values:S.snap.filters.tier},
    {key:'split', label:'Split', values:S.snap.filters.split},
  ];
  $('filters').innerHTML = groups.map(g => `
    <div class="fgroup"><div class="flabel">${g.label}</div>
      <div class="fchips" data-key="${g.key}">
        ${g.values.map(v => `<button class="fchip" data-v="${esc(v)}" aria-pressed="false">${esc(v)}</button>`).join('')}
      </div></div>`).join('');
  $('filters').onclick = e => {
    const b = e.target.closest('.fchip'); if (!b) return;
    const key = b.parentElement.dataset.key, v = b.dataset.v, set = S.filters[key];
    set.has(v) ? set.delete(v) : set.add(v);
    b.setAttribute('aria-pressed', set.has(v));
    renderCaseList();
  };
}

function visibleCases() {
  return S.cases.filter(c =>
    (!S.filters.tier.size || S.filters.tier.has(c.tier)) &&
    (!S.filters.split.size || S.filters.split.has(c.split)) &&
    (!S.filters.condition.size ||
      S.filters.condition.has(S.researchSnap?.condition_by_case?.[c.case_id])) &&
    (!S.search || c.case_id.toLowerCase().includes(S.search) || c.dataset.toLowerCase().includes(S.search)
      || c.sourcetypes.join(' ').toLowerCase().includes(S.search)));
}

function renderCaseList() {
  const rows = visibleCases();
  $('caseCount').textContent = `${rows.length}/${S.cases.length}`;
  $('caseList').innerHTML = rows.map(c => `
    <button class="caserow" data-id="${c.case_id}" aria-current="${c.case_id === S.caseId}">
      <span class="cid">${esc(c.case_id)}</span>
      <span class="cname">${esc(c.dataset)} · ${esc(c.sourcetypes.join(', ') || 'unknown sensor')}</span>
      <span class="badges"><span class="tiny">${esc(c.tier)}</span><span class="tiny">${esc(c.split)}</span>
        <span class="tiny num">${esc(c.event_count)} ev</span></span>
    </button>`).join('') || '<div class="empty small">No cases match.</div>';
  $('caseList').querySelectorAll('.caserow').forEach(b =>
    b.addEventListener('click', () => selectCase(b.dataset.id)));
}

/* ---------------- centre: package + timeline ---------------- */
async function selectCase(caseId, keepModel, keepPreset) {
  if (!keepPreset) clearPresetContext();
  S.caseId = caseId;
  renderCaseList();
  const data = await api(`/api/case?case_id=${encodeURIComponent(caseId)}`);
  S.pkg = data.package; S.available = data.available;
  const c = data.case;
  $('pkgMeta').textContent = `${c.case_id} · ${c.event_count} events · ${c.derivation_count} derivations`;
  renderEvidence();
  wireEvidencePane();
  buildModelBar(keepModel);
  await loadOutput();
}

/* ---------------- alert field grouping ----------------
   The 41 packages carry 78 distinct attribute keys across 14 event types and two providers, so
   fields are bucketed by rule rather than by a per-event-type table: whatever matches nothing
   falls through to the primary group, which is named after the event type. Order matters —
   parent_process_guid is an opaque identifier first and a parent-process field second. */
const ID_FIELD = (k) => /_guid$/.test(k) || /_id$/.test(k) || k === 'hashes';
const IDENTITY_FIELD = (k) => /^(user|subject_user|run_as|integrity_level|mandatory_label)$/.test(k)
  || /_(user_name|domain_name)$/.test(k);
const PARENT_FIELD = (k) => k.startsWith('parent_') || k === 'creator_process_name';
const PRIMARY_LABEL = [
  [/^process_create$/, 'Process'], [/^failed_logon$/, 'Logon attempt'],
  [/^network_connection$/, 'Network'], [/^file_create$/, 'File'],
  [/^registry_/, 'Registry'], [/^process_access$/, 'Process access'],
  [/^network_share_object_access$/, 'Share access'],
  [/^scheduled_task_created$/, 'Scheduled task'],
  [/^create_remote_thread$/, 'Remote thread'], [/^wmi_/, 'WMI'],
];
const primaryLabel = (t) => (PRIMARY_LABEL.find(([re]) => re.test(t || '')) || [null, 'Event'])[1];
// Only values long enough to dominate the card are clamped; whether the clamp actually bites is
// measured after layout by fitFieldValues(), so short-but-wrapping values keep no stray control.
const LONG_VALUE = 120;
const COPY_ICON = '<svg viewBox="0 0 16 16" width="12" height="12" aria-hidden="true" fill="none" '
  + 'stroke="currentColor" stroke-width="1.6"><rect x="5.5" y="5.5" width="8" height="8" rx="1.6"/>'
  + '<path d="M10.5 3.5H3.6a1.1 1.1 0 0 0-1.1 1.1v6.9"/></svg>';

function attrRows(attrs, eventType) {
  const entries = Object.entries(attrs || {}).filter(([, v]) => v !== null && v !== '' &&
    !(Array.isArray(v) && !v.length));
  if (!entries.length) return '<span class="mut">no attributes</span>';
  const bucket = {primary: [], identity: [], parent: [], ids: []};
  entries.forEach(([k, v]) => {
    const where = ID_FIELD(k) ? 'ids' : IDENTITY_FIELD(k) ? 'identity'
      : PARENT_FIELD(k) ? 'parent' : 'primary';
    bucket[where].push([k, v]);
  });
  const rows = (list) => list.map(([k, v]) => {
    const text = typeof v === 'object' ? JSON.stringify(v) : String(v);
    const long = text.length > LONG_VALUE;
    // Copy is offered only where the three-line clamp hides part of the value: that text cannot
    // be selected with the mouse without expanding first. A short value is a double-click away,
    // so a button on every row would be noise. The 20px column is kept either way so values
    // share one right edge.
    // The button is a grid sibling of the value, not a child: an unbreakable base64 command line
    // consumes the whole line and would otherwise displace it onto a second row.
    return `<div class="arow">
      <b class="fname">${esc(k)}</b>
      <div class="fval">
        <span class="fv${long ? ' clamp' : ''}">${esc(text)}</span>
        ${long ? '<button class="fmore" type="button" hidden aria-expanded="false">Expand</button>' : ''}
      </div>
      ${long ? `<button class="fcopy" type="button" title="Copy value"
        aria-label="Copy ${esc(k)}">${COPY_ICON}</button>` : ''}</div>`;
  }).join('');
  const section = (label, list) => list.length
    ? `<div class="fgroup"><div class="fglabel">${esc(label)}</div>${rows(list)}</div>` : '';
  const ids = bucket.ids.length
    ? `<details class="idfold"><summary>Identifiers · ${bucket.ids.length}</summary>
       <div class="fgroup">${rows(bucket.ids)}</div></details>` : '';
  return `${section(primaryLabel(eventType), bucket.primary)}
    ${section('Identity', bucket.identity)}
    ${section('Parent process', bucket.parent)}
    ${ids}`;
}

// Reveal Expand only where the clamp actually cuts something off — same measured approach as the
// chart labels, because whether three lines is enough depends on the pane width.
function fitFieldValues() {
  document.querySelectorAll('#evidencePane .fv.clamp').forEach(v => {
    const more = v.parentElement.querySelector('.fmore');
    if (!more) return;
    if (v.classList.contains('open')) return;
    more.hidden = v.scrollHeight <= v.clientHeight + 1;
  });
}

function renderEvidence() {
  const p = S.pkg, cited = new Set((S.output?.key_evidence || []).map(x => x.toUpperCase()));
  const oc = p.observed_context || {};
  // Role badges come from ground truth, so they exist only once Research mode has been opened for
  // this exact output. They are tagged `research` in the UI and never reach the runtime path.
  const g = researchGrounding();
  const role = (id) => {
    const u = String(id).toUpperCase();
    if (g.counter.has(u)) return '<span class="rolebadge counter" title="Ground truth marks this as counter-evidence">counter · research</span>';
    if (g.supporting.has(u)) return '<span class="rolebadge supporting" title="Ground truth marks this as supporting evidence">supporting · research</span>';
    return '';
  };
  const ev = (item, kind) => {
    const id = item.evidence_id;
    const isCited = cited.has(String(id).toUpperCase());
    return `<div class="tevent ${kind} ${isCited ? 'cited' : ''}" data-ev="${esc(String(id).toUpperCase())}">
      <div class="card">
        <div class="trow"><span class="evid">${esc(id)}</span>${role(id)}
          <span class="ttime mono">${esc(item.event_time_utc || '')}</span>
          <span class="ttype">${esc(item.event_type || '')}</span>
          ${item.source_event?.event_code != null ? `<span class="ttime mono">EID ${esc(item.source_event.event_code)}</span>` : ''}
          ${isCited ? '<span class="citedtag">cited</span>' : ''}</div>
        <div class="attrs">${attrRows(item.attributes, item.event_type)}</div>
      </div></div>`;
  };
  const derivations = (p.deterministic_derivations || []).map(d => `
    <div class="tevent der ${cited.has(String(d.derivation_id).toUpperCase()) ? 'cited' : ''}">
      <div class="card dercard">
        <div class="trow"><span class="evid">${esc(d.derivation_id)}</span>
          <span class="derlabel">deterministic derivation</span>
          ${cited.has(String(d.derivation_id).toUpperCase()) ? '<span class="citedtag">cited</span>' : ''}</div>
        <div class="attrs">
          <div class="arow"><b class="fname">derived_field</b><span class="fv">${esc(d.derived_field)}</span></div>
          <div class="arow"><b class="fname">from</b><span class="fv">${esc(d.source_evidence_id)} · ${esc(d.source_field)}</span></div>
          <div class="arow"><b class="fname">method</b><span class="fv">${esc(d.derivation_method)}</span></div>
          <div class="arow"><b class="fname">value</b><span class="fv">${esc(d.value)}</span></div>
        </div></div></div>`).join('');

  $('evidencePane').innerHTML = `
    <div class="alertcard" data-ev="A0">
      <div class="ahead"><span class="evid">A0</span><b>Triggering alert</b>${role('A0')}
        <span class="ttime mono">${esc(p.main_alert.event_time_utc || '')}</span></div>
      <div class="attrs">${attrRows(p.main_alert.attributes, p.main_alert.event_type)}</div>
      <div class="metaline" style="margin-top:9px">${esc((oc.sourcetypes_present||[]).join(', '))}
        · window ${esc(oc.time_window_utc?.start || '')} → ${esc(oc.time_window_utc?.end || '')}</div>
    </div>
    <div class="eyebrow" style="margin-bottom:9px">Contextual evidence · chronological</div>
    <div class="timeline">
      ${(p.evidence_items || []).map(i => ev(i, 'evt')).join('') || '<div class="empty small">No additional evidence items.</div>'}
      ${derivations}
    </div>`;
  fitFieldValues();
}

/* Bring one or more evidence items into view and flash them. Returns how many were found, so a
   caller can report an unresolvable reference instead of silently doing nothing — C1 exists
   precisely because models cite IDs that are not in the package. */
function focusEvidence(ids) {
  const want = (Array.isArray(ids) ? ids : [ids]).map(x => String(x).toUpperCase());
  const pane = $('evidencePane');
  pane.querySelectorAll('.flash').forEach(n => n.classList.remove('flash'));
  const found = want.map(id => pane.querySelector(`[data-ev="${CSS.escape(id)}"]`)).filter(Boolean);
  found.forEach(n => { n.classList.add('flash'); });
  if (found.length) {
    // Instant jump, not a smooth scroll: a long slide makes the jump harder to follow, and
    // behavior:"smooth" is a silent no-op in some engines — verified scrolling 0px here while
    // the default jumped correctly. The 150ms flash carries the transition instead.
    found[0].scrollIntoView({block: 'center'});
    setTimeout(() => found.forEach(n => n.classList.remove('flash')), 1600);
  }
  return {found: found.length, missing: want.length - found.length};
}

// Delegated once on the pane, so the listeners survive every re-render without accumulating.
function wireEvidencePane() {
  const pane = $('evidencePane');
  if (!pane || pane.dataset.wired) return;
  pane.dataset.wired = '1';
  pane.addEventListener('click', async (e) => {
    const more = e.target.closest('.fmore');
    if (more) {
      const v = more.parentElement.querySelector('.fv');
      const open = v.classList.toggle('open');
      more.textContent = open ? 'Collapse' : 'Expand';
      more.setAttribute('aria-expanded', String(open));
      return;
    }
    const copy = e.target.closest('.fcopy');
    if (!copy) return;
    const text = copy.closest('.arow').querySelector('.fv').textContent;
    try {
      await navigator.clipboard.writeText(text);
      copy.classList.add('ok');
      setTimeout(() => copy.classList.remove('ok'), 1100);
    } catch {
      // Clipboard access can be refused even on localhost; say so rather than fail silently.
      copy.classList.add('bad');
      setTimeout(() => copy.classList.remove('bad'), 1600);
    }
  });
}

/* ---------------- right: model switching + output ---------------- */
function buildModelBar(keepModel) {
  const avail = S.available;
  const models = Object.keys(avail);
  if (!models.length) { $('modelBar').innerHTML = '<span class="mut small">No saved outputs for this case.</span>'; return; }
  // Fall back through preference order, then to whatever the case actually has: not every case
  // is guaranteed an output for the preferred model.
  const PREFERRED = ['gemini-2.5-flash', 'claude-sonnet-4-6'];
  if (!keepModel || !avail[S.model]) {
    S.model = avail[S.model] ? S.model : (PREFERRED.find(m => avail[m]) || models[0]);
  }
  const arms = Object.keys(avail[S.model] || {});
  if (!arms.includes(S.arm)) S.arm = arms.includes('A2_evidence_prompt') ? 'A2_evidence_prompt' : arms[0];
  const rounds = Object.keys(avail[S.model]?.[S.arm] || {}).map(Number).sort((a, b) => a - b);
  if (!rounds.includes(S.round)) S.round = rounds[0] || 1;

  $('modelBar').innerHTML = `
    <div class="mgroup"><span class="glabel">Model</span>
      ${models.map(m => `<button class="mbtn label" data-kind="model" data-v="${esc(m)}"
        aria-pressed="${m === S.model}">${esc(MODEL_LABEL[m] || m)}</button>`).join('')}</div>
    <div class="mgroup"><span class="glabel">Arm</span>
      ${arms.map(a => `<button class="mbtn label" data-kind="arm" data-v="${esc(a)}"
        aria-pressed="${a === S.arm}">${esc(ARM_LABEL[a] || a)}</button>`).join('')}</div>
    <div class="mgroup"><span class="glabel">Round</span>
      ${rounds.map(r => `<button class="mbtn" data-kind="round" data-v="${r}"
        aria-pressed="${r === S.round}" title="Repeated run — use to inspect stability">${r}</button>`).join('')}</div>`;
  $('modelBar').querySelectorAll('.mbtn').forEach(b => b.addEventListener('click', async () => {
    const {kind, v} = b.dataset;
    clearPresetContext();
    S[kind] = kind === 'round' ? Number(v) : v;
    buildModelBar(true);
    await loadOutput();
  }));
}

async function loadOutput() {
  S.runtime = null; resetRuntimeUI();
  if (!Object.keys(S.available).length) { S.output = null; $('outputPane').innerHTML =
    '<div class="empty">No saved output for this case.</div>'; $('validateBtn').disabled = true; return; }
  try {
    const d = await api(`/api/output?case_id=${encodeURIComponent(S.caseId)}&model=${encodeURIComponent(S.model)}`
      + `&arm=${encodeURIComponent(S.arm)}&round=${S.round}`);
    S.output = d.output; S.outputRel = d.output_rel;
  } catch (e) { S.output = null; $('outputPane').innerHTML = `<div class="empty">${esc(e.message)}</div>`;
    $('validateBtn').disabled = true; return; }
  renderOutput(); renderEvidence();
  $('validateBtn').disabled = false;
  if (S.tab === 'research') openResearch();
}

function renderOutput() {
  const o = S.output;
  $('outputPane').innerHTML = `
    <div class="decision">${chip(o.verdict)}${chip(o.severity)}${chip(o.recommended_action)}</div>
    <div class="field"><div class="flab">Confidence <span class="mono num">${o.confidence}</span></div>
      <div class="confbar"><span style="width:${Math.round(o.confidence * 100)}%"></span></div></div>
    <div class="field"><div class="flab">Key evidence</div>
      <div class="keyev">${(o.key_evidence || []).map(k =>
        `<button type="button" class="kev" data-goto="${esc(String(k).toUpperCase())}"
          title="Show ${esc(k)} in the alert package">${esc(k)}</button>`).join('')}</div></div>
    <div class="field"><div class="flab">Rationale</div>
      <div class="rationale">${esc(o.rationale)}</div></div>
    <div class="metaline">${esc(S.outputRel || '')}</div>`;
}

/* ---------------- runtime validation (deployable path) ---------------- */
function showTriageView() {
  $('triageView').hidden = false;
  $('runtimeView').hidden = true;
  $('rightHeading').textContent = 'LLM triage output';
  $('rightModeBadge').textContent = 'replayed';
  $('rightModeBadge').title = 'Saved output replayed from disk; no provider is called';
}

function showRuntimeDetail() {
  if (!S.runtime) return;
  renderRuntimeDetail();
  $('triageView').hidden = true;
  $('runtimeView').hidden = false;
  $('rightHeading').textContent = 'Runtime validation';
  $('rightModeBadge').textContent = '0 tokens';
  $('rightModeBadge').title = 'Ground-truth-free deterministic policy; no provider is called';
  $('runtimeDetail').scrollTop = 0;
}

function resetRuntimeUI() {
  $('runtimeSummary').hidden = true;
  $('runtimeSummary').innerHTML = '';
  $('runtimeDetail').innerHTML = '';
  showTriageView();
}

async function runValidation() {
  $('validateBtn').disabled = true; $('validateBtn').textContent = 'Validating…';
  try {
    S.runtime = await api('/api/validate', {method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({case_id:S.caseId, model:S.model, arm:S.arm, round:S.round})});
    renderRuntimeSummary();
    renderRuntimeDetail();
    showRuntimeDetail();
  } catch (e) { toast(`Validation failed: ${e.message}`); }
  finally { $('validateBtn').disabled = false; $('validateBtn').textContent = 'Validate'; }
}

function buildProfileSelect() {
  const profiles = S.snap.runtime.profiles;
  $('profileSel').innerHTML = Object.entries(profiles).map(([n, p]) =>
    `<option value="${esc(n)}" ${n === S.snap.runtime.default_profile ? 'selected' : ''}>
      ${esc(n)}${n === S.snap.runtime.default_profile ? ' (default)' : ''}</option>`).join('');
  $('profileSel').title = Object.entries(profiles).map(([n, p]) => `${n}: ${p.description}`).join('\n');
}

function runtimeOutcome() {
  const c = S.runtime.case;
  return {c, outcome:c.profile_outcomes[S.profile], findings:c.findings || []};
}

function renderRuntimeSummary() {
  if (!S.runtime) return;
  const {c, outcome, findings} = runtimeOutcome();
  const reviewLabel = outcome.requires_human_review ? 'Human review required' : 'No human review required';
  $('runtimeSummary').innerHTML = `
    <span class="peekkicker"><b>Runtime validation result</b><span>ground-truth-free · 0 tokens</span></span>
    <span class="peekstatus s-${outcome.status}">${esc(outcome.status)}</span>
    <span class="peekcopy"><b>${reviewLabel}</b>
      <span>${findings.length} finding${findings.length === 1 ? '' : 's'} · ${c.signals.length} routing signal${c.signals.length === 1 ? '' : 's'} · ${esc(S.profile)}</span></span>
    <span class="peekarrow"><small>Open report</small><b>Details &#8594;</b></span>`;
  $('runtimeSummary').hidden = false;
}

function renderRuntimeDetail() {
  if (!S.runtime) return;
  const r = S.runtime, c = r.case;
  const outcome = c.profile_outcomes[S.profile];
  const findings = c.findings || [];
  const profileDesc = S.snap.runtime.profiles[S.profile]?.description || '';

  const findingHtml = findings.length ? findings.map(f => `
    <div class="finding ${f.level}"><div class="fcode">${esc(f.code)} · ${esc(f.level)}</div>
      <div class="fmsg">${esc(f.message)}</div>
      ${f.details ? `<div class="metaline" style="margin-top:3px">${esc(JSON.stringify(f.details).slice(0, 220))}</div>` : ''}
    </div>`).join('') : '<div class="mut small">No policy findings — the output is well-formed, its citations resolve, and verdict/severity/action are internally consistent.</div>';

  const signalHtml = c.signals.length ? c.signals.map(s => `
    <div class="finding review"><div class="fcode">${esc(s.code)}</div>
      <div class="fmsg">${esc(s.description)}</div></div>`).join('')
    : '<div class="mut small">No routing signals raised.</div>';

  $('runtimeDetail').innerHTML = `
    <div class="statusrow">
      <span class="bigstatus s-${outcome.status}">${esc(outcome.status)}</span>
      <div><div style="font-weight:600">${outcome.requires_human_review ? 'Human review required' : 'No human review required by policy'}</div>
        <div class="metaline">profile <b>${esc(S.profile)}</b> · ${esc(profileDesc)}</div></div>
      <div class="spacer"></div>
      <div class="metaline">${esc(r.validator)} v${esc(r.validator_version)} · policy v${esc(r.policy_version)}
        · <b>${r.token_calls} tokens</b></div>
    </div>
    <div class="dgrid">
      <div class="dcard"><h3>Triggered policy findings (${findings.length})</h3>${findingHtml}</div>
      <div class="dcard"><h3>Routing signals (${c.signals.length})</h3>${signalHtml}</div>
      <div class="dcard"><h3>Outcome by routing profile</h3>
        <table class="proftable"><tbody>${Object.entries(c.profile_outcomes).map(([n, o]) => `
          <tr class="${n === S.profile ? 'activeprof' : ''}"><td class="pname">${esc(n)}</td>
            <td class="pstat ${o.status}">${esc(o.status)}</td>
            <td class="metaline">${o.reasons.length ? esc(o.reasons.join(', ')) : '—'}</td></tr>`).join('')}
        </tbody></table></div>
      <div class="dcard"><h3>Runtime input identities</h3>
        <div class="metaline">${r.inputs_read.map(p => esc(p)).join('<br>')}</div>
        <div class="mut small" style="margin-top:8px">${esc(r.input_contract)}</div></div>
    </div>
    <div class="noclaim"><b>What a ${esc(outcome.status)} does and does not mean</b>
      <ul>${r.non_claims.map(n => `<li>${esc(n)}</li>`).join('')}</ul></div>`;
}

/* ---------------- research mode (offline, ground truth) ---------------- */
async function ensureResearchSnapshot() {
  if (S.researchSnap) return S.researchSnap;
  S.researchSnap = await api('/api/research-snapshot');
  buildFilters();
  buildPresets();
  $('presetLoad').hidden = true;
  $('presetSel').hidden = false;
  return S.researchSnap;
}

async function loadResearchPresets() {
  try {
    await ensureResearchSnapshot();
    $('presetSel').focus();
  } catch (e) {
    toast(`Cannot load research presets: ${e.message}`);
  }
}

async function switchTab(tab) {
  if (tab !== 'workbench') {
    try { await ensureResearchSnapshot(); }
    catch (e) { toast(`Cannot open ${tab}: ${e.message}`); return; }
  }
  S.tab = tab;
  document.querySelectorAll('.tab').forEach(b => b.setAttribute('aria-current', b.dataset.tab === tab));
  $('workbenchShell').hidden = tab !== 'workbench';
  $('researchSheet').hidden = tab !== 'research';
  $('dashSheet').hidden = tab !== 'dashboard';
  if (tab === 'research') await openResearch();
  if (tab === 'dashboard') renderDashboard();
}

/* One axis per decision dimension: the admissible ground-truth band is drawn on the ladder and
   the model's own choice is marked on it, so over- and under-triage is a position, not a label.
   The direction comes from the evaluator, not from re-deriving it here. */
function bandScale(title, kind, band, model, direction) {
  const steps = LADDER[kind] || [];
  const inBand = new Set((band || []).map(String));
  const modelIndex = steps.indexOf(model);
  const bandIndexes = [...inBand].map(v => steps.indexOf(v)).filter(v => v >= 0);
  let distance = 0;
  if (modelIndex >= 0 && bandIndexes.length) {
    const lo = Math.min(...bandIndexes), hi = Math.max(...bandIndexes);
    distance = modelIndex < lo ? modelIndex - lo : modelIndex > hi ? modelIndex - hi : 0;
  }
  const distanceNote = distance === 0 ? ''
    : ` · ${distance > 0 ? '+' : ''}${distance} step${Math.abs(distance) === 1 ? '' : 's'}`;
  const note = direction === 'in_band' ? 'inside the supported band'
    : direction === 'over' ? 'above the supported band'
    : direction === 'under' ? 'below the supported band' : String(direction || '');
  const cells = steps.map(s => {
    const isBand = inBand.has(s), isModel = s === model;
    return `<span class="step${isBand ? ' band' : ''}${isModel ? ' model' : ''}"
      >${isModel ? '<i class="dot" aria-hidden="true"></i>' : ''}${esc(STEP_LABEL(s))}</span>`;
  }).join('');
  // A model value outside the ladder would silently render no marker; say so instead.
  const unknown = model && !steps.includes(model)
    ? `<span class="scalewarn">model value “${esc(model)}” is not on this ladder</span>` : '';
  return `<div class="scale dir-${esc(direction)}">
    <div class="scalehead"><b>${esc(title)}</b>
      <span class="scalenote">model <b>${esc(STEP_LABEL(String(model || '—')))}</b> · ${esc(note)}${esc(distanceNote)}</span></div>
    <div class="scaletrack">${cells}</div>${unknown}</div>`;
}

function renderResearchContext() {
  const c = S.cases.find(x => x.case_id === S.caseId);
  const o = S.output;
  if (!c || !o) {
    $('researchContext').innerHTML = '<div class="empty small">Select a case and model in Workbench.</div>';
    return;
  }
  const keys = o.key_evidence || [];
  const packageCount = Number(c.event_count || 0);
  const derivationCount = Number(c.derivation_count || 0);
  $('researchContext').innerHTML = `
    <section class="contextsection first">
      <span class="contextlabel">Selected case</span>
      <b class="contextcase">${esc(c.case_id)}</b>
      <span class="contextname">${esc(c.dataset)} · ${esc(c.sourcetypes.join(', ') || 'unknown sensor')}</span>
      <div class="contextbadges"><span class="tiny">${esc(c.tier)}</span><span class="tiny">${esc(c.split)}</span>
        <span class="tiny num">${packageCount} events</span>
        ${derivationCount ? `<span class="tiny num">${derivationCount} derivation${derivationCount === 1 ? '' : 's'}</span>` : ''}</div>
    </section>
    <section class="contextsection">
      <span class="contextlabel">Replayed model output</span>
      <div class="contextmodel">${esc(MODEL_LABEL[S.model] || S.model)}</div>
      <div class="contextconfig">${esc(ARM_LABEL[S.arm] || S.arm)} · round ${S.round}</div>
      <div class="contextdecision">${chip(o.verdict)}${chip(o.severity)}${chip(o.recommended_action)}</div>
      <div class="contextconfidence"><span>Confidence</span><b class="mono num">${esc(o.confidence)}</b></div>
    </section>
    <section class="contextsection">
      <span class="contextlabel">Model-cited evidence</span>
      <div class="keyev contextkeys">${keys.map(k =>
        `<button type="button" class="kev" data-goto="${esc(String(k).toUpperCase())}"
          title="Open ${esc(k)} in Workbench">${esc(k)}</button>`).join('') || '<span class="mut small">None cited</span>'}</div>
      <button type="button" class="contextopen" data-goto="A0">Open full alert package →</button>
    </section>`;
}

async function openResearch() {
  if (!S.caseId || !S.output) return;
  $('researchTitle').textContent = `A4 evaluation — ${S.caseId}`;
  renderResearchContext();
  $('researchBody').innerHTML = '<div class="empty small">Evaluating…</div>';
  let d;
  try {
    d = await api(`/api/research?case_id=${encodeURIComponent(S.caseId)}&model=${encodeURIComponent(S.model)}`
      + `&arm=${encodeURIComponent(S.arm)}&round=${S.round}`);
  } catch (e) { $('researchBody').innerHTML = `<div class="empty">${esc(e.message)}</div>`; return; }
  // Remember which selection this describes, then re-render the timeline so supporting/counter
  // badges appear on the events themselves.
  S.research = d; S.researchKey = selectionKey();
  renderEvidence();

  const names = S.researchSnap.research.checks;
  const K = {C1:'C1_reference_integrity', C2:'C2_decision_calibration',
             C3:'C3_counter_acknowledgement', C4:'C4_action_calibration'};
  /* Only C1 and C3 attribute a failure to particular evidence items; C2 and C4 compare decision
     bands and name no evidence at all, so they get the ladder above rather than an invented
     highlight. */
  const blame = (c) => {
    const k = d.checks[K[c]];
    if (c === 'C1') {
      const ids = [...(k.invalid_key_evidence_ids || []), ...(k.invalid_rationale_ids || [])];
      return ids.length ? {ids, what: 'cited IDs that are not in the package'} : null;
    }
    if (c === 'C3') {
      const citedC = new Set(k.cited_counter_evidence_ids || []);
      const ids = (k.counter_evidence_ids || []).filter(x => !citedC.has(x));
      return ids.length ? {ids, what: 'counter-evidence the model did not acknowledge'} : null;
    }
    return null;
  };
  const cards = Object.keys(names).map(c => {
    const pass = d.checks[K[c]].pass;
    const b = pass ? null : blame(c);
    const link = b
      ? `<button type="button" class="blamebtn" data-goto="${esc(b.ids.join(','))}"
           >Show ${esc(b.ids.join(', '))} →<span class="blamewhat">${esc(b.what)}</span></button>`
      : (!pass ? `<span class="blamenone">compares decision bands — no single evidence item
           is responsible; see the ladder above</span>` : '');
    return `<div class="checkcard ${pass ? 'pass' : 'fail'}">
      <div class="cid">${c} ${pass ? '✓ pass' : '✗ fail'}</div>
      <div class="cwhat">${esc(names[c])}</div>${link}</div>`;
  }).join('');
  const o = S.output;
  const dirTag = (k, v) => `<span class="dirtag dir-${esc(v)}">${esc(k)}: ${esc(v)}</span>`;

  $('researchBody').innerHTML = `
    <div class="scales">
      ${bandScale('Verdict', 'verdict', [d.expected.verdict], o.verdict, d.directions.verdict)}
      ${bandScale('Severity', 'severity', d.expected.severity, o.severity, d.directions.severity)}
      ${bandScale('Action', 'action', d.expected.actions, o.recommended_action, d.directions.action)}
    </div>
    <div class="statusrow">
      <span class="tiny">condition <b>${esc(d.evidence_condition)}</b></span>
      <span class="tiny">role ${esc(d.calibration_role || '—')}</span>
      ${dirTag('verdict', d.directions.verdict)} ${dirTag('severity', d.directions.severity)}
      ${dirTag('action', d.directions.action)}
      <span class="bigstatus ${d.a4_ok ? 's-pass' : 's-block'}" style="font-size:12px;padding:4px 12px">
        A4 ${d.a4_ok ? 'all checks pass' : 'fails ' + d.failed_checks.join(', ')}</span>
    </div>
    <div class="checkgrid">${cards}</div>
    <div class="sect"><h3>Why this is the supported answer</h3></div>
    <div class="rationale">${esc(d.rationale || '—')}</div>
    ${d.must_not_assert?.length ? `<div class="sect"><h3>Claims the evidence does not support</h3></div>
      <ul class="mut small">${d.must_not_assert.map(m => `<li>${esc(m)}</li>`).join('')}</ul>` : ''}
    <div class="sect"><h3>Grounding</h3></div>
    <div class="small mut">supporting: <span class="mono">${esc((d.grounding.supporting_evidence||[]).join(', ') || '—')}</span>
      &nbsp;·&nbsp; counter: <span class="mono">${esc((d.grounding.counter_evidence||[]).join(', ') || '—')}</span></div>
    <div class="noclaim">${esc(d.scope)} · evaluator ${esc(d.evaluator)}, rubric v${esc(d.rubric_version)}.
      ${S.runtime ? `Runtime said <b>${esc(S.runtime.case.profile_outcomes[S.profile].status)}</b> for the same output under
      <b>${esc(S.profile)}</b> — a runtime pass never implies A4 agreement.` : ''}</div>`;
}

/* ---------------- dashboard ---------------- */
function renderDashboard() {
  const d = S.researchSnap.dashboard;
  const deep = d.deepening || null;
  const external = d.external_replication || null;
  // Rounds of the same run are near-identical, so a flat row per round was mostly repetition.
  // Each line aggregates its rounds (a range when they disagree) and expands to the per-round
  // figures, so the summary stays scannable without hiding the underlying variance.
  const agg = (vals) => {
    const mn = Math.min(...vals), mx = Math.max(...vals);
    return {min: mn, max: mx, vals, varies: mn !== mx, text: mn === mx ? `${mn}` : `${mn}\u2013${mx}`};
  };
  const runs = [];
  Object.values(d.models).forEach(m => Object.entries(m.splits).forEach(([split, sp]) => {
    const rs = Object.entries(sp.rounds).map(([r, v]) => ({round: Number(r), ...v}))
      .sort((a, b) => a.round - b.round);
    const col = k => agg(rs.map(r => r[k]));
    runs.push({model: m.model, arm: m.arm, split, rounds: rs, n: rs[0].n,
      // Named for what they measure: a4all is C1-C4 all passing, decision is C2 alone
      // (verdict + severity). The two differ — Gemini A1 dev is 8 and 9 respectively — so
      // neither may be called "joint" without saying which.
      a4all: col('a4_ok'), decision: col('joint'), over: col('over'), under: col('under'),
      passed: col('runtime_pass'), unsafe: col('pass_but_a4_fail')});
  }));
  const MODEL_ORDER = ['gemini-2.5-flash', 'claude-sonnet-4-6'];
  runs.sort((a, b) => (MODEL_ORDER.indexOf(a.model) - MODEL_ORDER.indexOf(b.model))
    || String(a.arm).localeCompare(String(b.arm)) || (a.split === 'dev' ? -1 : 1));

  const pc = (v, n) => Math.round(100 * v / n);
  // Bar: solid to the minimum (achieved in every round), lighter to the maximum (round spread).
  const scoreCell = (c, n, rounds, key) => {
    const tip = rounds.map(r => `Round ${r.round}: ${r[key]}/${n}`).join('  \u00b7  ');
    const lo = pc(c.min, n), hi = pc(c.max, n);
    return `<div class="score" title="${esc(tip)}">
      <div class="scorebar"><span class="fill-min" style="width:${lo}%"></span>
        ${c.varies ? `<span class="fill-range" style="left:${lo}%;width:${hi - lo}%"></span>` : ''}</div>
      <div class="scorenums">
        <span class="scoreval num"><b>${c.text}</b><span class="mut">/${n}</span></span>
        <span class="scorepct num">${lo === hi ? `${lo}%` : `${lo}\u2013${hi}%`}</span></div></div>`;
  };

  const stabilityFor = (model) => d.stability.find(x =>
    String(x.model_tag).startsWith(model) && x.split === 'heldout');
  const modelSummary = (model) => {
    const held = runs.filter(r => r.model === model && r.split === 'heldout');
    const bits = [];
    if (held.length) bits.push(`held-out best <b>${Math.max(...held.map(r => pc(r.a4all.max, r.n)))}%</b>`);
    const st = stabilityFor(model);
    if (st) bits.push(`round agreement <b>${st.exact_agreement_n}/${st.denominator}</b>`);
    return bits.join(' \u00b7 ');
  };

  let lastModel = null;
  const perfRows = runs.map((r, i) => {
    const head = r.model === lastModel ? '' :
      `<tr class="grouphead"><td colspan="9"><span class="gname">${esc(MODEL_LABEL[r.model] || r.model)}</span>
        <span class="gsum">${modelSummary(r.model)}</span></td></tr>`;
    lastModel = r.model;
    const detail = r.rounds.map(x => `<tr class="roundrow" data-for="${i}" hidden>
        <td colspan="3" class="rlab">Round ${x.round}</td>
        <td class="dom-start numcell num">${x.a4_ok}<span class="mut">/${r.n}</span></td>
        <td class="numcell num">${x.joint}<span class="mut">/${r.n}</span></td>
        <td class="numcell num over">${x.over}</td>
        <td class="numcell num under">${x.under}</td>
        <td class="dom-start numcell num">${x.runtime_pass}<span class="mut">/${r.n}</span></td>
        <td class="numcell num">${x.pass_but_a4_fail}</td></tr>`).join('');
    return head + `<tr class="runrow" data-run="${i}" tabindex="0" role="button" aria-expanded="false">
      <td class="armcell">${esc(ARM_LABEL[r.arm] || r.arm)}<span class="expand">View rounds \u2192</span></td>
      <td>${esc(r.split)}</td>
      <td class="numcell num mut">\u00d7${r.rounds.length}</td>
      <td class="dom-start scorecol">${scoreCell(r.a4all, r.n, r.rounds, 'a4_ok')}</td>
      <td class="scorecol">${scoreCell(r.decision, r.n, r.rounds, 'joint')}</td>
      <td class="numcell num over">${r.over.text}</td>
      <td class="numcell num under">${r.under.text}</td>
      <td class="dom-start numcell num">${r.passed.text}<span class="mut">/${r.n}</span></td>
      <td class="numcell"><span class="failtag num">${r.unsafe.text}</span></td></tr>` + detail;
  }).join('');

  const perf = `<div class="tablewrap"><table class="data perf">
    <thead>
      <tr class="domrow"><th colspan="3"></th>
        <th colspan="4" class="dom dom-start dom-a4">A4 evaluation<span class="domsub">frozen ground truth \u00b7 research only</span></th>
        <th colspan="2" class="dom dom-start dom-rt">Runtime policy \u00b7 ${esc(S.snap.runtime.default_profile)}<span class="domsub">deployable \u00b7 no ground truth</span></th></tr>
      <tr><th>Arm</th><th>Split</th><th class="numcell">Rounds</th>
        <th class="dom-start">A4 all-check pass<span class="thsub">C1\u2013C4 all passed</span></th>
        <th>Decision in-band<span class="thsub">verdict + severity (C2)</span></th>
        <th class="numcell">Over-triage</th><th class="numcell">Under-triage</th>
        <th class="dom-start numcell">Policy passed</th>
        <th class="numcell">Passed, A4 fail<span class="thsub">policy clean, A4 flags</span></th></tr>
    </thead><tbody>${perfRows}</tbody></table></div>`;

  const cap = (t) => String(t).charAt(0).toUpperCase() + String(t).slice(1);
  const pct1 = v => `${(100 * Number(v || 0)).toFixed(1)}%`;
  const ci = xs => `${pct1(xs?.[0])}–${pct1(xs?.[1])}`;
  const signed = v => `${Number(v) >= 0 ? '+' : ''}${Number(v).toFixed(2)}`;
  let depth = '';
  if (deep) {
    const main = deep.unit_summaries || [];
    const paired = deep.paired_heldout_round1 || {};
    const modelMeasures = main.map(row => {
      const rate = 100 * row.C2_joint_rate;
      const lo = 100 * row.C2_wilson_95[0], hi = 100 * row.C2_wilson_95[1];
      return `<div class="depthmodel">
        <div class="depthmodelhead"><b>${esc(MODEL_LABEL[row.model] || row.model)}</b>
          <span class="num"><strong>${pct1(row.C2_joint_rate)}</strong> · ${row.C2_joint_n}/${row.n}</span></div>
        <div class="ciscale" title="Wilson 95% CI ${esc(ci(row.C2_wilson_95))}">
          <span class="cirange" style="left:${lo}%;width:${Math.max(0, hi-lo)}%"></span>
          <i class="ciestimate" style="left:${rate}%"></i></div>
        <div class="cicap"><span>0%</span><b>95% CI ${esc(ci(row.C2_wilson_95))}</b><span>100%</span></div>
      </div>`;
    }).join('');
    const ordinalRows = main.map(row => {
      const values = Object.entries(row.fields).map(([field, value]) => ({
        field, value: Number(value.mean_signed_distance), absolute: Number(value.mean_absolute_distance)
      }));
      return `<div class="ordmodel"><b>${esc(MODEL_LABEL[row.model] || row.model)}</b>
        ${values.map(x => {
          const pos = Math.max(3, Math.min(97, 50 + 50 * x.value / 0.5));
          return `<div class="ordrow"><span>${esc(cap(x.field))}</span>
            <div class="ordtrack"><i class="ordzero"></i><i class="ordpoint" style="left:${pos}%"></i></div>
            <b class="num ${x.value < 0 ? 'ordunder' : x.value > 0 ? 'ordover' : ''}">${signed(x.value)}</b>
            <small class="mut num">|d| ${x.absolute.toFixed(2)}</small></div>`;
        }).join('')}</div>`;
    }).join('');
    const rd = Number(paired.paired_risk_difference_gemini_minus_claude || 0);
    const rdci = paired.paired_risk_difference_bootstrap_95 || [0, 0];
    depth = `<div class="depthpanel">
      <div class="depthlead">
        <div><span class="depthkicker">Held-out · A2 · round 1 · paired by case</span>
          <h3>No reliable model advantage</h3>
          <p>Gemini is ahead by one case, but the paired interval crosses zero widely.</p></div>
        <div class="effect"><span>Gemini − Claude</span><b class="num">${rd >= 0 ? '+' : ''}${(100*rd).toFixed(0)} pp</b>
          <small class="num">95% CI ${(100*rdci[0]).toFixed(0)} to +${(100*rdci[1]).toFixed(0)} pp · McNemar p=${Number(paired.mcnemar_exact_two_sided_p).toFixed(3)}</small></div>
      </div>
      <div class="depthmodels">${modelMeasures}</div>
      <div class="depthmeta"><span><b class="num">${deep.conformance.passed_n}/${deep.conformance.n}</b> validator conformance</span>
        <span><b>0</b> new model calls</span><span>secondary offline analysis</span></div>
    </div>
    <div class="ordinalcard"><div class="ordinalhead"><div><h3>Signed ordinal calibration distance</h3>
      <p>Zero is in band; left is under-triage and right is over-triage.</p></div><span class="viewtag">Error magnitude</span></div>
      <div class="ordaxis"><span>Under</span><i></i><span>Over</span></div>${ordinalRows}</div>`;
  }

  let replication = '';
  if (external) {
    const p = external.paired;
    const money = v => `$${Number(v || 0).toFixed(3)}`;
    const extModels = MODEL_ORDER.map(model => ({model, ...external.models[model]}));
    const modelBlocks = extModels.map(row => {
      const rate = 100 * row.a4_rate;
      const actual = row.cost.actual_usd;
      const costLine = actual === 0
        ? `Free-tier actual · ${money(row.cost.paid_list_equivalent_usd)} list-equivalent`
        : `${money(actual)} actual · standard realtime`;
      return `<div class="repmodel ${row.model.startsWith('claude') ? 'repclaude' : 'repgemini'}">
        <div class="repmodelhead"><b>${esc(MODEL_LABEL[row.model] || row.model)}</b>
          <span class="num">${row.tokens.input.toLocaleString()} in · ${row.tokens.output.toLocaleString()} out</span></div>
        <div class="repscore"><strong class="num">${row.a4_pass_n}/${row.n}</strong>
          <span class="num">${rate.toFixed(0)}%</span></div>
        <div class="repbar" aria-label="${esc(MODEL_LABEL[row.model] || row.model)} ${rate.toFixed(0)} percent A4 pass">
          <i style="width:${rate}%"></i></div>
        <div class="repci num">Wilson 95% CI ${esc(ci(row.a4_wilson_95))}</div>
        <div class="repchecks"><span>C2 failures <b class="num">${row.check_failure_counts.C2}</b></span>
          <span>C4 failures <b class="num">${row.check_failure_counts.C4}</b></span>
          <span>high-confidence errors <b class="num">${row.high_confidence_error_n}</b></span></div>
        <div class="repcost">${esc(costLine)}</div>
      </div>`;
    }).join('');

    const condOrder = ['strong', 'weak', 'missing', 'counter'];
    const conditionRows = condOrder.map(condition => {
      const g = external.models['gemini-2.5-flash'].conditions[condition];
      const c = external.models['claude-sonnet-4-6'].conditions[condition];
      const cell = (row, cls) => `<div class="repcell"><b class="num">${row.a4_pass_n}/${row.n}</b>
        <span class="repminibar ${cls}"><i style="width:${100*row.a4_rate}%"></i></span></div>`;
      return `<div class="repcondrow"><b>${esc(cap(condition))}</b>
        ${cell(g, 'repgemini')}${cell(c, 'repclaude')}</div>`;
    }).join('');

    const gem = external.models['gemini-2.5-flash'];
    const claude = external.models['claude-sonnet-4-6'];
    const corpusRow = (label, gPass, gN, cPass, cN, emphasis='') =>
      `<div class="repcorpusrow ${emphasis}"><span>${esc(label)}</span>
        <b class="num">${gPass}/${gN}</b><i>vs</i><b class="num">${cPass}/${cN}</b></div>`;

    replication = `<div class="reppanel">
      <div class="replead"><div><span class="depthkicker">Frozen A2 · one round · four cases per condition</span>
        <h3>Claude recovered five external-set errors with no paired regression</h3>
        <p>The advantage appears on the independently sourced replication set, not uniformly across corpora.</p></div>
        <div class="repeffect"><span>Claude − Gemini</span><b class="num">+${p.claude_minus_gemini_pp.toFixed(1)} pp</b>
          <small class="num">5 Claude-only · 0 Gemini-only · McNemar p=${Number(p.mcnemar_exact_two_sided_p).toFixed(3)}</small></div></div>
      <div class="repmodels">${modelBlocks}</div>
      <div class="repdetail">
        <div class="repconditions"><div class="repcondhead"><span>Evidence condition</span>
          <b>Gemini</b><b>Claude</b></div>${conditionRows}</div>
        <div class="repcorpus"><h4>Corpus dependence</h4>
          ${corpusRow('Canonical held-out', gem.canonical_heldout.a4_pass_n, gem.canonical_heldout.n,
            claude.canonical_heldout.a4_pass_n, claude.canonical_heldout.n)}
          ${corpusRow('External replication', gem.a4_pass_n, gem.n, claude.a4_pass_n, claude.n, 'active')}
          <div class="repcorpuslegend"><span>Gemini</span><i></i><span>Claude</span></div>
          <p>The ordering reverses across datasets, so this is evidence of a model-by-corpus interaction rather than universal model superiority.</p></div>
      </div>
      <div class="repmeta"><span><b class="num">${external.n}</b> independent cases</span>
        <span><b class="num">${external.model_calls}</b> model calls</span>
        <span><b class="num">${p.both_fail}</b> shared failures</span>
        <span>descriptive paired result · small n</span></div>
    </div>`;
  }

  const routing = Object.entries(d.routing).map(([split, profs]) => `
    <div class="dcard"><h3>Routing profiles — ${esc(split)} (A2, round 1, n=${Object.values(profs)[0]?.n ?? '?'})</h3>
      <div class="tablewrap"><table class="data"><thead><tr><th>Profile</th><th>Pass</th><th>Review</th><th>Block</th><th>Human review</th></tr></thead>
      <tbody>${Object.entries(profs).map(([n, v]) => `<tr><td class="mono">${esc(n)}</td>
        <td class="num" style="color:var(--good)">${v.pass}</td><td class="num" style="color:var(--mid)">${v.review}</td>
        <td class="num" style="color:var(--crit)">${v.block}</td>
        <td class="num"><b>${(v.human_review_rate*100).toFixed(0)}%</b></td></tr>`).join('')}
      </tbody></table></div></div>`).join('');

  const runtimeCI = deep ? `<div class="tablewrap runtimeci"><table class="data"><thead><tr>
      <th>Split</th><th>Profile</th><th>Calibration recall</th><th>Wilson 95% CI</th>
      <th>Human review</th><th>Wilson 95% CI</th><th>Unrouted errors</th></tr></thead><tbody>
    ${(deep.runtime_uncertainty || []).filter(x => ['consequence_gate','safety_first'].includes(x.profile))
      .map(x => `<tr><td>${esc(x.split)}</td><td class="mono">${esc(x.profile)}</td>
        <td class="num"><b>${x.recall_n}/${x.oracle_positive_n}</b> (${pct1(x.recall_rate)})</td>
        <td class="num">${esc(ci(x.recall_wilson_95))}</td>
        <td class="num"><b>${x.review_n}</b> (${pct1(x.review_rate)})</td>
        <td class="num">${esc(ci(x.review_wilson_95))}</td>
        <td class="num">${x.unrouted_error_n}</td></tr>`).join('')}
    </tbody></table><p class="cihint">Intervals show how uncertain these routing rates remain at n=21/20; they are not additional model runs.</p></div>` : '';

  // Calibration by evidence condition. Percentages lead because the four conditions have
  // different denominators; exact counts live in the tooltip. Colour follows SOC consequence:
  // under-triage (possible missed detection) reads as risk, over-triage as analyst load.
  const condRows = Object.entries(S.researchSnap.research.condition_policy).map(([c, p]) => {
    const rs = S.researchSnap.sweep.filter(r => r.condition === c
      && r.arm === 'A2_evidence_prompt' && r.round === 1 && r.research);
    const over = rs.filter(r => r.research.severity_direction === 'over').length;
    const under = rs.filter(r => r.research.severity_direction === 'under').length;
    const n = rs.length, inb = n - over - under, t = n || 1;
    const share = v => Math.round(100 * v / t);
    // Every segment carries its share; fitCondLabels() drops the ones that do not fit after
    // layout. A fixed percentage cut-off was wrong — 7% of a wide bar is 60px, plenty of room.
    const seg = (v, cls, label) => {
      if (!v) return '';
      const w = share(v);
      return `<span class="seg ${cls}" data-pct="${w}%" style="width:${100 * v / t}%"
        title="${esc(label)} · ${v} of ${n} (${w}%)">${w}%</span>`;
    };
    // Headline: the finding that matters for this condition.
    const lead = over >= inb ? {v: share(over), k: 'over-triage', cls: 'lead-over'}
                             : {v: share(inb), k: 'in-band', cls: 'lead-in'};
    return `<div class="condrow">
      <div class="condinfo">
        <div class="condname">${esc(cap(c))}</div>
        <div class="condband">${esc(cap(p.verdict))} · ${esc(p.severity.map(cap).join('\u2013'))}</div>
        <div class="condn num">n = ${n}</div>
      </div>
      <div class="condbar" role="img"
        aria-label="${esc(cap(c))}: ${share(over)}% over-triage, ${share(inb)}% in band, ${share(under)}% under-triage">
        ${seg(over, 's-over', 'over-triage')}${seg(inb, 's-in', 'in band')}${seg(under, 's-under', 'under-triage')}
        <span class="ref50" aria-hidden="true"></span>
      </div>
      <div class="condresult ${lead.cls}"><b class="num">${lead.v}%</b><span>${lead.k}</span></div>
    </div>`;
  }).join('');

  const cond = `<div class="condchart">${condRows}
    <div class="condlegend">
      <span><i class="sw s-over"></i>Over-triage</span>
      <span><i class="sw s-in"></i>In band</span>
      <span><i class="sw s-under"></i>Under-triage</span>
      <span class="mut">Expected values denote the admissible ground-truth decision band.</span>
    </div></div>
    <div class="insight">Over-triage was concentrated in non-decisive evidence conditions:
      <b>58%</b> of Weak cases, <b>67%</b> of Missing cases and <b>50%</b> of Counter cases
      exceeded the admissible decision band.</div>`;

  const deepStability = deep?.stability || [];
  const stab = deepStability.length ? `<div class="tablewrap"><table class="data stabilitytable"><thead><tr>
      <th>Model</th><th>Split</th><th>Verdict</th><th>Severity</th><th>Action</th><th>Full tuple</th><th>Changed cases</th></tr></thead><tbody>
    ${deepStability.map(s => { const a=s.all_three_rounds_agree, r=s.all_three_rounds_agree_rate;
      return `<tr><td>${esc(MODEL_LABEL[s.model] || s.model)}</td><td>${esc(s.split)}</td>
        <td class="num">${a.verdict}/${s.n}<span class="rate">${pct1(r.verdict)}</span></td>
        <td class="num">${a.severity}/${s.n}<span class="rate">${pct1(r.severity)}</span></td>
        <td class="num"><b>${a.action}/${s.n}</b><span class="rate">${pct1(r.action)}</span></td>
        <td class="num"><b>${a.tuple}/${s.n}</b><span class="rate">${pct1(r.tuple)}</span></td>
        <td class="num">${s.one_field_variation_n + s.multi_field_variation_n}</td></tr>`; }).join('')}
  </tbody></table></div>` : '';

  const cost = Object.entries(d.cost).map(([split, c]) => `
    <div class="dcard"><h3>Token usage &amp; cost — ${esc(split)}</h3>
      <div class="small">calls <b class="num">${c.total.calls}</b> · input
        <b class="num">${c.total.input_tokens.toLocaleString()}</b> · output
        <b class="num">${c.total.output_tokens.toLocaleString()}</b></div>
      <div class="small" style="margin-top:4px">incurred <b class="num">$${c.total.actual_cost_usd.toFixed(2)}</b>
        <span class="mut num">(list-equivalent $${c.total.paid_list_equivalent_usd.toFixed(2)})</span></div>
      <div class="mut small" style="margin-top:6px">Current append-only usage logs at snapshot build time.
        Runtime policy validation adds <b>0</b> tokens.</div>
      ${c.incomplete_tags.length ? `<div class="costwarn">Usage coverage incomplete: ${esc(c.incomplete_tags.join(', '))}</div>` : ''}</div>`).join('');

  const chapterDefs = [
    {id: 'performance', n: '01', verb: 'Measure', label: 'Canonical benchmark'},
    ...(external ? [{id: 'replication', n: '02', verb: 'Replicate', label: 'Independent cases'}] : []),
    {id: 'deployment', n: external ? '03' : '02', verb: 'Deploy', label: 'Ground-truth-free policy'},
    {id: 'operations', n: external ? '04' : '03', verb: 'Operationalize', label: 'Stability and cost'},
  ];
  if (!chapterDefs.some(x => x.id === S.dashboardView)) S.dashboardView = chapterDefs[0].id;
  const chapterNav = chapterDefs.map((x, i) => `<button class="dashstep"
      id="dashTab-${x.id}" role="tab" aria-controls="dashChapter-${x.id}"
      aria-selected="${S.dashboardView === x.id}" tabindex="${S.dashboardView === x.id ? '0' : '-1'}"
      data-dash-view="${x.id}">
      <span class="dashstepnum">${x.n}</span><span class="dashstepcopy"><b>${x.verb}</b><small>${x.label}</small></span>
      ${i < chapterDefs.length - 1 ? '<i aria-hidden="true">→</i>' : ''}</button>`).join('');
  const hidden = id => S.dashboardView === id ? '' : ' hidden';
  const moduleHead = (kicker, title, note='', tag='') => `<div class="dashmodulehead">
      <div><span>${esc(kicker)}</span><h3>${esc(title)}</h3>${note ? `<p>${esc(note)}</p>` : ''}</div>
      ${tag ? `<span class="viewtag">${esc(tag)}</span>` : ''}</div>`;

  $('dashBody').innerHTML = `
    <nav class="dashlogic" role="tablist" aria-label="Evaluation logic">${chapterNav}</nav>

    <section class="dashchapter" id="dashChapter-performance" role="tabpanel"
      aria-labelledby="dashTab-performance"${hidden('performance')}>
      <header class="chapterhead">
        <span class="chapterindex">01</span><div><span class="chapterkicker">Canonical benchmark</span>
          <h2>How well do the models calibrate evidence?</h2>
          <p>Measure end-to-end decision quality, then quantify uncertainty and error magnitude.</p></div>
        <span class="chaptertag">41 frozen cases</span>
      </header>
      ${moduleHead('Primary outcome', 'Model performance', 'A1 and A2 across development and held-out splits')}
      ${perf}
      <div class="footnote"><b>A4 all-check pass</b> requires C1–C4 together; <b>Decision in-band</b>
        is C2 alone. <b>Passed, A4 fail</b> exposes the limit of a ground-truth-free runtime policy.
        <details class="method"><summary>Read the measurement notes</summary>
          <p>The runtime policy reads only the alert package, model output and a generic policy. It can
          check structural integrity, evidence references, internal consistency and high-consequence
          actions, but it cannot determine factual correctness without a reference standard.</p>
          <p>Rounds repeat the same input. A range means rounds disagreed; the solid bar is the value
          reached in every round and the lighter segment is the spread. Open a row for exact figures.</p>
          <p>Over- and under-triage mean severity fell outside the evidence-supported band. Under-triage
          is red because a missed detection carries greater operational risk than analyst over-escalation.</p>
        </details></div>
      ${moduleHead('Statistical depth', 'Uncertainty and error magnitude',
        'Paired effects, confidence intervals and ordinal distance', 'Zero new calls')}
      ${depth}
    </section>

    ${external ? `<section class="dashchapter" id="dashChapter-replication" role="tabpanel"
      aria-labelledby="dashTab-replication"${hidden('replication')}>
      <header class="chapterhead">
        <span class="chapterindex">02</span><div><span class="chapterkicker">Independent replication</span>
          <h2>Does performance generalize beyond the canonical corpus?</h2>
          <p>Repeat the frozen A2 comparison on independently sourced, balanced held-out cases.</p></div>
        <span class="chaptertag">16 new cases</span>
      </header>
      ${moduleHead('External validity', 'Cross-corpus replication',
        'Four cases per evidence condition', 'Frozen one-round comparison')}
      ${replication}
    </section>` : ''}

    <section class="dashchapter" id="dashChapter-deployment" role="tabpanel"
      aria-labelledby="dashTab-deployment"${hidden('deployment')}>
      <header class="chapterhead">
        <span class="chapterindex">${external ? '03' : '02'}</span><div><span class="chapterkicker">Deployment boundary</span>
          <h2>What can be checked without ground truth?</h2>
          <p>Compare deterministic routing coverage with the semantic failures found by offline A4.</p></div>
        <span class="chaptertag">0 runtime tokens</span>
      </header>
      ${moduleHead('Policy layer', 'Runtime routing',
        'Pass, review and block outcomes under each deployment profile')}
      <div class="dgrid">${routing}</div>${runtimeCI}
      ${moduleHead('Failure structure', 'Calibration by evidence condition',
        'Pooled A2 round 1 results across Gemini and Claude', 'Descriptive view')}
      ${cond}
    </section>

    <section class="dashchapter" id="dashChapter-operations" role="tabpanel"
      aria-labelledby="dashTab-operations"${hidden('operations')}>
      <header class="chapterhead">
        <span class="chapterindex">${external ? '04' : '03'}</span><div><span class="chapterkicker">Operational evidence</span>
          <h2>Are the results stable and affordable?</h2>
          <p>Separate decision consistency from the token and monetary cost of producing it.</p></div>
        <span class="chaptertag">Repeated runs</span>
      </header>
      ${moduleHead('Reliability', 'Stability across repeated rounds',
        'Agreement by output field and complete decision tuple')}
      ${stab}
      ${moduleHead('Resource use', 'Token usage and cost',
        'Recorded provider usage; runtime validation itself adds no model calls')}
      <div class="dgrid">${cost}</div>
    </section>`;

  // Aggregate rows expand to their per-round figures (click or Enter/Space).
  const toggleRun = (row) => {
    const open = row.getAttribute('aria-expanded') === 'true';
    row.setAttribute('aria-expanded', String(!open));
    $('dashBody').querySelectorAll(`.roundrow[data-for="${row.dataset.run}"]`)
      .forEach(r => { r.hidden = open; });
  };
  $('dashBody').querySelectorAll('.runrow').forEach(row => {
    row.addEventListener('click', () => toggleRun(row));
    row.addEventListener('keydown', e => {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggleRun(row); }
    });
  });
  const activateDashboardView = (view, resetScroll=false) => {
    if (!chapterDefs.some(x => x.id === view)) view = chapterDefs[0].id;
    S.dashboardView = view;
    $('dashBody').querySelectorAll('.dashstep').forEach(button => {
      const active = button.dataset.dashView === view;
      button.setAttribute('aria-selected', String(active));
      button.tabIndex = active ? 0 : -1;
    });
    $('dashBody').querySelectorAll('.dashchapter').forEach(chapter => {
      chapter.hidden = chapter.id !== `dashChapter-${view}`;
    });
    if (view === 'deployment') fitCondLabels();
    if (resetScroll) $('dashSheet').scrollTo({top: 0, behavior: 'smooth'});
  };
  const dashButtons = [...$('dashBody').querySelectorAll('.dashstep')];
  dashButtons.forEach((button, index) => {
    button.addEventListener('click', () => activateDashboardView(button.dataset.dashView, true));
    button.addEventListener('keydown', e => {
      let next = null;
      if (e.key === 'ArrowRight') next = (index + 1) % dashButtons.length;
      if (e.key === 'ArrowLeft') next = (index - 1 + dashButtons.length) % dashButtons.length;
      if (e.key === 'Home') next = 0;
      if (e.key === 'End') next = dashButtons.length - 1;
      if (next === null) return;
      e.preventDefault();
      dashButtons[next].focus();
      activateDashboardView(dashButtons[next].dataset.dashView, true);
    });
  });
  watchCondChart($('dashBody').querySelector('.condchart'));
  activateDashboardView(S.dashboardView);
}

// A segment shows its percentage whenever the text actually fits; only genuinely too-narrow
// slivers fall back to the tooltip. Whether it fits is width-dependent, so it is measured
// rather than guessed from a percentage cut-off.
function fitCondLabels() {
  document.querySelectorAll('.condbar .seg[data-pct]').forEach(s => {
    s.textContent = s.dataset.pct;
    if (s.scrollWidth > s.clientWidth) s.textContent = '';
  });
}

// Re-fit on live resize. Both hooks are registered on purpose: the ResizeObserver also catches
// the sheet being re-laid-out without the window changing, while the window listener covers
// engines that deliver resize events but not observer callbacks. Setting textContent does not
// alter the observed box, so neither path can feed back on itself. Correctness of the first
// paint does not depend on either — renderDashboard() calls fitCondLabels() directly.
let condObserver = null;
function watchCondChart(chart) {
  if (!chart || !window.ResizeObserver) return;
  if (condObserver) condObserver.disconnect();
  condObserver = new ResizeObserver(fitCondLabels);
  condObserver.observe(chart);
}
window.addEventListener('resize', () => {
  if (document.querySelector('.condbar')) fitCondLabels();
});

/* ---------------- guided present mode ----------------
   Five steps over the real interface — each one performs the action a presenter would perform by
   hand, so nothing here is a mock-up. Step 4 runs the actual validator and step 5 opens the real
   A4 evaluation. */
const PRESENT_STEPS = [
  {n: 'Case', focus: 'leftPanel',
   say: 'One frozen case from the 41-case benchmark. The package is neutral — no label, no hint.',
   go: async () => { switchTab('workbench'); await selectCase('ACCT-001'); }},
  {n: 'Evidence', focus: 'evidencePane',
   say: 'The triggering alert and its contextual evidence, grouped by meaning rather than dumped as JSON.',
   go: async () => { switchTab('workbench'); $('evidencePane').scrollTop = 0; }},
  {n: 'LLM decision', focus: 'outputPane',
   say: 'Gemini returns malicious / high / escalate at 0.9 confidence — complete, well-formed and confident.',
   go: async () => { switchTab('workbench'); showTriageView(); }},
  {n: 'Runtime validation', focus: 'rightPanel',
   say: 'The deployable, ground-truth-free policy runs. It passes: nothing machine-checkable is wrong.',
   go: async () => { switchTab('workbench'); if (!S.runtime) await runValidation();
     showRuntimeDetail(); }},
  {n: 'A4 evaluation', focus: 'researchSheet',
   say: 'With frozen ground truth, A4 shows the same output over-triaged on verdict, severity and action. That gap is the finding.',
   go: async () => { await switchTab('research'); }},
];
let presentIx = -1;

function presentRender() {
  $('presentSteps').innerHTML = PRESENT_STEPS.map((s, i) =>
    `<li class="pstep${i === presentIx ? ' now' : ''}${i < presentIx ? ' done' : ''}">
      <span class="pnum">${i + 1}</span>${esc(s.n)}</li>`).join('');
  const s = PRESENT_STEPS[presentIx];
  $('presentTitle').textContent = s ? `${presentIx + 1}. ${s.n}` : '';
  $('presentSay').textContent = s ? s.say : '';
  $('presentPrev').disabled = presentIx <= 0;
  $('presentNext').disabled = presentIx >= PRESENT_STEPS.length - 1;
  document.querySelectorAll('.spotlight').forEach(n => n.classList.remove('spotlight'));
  if (s) { const el = $(s.focus); if (el) el.classList.add('spotlight'); }
}

async function presentGo(ix) {
  if (ix < 0 || ix >= PRESENT_STEPS.length) return;
  presentIx = ix;
  presentRender();
  try { await PRESENT_STEPS[ix].go(); } catch (e) { toast(`Step failed: ${e.message}`); }
  presentRender();
}

function presentSet(on) {
  document.body.classList.toggle('presenting', on);
  $('presentBar').hidden = !on;
  $('presentBtn').setAttribute('aria-pressed', String(on));
  if (on) presentGo(0);
  else {
    presentIx = -1;
    document.querySelectorAll('.spotlight').forEach(n => n.classList.remove('spotlight'));
  }
}

/* ---------------- presets ---------------- */
function buildPresets() {
  $('presetSel').innerHTML = '<option value="">Pick a scenario</option>' +
    S.researchSnap.presets.map(p => `<option value="${esc(p.key)}">${esc(p.title)}</option>`).join('');
}

function clearPresetContext() {
  S.activePreset = null;
  $('scenarioBar').hidden = true;
  $('presetSel').value = '';
}

function showPresetContext(p) {
  S.activePreset = p;
  $('scenarioTitle').textContent = p.title;
  $('scenarioTeaching').textContent = p.teaching;
  $('scenarioBar').hidden = false;
}

async function applyPreset(key) {
  await ensureResearchSnapshot();
  const p = S.researchSnap.presets.find(x => x.key === key); if (!p) return;
  $('presetSel').value = key;
  S.model = p.model; S.arm = p.arm; S.round = p.round;
  S.filters.tier.clear(); S.filters.split.clear(); S.filters.condition.clear();
  document.querySelectorAll('.fchip').forEach(b => b.setAttribute('aria-pressed', 'false'));
  S.search = ''; $('caseSearch').value = '';
  await switchTab('workbench');
  await selectCase(p.case_id, true, true);
  showPresetContext(p);
}
