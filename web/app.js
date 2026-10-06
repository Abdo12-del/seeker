/* Seeker console.  No build step, no frameworks, no CDN: it has to work on a
   laptop with no internet as often as not. */
const STR = {
  ar: {
    tab_campaigns: 'الحملات', tab_live: 'الأحداث المباشرة', tab_audit: 'تدقيق الصفحات',
    tab_integrity: 'النزاهة والخصوصية', lang: 'EN', lock: 'قفل',
    new_campaign: 'حملة جديدة', name: 'اسم الحملة', scenario: 'السيناريو',
    authorizer: 'المُصرّح (اسم شخص)', scope: 'النطاق (من المستهدف)',
    group: 'المجموعة', links: 'عدد الروابط', days: 'مدة الصلاحية (أيام)',
    create: 'إنشاء الحملة',
    authz_note: 'لا تعمل أي حملة بدون مُصرّح ونطاق واضحَين. يُوقّع السجل ويُحفظ كدليل، '
      + 'وترفض الصفحات العمل عند انتهاء المدة أو إيقاف الحملة.',
    authorised: 'مصرّح', stopped: 'موقوف', expired: 'منتهي',
    links_label: 'روابط', export_csv: 'CSV', export_json: 'JSON',
    export_kml: 'KML', export_html: 'تقرير HTML', stop: 'إيقاف', activate: 'تشغيل',
    live_title: 'الأحداث المباشرة', no_events: 'لا أحداث بعد — افتح أحد الروابط.',
    audit_title: 'تدقيق صفحة', audit_hint: 'الصق HTML أو أدخل رابطًا. '
      + 'التحليل يجري محليًا أو بجلب مباشر للصفحة، ولا يُرسل أي شيء لجهة ثالثة.',
    audit_btn: 'حلّل', audit_history: 'عمليات تدقيق سابقة',
    integrity_title: 'سجل النزاهة', groups_title: 'حسب المجموعة',
    privacy_title: 'سياسة تقليل البيانات',
    events: 'أحداث', intact: 'السلسلة سليمة', broken: 'السلسلة مكسورة',
    consent_records: 'سجلات الموافقة', valid: 'التواقيع صحيحة', invalid: 'تواقيع غير صحيحة',
    group_col: 'المجموعة', opened_col: 'فتح', shared_col: 'شارك', reported_col: 'أبلغ',
    share_col: 'نسبة المشاركة', report_col: 'نسبة الإبلاغ',
    precision: 'دقة التخزين', retention: 'مدة الاحتفاظ', ip_recon: 'تحقّق IP خارجي',
    on: 'مفعل', off: 'معطل', token_bad: 'الرمز غير صحيح',
    audit_placeholder: 'الصق HTML الصفحة هنا، أو استخدم حقل الرابط بالأسفل.',
    verdict: 'النتيجة', score: 'الدرجة', recommendations: 'التوصيات',
    copy_link: 'نسخ الرابط', copied: 'تم النسخ',
    total_links: 'روابط مُصدَرة', total_opened: 'فتح', total_shared: 'شارك الموقع',
    total_declined: 'رفض', total_reported: 'أبلغ', susceptibility: 'القابلية',
    open_rate: 'نسبة الفتح', confirm_purge: 'حذف الحملة وكل بياناتها؟',
  },
  en: {
    tab_campaigns: 'Campaigns', tab_live: 'Live events', tab_audit: 'Page audit',
    tab_integrity: 'Integrity', lang: 'ع', lock: 'Lock',
    new_campaign: 'New campaign', name: 'Campaign name', scenario: 'Scenario',
    authorizer: 'Authorizer (a named person)', scope: 'Scope (who may be targeted)',
    group: 'Group', links: 'Links', days: 'Valid for (days)',
    create: 'Create campaign',
    authz_note: 'No campaign runs without a named authorizer and a scope. The record is '
      + 'signed and kept as evidence; pages stop serving when the window closes or the campaign is stopped.',
    authorised: 'authorised', stopped: 'stopped', expired: 'expired',
    links_label: 'links', export_csv: 'CSV', export_json: 'JSON',
    export_kml: 'KML', export_html: 'HTML report', stop: 'Stop', activate: 'Activate',
    live_title: 'Live events', no_events: 'No events yet — open one of the links.',
    audit_title: 'Page audit', audit_hint: 'Paste HTML or enter a URL. Analysis runs locally; '
      + 'nothing is forwarded to a third party.',
    audit_btn: 'Analyse', audit_history: 'Previous audits',
    integrity_title: 'Audit log integrity', groups_title: 'By group',
    privacy_title: 'Data-minimisation policy',
    events: 'events', intact: 'chain intact', broken: 'BROKEN CHAIN',
    consent_records: 'consent records', valid: 'signatures valid', invalid: 'invalid signatures',
    group_col: 'Group', opened_col: 'Opened', shared_col: 'Shared', reported_col: 'Reported',
    share_col: 'Share rate', report_col: 'Report rate',
    precision: 'Stored precision', retention: 'Retention', ip_recon: 'External IP lookup',
    on: 'on', off: 'off', token_bad: 'Token rejected',
    audit_placeholder: 'Paste the page HTML here, or use the URL field below.',
    verdict: 'Verdict', score: 'Score', recommendations: 'Recommendations',
    copy_link: 'Copy link', copied: 'Copied',
    total_links: 'Links issued', total_opened: 'Opened', total_shared: 'Shared location',
    total_declined: 'Declined', total_reported: 'Reported', susceptibility: 'Susceptibility',
    open_rate: 'Open rate', confirm_purge: 'Delete this campaign and all its data?',
    no_campaigns: 'No campaigns yet — create one above.',
    share_rate: 'Share rate',
  },
};

let LANG = localStorage.getItem('seeker_lang') || 'ar';
let TOKEN = localStorage.getItem('seeker_token') || '';
let STATE = {};
let STREAM = null;

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));
const L = (key) => (STR[LANG] && STR[LANG][key]) || STR.en[key] || key;
const esc = (v) => String(v == null ? '' : v).replace(/[&<>"']/g,
  (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function api(path, opts = {}) {
  const headers = Object.assign({ Authorization: 'Bearer ' + TOKEN }, opts.headers || {});
  if (opts.json) headers['Content-Type'] = 'application/json';
  return fetch(path, Object.assign({}, opts, { headers })).then((res) => {
    if (res.status === 401) { lock(); throw new Error('unauthorized'); }
    return res.json().catch(() => ({}));
  });
}

/* ---------------- shell ---------------- */
function applyLang() {
  document.documentElement.lang = LANG;
  document.documentElement.dir = LANG === 'ar' ? 'rtl' : 'ltr';
  const map = [
    ['[data-tab="campaigns"]', 'tab_campaigns'], ['[data-tab="live"]', 'tab_live'],
    ['[data-tab="audit"]', 'tab_audit'], ['[data-tab="integrity"]', 'tab_integrity'],
    ['#newTitle', 'new_campaign'], ['#createBtn', 'create'], ['#liveTitle', 'live_title'],
    ['#auditTitle', 'audit_title'], ['#auditBtn', 'audit_btn'],
    ['#integrityTitle', 'integrity_title'], ['#groupsTitle', 'groups_title'],
    ['#privacyTitle', 'privacy_title'], ['#auditHistory', 'audit_history'],
  ];
  map.forEach(([sel, key]) => { const el = $(sel); if (el) el.textContent = L(key); });
  $('#langBtn').textContent = L('lang');
  $('#lockBtn').textContent = L('lock');
  $('#authzNote').textContent = L('authz_note');
  $('#auditHint').textContent = L('audit_hint');
  $('#auditInput').placeholder = L('audit_placeholder');
  const labels = [
    ['name'], ['scenario'], ['authorizer'], ['scope'], ['group'], ['links'], ['days'],
  ];
  const inputs = $$('#campaignForm label .lbl');
  labels.forEach((pair, i) => { if (inputs[i]) inputs[i].textContent = L(pair[0]); });
  render(STATE);
}

function lock() {
  TOKEN = '';
  localStorage.removeItem('seeker_token');
  if (STREAM) { STREAM.close(); STREAM = null; }
  document.body.classList.add('locked');
  $('#app').hidden = true;
  $('#gate').hidden = false;
}

function unlock(token) {
  TOKEN = token;
  localStorage.setItem('seeker_token', token);
  document.body.classList.remove('locked');
  $('#gate').hidden = true;
  $('#app').hidden = false;
  refresh();
  startStream();
}

/* ---------------- rendering ---------------- */
function stat(value, label) {
  return `<div class="stat"><b>${esc(value)}</b><span>${esc(label)}</span></div>`;
}

function render(state) {
  STATE = state || STATE;
  if (!STATE || !STATE.totals) return;
  const t = STATE.totals;
  $('#stats').innerHTML = [
    stat(t.links_issued, L('total_links')), stat(t.opened, L('total_opened')),
    stat(t.shared_location, L('total_shared')), stat(t.consent_denied, L('total_declined')),
    stat(t.reported, L('total_reported')), stat(t.susceptibility, L('susceptibility')),
  ].join('');
  $('#orgLabel').textContent = STATE.org || '';
  renderScenarios();
  renderCampaigns();
  renderAudit();
  renderIntegrity();
}

function renderScenarios() {
  const sel = $('#scenarioSelect');
  if (!sel || !STATE.scenarios) return;
  const current = sel.value;
  sel.innerHTML = (STATE.scenarios || []).map((s) =>
    `<option value="${esc(s.id)}">${esc(s.name || s.id)}</option>`).join('');
  if (current) sel.value = current;
}

function renderCampaigns() {
  const box = $('#campaignList');
  if (!box) return;
  const list = STATE.campaigns || [];
  if (!list.length) {
    box.innerHTML = `<div class="card"><div class="empty">${esc(L('no_campaigns'))}</div></div>`;
    return;
  }
  box.innerHTML = list.map((c) => {
    const f = c.funnel || {};
    const pill = c.authorized
      ? `<span class="pill ok">${esc(L('authorised'))}</span>`
      : `<span class="pill bad">${esc(c.authorization_note || L('broken'))}</span>`;
    const links = ((STATE.linkMap && STATE.linkMap[c.id]) || []).map(
      (u) => (u.indexOf('http') === 0 ? u : window.location.origin + u));
    return `<div class="card">
      <h4>${esc(c.name)} <span class="pill ${c.status === 'active' ? 'ok' : 'warn'}">${esc(c.status)}</span> ${pill}</h4>
      <div class="meta">${esc(c.id)} · ${esc(c.scenario)} · ${esc(c.authorizer || '')} · ${esc(c.scope || '')} · ${esc((c.expires_at || '').slice(0, 10))}</div>
      <div class="funnel">
        <span class="chip">${esc(L('links_label'))} <b>${esc(c.links)}</b></span>
        <span class="chip">${esc(L('total_opened'))} <b>${esc(f.opened || 0)}</b></span>
        <span class="chip">${esc(L('total_shared'))} <b>${esc(f.shared_location || 0)}</b></span>
        <span class="chip">${esc(L('total_declined'))} <b>${esc(f.consent_denied || 0)}</b></span>
        <span class="chip">${esc(L('total_reported'))} <b>${esc(f.reported || 0)}</b></span>
        <span class="chip">${esc(L('open_rate'))} <b>${esc(f.open_rate || 0)}%</b></span>
        <span class="chip">${esc(L('share_rate')) || 'share'} <b>${esc(f.share_rate || 0)}%</b></span>
      </div>
      ${links.length ? `<div class="meta" style="margin-top:10px;direction:ltr;text-align:left">${links
        .map((u) => `<div>${esc(u)}</div>`).join('')}</div>` : ''}
      <div class="tools">
        <button class="ghost small" data-act="links" data-id="${esc(c.id)}">${esc(L('links_label'))}</button>
        <button class="ghost small" data-act="csv" data-id="${esc(c.id)}">${esc(L('export_csv'))}</button>
        <button class="ghost small" data-act="json" data-id="${esc(c.id)}">${esc(L('export_json'))}</button>
        <button class="ghost small" data-act="kml" data-id="${esc(c.id)}">${esc(L('export_kml'))}</button>
        <button class="ghost small" data-act="html" data-id="${esc(c.id)}">${esc(L('export_html'))}</button>
        <button class="ghost small" data-act="toggle" data-id="${esc(c.id)}">${esc(c.status === 'active' ? L('stop') : L('activate'))}</button>
      </div>
    </div>`;
  }).join('');
}

function renderAudit() {
  const box = $('#auditList');
  if (!box || !STATE.audits) return;
  box.innerHTML = STATE.audits.length ? STATE.audits.map((a) => `
    <div class="ev">
      <span class="ts">${esc((a.ts || '').slice(11, 19))}</span>
      <span class="ty">${esc(a.verdict)}</span>
      <span class="pl">${esc(a.score)}/100 · ${esc(a.target || '')}</span>
    </div>`).join('') : `<div class="empty">${esc(L('no_events'))}</div>`;
}

function renderIntegrity() {
  if (!STATE.chain && !STATE.groups) return;
  const chain = STATE.chain || {};
  const consent = STATE.consent || {};
  $('#integrityBox').innerHTML = `
    <div class="ev"><span class="ty">${esc(L('events'))}</span>
      <span class="pl">${esc(chain.events || 0)} ·
      <b class="${chain.ok ? 'ty-report' : 'ty-location'}">${esc(chain.ok ? L('intact') : L('broken'))}</b></span></div>
    <div class="ev"><span class="ty">${esc(L('consent_records'))}</span>
      <span class="pl">${esc(consent.records || 0)} ·
      <b class="${consent.ok ? 'ty-report' : 'ty-location'}">${esc(consent.ok ? L('valid') : L('invalid'))}</b></span></div>`;
  const groups = STATE.groups || [];
  $('#groupsBox').innerHTML = groups.length ? `<table>
    <thead><tr><th>${esc(L('group_col'))}</th><th>${esc(L('opened_col'))}</th>
    <th>${esc(L('shared_col'))}</th><th>${esc(L('reported_col'))}</th>
    <th>${esc(L('share_col'))}</th><th>${esc(L('report_col'))}</th></tr></thead>
    <tbody>${groups.map((g) => `<tr><td>${esc(g.group)}</td><td>${esc(g.opened)}</td>
      <td>${esc(g.shared)}</td><td>${esc(g.reported)}</td>
      <td>${esc(g.share_rate)}%</td><td>${esc(g.report_rate)}%</td></tr>`).join('')}</tbody>
  </table>` : `<div class="empty">${esc(L('no_events'))}</div>`;
  $('#privacyBox').innerHTML = `
    <div class="ev"><span class="ty">${esc(L('precision'))}</span><span class="pl">${esc(STATE.precision)}</span></div>
    <div class="ev"><span class="ty">${esc(L('retention'))}</span><span class="pl">${esc(STATE.retention_days)} ${esc('days')}</span></div>
    <div class="ev"><span class="ty">${esc('auth gate')}</span><span class="pl">${esc(STATE.require_authorization ? L('on') : L('off'))}</span></div>`;
}

function pushEvent(ev) {
  const feed = $('#liveFeed');
  if (!feed) return;
  const empty = feed.querySelector('.empty');
  if (empty) empty.remove();
  const payload = typeof ev.payload === 'string' ? ev.payload : JSON.stringify(ev.payload || {});
  const row = document.createElement('div');
  row.className = 'ev';
  row.innerHTML = `<span class="ts">${esc((ev.ts || '').slice(11, 19))}</span>
    <span class="ty ty-${esc(ev.type)}">${esc(ev.type)}</span>
    <span class="pl">${esc(ev.rid || '')} ${esc(payload.slice(0, 160))}</span>`;
  feed.prepend(row);
  while (feed.children.length > 120) feed.lastChild.remove();
}

/* ---------------- data ---------------- */
async function refresh() {
  try {
    const state = await api('/api/state');
    if (!state.ok) return;
    const chain = await api('/api/chain');
    state.chain = chain.events;
    state.consent = chain.consent;
    render(state);
    if (!$('#liveFeed').children.length) {
      const evs = await api('/api/events?limit=40');
      (evs.events || []).slice().reverse().forEach(pushEvent);
    }
  } catch (err) {
    /* offline - keep last state */
  }
}

function startStream() {
  if (STREAM) STREAM.close();
  STREAM = new EventSource('/api/stream?token=' + encodeURIComponent(TOKEN));
  STREAM.onmessage = (msg) => {
    try {
      const data = JSON.parse(msg.data);
      if (data.kind === 'event') { pushEvent(data.event); refreshSoon(); }
    } catch (e) { /* ignore */ }
  };
}

let soonTimer = null;
function refreshSoon() {
  clearTimeout(soonTimer);
  soonTimer = setTimeout(refresh, 900);
}

/* ---------------- events ---------------- */
$('#gateForm').addEventListener('submit', (e) => {
  e.preventDefault();
  const token = $('#gateToken').value.trim();
  fetch('/api/state', { headers: { Authorization: 'Bearer ' + token } })
    .then((res) => {
      if (!res.ok) throw new Error('bad');
      $('#gateError').textContent = '';
      unlock(token);
    })
    .catch(() => { $('#gateError').textContent = L('token_bad'); });
});

$('#lockBtn').addEventListener('click', lock);
$('#langBtn').addEventListener('click', () => {
  LANG = LANG === 'ar' ? 'en' : 'ar';
  localStorage.setItem('seeker_lang', LANG);
  applyLang();
});

$$('.tab').forEach((btn) => btn.addEventListener('click', () => {
  $$('.tab').forEach((b) => b.classList.remove('active'));
  btn.classList.add('active');
  $$('.tab-body').forEach((body) => { body.hidden = true; });
  const body = $('#tab-' + btn.dataset.tab);
  if (body) body.hidden = false;
  if (btn.dataset.tab === 'integrity') refresh();
}));

$('#campaignForm').addEventListener('submit', (e) => {
  e.preventDefault();
  const form = new FormData(e.target);
  const body = {};
  form.forEach((v, k) => { body[k] = (k === 'links' || k === 'duration_days') ? Number(v) : v; });
  api('/api/campaigns', { method: 'POST', json: 1, body: JSON.stringify(body) })
    .then((res) => {
      if (res.error) { alert(res.error); return; }
      STATE.linkMap = STATE.linkMap || {};
      STATE.linkMap[res.id] = res.links;
      e.target.reset();
      return refresh();
    })
    .then(() => {
      const id = Object.keys(STATE.linkMap || {}).pop();
      if (id && STATE.linkMap[id]) renderCampaigns();
    });
});

$('#campaignList').addEventListener('click', (e) => {
  const btn = e.target.closest('button[data-act]');
  if (!btn) return;
  const id = btn.dataset.id;
  const act = btn.dataset.act;
  if (act === 'csv' || act === 'json' || act === 'kml' || act === 'html') {
    window.location = `/api/campaigns/${id}/export?format=${act}&token=${encodeURIComponent(TOKEN)}`;
  } else if (act === 'toggle') {
    const campaign = (STATE.campaigns || []).find((c) => c.id === id);
    const status = campaign && campaign.status === 'active' ? 'stopped' : 'active';
    api(`/api/campaigns/${id}/status`, {
      method: 'POST', json: 1, body: JSON.stringify({ status }),
    }).then(refresh);
  } else if (act === 'links') {
    api(`/api/campaigns/${id}/links`)
      .then((res) => {
        STATE.linkMap = STATE.linkMap || {};
        STATE.linkMap[id] = res.links || [];
        renderCampaigns();
      })
      .catch(() => {});
  }
});

$('#auditBtn').addEventListener('click', () => {
  const html = $('#auditInput').value;
  const url = $('#auditUrl').value.trim();
  if (!html && !url) return;
  const btn = $('#auditBtn');
  btn.disabled = true;
  api('/api/analyze', {
    method: 'POST', json: 1,
    body: JSON.stringify(url ? { url } : { html }),
  }).then((res) => {
    btn.disabled = false;
    const box = $('#auditResult');
    if (res.error) { box.innerHTML = `<p class="error">${esc(res.error)}</p>`; return; }
    const r = res.result;
    box.innerHTML = `
      <div class="verdict"><b class="ty-${r.verdict === 'deceptive' ? 'location' : r.verdict === 'suspicious' ? 'reveal' : 'report'}">${esc(r.verdict.toUpperCase())}</b>
      <span class="muted">${esc(L('score'))} ${esc(r.score)}/100 · ${esc(r.size)} bytes</span></div>
      <div class="findings">${r.findings.map((f) => `
        <div class="finding">
          <div class="head"><b>${esc(f.title)}</b><span class="sev sev-${esc(f.severity)}">${esc(f.severity)} +${esc(f.weight)}</span></div>
          <div class="muted">${esc(f.detail)}</div>
          ${f.evidence ? `<div class="ev">${esc(f.evidence.slice(0, 300))}</div>` : ''}
        </div>`).join('')}</div>
      <h3>${esc(L('recommendations'))}</h3>
      <ul>${r.recommendations.map((x) => `<li>${esc(x)}</li>`).join('')}</ul>`;
    return refresh();
  }).catch(() => { btn.disabled = false; });
});

/* boot */
applyLang();
if (TOKEN) {
  fetch('/api/state', { headers: { Authorization: 'Bearer ' + TOKEN } })
    .then((res) => { if (res.ok) unlock(TOKEN); else lock(); })
    .catch(lock);
}
setInterval(() => { if (TOKEN) refresh(); }, 15000);
