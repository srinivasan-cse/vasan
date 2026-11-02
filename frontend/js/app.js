/* ZTACS front-end – vanilla JS, no build step */
const $ = (s, r = document) => r.querySelector(s), $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmtT = t => t ? new Date(t * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '-';
const fmtD = t => t ? new Date(t * 1000).toLocaleString([], { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' }) : '-';
const S = { token: null, user: null, policies: [], logs: [], timers: null, cfg: { idle: 180, heartbeat: 45 }, mfa: null, lastThr: 0.3, view: 'overview', timers_: [], heroTrust: 0.82, deviceDirectory: null, deviceDirectoryStack: [], deviceEntries: new Map(), deviceEditingName: null, devicePreviewUrl: null };
try { S.token = sessionStorage.getItem('ztacs_token'); } catch (e) { }

/* ---------- helpers ---------- */
function toast(msg, kind = '') {
  const t = document.createElement('div'); t.className = 'toast ' + kind; t.textContent = msg; $('#toasts').append(t);
  setTimeout(() => { t.classList.add('out'); setTimeout(() => t.remove(), 300); }, 3800);
}
async function api(path, method = 'GET', body) {
  const h = { 'Content-Type': 'application/json' }; if (S.token) h.Authorization = 'Bearer ' + S.token;
  try {
    const r = await fetch('/api/' + path, { method, headers: h, body: body ? JSON.stringify(body) : undefined });
    const data = await r.json().catch(() => ({}));
    if (r.status === 401 && data.forced) { forceLogout(data.reason); }
    return { ok: r.ok, status: r.status, data };
  } catch (e) { toast('Cannot reach the server. Access stays denied until it is back.', 'err'); return { ok: false, data: { error: 'offline' } }; }
}
document.addEventListener('click', e => {      // button ripple
  const b = e.target.closest('.btn'); if (!b) return;
  const r = b.getBoundingClientRect(), d = Math.max(r.width, r.height), s = document.createElement('span');
  s.className = 'rip'; s.style.cssText = `width:${d}px;height:${d}px;left:${e.clientX - r.left - d / 2}px;top:${e.clientY - r.top - d / 2}px`;
  b.append(s); setTimeout(() => s.remove(), 600);
});

/* ---------- trust dial ---------- */
function makeDial(el, opts = {}) {
  const L = Math.PI * 120;
  el.innerHTML = `<svg viewBox="0 0 300 175" role="img" aria-label="Trust dial">
    <path class="track" d="M30 150A120 120 0 0 1 270 150"/>
    <path class="fill" d="M30 150A120 120 0 0 1 270 150" stroke-dasharray="${L}" stroke-dashoffset="${L}"/>
    <line class="notch" x1="150" y1="14" x2="150" y2="44"/>
    <line class="needle" x1="150" y1="150" x2="150" y2="62"/><circle class="hub" cx="150" cy="150" r="7"/>
    <text class="tick" x="22" y="168">0</text><text class="tick" x="262" y="168">1</text></svg>
    <div class="val"><span class="n">0.00</span><small>${opts.label || 'trust'}</small></div>`;
  const fill = $('.fill', el), needle = $('.needle', el), notch = $('.notch', el), n = $('.n', el);
  let cur = 0;
  const ang = v => -90 + v * 180;
  return {
    set(v, thr) {
      v = Math.max(0, Math.min(1, v));
      fill.style.strokeDashoffset = L * (1 - v);
      fill.style.stroke = v < .3 ? 'var(--coral)' : v < .6 ? 'var(--amber)' : 'var(--teal)';
      needle.style.transform = `rotate(${ang(v)}deg)`;
      if (thr != null) notch.style.transform = `rotate(${ang(thr)}deg)`; else notch.style.opacity = 0;
      const from = cur, t0 = performance.now();          // count the number up with the needle
      (function tick(t) { const p = Math.min(1, (t - t0) / 1000); n.textContent = (from + (v - from) * (1 - Math.pow(1 - p, 3))).toFixed(2); if (p < 1) requestAnimationFrame(tick); })(t0);
      cur = v;
    }
  };
}
const heroDial = makeDial($('#heroDial')); heroDial.set(0, .5);
S.heroTrust = 0.82;
setTimeout(() => heroDial.set(0.1, .5), 250); setTimeout(() => { S.heroTrust = 0.82; heroDial.set(0.82, .5); }, 1500);
const mainDial = makeDial($('#mainDial'));

/* ---------- auth view ---------- */
function showPane(name) {
  $$('.pane').forEach(p => p.classList.remove('on'));
  $('#' + name + 'Form').classList.add('on');
  const tabs = $('#authTabs'); tabs.style.display = name === 'otp' ? 'none' : '';
  $$('.tab').forEach(t => t.classList.toggle('on', t.dataset.tab === name));
  inkTo($('.tab.on'));
}
function inkTo(t) { if (!t) return; const i = $('.tab-ink'); i.style.width = t.offsetWidth + 'px'; i.style.transform = `translateX(${t.offsetLeft}px)`; }
$$('.tab').forEach(t => t.onclick = () => showPane(t.dataset.tab)); window.addEventListener('load', () => inkTo($('.tab.on')));

$('#registerForm').onsubmit = async e => {
  e.preventDefault(); const f = Object.fromEntries(new FormData(e.target));
  const r = await api('register', 'POST', f);
  if (r.ok) { toast(r.data.message, 'good'); e.target.reset(); showPane('login'); $('#loginForm [name=username]').value = f.username; $('#loginForm [name=password]').focus(); }
  else toast(r.data.error || 'Could not create the account.', 'err');
};
$('#loginForm').onsubmit = async e => {
  e.preventDefault(); const btn = $('button[type=submit]', e.target); btn.disabled = true;
  const form = Object.fromEntries(new FormData(e.target));
  const r = await api('login', 'POST', form);
  btn.disabled = false;
  if (!r.ok) {
    toast(r.data.error || 'Sign-in failed.', 'err');
    const current = Number((S.heroTrust ?? 0.82).toFixed(2));
    const next = Math.max(0.05, Number((current - 0.08).toFixed(2)));
    S.heroTrust = next;
    heroDial.set(next, 0.5);
    return;
  }
  S.mfa = r.data; startOtp(r.data);
};

function startOtp(d) {
  $('#otpInfo').textContent = `We sent a 6-digit code to ${d.mobile}.`;
  const box = $('#otpBoxes'); box.className = 'otp'; box.innerHTML = '';
  for (let i = 0; i < 6; i++) { const x = document.createElement('input'); x.inputMode = 'numeric'; x.maxLength = 1; x.autocomplete = 'one-time-code'; x.setAttribute('aria-label', 'Digit ' + (i + 1)); box.append(x); }
  const ins = $$('input', box);
  ins.forEach((x, i) => {
    x.oninput = () => { x.value = x.value.replace(/\D/g, ''); if (x.value && ins[i + 1]) ins[i + 1].focus(); if (ins.every(y => y.value)) $('#otpForm').requestSubmit(); };
    x.onkeydown = e => { if (e.key === 'Backspace' && !x.value && ins[i - 1]) { ins[i - 1].focus(); ins[i - 1].value = ''; } };
    x.onpaste = e => { const t = (e.clipboardData.getData('text') || '').replace(/\D/g, '').slice(0, 6); if (!t) return; e.preventDefault(); [...t].forEach((c, k) => ins[k].value = c); ins[Math.min(t.length, 5)].focus(); if (t.length === 6) $('#otpForm').requestSubmit(); };
  });
  showPane('otp'); ins[0].focus(); otpCountdown(d.valid_seconds); if (d.demo_otp) showSms(d.demo_otp);
}
let otpTimerId;
function otpCountdown(sec) {
  clearInterval(otpTimerId); let left = sec; const el = $('#otpTimer');
  const tick = () => { el.textContent = left > 0 ? `Code expires in ${Math.floor(left / 60)}:${String(left % 60).padStart(2, '0')}` : 'Code expired'; left--; if (left < -1) clearInterval(otpTimerId); };
  tick(); otpTimerId = setInterval(tick, 1000);
}
function showSms(code) {
  const s = $('#sms'); $('#smsText').textContent = `Your ZTAC verification code is ${code}. Tap to fill it in.`;
  s.hidden = false; s.classList.remove('out');
  s.onclick = () => { $$('#otpBoxes input').forEach((x, i) => x.value = code[i]); hideSms(); $('#otpForm').requestSubmit(); };
  clearTimeout(showSms.t); showSms.t = setTimeout(hideSms, 14000);
}
function hideSms() { const s = $('#sms'); s.classList.add('out'); setTimeout(() => s.hidden = true, 400); }
$('#resendBtn').onclick = async () => {
  const r = await api('resend-otp', 'POST', { mfa_token: S.mfa.mfa_token });
  if (r.ok) { toast('A new code is on its way.', 'good'); otpCountdown(S.mfa.valid_seconds); if (r.data.demo_otp) showSms(r.data.demo_otp); } else toast(r.data.error, 'err');
};
$('#otpBack').onclick = () => { clearInterval(otpTimerId); hideSms(); showPane('login'); };
$('#otpForm').onsubmit = async e => {
  e.preventDefault(); const code = $$('#otpBoxes input').map(x => x.value).join('');
  if (code.length < 6) return toast('Enter all 6 digits.', 'err');
  const r = await api('verify-otp', 'POST', { mfa_token: S.mfa.mfa_token, otp: code });
  const box = $('#otpBoxes');
  if (!r.ok) { box.classList.remove('shake'); void box.offsetWidth; box.classList.add('shake'); toast(r.data.error, 'err'); $$('input', box).forEach(x => x.value = ''); $('input', box).focus(); return; }
  box.classList.add('ok'); hideSms(); clearInterval(otpTimerId);
  S.token = r.data.token; try { sessionStorage.setItem('ztacs_token', S.token); } catch (e) { }
  S.user = r.data.user; S.cfg = r.data.config;
  setTimeout(enterApp, 450);
};

/* ---------- app shell ---------- */
async function enterApp() {
  $('#auth').hidden = true; $('#app').hidden = false;
  $('#adminNav').hidden = S.user.role !== 'admin'; $('#whoName').textContent = S.user.username;
  go('overview'); await loadMe(true);
  S.timers_.push(setInterval(beat, 10000), setInterval(tickIdle, 1000), setInterval(() => { if (S.view === 'admin') loadAdmin(); }, 8000));
}
function leaveApp() {
  S.timers_.forEach(clearInterval); S.timers_ = []; S.token = null; try { sessionStorage.removeItem('ztacs_token'); } catch (e) { }
  S.deviceDirectory = null; S.deviceDirectoryStack = []; S.deviceEntries.clear(); S.deviceEditingName = null; clearDevicePreview();
  $('#deviceFolderInfo').textContent = 'No device folder selected. Folder access is granted by you in the browser.';
  $('#deviceFileRows').innerHTML = '<tr><td colspan="4" class="empty">Choose a device folder to get started.</td></tr>';
  $('#deviceUpFolder').disabled = true;
  $('#app').hidden = true; $('#auth').hidden = false; $('#otpForm').classList.remove('on'); showPane('login'); $('#loginForm').reset();
}
let forced = false;
function forceLogout(reason) {
  if (forced || !S.token) return; forced = true;
  S.timers_.forEach(clearInterval); S.timers_ = [];
  $('#mTitle').textContent = 'You were signed out'; $('#mText').textContent = `Reason: ${reason || 'session ended'}. Sign in again to continue.`;
  $('#modal').hidden = false;
}
$('#mBtn').onclick = () => { $('#modal').hidden = true; forced = false; leaveApp(); };
$('#logoutBtn').onclick = async () => { await api('logout', 'POST'); toast('Signed out.'); leaveApp(); };
$$('#nav button').forEach(b => b.onclick = () => go(b.dataset.view));
function go(v) {
  S.view = v; $$('#nav button').forEach(b => b.classList.toggle('on', b.dataset.view === v));
  $$('.view').forEach(x => x.classList.toggle('on', x.id === 'v-' + v));
  if (v === 'overview') renderSpark(); if (v === 'activity') loadSessions(); if (v === 'admin') { loadAdmin(); loadAudit(); }
}
async function beat() { const r = await api('heartbeat', 'POST'); if (r.ok) { S.timers = r.data.timers; await loadMe(); } }

async function loadMe(first) {
  const r = await api('me'); if (!r.ok) return;
  const prev = S.user && S.user.state;
  Object.assign(S, { user: r.data.user, policies: r.data.policies, logs: r.data.logs, timers: r.data.timers, cfg: r.data.config });
  if (prev && prev !== S.user.state) toast(`Account state changed to ${S.user.state}.`, S.user.state === 'NORMAL' ? 'good' : 'err');
  render();
}
function render() {
  const u = S.user, st = u.state.toLowerCase();
  const b = $('#stateBadge'); b.textContent = u.state; b.className = 'badge ' + st + (u.state !== 'NORMAL' ? ' pulse' : '');
  const last = S.logs[0]; if (last) S.lastThr = last.threshold;
  mainDial.set(u.trust, S.lastThr);
  const T = u.trust;
  $('#trustHeadline').textContent = T < .3 ? 'Building trust' : T < .6 ? 'Trusted for everyday tasks' : T < .8 ? 'Trusted for most actions' : 'High trust';
  $('#trustSub').textContent = `Your trust is ${T.toFixed(2)}. Normal activity raises it; denied or unusual requests lower it.`;
  $('#stateSteps').innerHTML = ['NORMAL', 'BLOCKED', 'RESTRICTED', 'LOCKED'].map(s => `<div class="step ${u.state === s ? 'on ' + s.toLowerCase() : ''}">${s[0] + s.slice(1).toLowerCase()}</div>`).join('');
  const left = u.state_until ? Math.max(0, Math.round(u.state_until - Date.now() / 1000)) : 0;
  $('#stateMsg').textContent = u.state === 'NORMAL' ? 'No restrictions on your account.' : `${u.state_reason}.${left ? ' Clears automatically in ' + Math.ceil(left / 60) + ' min.' : ' An administrator must unlock it.'}`;
  $('#sessInfo').textContent = `Signed in as ${u.username} (${u.role}). Mobile ${u.mobile}.`;
  updateDeviceControls();
  renderSpark(); renderCards(); renderActivity();
}
function tickIdle() {
  if (!S.timers) return; S.timers.idle_remaining = Math.max(0, S.timers.idle_remaining - 1);
  const f = S.timers.idle_remaining / S.timers.idle_total, ring = $('#idleRing');
  ring.style.strokeDashoffset = 100 * (1 - f); ring.style.stroke = f < .15 ? 'var(--coral)' : f < .35 ? 'var(--amber)' : 'var(--teal)';
  const s = S.timers.idle_remaining; $('#idleLeft').textContent = `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
}
function renderSpark() {
  const svg = $('#spark'), pts = [...S.logs].reverse().map(l => l.trust_after), note = $('#sparkNote');
  if (pts.length < 2) { svg.innerHTML = ''; note.textContent = 'Open Resources and request a few actions to see your trust move.'; return; }
  const W = 600, H = 140, p = 10, x = i => p + i * (W - 2 * p) / (pts.length - 1), y = v => H - p - v * (H - 2 * p);
  const d = pts.map((v, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)} ${y(v).toFixed(1)}`).join('');
  svg.innerHTML = `<path class="area" d="${d}L${x(pts.length - 1)} ${H}L${x(0)} ${H}Z"/><path class="line" d="${d}"/><circle class="dot" cx="${x(pts.length - 1)}" cy="${y(pts.at(-1))}" r="5" fill="var(--teal)"/>`;
  note.textContent = `Last ${pts.length} requests. Now at ${pts.at(-1).toFixed(2)}.`;
}

/* ---------- resources ---------- */
function renderCards() {
  const T = S.user.trust;
  $('#resCards').innerHTML = S.policies.map(p => {
    const admin = p.role === 'admin' && S.user.role !== 'admin';
    return `<article class="rc" data-p="${esc(p.permission)}">
      <div><h3>${esc(p.title)}</h3><code>${esc(p.permission)}</code></div>
      <p class="muted sm">${esc(p.description)}${admin ? ' Administrators only.' : ''}</p>
      <div class="meter"><i style="width:${T * 100}%"></i><b style="left:calc(${p.threshold * 100}% - 1px)"></b></div>
      <div class="meter-l"><span>Needs ${p.threshold.toFixed(2)}</span><span>You have ${T.toFixed(2)}</span></div>
      <div class="verdict" aria-live="polite"></div>
      <button class="btn ghost req">Request access</button></article>`;
  }).join('');
  $$('.rc .req').forEach(b => b.onclick = () => request(b.closest('.rc').dataset.p, b.closest('.rc')));
}

const fmtSize = n => n < 1024 ? `${n} B` : n < 1024 * 1024 ? `${(n / 1024).toFixed(1)} KB` : `${(n / (1024 * 1024)).toFixed(1)} MB`;
const EDITABLE_FILE_SIZE = 1024 * 1024;
const TEXT_FILE_EXTENSIONS = new Set(['txt', 'md', 'csv', 'tsv', 'json', 'xml', 'yaml', 'yml', 'log', 'js', 'css', 'html', 'htm', 'py', 'java', 'c', 'cpp', 'h', 'sh']);
function isEditableTextFile(file) {
  const ext = file.name.includes('.') ? file.name.split('.').pop().toLowerCase() : '';
  return file.type.startsWith('text/') || ['application/json', 'application/xml', 'application/javascript'].includes(file.type) || TEXT_FILE_EXTENSIONS.has(ext);
}
function deviceThreshold(permission, fallback) {
  const policy = S.policies.find(item => item.permission === permission);
  return policy ? Number(policy.threshold) : fallback;
}
function updateDeviceControls() {
  if (!S.user) return;
  const trust = Number(S.user.trust);
  const read = deviceThreshold('storage:read', .30);
  const write = deviceThreshold('storage:write', .50);
  const remove = deviceThreshold('storage:delete', .80);
  const allActions = Math.max(read, write, remove);
  const tier = trust < read ? 'LOW' : trust >= allActions ? 'HIGH' : 'MEDIUM';
  const badge = $('#deviceTrust');
  badge.textContent = `${tier} TRUST · ${trust.toFixed(2)}`;
  badge.className = `badge ${tier.toLowerCase()}`;
  $('#devicePolicy').textContent = `Low (<${read.toFixed(2)}): no viewing. Medium: view at ${read.toFixed(2)}, edit at ${write.toFixed(2)}. High (≥${allActions.toFixed(2)}): view, edit, and delete. Thresholds follow the active trust policies.`;
  $('#refreshDeviceFiles').disabled = !S.deviceDirectory || trust < read;
  $('#deviceUpFolder').disabled = S.deviceDirectoryStack.length < 2 || trust < read;
  if (trust < read && S.deviceEntries.size) {
    S.deviceEntries.clear();
    $('#deviceFileRows').innerHTML = '<tr><td colspan="4" class="empty">Trust is below the viewing threshold. The file list is hidden.</td></tr>';
    clearDevicePreview();
  }
  $$('[data-device-action="view"]').forEach(button => { button.disabled = trust < read; });
  $$('[data-device-action="open-folder"]').forEach(button => { button.disabled = trust < read; });
  $$('[data-device-action="edit"]').forEach(button => { button.disabled = trust < write; });
  $$('[data-device-action="delete"]').forEach(button => { button.disabled = trust < remove; });
}
async function authorizeDeviceAction(permission) {
  const decision = await request(permission);
  if (!decision) return false;
  if (!decision.allowed) toast(`Access denied: ${decision.reason}`, 'err');
  return decision.allowed;
}
async function refreshDeviceFiles() {
  if (!S.deviceDirectory) return;
  if (!await authorizeDeviceAction('storage:read')) {
    S.deviceEntries.clear();
    $('#deviceFileRows').innerHTML = '<tr><td colspan="4" class="empty">Trust policy denied access to this folder.</td></tr>';
    return;
  }
  try {
    const entries = new Map(), rows = [];
    for await (const [name, handle] of S.deviceDirectory.entries()) {
      entries.set(name, handle);
      if (handle.kind === 'directory') {
        rows.push({ name, handle });
      } else {
        rows.push({ name, handle, file: await handle.getFile() });
      }
    }
    S.deviceEntries = entries;
    const selectedPath = S.deviceDirectoryStack.map(item => item.name).join('\\');
    $('#deviceFolderInfo').textContent = `Selected folder: ${selectedPath}. Only this folder is listed.`;
    $('#deviceFileRows').innerHTML = rows.length ? rows.map(({ name, handle, file }) => {
      if (handle.kind === 'directory') {
        return `<tr><td><b>📁 ${esc(name)}</b></td><td>Folder</td><td>—</td><td class="file-actions"><button class="btn ghost small" type="button" data-device-action="open-folder" data-device-name="${esc(name)}">Open</button></td></tr>`;
      }
      const editable = isEditableTextFile(file) && file.size <= EDITABLE_FILE_SIZE;
      return `<tr><td><b>${esc(name)}</b></td><td>${fmtSize(file.size)}</td><td>${fmtD(file.lastModified / 1000)}</td><td class="file-actions">
        <button class="btn ghost small" type="button" data-device-action="view" data-device-name="${esc(name)}">View</button>
        ${editable ? `<button class="btn ghost small" type="button" data-device-action="edit" data-device-name="${esc(name)}">Edit</button>` : ''}
        <button class="btn danger small" type="button" data-device-action="delete" data-device-name="${esc(name)}">Delete</button>
      </td></tr>`;
    }).join('') : '<tr><td colspan="4" class="empty">No files in this folder.</td></tr>';
    updateDeviceControls();
  } catch (error) {
    toast(`Could not read the selected folder: ${error.message}`, 'err');
  }
}
async function requestDeviceWritePermission() {
  if (!S.deviceDirectory || typeof S.deviceDirectory.requestPermission !== 'function') {
    toast('This browser cannot grant write access to the selected folder.', 'err');
    return false;
  }
  try {
    const permission = await S.deviceDirectory.requestPermission({ mode: 'readwrite' });
    if (permission !== 'granted') toast('Device folder write permission was not granted.', 'err');
    return permission === 'granted';
  } catch (error) {
    toast(`Could not request device folder permission: ${error.message}`, 'err');
    return false;
  }
}
function clearDevicePreview() {
  if (S.devicePreviewUrl) URL.revokeObjectURL(S.devicePreviewUrl);
  S.devicePreviewUrl = null;
  S.deviceEditingName = null;
  const preview = $('#devicePreview');
  if (!preview) return;
  preview.hidden = true;
  $('#devicePreviewContent').replaceChildren();
  $('#deviceEditor').value = '';
  $('#deviceEditor').hidden = true;
  $('#deviceSave').hidden = true;
  $('#deviceCancelEdit').hidden = true;
}
async function openDeviceFile(name, editing = false) {
  const handle = S.deviceEntries.get(name);
  if (!handle) return toast('File is no longer in the selected folder. Refresh and try again.', 'err');
  if (editing && !await requestDeviceWritePermission()) return;
  if (!await authorizeDeviceAction('storage:read')) return;
  if (editing) {
    if (!await authorizeDeviceAction('storage:write')) return;
  }
  try {
    const file = await handle.getFile();
    if (editing && !isEditableTextFile(file)) return toast('Only text files can be edited here.', 'err');
    if (editing && file.size > EDITABLE_FILE_SIZE) return toast('Text files larger than 1 MB cannot be edited here.', 'err');
    clearDevicePreview();
    $('#devicePreview').hidden = false;
    $('#devicePreviewTitle').textContent = name;
    $('#devicePreviewInfo').textContent = `${fmtSize(file.size)} · ${file.type || 'Unknown file type'}`;
    if (editing) {
      S.deviceEditingName = name;
      $('#deviceEditor').value = await file.text();
      $('#deviceEditor').hidden = false;
      $('#deviceSave').hidden = false;
      $('#deviceCancelEdit').hidden = false;
    } else if (isEditableTextFile(file) && file.size <= EDITABLE_FILE_SIZE) {
      const preview = document.createElement('pre');
      preview.className = 'device-text-preview';
      preview.textContent = await file.text();
      $('#devicePreviewContent').append(preview);
    } else {
      S.devicePreviewUrl = URL.createObjectURL(file);
      if (file.type.startsWith('image/')) {
        const image = document.createElement('img');
        image.className = 'device-image-preview';
        image.src = S.devicePreviewUrl;
        image.alt = name;
        $('#devicePreviewContent').append(image);
      } else {
        const link = document.createElement('a');
        link.href = S.devicePreviewUrl;
        link.target = '_blank';
        link.rel = 'noopener';
        link.textContent = 'Open this file in a new tab';
        $('#devicePreviewContent').append(link);
      }
    }
  } catch (error) {
    toast(`Could not open ${name}: ${error.message}`, 'err');
  }
}
$('#selectDeviceFolder').onclick = async () => {
  if (typeof window.showDirectoryPicker !== 'function') {
    toast('Folder access is not supported by this browser. Use the optional app-server upload feature for individual files.', 'err');
    return;
  }
  try {
    const directory = await window.showDirectoryPicker({ mode: 'read' });
    S.deviceDirectory = directory;
    S.deviceDirectoryStack = [{ name: directory.name, handle: directory }];
    S.deviceEntries.clear();
    clearDevicePreview();
    $('#deviceFolderInfo').textContent = `Selected folder: ${directory.name}. Checking trust policy…`;
    await refreshDeviceFiles();
  } catch (error) {
    if (error.name !== 'AbortError') toast(`Could not select a device folder: ${error.message}`, 'err');
  }
};
$('#refreshDeviceFiles').onclick = refreshDeviceFiles;
$('#deviceUpFolder').onclick = async () => {
  if (S.deviceDirectoryStack.length < 2) return;
  S.deviceDirectoryStack.pop();
  S.deviceDirectory = S.deviceDirectoryStack[S.deviceDirectoryStack.length - 1].handle;
  S.deviceEntries.clear();
  clearDevicePreview();
  await refreshDeviceFiles();
};
$('#deviceFileRows').addEventListener('click', async event => {
  const button = event.target.closest('[data-device-action]');
  if (!button || button.disabled) return;
  const { deviceAction: action, deviceName: name } = button.dataset;
  if (action === 'open-folder') {
    const handle = S.deviceEntries.get(name);
    if (!handle || handle.kind !== 'directory') return toast('Folder is no longer available. Refresh and try again.', 'err');
    S.deviceDirectory = handle;
    S.deviceDirectoryStack.push({ name, handle });
    S.deviceEntries.clear();
    clearDevicePreview();
    return refreshDeviceFiles();
  }
  if (action === 'view') return openDeviceFile(name);
  if (action === 'edit') return openDeviceFile(name, true);
  if (action === 'delete') {
    if (!confirm(`Delete "${name}" from this device folder? This cannot be undone.`)) return;
    if (!await requestDeviceWritePermission()) return;
    if (!await authorizeDeviceAction('storage:delete')) return;
    try {
      await S.deviceDirectory.removeEntry(name);
      clearDevicePreview();
      toast('Device file deleted.', 'good');
      await refreshDeviceFiles();
    } catch (error) {
      toast(`Could not delete ${name}: ${error.message}`, 'err');
    }
  }
});
$('#deviceSave').onclick = async () => {
  const name = S.deviceEditingName;
  if (!name) return;
  const content = $('#deviceEditor').value;
  const handle = S.deviceEntries.get(name);
  if (!handle) return toast('File is no longer in the selected folder. Refresh and try again.', 'err');
  if (!await requestDeviceWritePermission()) return;
  if (!await authorizeDeviceAction('storage:write')) return;
  try {
    const writable = await handle.createWritable();
    await writable.write(content);
    await writable.close();
    S.deviceEditingName = null;
    clearDevicePreview();
    toast('Device file updated.', 'good');
    await refreshDeviceFiles();
  } catch (error) {
    toast(`Could not update ${name}: ${error.message}`, 'err');
  }
};
$('#deviceCancelEdit').onclick = () => {
  S.deviceEditingName = null;
  clearDevicePreview();
};
$('#deviceClosePreview').onclick = () => {
  S.deviceEditingName = null;
  clearDevicePreview();
};
async function loadFiles() {
  const r = await api('files');
  if (r.data.user) S.user = r.data.user;
  if (!r.ok) {
    $('#fileRows').innerHTML = `<tr><td colspan="4" class="empty">${esc(r.data.reason || r.data.error || 'Storage access denied.')}</td></tr>`;
    $('#fileCount').textContent = 'Access denied by current trust policy';
    $('#fileAccessNote').textContent = `Current trust ${S.user.trust.toFixed(2)}. Access is re-evaluated on every request.`;
    await loadMe();
    return;
  }
  const files = r.data.files;
  $('#fileCount').textContent = `${files.length} ${files.length === 1 ? 'file' : 'files'} in your account`;
  $('#fileAccessNote').textContent = `Access granted at trust ${r.data.trust.toFixed(2)} (required ${r.data.threshold.toFixed(2)}).`;
  $('#fileRows').innerHTML = files.length ? files.map(f => `<tr><td><b>${esc(f.filename)}</b></td><td>${fmtSize(f.size)}</td><td>${fmtD(f.uploaded)}</td><td class="file-actions"><button class="btn ghost small" data-download="${f.id}" data-name="${esc(f.filename)}">Download</button><button class="btn danger small" data-delete="${f.id}">Delete</button></td></tr>`).join('') : '<tr><td colspan="4" class="empty">No files yet. Upload your first file when your trust score meets the write threshold.</td></tr>';
  await loadMe();
}
async function downloadFile(id, name) {
  try {
    const r = await fetch(`/api/files/${id}/download`, { headers: { Authorization: 'Bearer ' + S.token } });
    if (!r.ok) {
      const d = await r.json().catch(() => ({}));
      if (r.status === 401 && d.forced) forceLogout(d.reason);
      toast(d.reason || d.error || 'Download denied.', 'err');
      if (d.user) S.user = d.user;
      return;
    }
    const url = URL.createObjectURL(await r.blob()), a = document.createElement('a');
    a.href = url; a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
    loadMe();
  } catch (_) { toast('Could not reach the storage service.', 'err'); }
}
$('#refreshFiles').onclick = loadFiles;
$('#serverStorage').addEventListener('toggle', () => {
  if ($('#serverStorage').open) loadFiles();
});
$('#uploadForm').onsubmit = async e => {
  e.preventDefault();
  const file = $('#fileInput').files[0];
  if (!file) return toast('Choose a file first.', 'err');
  const btn = $('#uploadBtn'); btn.disabled = true;
  const form = new FormData(); form.append('file', file);
  try {
    const r = await fetch('/api/files', { method: 'POST', headers: { Authorization: 'Bearer ' + S.token }, body: form });
    const d = await r.json().catch(() => ({}));
    if (r.status === 401 && d.forced) forceLogout(d.reason);
    if (!r.ok) toast(d.reason || d.error || 'Upload denied.', 'err');
    else { toast('File uploaded securely.', 'good'); e.target.reset(); }
    if (d.user) S.user = d.user;
    await loadMe(); await loadFiles();
  } catch (_) { toast('Could not reach the storage service.', 'err'); }
  finally { btn.disabled = false; }
};
$('#fileRows').addEventListener('click', async e => {
  const download = e.target.closest('[data-download]');
  if (download) return downloadFile(download.dataset.download, download.dataset.name);
  const remove = e.target.closest('[data-delete]');
  if (!remove || !confirm('Delete this file permanently?')) return;
  const r = await api(`files/${remove.dataset.delete}`, 'DELETE');
  if (r.data.user) S.user = r.data.user;
  if (r.ok) { toast('File deleted.', 'good'); await loadMe(); await loadFiles(); }
  else toast(r.data.reason || r.data.error || 'Delete denied.', 'err');
});
async function request(perm, card) {
  const r = await api('access', 'POST', { permission: perm }); const d = r.data;
  if (d.forced) return;
  if (!card) card = $(`.rc[data-p="${perm}"]`);
  if (d.user) { S.user = d.user; S.lastThr = d.threshold; }
  if (card) {
    const v = $('.verdict', card); v.className = 'verdict ' + (d.allowed ? 'ok' : 'no'); v.textContent = d.reason || d.error;
    card.classList.remove('ok', 'no'); void card.offsetWidth; card.classList.add(d.allowed ? 'ok' : 'no');
  }
  await loadMe();
  if (d.session_ended) forceLogout(d.session_reason);
  return d;
}
$('#attackBtn').onclick = async e => {
  const b = e.currentTarget; b.disabled = true; toast('Simulating a compromised account hitting sensitive resources…');
  const seq = ['storage:delete', 'compute:start', 'storage:delete', 'network:admin', 'storage:delete', 'compute:start', 'network:admin', 'storage:delete', 'compute:start', 'storage:delete'];
  for (const p of seq) {
    if (!S.token || forced || S.user.state === 'LOCKED') break;
    await request(p); await new Promise(r => setTimeout(r, 650));
  }
  b.disabled = false;
};

/* ---------- activity ---------- */
function renderActivity() {
  $('#actRows').innerHTML = S.logs.length ? S.logs.map(l => `<tr><td>${fmtT(l.ts)}</td><td><code>${esc(l.action)}</code></td>
    <td><span class="pill ${l.allowed ? 'y' : 'n'}">${l.allowed ? 'Allowed' : 'Denied'}</span></td><td>${esc(l.reason)}</td>
    <td>${(l.anomaly * 100).toFixed(0)}%</td><td>${l.trust_after.toFixed(2)}</td></tr>`).join('')
    : '<tr><td colspan="6" class="empty">Nothing yet. Request an action in Resources.</td></tr>';
}
async function loadSessions() {
  const r = await api('my/sessions'); if (!r.ok) return;
  $('#sessRows').innerHTML = r.data.sessions.map(s => `<tr><td>${fmtD(s.created)}</td><td><span class="pill ${s.status === 'ACTIVE' ? 'y' : 'n'}">${s.id === r.data.current ? 'This session' : s.status === 'ACTIVE' ? 'Active' : 'Ended'}</span></td><td>${esc(s.reason || '')}</td><td>${esc(s.ip)}</td></tr>`).join('');
}

/* ---------- admin ---------- */
async function loadAdmin() {
  const r = await api('admin/overview'); if (!r.ok) return; const d = r.data, s = d.stats;
  $('#adminTiles').innerHTML = [['Accounts', s.users], ['Active sessions', s.active_sessions], ['Open alerts', s.open_alerts], ['Denied in last hour', s.denied_hour], ['Restricted accounts', s.restricted], ['Agent experiences', d.replay]]
    .map(([k, v]) => `<div class="tile"><b>${v}</b><span>${k}</span></div>`).join('');
  $('#userRows').innerHTML = d.users.map(u => `<tr><td>${esc(u.username)}<br><small class="muted">${esc(u.role)} · ${esc(u.mobile)}</small></td><td>${u.trust.toFixed(2)}</td>
    <td><span class="badge ${u.state.toLowerCase()}">${u.state}</span></td>
    <td>${u.state !== 'NORMAL' ? `<button class="btn ghost small" data-a="unlock" data-id="${u.id}">Unlock</button>` : u.id !== S.user.id ? `<button class="btn ghost small" data-a="lock" data-id="${u.id}">Lock</button>` : ''}</td></tr>`).join('');
  $('#alertList').innerHTML = d.alerts.length ? d.alerts.map(a => `<div class="al"><i class="sev ${a.severity}"></i><div>${esc(a.message)}<small>${esc(a.username)} · ${fmtT(a.ts)}</small></div><button class="btn ghost small" data-ack="${a.id}">Dismiss</button></div>`).join('') : '<p class="empty">No open alerts.</p>';
  $('#activeRows').innerHTML = d.sessions.map(x => `<tr><td>${esc(x.username)}</td><td>${fmtT(x.created)}</td><td>${esc(x.ip)}</td><td>${false ? '' : `<button class="btn ghost small" data-kill="${x.id}">Sign out</button>`}</td></tr>`).join('');
  $('#polList').innerHTML = d.policies.map(p => `<div class="pol"><span><b>${esc(p.permission)}</b><br><small class="muted">base ${p.base_threshold.toFixed(2)} · agent now ${p.threshold.toFixed(2)}</small></span><input type="number" step="0.05" min="0.05" max="0.95" value="${p.base_threshold}" data-pol="${p.permission}" aria-label="Threshold for ${esc(p.permission)}"></div>`).join('');
}
$('#v-admin').addEventListener('click', async e => {
  const t = e.target.closest('button'); if (!t) return; let r;
  if (t.dataset.a) r = await api(`admin/users/${t.dataset.id}/${t.dataset.a}`, 'POST');
  else if (t.dataset.ack) r = await api(`admin/alerts/${t.dataset.ack}/ack`, 'POST');
  else if (t.dataset.kill) r = await api(`admin/sessions/${t.dataset.kill}/terminate`, 'POST');
  else return;
  if (r.ok) { toast('Done.', 'good'); loadAdmin(); loadAudit(); } else toast(r.data.error, 'err');
});
$('#v-admin').addEventListener('change', async e => {
  const i = e.target.closest('[data-pol]'); if (!i) return;
  const r = await api('admin/policies', 'POST', { permission: i.dataset.pol, threshold: parseFloat(i.value) });
  toast(r.ok ? 'Threshold saved.' : r.data.error, r.ok ? 'good' : 'err'); loadAdmin();
});
async function loadAudit() {
  const r = await api('admin/audit'); if (!r.ok) return; const c = $('#chainBadge');
  c.className = 'badge ' + (r.data.chain_ok ? 'normal' : 'restricted'); c.textContent = r.data.chain_ok ? 'hash chain intact' : 'TAMPERING at entry ' + r.data.broken_at;
  $('#auditRows').innerHTML = r.data.rows.map(a => `<tr><td>${a.id}</td><td>${fmtD(a.ts)}</td><td><code>${esc(a.event)}</code></td><td>${esc(a.user)}</td><td class="det">${esc(a.detail)}</td></tr>`).join('');
}
$('#auditBtn').onclick = loadAudit;

/* ---------- resume ---------- */
(async () => {
  if (!S.token) return;
  const r = await api('me'); if (!r.ok) { S.token = null; return; }
  S.user = r.data.user; S.cfg = r.data.config; forced = false; enterApp();
})();
