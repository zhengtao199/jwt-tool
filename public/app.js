'use strict';

const $ = (sel) => document.querySelector(sel);
// 示例令牌：用默认字典中的弱密钥 secret 签发的 HS256，点「校验」即可看到命中效果
const SAMPLE =
  'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IuW8oOS4iSIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTcxMDAwMDAwMCwiZXhwIjoxOTI1MzYwMDAwfQ.sBA7JP6N3_icXDKK9jEk400_UYMbxydBYHpxGJVF6Dc';

let currentToken = '';
let keys = [];

/* ---------- 通用 ---------- */

const OFFLINE_MSG = '无法连接后端服务。请在 jwt-tool 目录双击 start.bat（或执行 node server.js）后刷新页面。';

async function api(path, options) {
  let res;
  try {
    res = await fetch('/api' + path, Object.assign({ headers: { 'Content-Type': 'application/json' } }, options));
  } catch (_) {
    throw new Error(OFFLINE_MSG);
  }
  let data;
  try {
    data = await res.json();
  } catch (_) {
    throw new Error('服务返回异常');
  }
  if (!data.ok) throw new Error(data.error || '请求失败');
  return data.data;
}

function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

/** JSON 高亮：先转义再着色，避免 XSS */
function highlightJson(value) {
  const text = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
  const escaped = escapeHtml(text);
  return escaped
    .replace(/&quot;([^&]*?)&quot;(\s*:)/g, '<span class="j-key">&quot;$1&quot;</span>$2')
    .replace(/:\s*&quot;([^&]*?)&quot;/g, ': <span class="j-str">&quot;$1&quot;</span>')
    .replace(/:\s*(-?\d+(?:\.\d+)?)/g, ': <span class="j-num">$1</span>')
    .replace(/:\s*(true|false)/g, ': <span class="j-bool">$1</span>')
    .replace(/:\s*null/g, ': <span class="j-null">null</span>');
}

function toast(msg) {
  const el = document.createElement('div');
  el.textContent = msg;
  el.style.cssText = 'position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background:#1f2329;color:#fff;padding:8px 16px;border-radius:6px;font-size:13px;z-index:99';
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 1600);
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast('已复制');
  } catch (_) {
    toast('复制失败，请手动选择');
  }
}

/* ---------- 解码 ---------- */

function renderDecode(data) {
  const errBox = $('#decode-error');
  const warnBox = $('#decode-warnings');
  const result = $('#decode-result');

  errBox.innerHTML = '';
  warnBox.innerHTML = '';
  $('#verify-result').innerHTML = '';

  if (!data.valid) {
    errBox.textContent = data.errors.join('；');
    errBox.classList.remove('hidden');
    result.classList.add('hidden');
    return;
  }

  errBox.classList.add('hidden');
  result.classList.remove('hidden');

  $('#seg-header').textContent = data.parts.header;
  $('#seg-payload').textContent = data.parts.payload;
  $('#seg-signature').textContent = data.parts.signature || '（空）';

  $('#out-header').innerHTML = data.header.ok
    ? highlightJson(data.header.json)
    : '<span class="j-null">' + escapeHtml(data.header.error) + '</span>';
  $('#out-payload').innerHTML = data.payload.ok
    ? highlightJson(data.payload.json)
    : '<span class="j-null">' + escapeHtml(data.payload.error) + '</span>';

  const tbody = $('#claims-table').querySelector('tbody');
  tbody.innerHTML = '';
  (data.claims || []).forEach((c) => {
    const tr = document.createElement('tr');
    const status = c.status ? '<span class="status ' + c.status + '">' + (c.note || '') + '</span>' : '';
    tr.innerHTML =
      '<td>' + escapeHtml(c.label) + '</td>' +
      '<td class="mono">' + escapeHtml(JSON.stringify(c.value)) + '</td>' +
      '<td>' + (c.readable ? escapeHtml(c.readable) : '—') + '</td>' +
      '<td>' + status + '</td>';
    tbody.appendChild(tr);
  });
  $('#claims-card').classList.toggle('hidden', !(data.claims && data.claims.length));

  warnBox.innerHTML = (data.warnings || [])
    .map((w) => '<div class="alert ' + w.level + '">' + escapeHtml(w.text) + '</div>')
    .join('');
}

async function decodeInput() {
  const token = $('#token-input').value.trim();
  if (!token) {
    $('#decode-result').classList.add('hidden');
    $('#decode-error').classList.add('hidden');
    $('#decode-warnings').innerHTML = '';
    currentToken = '';
    return;
  }
  try {
    const data = await api('/decode', { method: 'POST', body: JSON.stringify({ token }) });
    currentToken = data.token;
    renderDecode(data);
    if (!data.valid) return;
    if (autoVerify()) maybeAutoVerify();
  } catch (err) {
    $('#decode-result').classList.add('hidden');
    $('#decode-error').textContent = err.message;
    $('#decode-error').classList.remove('hidden');
  }
}

let verifying = false;

const AUTO_KEY = 'jwt_auto_verify';
const AUTO_LIMIT = 200000; // 字典过大时不自动跑，避免每次粘贴都卡住

function autoVerify() {
  return localStorage.getItem(AUTO_KEY) === '1';
}

function maybeAutoVerify() {
  if (!autoVerify()) return;
  if (!selectedIds.size && view.total > AUTO_LIMIT) {
    $('#verify-result').innerHTML = '<div class="verify-miss">字典有 ' + view.total +
      ' 条，已跳过自动校验（超过 ' + AUTO_LIMIT + ' 条）。请在「密钥字典」页勾选部分密钥，或手动点「开始校验」。</div>';
    return;
  }
  runVerify();
}

async function runVerify() {
  if (!currentToken) {
    toast('请先解码一个令牌');
    return;
  }
  if (verifying) return;
  verifying = true;

  const box = $('#verify-result');
  const ids = selectedIds.size ? Array.from(selectedIds) : null;
  const scopeText = ids ? '已选 ' + ids.length + ' 条' : '全部 ' + view.total + ' 条';
  $('#btn-verify').disabled = true;
  box.innerHTML = '<div class="verify-miss">正在校验（' + scopeText + '）…</div>';
  try {
    const data = await api('/verify', { method: 'POST', body: JSON.stringify({ token: currentToken, ids }) });
    if (data.matches && data.matches.length) {
      box.innerHTML = data.matches
        .map((m) => '<div class="verify-hit">✔ 命中密钥：<b>' + escapeHtml(m.name) + '</b>（算法 ' + escapeHtml(m.alg) + '，编码 ' + escapeHtml(m.encoding) + '）</div>')
        .join('');
    } else {
      box.innerHTML = '<div class="verify-miss">✘ 未命中：已尝试 ' + data.tried + ' 个密钥（' + escapeHtml(scopeText) +
        '），签名均不匹配（可能是非 HS 算法，或密钥不在范围内）。</div>';
    }
  } catch (err) {
    box.innerHTML = '<div class="verify-miss">' + escapeHtml(err.message) + '</div>';
  } finally {
    $('#btn-verify').disabled = false;
    verifying = false;
  }
}

/* ---------- 密钥字典 ---------- */

const view = { q: '', limit: 100, offset: 0, total: 0 };
const selectedIds = new Set();

function updateSelUi() {
  $('#sel-count').textContent = selectedIds.size;
  $('#verify-scope').textContent = selectedIds.size ? '已选 ' + selectedIds.size + ' 条' : '全部 ' + view.total + ' 条';
  const box = $('#sel-all');
  if (box) {
    const pageIds = keys.map((k) => k.id);
    box.checked = pageIds.length > 0 && pageIds.every((id) => selectedIds.has(id));
    box.indeterminate = !box.checked && pageIds.some((id) => selectedIds.has(id));
  }
}

function renderKeys() {
  const tbody = $('#key-rows');
  tbody.innerHTML = '';
  $('#key-count').textContent = view.total;

  if (!keys.length) {
    tbody.innerHTML = '<tr><td colspan="6" style="color:var(--text-dim)">' +
      (view.q ? '没有匹配的密钥' : '暂无密钥，请在上方添加或从 txt 导入。') + '</td></tr>';
  }

  keys.forEach((k) => {
    const tr = document.createElement('tr');
    const on = selectedIds.has(k.id) ? ' checked' : '';
    tr.innerHTML =
      '<td><input type="checkbox" data-sel="' + escapeHtml(k.id) + '"' + on + '></td>' +
      '<td>' + escapeHtml(k.name) + '</td>' +
      '<td class="mono">' + escapeHtml(k.preview) + '</td>' +
      '<td>' + k.length + '</td>' +
      '<td>' + escapeHtml(k.encoding) + '</td>' +
      '<td><button class="btn ghost small" data-del="' + escapeHtml(k.id) + '">删除</button></td>';
    tbody.appendChild(tr);
  });

  const sel = $('#sign-keyid');
  const prev = sel.value;
  sel.innerHTML = keys.length
    ? keys.map((k) => '<option value="' + escapeHtml(k.id) + '">' + escapeHtml(k.name) + '</option>').join('')
    : '<option value="">（字典为空）</option>';
  if (keys.some((k) => k.id === prev)) sel.value = prev;

  const start = view.total ? view.offset + 1 : 0;
  const end = view.offset + keys.length;
  $('#pager-info').textContent = '第 ' + start + '-' + end + ' 条 / 共 ' + view.total + ' 条';
  $('#btn-prev').disabled = view.offset <= 0;
  $('#btn-next').disabled = end >= view.total;
  updateSelUi();
}

async function loadKeys() {
  const qs = '?q=' + encodeURIComponent(view.q) + '&limit=' + view.limit + '&offset=' + view.offset;
  const data = await api('/keys' + qs);
  keys = data.keys;
  view.total = data.total;
  view.offset = data.offset;
  renderKeys();
}

/* ---------- 签发 ---------- */

async function runSign() {
  const errBox = $('#sign-error');
  const out = $('#sign-result');
  errBox.classList.add('hidden');
  out.classList.add('hidden');

  const useDict = $('#sign-key-source').value === 'dict';
  const body = {
    alg: $('#sign-alg').value,
    header: $('#sign-header').value,
    payload: $('#sign-payload').value,
  };
  if (useDict) {
    body.keyId = $('#sign-keyid').value;
  } else {
    body.secret = $('#sign-secret').value;
    body.encoding = $('#sign-encoding').value;
  }

  try {
    const data = await api('/sign', { method: 'POST', body: JSON.stringify(body) });
    $('#sign-out').textContent = data.token;
    out.classList.remove('hidden');
  } catch (err) {
    errBox.textContent = err.message;
    errBox.classList.remove('hidden');
  }
}

/* ---------- 事件绑定 ---------- */

$('#tabs').addEventListener('click', (e) => {
  const btn = e.target.closest('.tab');
  if (!btn) return;
  document.querySelectorAll('.tab').forEach((t) => t.classList.toggle('active', t === btn));
  document.querySelectorAll('.panel').forEach((p) => p.classList.toggle('active', p.id === 'panel-' + btn.dataset.tab));
  if (btn.dataset.tab === 'keys') loadKeys().catch((e) => toast(e.message));
});

let timer = null;
$('#token-input').addEventListener('input', () => {
  clearTimeout(timer);
  timer = setTimeout(decodeInput, 250);
});
$('#btn-sample').addEventListener('click', () => {
  $('#token-input').value = SAMPLE;
  decodeInput();
});
$('#btn-clear').addEventListener('click', () => {
  $('#token-input').value = '';
  decodeInput();
});
$('#btn-verify').addEventListener('click', runVerify);

document.addEventListener('change', (e) => {
  const sel = e.target.closest('[data-sel]');
  if (sel) {
    const id = sel.dataset.sel;
    if (sel.checked) selectedIds.add(id);
    else selectedIds.delete(id);
    updateSelUi();
  }
});

document.addEventListener('click', (e) => {
  const copyBtn = e.target.closest('[data-copy]');
  if (copyBtn) {
    const target = document.getElementById(copyBtn.dataset.copy);
    copyText(target.textContent);
    return;
  }
  const delBtn = e.target.closest('[data-del]');
  if (delBtn) {
    const id = delBtn.dataset.del;
    selectedIds.delete(id);
    api('/keys', {
      method: 'DELETE',
      body: JSON.stringify({ id, q: view.q, limit: view.limit, offset: view.offset }),
    })
      .then(() => { loadKeys(); toast('已删除'); })
      .catch((err) => toast(err.message));
  }
});

$('#key-form').addEventListener('submit', (e) => {
  e.preventDefault();
  const secret = $('#key-secret').value.trim();
  if (!secret) return toast('密钥不能为空');
  api('/keys', {
    method: 'POST',
    body: JSON.stringify({
      name: $('#key-name').value.trim() || '未命名密钥',
      secret,
      encoding: $('#key-encoding').value,
      q: view.q,
      limit: view.limit,
      offset: view.offset,
    }),
  })
    .then(() => {
      $('#key-name').value = '';
      $('#key-secret').value = '';
      toast('已添加');
      return loadKeys();
    })
    .catch((err) => toast(err.message));
});
$('#btn-reload-keys').addEventListener('click', () => loadKeys().catch((e) => toast(e.message)));

let searchTimer = null;
$('#key-search').addEventListener('input', (e) => {
  clearTimeout(searchTimer);
  const val = e.target.value;
  searchTimer = setTimeout(() => {
    view.q = val;
    view.offset = 0;
    loadKeys().catch((err) => toast(err.message));
  }, 300);
});
$('#page-size').addEventListener('change', (e) => {
  view.limit = Number(e.target.value);
  view.offset = 0;
  loadKeys().catch((err) => toast(err.message));
});
$('#sel-all').addEventListener('change', (e) => {
  keys.forEach((k) => {
    if (e.target.checked) selectedIds.add(k.id);
    else selectedIds.delete(k.id);
  });
  renderKeys();
});

$('#btn-clear-sel').addEventListener('click', () => {
  selectedIds.clear();
  renderKeys();
});

$('#btn-prev').addEventListener('click', () => {
  view.offset = Math.max(0, view.offset - view.limit);
  loadKeys().catch((err) => toast(err.message));
});
$('#btn-next').addEventListener('click', () => {
  view.offset += view.limit;
  loadKeys().catch((err) => toast(err.message));
});

/* ---------- txt 导入 ---------- */

const MAX_UPLOAD_MB = 64;
const PREVIEW_LIMIT = 1024 * 1024; // 超过 1MB 不进预览框，避免浏览器卡死
let pendingFile = null;

function formatSize(bytes) {
  if (bytes >= 1048576) return (bytes / 1048576).toFixed(1) + ' MB';
  if (bytes >= 1024) return Math.round(bytes / 1024) + ' KB';
  return bytes + ' B';
}

$('#key-file').addEventListener('change', (e) => {
  const file = e.target.files && e.target.files[0];
  e.target.value = '';
  if (!file) return;
  const box = $('#import-result');
  if (file.size > MAX_UPLOAD_MB * 1024 * 1024) {
    pendingFile = null;
    box.innerHTML = '<div class="alert danger">文件 ' + formatSize(file.size) + ' 超过 ' + MAX_UPLOAD_MB +
      'MB 上限。请拆分文件，或用 JWT_MAX_UPLOAD_MB=200 重启服务放宽上限。</div>';
    return;
  }
  pendingFile = file;
  box.innerHTML = '';
  $('#file-name').textContent = '已选择：' + file.name + '（' + formatSize(file.size) + '）';
  if (file.size <= PREVIEW_LIMIT) {
    const reader = new FileReader();
    reader.onload = () => {
      $('#import-content').value = String(reader.result || '');
    };
    reader.onerror = () => {
      box.innerHTML = '<div class="alert danger">文件读取失败</div>';
    };
    reader.readAsText(file, 'utf-8');
  } else {
    $('#import-content').value = '';
    $('#import-content').placeholder = '（大文件已就绪，不载入预览；直接点「导入」即可）';
  }
});

function readFileText(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result || ''));
    reader.onerror = () => reject(new Error('文件读取失败'));
    reader.readAsText(file, 'utf-8');
  });
}

async function apiRaw(path, text, params) {
  let res;
  try {
    res = await fetch('/api' + path + params, {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain; charset=utf-8' },
      body: text,
    });
  } catch (_) {
    throw new Error(OFFLINE_MSG);
  }
  const data = await res.json();
  if (!data.ok) throw new Error(data.error || '导入失败');
  return data.data;
}

$('#btn-import').addEventListener('click', async () => {
  const box = $('#import-result');
  const encoding = $('#import-encoding').value;
  const dedupe = $('#import-dedupe').checked;

  let text = $('#import-content').value;
  if (pendingFile && !text) {
    box.innerHTML = '<div class="alert info">正在读取 ' + escapeHtml(pendingFile.name) + '（' + formatSize(pendingFile.size) + '）…</div>';
    try {
      text = await readFileText(pendingFile);
    } catch (err) {
      box.innerHTML = '<div class="alert danger">' + escapeHtml(err.message) + '</div>';
      return;
    }
  }
  if (!text.trim()) {
    box.innerHTML = '<div class="alert danger">请先选择文件或粘贴密钥内容</div>';
    return;
  }

  box.innerHTML = '<div class="alert info">正在导入（' + formatSize(text.length) + '），请稍候…</div>';
  try {
    const data = await apiRaw('/keys/import', text, '?encoding=' + encodeURIComponent(encoding) + '&dedupe=' + dedupe);
    const parts = ['<div class="alert ok">导入完成：新增 ' + data.imported + ' 条，跳过重复 ' + data.skipped +
      ' 条，当前共 ' + data.total + ' 条。</div>'];
    if (data.truncated) parts.push('<div class="alert warn">达到字典上限，末尾 ' + data.truncated + ' 条未导入（可用 JWT_MAX_KEYS 调大）。</div>');
    if (data.problems && data.problems.length) {
      parts.push('<div class="alert warn">' + data.problems.slice(0, 5).map(escapeHtml).join('<br>') + '</div>');
    }
    box.innerHTML = parts.join('');
    $('#import-content').value = '';
    $('#file-name').textContent = '';
    pendingFile = null;
    view.offset = 0;
    await loadKeys();
  } catch (err) {
    box.innerHTML = '<div class="alert danger">' + escapeHtml(err.message) + '</div>';
  }
});

$('#sign-key-source').addEventListener('change', (e) => {
  const manual = e.target.value === 'manual';
  $('#wrap-sign-keyid').classList.toggle('hidden', manual);
  $('#wrap-sign-secret').classList.toggle('hidden', !manual);
  $('#wrap-sign-encoding').classList.toggle('hidden', !manual);
});

$('#btn-fill-exp').addEventListener('click', () => {
  const area = $('#sign-payload');
  let obj;
  try {
    obj = JSON.parse(area.value || '{}');
  } catch (_) {
    return toast('Payload 不是合法 JSON');
  }
  obj.iat = Math.floor(Date.now() / 1000);
  obj.exp = obj.iat + 86400;
  area.value = JSON.stringify(obj, null, 2);
});

$('#btn-sign').addEventListener('click', runSign);
$('#btn-copy-token').addEventListener('click', () => copyText($('#sign-out').textContent));
$('#btn-back-decode').addEventListener('click', () => {
  $('#token-input').value = $('#sign-out').textContent;
  document.querySelector('.tab[data-tab="decode"]').click();
  decodeInput();
});

/* ---------- 初始化 ---------- */

$('#btn-retry').addEventListener('click', () => location.reload());

const autoBox = $('#auto-verify');
autoBox.checked = autoVerify();
autoBox.addEventListener('change', () => {
  localStorage.setItem(AUTO_KEY, autoBox.checked ? '1' : '0');
  toast(autoBox.checked ? '已开启：解码后自动校验' : '已关闭自动校验');
});

loadKeys()
  .then(() => $('#offline-banner').classList.add('hidden'))
  .catch(() => {
    $('#offline-text').textContent = OFFLINE_MSG;
    $('#offline-banner').classList.remove('hidden');
  });
