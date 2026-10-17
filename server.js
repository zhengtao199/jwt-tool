/**
 * JWT 工具 - 本地后端服务（零外部依赖）
 * 所有计算均在本机完成，不发起任何外部网络请求。
 */
'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { exec } = require('node:child_process');

const PORT = Number(process.env.PORT || 5273);
const HOST = process.env.HOST || '127.0.0.1';
const MAX_PORT_TRY = 20;

// 导入上限：默认 64MB / 200 万行，可用环境变量调整
const MAX_UPLOAD_BYTES = Number(process.env.JWT_MAX_UPLOAD_MB || 64) * 1024 * 1024;
const MAX_IMPORT_LINES = Number(process.env.JWT_MAX_LINES || 2000000);
const MAX_KEYS = Number(process.env.JWT_MAX_KEYS || 5000000);
const MAX_PROBLEMS = 20;
const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, 'public');
const DATA_DIR = path.join(ROOT, 'data');
const KEYS_FILE = path.join(DATA_DIR, 'keys.json');

const HMAC_ALGS = {
  HS256: 'sha256',
  HS384: 'sha384',
  HS512: 'sha512',
};

const DEFAULT_KEYS = [
  { name: '常见弱密钥-secret', secret: 'secret', encoding: 'utf8' },
  { name: '常见弱密钥-123456', secret: '123456', encoding: 'utf8' },
  { name: '常见弱密钥-admin', secret: 'admin', encoding: 'utf8' },
  { name: '常见弱密钥-password', secret: 'password', encoding: 'utf8' },
  { name: '常见弱密钥-changeme', secret: 'changeme', encoding: 'utf8' },
];

/* ---------------- 工具函数 ---------------- */

function b64urlDecode(str) {
  return Buffer.from(String(str), 'base64url');
}

function b64urlEncode(buf) {
  return Buffer.from(buf).toString('base64url');
}

function decodeSegment(seg) {
  try {
    const json = b64urlDecode(seg).toString('utf8');
    return { ok: true, json, value: JSON.parse(json) };
  } catch (err) {
    // JSON 解析失败时保留原文，避免直接丢弃用户数据
    let raw = '';
    try {
      raw = b64urlDecode(seg).toString('utf8');
    } catch (_) {
      raw = '';
    }
    return { ok: false, json: raw, value: null, error: '该段不是合法 JSON：' + err.message };
  }
}

function formatTime(sec) {
  if (typeof sec !== 'number' || !Number.isFinite(sec)) return null;
  const ms = sec * 1000;
  const d = new Date(ms);
  if (Number.isNaN(d.getTime())) return null;
  const pad = (n) => String(n).padStart(2, '0');
  return (
    d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) +
    ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds())
  );
}

function humanizeDuration(ms) {
  const abs = Math.abs(ms);
  const s = Math.floor(abs / 1000);
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  const parts = [];
  if (d) parts.push(d + ' 天');
  if (h) parts.push(h + ' 小时');
  if (m) parts.push(m + ' 分钟');
  if (!d && !h) parts.push(sec + ' 秒');
  return parts.join(' ');
}

/**
 * 解析 JWT：拆段、解码、时间字段可读性处理、风险提示
 */
function parseToken(raw) {
  const token = String(raw || '').trim().replace(/^Bearer\s+/i, '');
  const result = { token, valid: false, parts: null, header: null, payload: null, signature: null, errors: [], warnings: [], claims: {} };

  if (!token) {
    result.errors.push('请输入 JWT');
    return result;
  }

  const parts = token.split('.');
  if (parts.length !== 3) {
    result.errors.push('JWT 应由 3 段（header.payload.signature）组成，当前为 ' + parts.length + ' 段');
    return result;
  }

  const [h, p, s] = parts;
  if (!/^[A-Za-z0-9_-]*$/.test(h) || !/^[A-Za-z0-9_-]*$/.test(p) || !/^[A-Za-z0-9_-]*$/.test(s)) {
    result.errors.push('包含非法字符，不是合法的 base64url 编码');
    return result;
  }

  const headerSeg = decodeSegment(h);
  const payloadSeg = decodeSegment(p);

  result.parts = { header: h, payload: p, signature: s };
  result.header = headerSeg;
  result.payload = payloadSeg;
  result.signature = {
    present: s.length > 0,
    raw: s,
    bytes: b64urlDecode(s).length,
    hex: b64urlDecode(s).toString('hex'),
  };
  result.valid = true;

  const headerObj = headerSeg.value || {};
  const payloadObj = payloadSeg.value || {};

  // 声明字段可读性
  const nowSec = Math.floor(Date.now() / 1000);
  const claims = [];
  const push = (key, label) => {
    if (payloadObj[key] === undefined) return;
    const v = payloadObj[key];
    const item = { key, label, value: v, readable: null, status: null, note: null };
    if (typeof v === 'number') {
      item.readable = formatTime(v);
      if (item.readable) {
        const diffMs = (v - nowSec) * 1000;
        if (key === 'exp') {
          item.status = diffMs <= 0 ? 'danger' : diffMs < 300000 ? 'warn' : 'ok';
          item.note = diffMs <= 0 ? '已过期 ' + humanizeDuration(diffMs) : '剩余 ' + humanizeDuration(diffMs);
        } else if (key === 'nbf') {
          item.status = diffMs > 0 ? 'warn' : 'ok';
          item.note = diffMs > 0 ? '将在 ' + humanizeDuration(diffMs) + '后生效' : '已生效';
        } else {
          item.note = humanizeDuration(Math.abs(diffMs)) + (diffMs <= 0 ? '前' : '后');
        }
      }
    }
    claims.push(item);
  };
  push('iss', '签发者');
  push('sub', '主题');
  push('aud', '受众');
  push('exp', '过期时间 exp');
  push('nbf', '生效时间 nbf');
  push('iat', '签发时间 iat');
  push('jti', '令牌 ID');
  result.claims = claims;

  // 风险提示
  const alg = headerObj.alg;
  if (!alg) {
    result.warnings.push({ level: 'warn', text: 'header 中缺少 alg 字段' });
  } else if (String(alg).toLowerCase() === 'none') {
    result.warnings.push({ level: 'danger', text: 'alg = none：该令牌未签名，可被任意伪造（典型安全漏洞）' });
  } else if (!HMAC_ALGS[alg] && !/^(RS|PS|ES)\d{3}$/.test(String(alg))) {
    result.warnings.push({ level: 'warn', text: '未知算法 alg = ' + alg });
  }
  if (!result.signature.present) {
    result.warnings.push({ level: 'danger', text: '签名为空' });
  }
  if (payloadObj.exp === undefined) {
    result.warnings.push({ level: 'warn', text: 'payload 中没有 exp，令牌永不过期' });
  }
  if (headerObj.alg && /^(RS|PS|ES)\d{3}$/.test(String(headerObj.alg))) {
    result.warnings.push({ level: 'info', text: 'alg = ' + headerObj.alg + '：非对称算法，需 PEM 公私钥才能验证，本工具密钥字典仅支持 HS256/384/512' });
  }

  return result;
}

function secretToBuffer(secret, encoding) {
  if (encoding === 'base64') return Buffer.from(String(secret), 'base64');
  if (encoding === 'hex') return Buffer.from(String(secret), 'hex');
  return Buffer.from(String(secret), 'utf8');
}

/**
 * 用单个密钥校验签名；返回 { matched, alg }
 */
function verifyWithSecret(parsed, secret, encoding) {
  if (!parsed.valid || !parsed.signature.present) return { matched: false, reason: '令牌无效或无签名' };
  const declaredAlg = (parsed.header && parsed.header.value && parsed.header.value.alg) || '';
  let algsToTry = [];
  if (HMAC_ALGS[declaredAlg]) algsToTry.push(declaredAlg);
  if (String(declaredAlg).toLowerCase() === 'none') algsToTry = ['HS256', 'HS384', 'HS512'];
  if (!algsToTry.length) algsToTry = ['HS256', 'HS384', 'HS512'];

  const signingInput = parsed.parts.header + '.' + parsed.parts.payload;
  const expected = b64urlDecode(parsed.parts.signature);
  let secretBuf;
  try {
    secretBuf = secretToBuffer(secret, encoding);
  } catch (_) {
    return { matched: false, reason: '密钥编码解析失败' };
  }

  for (const alg of algsToTry) {
    const digest = crypto.createHmac(HMAC_ALGS[alg], secretBuf).update(signingInput).digest();
    if (digest.length === expected.length && crypto.timingSafeEqual(digest, expected)) {
      return { matched: true, alg };
    }
  }
  return { matched: false };
}

function signToken(headerObj, payloadObj, secret, encoding, alg) {
  const a = HMAC_ALGS[alg] ? alg : 'HS256';
  const header = Object.assign({ alg: a, typ: 'JWT' }, headerObj || {});
  delete header.alg;
  header.alg = a;
  const h = b64urlEncode(Buffer.from(JSON.stringify(header), 'utf8'));
  const p = b64urlEncode(Buffer.from(JSON.stringify(payloadObj == null ? {} : payloadObj), 'utf8'));
  const signingInput = h + '.' + p;
  const sig = crypto.createHmac(HMAC_ALGS[a], secretToBuffer(secret, encoding)).update(signingInput).digest();
  return signingInput + '.' + b64urlEncode(sig);
}

/**
 * 解析 txt 密钥文件
 * 规则：一行一个密钥；# 开头为注释；空行跳过；
 *      可用 : 或 , 或 制表符 分隔「备注」与「密钥」（如 "测试环境:abc123"），无分隔符则整行作为密钥。
 */
function parseKeyFile(content, defaultEncoding) {
  const lines = String(content || '').split(/\r?\n/);
  const items = [];
  const problems = [];
  const MAX_LINES = MAX_IMPORT_LINES;

  lines.slice(0, MAX_LINES).forEach((line, i) => {
    const raw = line.trim();
    if (!raw || raw.startsWith('#')) return;

    let name = '';
    let secret = raw;
    let encoding = defaultEncoding;

    // 分隔符：制表符 > 逗号 > 冒号（避免与 base64 的 = 冲突）
    let idx = raw.indexOf('\t');
    if (idx < 0) idx = raw.indexOf(',');
    if (idx < 0) idx = raw.indexOf(':');
    if (idx > 0 && idx < raw.length - 1) {
      name = raw.slice(0, idx).trim();
      secret = raw.slice(idx + 1).trim();
    }
    if (!secret) return;
    if (secret.length > 4096) {
      if (problems.length < MAX_PROBLEMS) problems.push('第 ' + (i + 1) + ' 行密钥过长，已跳过');
      return;
    }
    items.push({ name: (name || '导入#' + (i + 1)).slice(0, 60), secret, encoding });
  });

  if (lines.length > MAX_LINES) problems.push('文件超过 ' + MAX_LINES + ' 行，仅处理前 ' + MAX_LINES + ' 行');
  return { items, problems };
}

/* ---------------- 密钥字典持久化 ---------------- */

let keyStore = [];

function loadKeys() {
  try {
    if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
    if (fs.existsSync(KEYS_FILE)) {
      const arr = JSON.parse(fs.readFileSync(KEYS_FILE, 'utf8'));
      if (Array.isArray(arr)) {
        keyStore = arr
          .filter((k) => k && typeof k.secret === 'string')
          .map((k, i) => ({
            id: k.id || 'k' + Date.now().toString(36) + i,
            name: String(k.name || '未命名'),
            secret: k.secret,
            encoding: ['utf8', 'base64', 'hex'].includes(k.encoding) ? k.encoding : 'utf8',
          }));
        return;
      }
    }
  } catch (err) {
    console.error('[ warn ] 密钥文件读取失败，使用默认字典：', err.message);
  }
  keyStore = DEFAULT_KEYS.map((k, i) => ({
    id: 'default' + i,
    name: k.name,
    secret: k.secret,
    encoding: k.encoding,
  }));
  saveKeys();
}

/** 大字典异步写盘，避免阻塞事件循环 */
function saveKeys() {
  try {
    if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFile(KEYS_FILE, JSON.stringify(keyStore), 'utf8', (err) => {
      if (err) console.error('[ error ] 密钥文件写入失败：', err.message);
    });
    return true;
  } catch (err) {
    console.error('[ error ] 密钥文件写入失败：', err.message);
    return false;
  }
}

function maskKey({ id, name, secret, encoding }) {
  return {
    id,
    name,
    encoding,
    secret,
    preview: secret.length > 12 ? secret.slice(0, 6) + '…' + secret.slice(-4) : '•'.repeat(Math.max(secret.length, 4)),
    length: secret.length,
  };
}

/** 分页 + 关键词搜索，避免返回整份字典把前端卡死 */
function pageKeys(q, limit, offset) {
  const kw = String(q || '').trim().toLowerCase();
  const list = kw
    ? keyStore.filter((k) => k.name.toLowerCase().includes(kw) || k.secret.toLowerCase().includes(kw))
    : keyStore;
  const lim = Math.min(Math.max(Number(limit) || 100, 1), 500);
  const off = Math.max(Number(offset) || 0, 0);
  return { keys: list.slice(off, off + lim).map(maskKey), total: list.length, limit: lim, offset: off };
}

/* ---------------- HTTP ---------------- */

function sendJson(res, code, data) {
  const body = JSON.stringify(data);
  res.writeHead(code, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
  });
  res.end(body);
}

function readBody(req, limit, raw) {
  const max = limit || 1024 * 1024;
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > max) {
        reject(new Error('内容超过 ' + Math.round(max / 1048576) + 'MB 上限，请拆分文件或调大 JWT_MAX_UPLOAD_MB'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      const text = Buffer.concat(chunks).toString('utf8');
      if (raw) return resolve(text);
      if (!text) return resolve({});
      try {
        resolve(JSON.parse(text));
      } catch (err) {
        reject(new Error('请求体不是合法 JSON'));
      }
    });
    req.on('error', reject);
  });
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.json': 'application/json; charset=utf-8',
};

function serveStatic(req, res, urlPath) {
  let rel = decodeURIComponent(urlPath.split('?')[0]);
  if (rel === '/' || rel === '') rel = '/index.html';
  const target = path.join(PUBLIC_DIR, path.normalize(rel).replace(/^([/\\])+/, ''));
  if (!target.startsWith(PUBLIC_DIR)) {
    res.writeHead(403).end('Forbidden');
    return;
  }
  fs.readFile(target, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }).end('404 Not Found');
      return;
    }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(target).toLowerCase()] || 'application/octet-stream', 'Cache-Control': 'no-cache' });
    res.end(data);
  });
}

async function handleApi(req, res, urlPath, method) {
  const route = urlPath.replace(/^\/api/, '').split('?')[0];
  const query = new URL(req.url, 'http://localhost').searchParams;

  if (route === '/decode' && method === 'POST') {
    const body = await readBody(req);
    return sendJson(res, 200, { ok: true, data: parseToken(body.token) });
  }

  if (route === '/keys') {
    if (method === 'GET') {
      return sendJson(res, 200, { ok: true, data: pageKeys(query.get('q'), query.get('limit'), query.get('offset')) });
    }
    if (method === 'POST') {
      const body = await readBody(req);
      const secret = typeof body.secret === 'string' ? body.secret : '';
      if (!secret) return sendJson(res, 400, { ok: false, error: '密钥不能为空' });
      if (keyStore.length >= MAX_KEYS) return sendJson(res, 400, { ok: false, error: '字典已达上限 ' + MAX_KEYS + ' 条' });
      keyStore.push({
        id: 'k' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
        name: String(body.name || '未命名密钥').slice(0, 60),
        secret,
        encoding: ['utf8', 'base64', 'hex'].includes(body.encoding) ? body.encoding : 'utf8',
      });
      saveKeys();
      return sendJson(res, 200, { ok: true, data: pageKeys(body.q, body.limit, body.offset) });
    }
    if (method === 'DELETE') {
      const body = await readBody(req).catch(() => ({}));
      const before = keyStore.length;
      keyStore = keyStore.filter((k) => k.id !== body.id);
      saveKeys();
      return sendJson(res, 200, { ok: true, data: pageKeys(body.q, body.limit, body.offset), removed: before - keyStore.length });
    }
    if (method === 'PUT') {
      const body = await readBody(req);
      const item = keyStore.find((k) => k.id === body.id);
      if (!item) return sendJson(res, 404, { ok: false, error: '密钥不存在' });
      if (typeof body.name === 'string') item.name = body.name.slice(0, 60);
      if (typeof body.secret === 'string' && body.secret) item.secret = body.secret;
      if (['utf8', 'base64', 'hex'].includes(body.encoding)) item.encoding = body.encoding;
      saveKeys();
      return sendJson(res, 200, { ok: true, data: pageKeys(body.q, body.limit, body.offset) });
    }
  }

  if (route === '/keys/import' && method === 'POST') {
    // 大文件直接以 text/plain 裸流上传（省掉 JSON 转义的一倍内存），参数走 query
    const isRaw = (req.headers['content-type'] || '').startsWith('text/plain');
    let content;
    let encoding;
    let dedupe;
    if (isRaw) {
      content = await readBody(req, MAX_UPLOAD_BYTES, true);
      encoding = query.get('encoding');
      dedupe = query.get('dedupe') !== 'false';
    } else {
      const body = await readBody(req, MAX_UPLOAD_BYTES);
      content = typeof body.content === 'string' ? body.content : '';
      encoding = body.encoding;
      dedupe = body.dedupe !== false;
    }
    if (!content.trim()) return sendJson(res, 400, { ok: false, error: '内容为空：请选择文件后导入' });
    const enc = ['utf8', 'base64', 'hex'].includes(encoding) ? encoding : 'utf8';

    const { items, problems } = parseKeyFile(content, enc);
    if (!items.length) return sendJson(res, 400, { ok: false, error: '没有解析到任何密钥', problems });

    const room = MAX_KEYS - keyStore.length;
    const existing = new Set(keyStore.map((k) => k.encoding + '\u0000' + k.secret));
    let imported = 0;
    let skipped = 0;
    let truncated = 0;

    for (let i = 0; i < items.length; i++) {
      const it = items[i];
      const sig = it.encoding + '\u0000' + it.secret;
      if (dedupe && existing.has(sig)) {
        skipped++;
        continue;
      }
      if (imported >= room) {
        truncated = items.length - i;
        break;
      }
      existing.add(sig);
      keyStore.push({
        id: 'k' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6) + i.toString(36),
        name: it.name,
        secret: it.secret,
        encoding: it.encoding,
      });
      imported++;
    }
    saveKeys();
    // 只回传统计，不回传整份字典（百万级字典回传会拖垮前端）
    return sendJson(res, 200, {
      ok: true,
      data: { imported, skipped, truncated, problems, total: keyStore.length },
    });
  }

  if (route === '/verify' && method === 'POST') {
    const body = await readBody(req);
    const parsed = parseToken(body.token);
    if (!parsed.valid) return sendJson(res, 400, { ok: false, error: parsed.errors[0] || '令牌无法解析', data: parsed });
    const only = Array.isArray(body.ids) && body.ids.length ? new Set(body.ids) : null;
    const candidates = keyStore.filter((k) => (only ? only.has(k.id) : true));

    // 分批让出事件循环，百万级字典不阻塞服务
    const matches = [];
    const BATCH = 5000;
    for (let i = 0; i < candidates.length; i += BATCH) {
      const end = Math.min(i + BATCH, candidates.length);
      for (let j = i; j < end; j++) {
        const k = candidates[j];
        const r = verifyWithSecret(parsed, k.secret, k.encoding);
        if (r.matched) matches.push({ id: k.id, name: k.name, encoding: k.encoding, alg: r.alg });
      }
      if (end < candidates.length) await new Promise((r) => setImmediate(r));
    }
    return sendJson(res, 200, { ok: true, data: { tried: candidates.length, matches } });
  }

  if (route === '/sign' && method === 'POST') {
    const body = await readBody(req);
    let headerObj = {};
    let payloadObj = {};
    try {
      headerObj = typeof body.header === 'string' ? JSON.parse(body.header || '{}') : body.header || {};
    } catch (err) {
      return sendJson(res, 400, { ok: false, error: 'header 不是合法 JSON：' + err.message });
    }
    try {
      payloadObj = typeof body.payload === 'string' ? JSON.parse(body.payload || '{}') : body.payload || {};
    } catch (err) {
      return sendJson(res, 400, { ok: false, error: 'payload 不是合法 JSON：' + err.message });
    }
    let secret = body.secret;
    let encoding = ['utf8', 'base64', 'hex'].includes(body.encoding) ? body.encoding : 'utf8';
    if (body.keyId) {
      const k = keyStore.find((x) => x.id === body.keyId);
      if (!k) return sendJson(res, 404, { ok: false, error: '指定的密钥不存在' });
      secret = k.secret;
      encoding = k.encoding;
    }
    if (typeof secret !== 'string' || !secret) {
      return sendJson(res, 400, { ok: false, error: '缺少密钥：请填写密钥或从字典中选择' });
    }
    const token = signToken(headerObj, payloadObj, secret, encoding, body.alg || 'HS256');
    return sendJson(res, 200, { ok: true, data: { token, alg: HMAC_ALGS[body.alg] ? body.alg : 'HS256', encoding } });
  }

  return sendJson(res, 404, { ok: false, error: '接口不存在' });
}

const server = http.createServer(async (req, res) => {
  const method = req.method || 'GET';
  const urlPath = (req.url || '/').split('#')[0];

  if (urlPath.startsWith('/api/')) {
    try {
      await handleApi(req, res, urlPath, method);
    } catch (err) {
      sendJson(res, 500, { ok: false, error: err.message || '服务端错误' });
    }
    return;
  }

  if (method === 'GET' || method === 'HEAD') {
    serveStatic(req, res, urlPath);
    return;
  }

  sendJson(res, 405, { ok: false, error: '方法不支持' });
});

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error('[ error ] 端口 ' + err.port + ' 已被占用，正在尝试下一个端口…');
    const next = Number(err.port) + 1;
    if (next - PORT < MAX_PORT_TRY) {
      setTimeout(() => server.listen(next, HOST), 200);
    } else {
      console.error('[ error ] 连续 ' + MAX_PORT_TRY + ' 个端口都被占用，请设置 PORT 环境变量后重试');
      process.exit(1);
    }
    return;
  }
  console.error('[ error ] 服务启动失败：', err.message);
  process.exit(1);
});

function openBrowser(url) {
  if (process.env.JWT_NO_OPEN === '1') return;
  const cmd = process.platform === 'win32' ? 'start "" "' + url + '"' : process.platform === 'darwin' ? 'open "' + url + '"' : 'xdg-open "' + url + '"';
  exec(cmd, () => {});
}

loadKeys();
server.listen(PORT, HOST, () => {
  const real = server.address().port;
  const url = 'http://' + HOST + ':' + real;
  console.log('');
  console.log('  JWT 工具已启动（仅本机访问，无任何外网请求）');
  console.log('  ➜  ' + url);
  console.log('  密钥字典文件：' + KEYS_FILE);
  console.log('  停止服务：Ctrl + C');
  console.log('');
  openBrowser(url);
});
