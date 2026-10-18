import express from 'express';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';

const PORT = process.env.PORT || 3000;
const KEY = process.env.VT_API_KEY || '';                 // optional: links + extra engine list
const DIR = process.env.DATA_DIR || '/tmp/safecheck';      // needs free space = your biggest file
const MB = 1024 * 1024;
const MAX_UPLOAD = Number(process.env.MAX_GB || 100) * 1024 * MB;
const VT = 'https://www.virustotal.com/api/v3';
const VT_MAX = 650 * MB;
const SINGLE = Number(process.env.SINGLE_MB || 3500) * MB; // ClamAV scans one file up to ~4 GB; bigger files are scanned in overlapping parts
const WIN = Number(process.env.WIN_MB || 1024) * MB;
const OVERLAP = Number(process.env.OVERLAP_MB || 64) * MB;
const PER_HOUR = Number(process.env.SCANS_PER_HOUR || 20);
const LOCAL = process.env.LOCAL_SCANNER !== 'off';         // 'off' = free mode: VirusTotal only

fs.mkdirSync(DIR, { recursive: true });
const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '10kb' }));
app.use(express.static('public'));

const hits = new Map();
function limit(req, res, next) {
  const now = Date.now(), list = (hits.get(req.ip) || []).filter(t => now - t < 3600e3);
  if (list.length >= PER_HOUR) return res.status(429).json({ error: `Limit reached: ${PER_HOUR} scans per hour. Try again later.` });
  list.push(now); hits.set(req.ip, list); next();
}

/* ---------- ClamAV ---------- */
function clam(file) {
  return new Promise(resolve => {
    const p = spawn('clamdscan', ['--no-summary', '--fdpass', file]);
    let out = '';
    p.stdout.on('data', d => out += d); p.stderr.on('data', d => out += d);
    p.on('error', e => resolve({ error: 'Scanner not available: ' + e.message }));
    p.on('close', code => {
      if (code === 1) { const m = out.match(/: (.+) FOUND/); resolve({ infected: true, name: m ? m[1] : 'Virus' }); }
      else if (code === 0) resolve({ infected: false });
      else resolve({ error: 'The scanner could not read this file. ' + out.slice(0, 200) });
    });
  });
}
async function clamBig(file, size) {
  const part = file + '.part';
  for (let s = 0; s < size; s += WIN - OVERLAP) {
    const e = Math.min(size, s + WIN) - 1;
    await new Promise((ok, no) => fs.createReadStream(file, { start: s, end: e }).on('error', no).pipe(fs.createWriteStream(part)).on('finish', ok).on('error', no));
    const r = await clam(part); fs.rmSync(part, { force: true });
    if (r.infected || r.error) return r;
    if (e === size - 1) break;
  }
  return { infected: false, parts: true };
}

/* ---------- VirusTotal (optional) ---------- */
async function vt(p, opts = {}) {
  if (!KEY) { const e = new Error('Link scanning needs a VirusTotal key on the server (VT_API_KEY).'); e.status = 400; throw e; }
  const r = await fetch(p.startsWith('http') ? p : VT + p, { ...opts, headers: { 'x-apikey': KEY, ...(opts.headers || {}) } });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) { const e = new Error(r.status === 429 ? 'VirusTotal is busy. Wait a minute and retry.' : (j?.error?.message || 'VirusTotal error')); e.status = r.status; throw e; }
  return j;
}
const fail = (res, e) => res.status(e.status && e.status < 600 ? e.status : 500).json({ error: e.message });

/* ---------- chunked upload: any size ---------- */
const uploads = new Map(), jobs = new Map();

app.post('/api/upload/start', limit, (req, res) => {
  const size = Number(req.body.size);
  if (!(size >= 0)) return res.status(400).json({ error: 'Bad file size' });
  if (size > MAX_UPLOAD) return res.status(413).json({ error: `This site accepts files up to ${MAX_UPLOAD / 1024 / MB} GB.` });
  if (!LOCAL && size > VT_MAX) return res.status(413).json({ error: 'Files over 650 MB can’t be uploaded here. Choose the file again and the page will check its fingerprint instead.' });
  const id = crypto.randomBytes(12).toString('hex'), file = path.join(DIR, id);
  fs.writeFileSync(file, '');
  uploads.set(id, { file, size, next: 0, got: 0, t: Date.now() });
  res.json({ id });
});

app.put('/api/upload/:id/:index', express.raw({ type: () => true, limit: '64mb' }), async (req, res) => {
  const u = uploads.get(req.params.id); if (!u) return res.status(404).json({ error: 'Upload expired. Start again.' });
  const idx = Number(req.params.index);
  if (idx < u.next) return res.json({ ok: true });                       // repeated chunk after a retry
  if (idx !== u.next) return res.status(409).json({ error: 'Chunk out of order' });
  try { await fs.promises.appendFile(u.file, req.body); u.next++; u.got += req.body.length; u.t = Date.now(); res.json({ ok: true }); }
  catch (e) { res.status(507).json({ error: 'The server ran out of disk space.' }); }
});

app.post('/api/upload/:id/finish', async (req, res) => {
  const u = uploads.get(req.params.id); if (!u) return res.status(404).json({ error: 'Upload expired. Start again.' });
  if (u.got !== u.size) return res.status(400).json({ error: 'The upload is incomplete. Try again.' });
  uploads.delete(req.params.id);
  const job = { status: 'scanning' }; jobs.set(req.params.id, job);
  res.json({ job: req.params.id });
  try {
    if (LOCAL) job.clam = u.size > SINGLE ? await clamBig(u.file, u.size) : await clam(u.file);
    if (job.clam?.error) { job.status = 'error'; job.error = job.clam.error; }
    else {
      if (KEY && u.size <= VT_MAX) {           // optional: also get the 70+ engine list for files up to 650 MB
        try {
          const target = u.size > 32 * MB ? (await vt('/files/upload_url')).data : VT + '/files';
          const form = new FormData(); form.append('file', await fs.openAsBlob(u.file), 'file');
          job.vtId = (await vt(target, { method: 'POST', body: form })).data.id;
        } catch (e) { job.vtNote = e.message; if (!LOCAL) throw e; }
      } else if (!LOCAL) throw new Error('This free version needs a VirusTotal key on the server (VT_API_KEY).');
      job.status = 'done';
    }
  } catch (e) { job.status = 'error'; job.error = e.message; }
  finally { fs.rm(u.file, { force: true }, () => {}); }
});

app.get('/api/job/:id', (req, res) => {
  const j = jobs.get(req.params.id); j ? res.json(j) : res.status(404).json({ error: 'Unknown scan' });
});

// delete abandoned uploads and old results
setInterval(() => {
  const now = Date.now();
  for (const [id, u] of uploads) if (now - u.t > 6 * 3600e3) { fs.rm(u.file, { force: true }, () => {}); uploads.delete(id); }
}, 600e3).unref();

app.get('/api/config', (req, res) => res.json({ local: LOCAL, vt: !!KEY }));

// Files over 650 MB: the browser sends only the SHA-256 fingerprint
app.get('/api/lookup/:hash', limit, async (req, res) => {
  try {
    const hash = req.params.hash.toLowerCase();
    if (!/^[a-f0-9]{64}$/.test(hash)) return res.status(400).json({ error: 'Bad fingerprint' });
    const a = (await vt('/files/' + hash)).data.attributes;
    const engines = Object.values(a.last_analysis_results || {}).map(r => ({ engine: r.engine_name, category: r.category, result: r.result }));
    res.json({ status: 'completed', stats: a.last_analysis_stats, engines, kind: 'file', report: 'https://www.virustotal.com/gui/file/' + hash });
  } catch (e) {
    if (e.status === 404) return res.status(404).json({ error: 'This file is over 650 MB, so it can’t be uploaded, and VirusTotal has never seen it before. Only well-known big files can be checked on the free version.' });
    fail(res, e);
  }
});

/* ---------- links ---------- */
app.post('/api/scan-url', limit, async (req, res) => {
  let u; try { u = new URL(String(req.body.url || '').trim()); if (!['http:', 'https:'].includes(u.protocol)) throw 0; }
  catch { return res.status(400).json({ error: 'Enter a full link starting with http:// or https://' }); }
  try {
    const j = await vt('/urls', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ url: u.href }) });
    res.json({ id: j.data.id });
  } catch (e) { fail(res, e); }
});

app.get('/api/analysis/:id', async (req, res) => {
  try {
    if (!/^[\w=-]+$/.test(req.params.id)) return res.status(400).json({ error: 'Bad id' });
    const j = await vt('/analyses/' + req.params.id), a = j.data.attributes, m = j.meta || {};
    const engines = Object.values(a.results || {}).map(r => ({ engine: r.engine_name, category: r.category, result: r.result }));
    const report = m.file_info?.sha256 ? 'https://www.virustotal.com/gui/file/' + m.file_info.sha256 : m.url_info?.id ? 'https://www.virustotal.com/gui/url/' + m.url_info.id : null;
    res.json({ status: a.status, stats: a.stats, engines, kind: m.file_info ? 'file' : 'url', report });
  } catch (e) { fail(res, e); }
});

app.listen(PORT, () => console.log('SafeCheck running on port ' + PORT));
