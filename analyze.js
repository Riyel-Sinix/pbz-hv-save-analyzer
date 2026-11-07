#!/usr/bin/env node
'use strict';
/*
 * PBZ 存档分析工具 — Phantom Blade Zero save analyzer (read-only).
 *
 *   node analyze.js [游戏目录] [--out report.html] [--open]
 *
 * Reads PBZSaveGame.sav (PBZS v3: AES-256-GCM + Oodle) and every backup in
 * 1RealTime / 2Hourly / 3Daily, and writes an HTML report: overview, per-boss
 * attempts / kills / deaths / best time, death timeline over play time.
 * The AES key is derived from PBZ.exe once and cached in key.txt.
 * Never writes to the game folder.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const oodle = require('./vendor/oodle');

const DEFAULT_GAME = 'D:\\Games\\Phantom Blade Zero';
const TOOL_DIR = __dirname;

// ------------------------------------------------------------------ args
const args = process.argv.slice(2);
let gameDir = DEFAULT_GAME, outFile = path.join(TOOL_DIR, 'report.html'), openAfter = false;
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--out') outFile = path.resolve(args[++i]);
  else if (args[i] === '--open') openAfter = true;
  else gameDir = args[i];
}

// ------------------------------------------------------------------ key
const MARKER = Buffer.from('sealed but block is PLAINTEXT', 'utf16le');
const KEY_SHA_PREFIX = 'cec857d9';

function findExe(dir) {
  for (const p of ['platform/steam/PBZ.exe', 'PBZ.exe', 'steam/PBZ.exe']) {
    const f = path.join(dir, p);
    if (fs.existsSync(f) && fs.statSync(f).size > 50e6) return f;
  }
  return null;
}

function deriveKey(exe) {
  const fd = fs.openSync(exe, 'r');
  try {
    const size = fs.fstatSync(fd).size, CH = 32 << 20;
    const buf = Buffer.alloc(CH + MARKER.length);
    for (let pos = 0; pos < size; pos += CH) {
      const n = fs.readSync(fd, buf, 0, Math.min(buf.length, size - pos), pos);
      let i = -1;
      while ((i = buf.subarray(0, n).indexOf(MARKER, i + 1)) !== -1) {
        if (i >= CH) break;
        const mat = Buffer.alloc(64);
        fs.readSync(fd, mat, 0, 64, pos + i + 66);
        if (crypto.createHash('sha256').update(mat).digest('hex').startsWith(KEY_SHA_PREFIX)) {
          const key = Buffer.alloc(32);
          for (let k = 0; k < 32; k++) key[k] = mat[k] ^ mat[32 + k];
          return key;
        }
      }
    }
  } finally { fs.closeSync(fd); }
  throw new Error('在 PBZ.exe 里没找到存档密钥（游戏版本变了？）');
}

function getKey() {
  const cache = path.join(TOOL_DIR, 'key.txt');
  if (fs.existsSync(cache)) {
    const k = Buffer.from(fs.readFileSync(cache, 'utf8').trim(), 'hex');
    if (k.length === 32) return k;
  }
  const exe = findExe(gameDir);
  if (!exe) throw new Error(`找不到 PBZ.exe：${gameDir}`);
  process.stdout.write('第一次运行，从 PBZ.exe 提取存档密钥…');
  const key = deriveKey(exe);
  fs.writeFileSync(cache, key.toString('hex'));
  console.log(' 完成');
  return key;
}

// ------------------------------------------------------------------ container
function openBlock(key, blk) {
  if (blk.length < 36 || blk.toString('latin1', 0, 4) !== 'PBZS') throw new Error('数据块头不对');
  const d = crypto.createDecipheriv('aes-256-gcm', key, blk.subarray(8, 20));
  d.setAuthTag(blk.subarray(20, 36));
  return Buffer.concat([d.update(blk.subarray(36)), d.final()]);
}

function readContainer(file, key) {
  const buf = fs.readFileSync(file);
  if (buf.toString('latin1', 0, 4) !== 'PBZS') throw new Error('不是 PBZS 存档');
  if (buf[4] !== 3) throw new Error(`不支持的存档版本 ${buf[4]}`);
  const dirLen = buf.readUInt32LE(8);
  const dir = openBlock(key, buf.subarray(12, 12 + dirLen));
  const base = 12 + dirLen, slots = {};
  let p = 12;
  while (p + 2 <= dir.length) {
    const nl = dir.readUInt16LE(p); p += 2;
    const name = dir.toString('utf8', p, p + nl); p += nl;
    const alg = dir[p], raw = dir.readUInt32LE(p + 2), off = dir.readUInt32LE(p + 6), size = dir.readUInt32LE(p + 10);
    p += 14;
    try {
      let b = openBlock(key, buf.subarray(base + off, base + off + size));
      if (alg === 2) b = Buffer.from(oodle.decompress(new Uint8Array(b), raw));
      else if (alg === 1) b = require('zlib').inflateSync(b);
      slots[name] = JSON.parse(b.toString('utf8').replace(/^\uFEFF/, '').replace(/\0+$/, ''));
    } catch (e) { slots[name] = { __error: e.message }; }
  }
  return slots;
}

// ------------------------------------------------------------------ save discovery
function findSaveDirs(dir) {
  const root = path.join(dir, 'ProjectPBZ', 'Saved', 'SaveGames');
  const out = [];
  const visit = (d, depth) => {
    if (!fs.existsSync(d) || depth > 3) return;
    if (fs.existsSync(path.join(d, 'PBZSaveGame.sav'))) out.push(d);
    for (const e of fs.readdirSync(d, { withFileTypes: true }))
      if (e.isDirectory() && !/^\d(RealTime|Hourly|Daily)$/.test(e.name)) visit(path.join(d, e.name), depth + 1);
  };
  visit(root, 0);
  const local = path.join(process.env.LOCALAPPDATA || '', 'ProjectPBZ', 'Saved', 'SaveGames');
  if (!out.length) visit(local, 0);
  return out;
}

// ------------------------------------------------------------------ names
let NAMES = {};
try { NAMES = JSON.parse(fs.readFileSync(path.join(TOOL_DIR, 'names.json'), 'utf8')); } catch { }
// → { name, title, en, note }
function bossInfo(cls) {
  const short = cls.replace(/^BP_Monster_/, '').replace(/_C$/, '');
  const norm = (v, suffix) => {
    const o = typeof v === 'string' ? { name: v } : { name: v['名字'] || v.name || short, title: v['称号'] || v.title || '', en: v['英文'] || v.en || '', note: v['备注'] || v.note || '' };
    if (suffix) o.title = [o.title, suffix].filter(Boolean).join(' · ');
    return o;
  };
  if (NAMES[cls]) return norm(NAMES[cls]);
  if (NAMES[short]) return norm(NAMES[short]);
  const parts = short.split('_');   // prefix match: AHua_GuiTouDao -> AHua
  for (let n = parts.length - 1; n > 0; n--) {
    const k = parts.slice(0, n).join('_');
    if (NAMES[k]) return norm(NAMES[k], parts.slice(n).join('_'));
  }
  return { name: short, title: '', en: '', note: '未命名，可在 names.json 里补' };
}
const bossName = (cls) => bossInfo(cls).name;

// ------------------------------------------------------------------ analysis
const fmtTime = (s) => { s = Math.round(s); const h = Math.floor(s / 3600), m = Math.floor(s % 3600 / 60); return h ? `${h}小时${m}分` : `${m}分${s % 60}秒`; };
const fmtMs = (ms) => { if (!ms && ms !== 0) return '—'; const s = ms / 1000; return `${Math.floor(s / 60)}:${(s % 60).toFixed(1).padStart(4, '0')}`; };
const isGameSlot = (n) => /^(AutoSave|ManualSave)\d+$/.test(n);

function bossTable(bossRecord) {
  const rows = [];
  for (const [cls, b] of Object.entries(bossRecord || {})) {
    let attempts = 0, kills = 0, best = null; const recs = [];
    for (const [rk, r] of Object.entries(b.Records || {})) {
      attempts += r.AttemptCount || 0; kills += r.KillCount || 0;
      if (r.BestTimeMs && (best === null || r.BestTimeMs < best)) best = r.BestTimeMs;
      recs.push(rk);
    }
    const info = bossInfo(cls);
    rows.push({ cls, name: info.name, title: info.title, en: info.en, note: info.note, attempts, kills, deaths: Math.max(0, attempts - kills), best, recs, path: b.ClassPath || '' });
  }
  rows.sort((a, b) => b.deaths - a.deaths || b.attempts - a.attempts);
  return rows;
}

function snapshot(slot) {
  const g = slot.PBZGameSystem || {};
  return {
    dt: g.DateTimeString || '',
    time: g.HasGameTime || 0,
    deaths: (slot.PBZDeathMeta || {}).DiedTimes || 0,
    bosses: bossTable(slot.BossRecord),
  };
}

function main() {
  const key = getKey();
  const dirs = findSaveDirs(gameDir);
  if (!dirs.length) throw new Error(`没找到 PBZSaveGame.sav（${gameDir}）`);
  const saveDir = dirs[0];
  const main = readContainer(path.join(saveDir, 'PBZSaveGame.sav'), key);

  const slotNames = Object.keys(main).filter(isGameSlot);
  const slotInfo = slotNames.map((n) => ({ name: n, s: main[n] })).filter((x) => !x.s.__error);
  slotInfo.sort((a, b) => (b.s.PBZGameSystem?.DateTimeString || '').localeCompare(a.s.PBZGameSystem?.DateTimeString || '') || (b.s.PBZGameSystem?.HasGameTime || 0) - (a.s.PBZGameSystem?.HasGameTime || 0));
  if (!slotInfo.length) throw new Error('存档里没有可读的游戏存档位');
  const latestName = main.__Advanced__?.LastContinueSlot && main[main.__Advanced__.LastContinueSlot] && !main[main.__Advanced__.LastContinueSlot].__error
    ? main.__Advanced__.LastContinueSlot : slotInfo[0].name;
  const cur = main[latestName];
  const g = cur.PBZGameSystem || {};

  // timeline from every slot of every file (main + backups), deduped by DateTimeString+time
  const seen = new Map();
  const addSnap = (slot) => { const sn = snapshot(slot); const k = sn.dt + '|' + sn.time; if (sn.dt && !seen.has(k)) seen.set(k, sn); };
  for (const x of slotInfo) addSnap(x.s);
  let backupFiles = 0, backupErrors = 0;
  for (const sub of ['1RealTime', '2Hourly', '3Daily']) {
    const d = path.join(saveDir, sub);
    if (!fs.existsSync(d)) continue;
    for (const f of fs.readdirSync(d).filter((f) => f.endsWith('.sav'))) {
      try {
        const c = readContainer(path.join(d, f), key); backupFiles++;
        for (const [n, s] of Object.entries(c)) if (isGameSlot(n) && !s.__error) addSnap(s);
      } catch { backupErrors++; }
    }
  }
  // only keep the line of play that leads to the current save (same or less time and deaths)
  const timeline = [...seen.values()].filter((s) => s.time <= (g.HasGameTime || 0)).sort((a, b) => a.time - b.time || a.deaths - b.deaths);

  // first kill time of each boss
  const firstKill = {};
  for (const s of timeline) for (const b of s.bosses) if (b.kills > 0 && !(b.cls in firstKill)) firstKill[b.cls] = s;

  const bosses = bossTable(cur.BossRecord);
  for (const b of bosses) b.firstKill = firstKill[b.cls] || null;
  const totalDeaths = (cur.PBZDeathMeta || {}).DiedTimes || 0;
  const bossDeaths = bosses.reduce((a, b) => a + b.deaths, 0);
  const otherDeaths = Math.max(0, totalDeaths - bossDeaths);

  const ach = main.__Achievements__?.UnlockedIds || [];
  const codex = main.__Advanced__?.Codex || {};
  const p = cur.Player || {};

  const data = {
    file: path.join(saveDir, 'PBZSaveGame.sav'), latestName, dt: g.DateTimeString, playTime: g.HasGameTime || 0,
    cycle: g.CycleCount || 0, difficulty: g.DifficultModeByte, level: g.CurrentLevelName, finished: !!g.bIsFinishGame,
    totalDeaths, bossDeaths, otherDeaths, bosses, timeline, dust: p.Dust, days: p.RemainingDays,
    achievements: ach.length, enemies: (codex.DiscoveredEnemies || []).length,
    slots: slotInfo.map((x) => ({ name: x.name, ...snapshot(x.s), level: x.s.PBZGameSystem?.CurrentLevelName })),
    backupFiles, backupErrors,
  };

  printConsole(data);
  fs.writeFileSync(outFile, renderHtml(data), 'utf8');
  console.log(`\n报告已生成：${outFile}`);
  if (openAfter) require('child_process').exec(`start "" "${outFile}"`);
}

// ------------------------------------------------------------------ console
function printConsole(d) {
  const w = (s, n) => { s = String(s); let len = 0; for (const c of s) len += /[⺀-鿿豈-﫿＀-｠]/.test(c) ? 2 : 1; return s + ' '.repeat(Math.max(0, n - len)); };
  console.log(`存档：${d.latestName}  ${d.dt}  地图 ${d.level}`);
  console.log(`游戏时长 ${fmtTime(d.playTime)}  周目 ${d.cycle + 1}  难度 ${d.difficulty}  死亡 ${d.totalDeaths} 次  尘 ${d.dust ?? '—'}  剩余天数 ${d.days ?? '—'}`);
  console.log('');
  console.log(w('BOSS', 28) + w('尝试', 6) + w('击败', 6) + w('死亡', 6) + '最快');
  for (const b of d.bosses) console.log(w(b.name + (b.title ? "（" + b.title + "）" : ""), 28) + w(b.attempts, 6) + w(b.kills, 6) + w(b.deaths, 6) + fmtMs(b.best));
  console.log(w('其他（小怪、摔落等）', 28) + w('', 12) + w(d.otherDeaths, 6));
}

// ------------------------------------------------------------------ html
// Style: the schedule site's William Blake "Songs of Innocence and of Experience" look —
// light = Innocence (morning wash, sky blue, primrose), dark = Experience (night, Prussian
// blue, forge fire). LXGW WenKai for Chinese and digits, IM Fell English italics for Latin.
const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

// Verses (public domain, Blake 1794) — Experience side suits a death ledger.
const VERSES = [
  ['Tyger Tyger, burning bright,', 'In the forests of the night;', 'What immortal hand or eye,', 'Could frame thy fearful symmetry?', 'The Tyger'],
  ['When the stars threw down their spears', 'And water’d heaven with their tears:', 'Did he smile his work to see?', 'Did he who made the Lamb make thee?', 'The Tyger'],
  ['Ah Sun-flower! weary of time,', 'Who countest the steps of the Sun:', 'Seeking after that sweet golden clime', 'Where the travellers journey is done.', 'Ah! Sun-flower'],
];

function deathChart(tl, bosses) {
  if (tl.length < 2) return '<p class="muted">存档快照不够，画不出曲线（多玩一会儿，游戏会自动备份）。</p>';
  const W = 860, H = 270, L = 40, R = 18, T = 18, B = 34;
  const maxT = Math.max(...tl.map((s) => s.time)) || 1, maxD = Math.max(1, ...tl.map((s) => s.deaths));
  const x = (t) => L + (W - L - R) * t / maxT, y = (v) => T + (H - T - B) * (1 - v / maxD);
  const f = (n) => n.toFixed(1);
  const pts = tl.map((s) => [x(s.time), y(s.deaths)]);
  const line = pts.map((p, i) => (i ? 'L' : 'M') + f(p[0]) + ' ' + f(p[1])).join('');
  const area = line + `L${f(pts[pts.length - 1][0])} ${H - B}L${f(pts[0][0])} ${H - B}Z`;
  let grid = '';
  const step = Math.max(1, Math.ceil(maxD / 5));
  for (let v = 0; v <= maxD; v += step) grid += `<path d="M${L} ${f(y(v))}H${W - R}" class="grid"/><text x="${L - 8}" y="${f(y(v) + 4)}" class="ax" text-anchor="end">${v}</text>`;
  const hStep = maxT > 4 * 3600 ? 3600 : maxT > 3600 ? 1800 : 600;
  for (let t = 0; t <= maxT; t += hStep) grid += `<text x="${f(x(t))}" y="${H - 10}" class="ax" text-anchor="middle">${t >= 3600 ? (t / 3600).toFixed(t % 3600 ? 1 : 0) + ' 时' : Math.round(t / 60) + ' 分'}</text>`;
  let marks = '';
  const used = [];
  for (const b of bosses) if (b.firstKill) {
    const cx = x(b.firstKill.time), cy = y(b.firstKill.deaths);
    const dup = used.some((u) => u[3] === b.name && Math.abs(u[4] - cx) < 3);
    const wd = 13 * b.name.length + 4, left = cx + 5 + wd > W - R;
    const x0 = left ? cx - 5 - wd : cx, x1 = left ? cx : cx + 5 + wd;
    let ly = T + 12; while (used.some((u) => u[2] === ly && u[0] < x1 + 6 && x0 < u[1] + 6)) ly += 18;
    if (!dup) used.push([x0, x1, ly, b.name, cx]);
    marks += `<g class="mark"><path d="M${f(cx)} ${ly + 4}V${H - B}"/>
      <path transform="translate(${f(cx)} ${f(cy)})" d="M0 -7L2 -2L7 0L2 2L0 7L-2 2L-7 0L-2 -2Z" class="star"/>
      ${dup ? '' : left ? `<text x="${f(cx - 5)}" y="${ly}" class="ml" text-anchor="end">${esc(b.name)}</text>` : `<text x="${f(cx + 5)}" y="${ly}" class="ml">${esc(b.name)}</text>`}
      <title>${esc(b.name)} 首次击败 · 游戏时长 ${fmtTime(b.firstKill.time)} · 当时累计死亡 ${b.firstKill.deaths}</title></g>`;
  }
  const dots = tl.map((s) => `<circle cx="${f(x(s.time))}" cy="${f(y(s.deaths))}" r="2.6" class="dot"><title>${esc(s.dt)} · 时长 ${fmtTime(s.time)} · 死亡 ${s.deaths}</title></circle>`).join('');
  return `<svg viewBox="0 0 ${W} ${H}" class="chart" role="img" aria-label="死亡曲线">
    <defs><linearGradient id="wash" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="var(--f1)" stop-opacity=".28"/><stop offset="1" stop-color="var(--f1)" stop-opacity="0"/></linearGradient></defs>
    ${grid}<path d="${area}" fill="url(#wash)" filter="url(#wob)"/><path d="${line}" class="line" filter="url(#wob)"/>${dots}${marks}</svg>`;
}

function renderHtml(d) {
  const maxDeath = Math.max(1, ...d.bosses.map((b) => b.deaths), d.otherDeaths);
  const bar = (v, cls = '') => `<div class="bar ${cls}"><span style="width:${Math.max(v ? 3 : 0, 100 * v / maxDeath).toFixed(1)}%"></span></div>`;
  const hue = (i) => [8, 28, 345, 200, 150, 260, 45][i % 7];
  const rows = d.bosses.map((b, i) => `<div class="boss" style="--h:${hue(i)}">
      <div class="bn"><div class="tt">${b.title ? `<span class="ti">${esc(b.title)}</span>` : ''}<b>${esc(b.name)}</b></div>
        <div class="en">${esc(b.en || b.cls)}</div>${b.note ? `<div class="nt">${esc(b.note)}</div>` : ''}</div>
      <div class="num"><b>${b.attempts}</b><span>尝试</span></div>
      <div class="num"><b>${b.kills}</b><span>击败</span></div>
      <div class="num death"><b>${b.deaths}</b><span>死亡</span></div>
      <div class="bc">${bar(b.deaths)}<div class="sub"><span>胜率 ${b.attempts ? Math.round(100 * b.kills / b.attempts) + '%' : '—'}</span><span>最快 ${fmtMs(b.best)}</span>${b.firstKill ? `<span>首杀于 ${fmtTime(b.firstKill.time)}</span>` : ''}</div></div>
    </div>`).join('');
  const other = `<div class="boss other">
      <div class="bn"><div class="tt"><b>其他</b></div><div class="en">小怪、精英、摔落、陷阱</div></div>
      <div class="num"></div><div class="num"></div>
      <div class="num death"><b>${d.otherDeaths}</b><span>死亡</span></div>
      <div class="bc">${bar(d.otherDeaths, 'gray')}<div class="sub">总死亡 − BOSS 死亡</div></div></div>`;
  const slotRows = d.slots.map((s) => `<tr${s.name === d.latestName ? ' class="cur"' : ''}><td>${esc(s.name)}${s.name === d.latestName ? ' <span class="htag">当前</span>' : ''}</td><td>${esc(s.dt.replace(/^(\d+)\.(\d+)\.(\d+)-(\d+)\.(\d+)\.\d+$/, '$2 月 $3 日 $4:$5'))}</td><td class="n">${fmtTime(s.time)}</td><td class="n">${s.deaths}</td><td class="n">${s.bosses.filter((b) => b.kills).length}</td></tr>`).join('');
  const hardest = d.bosses[0];
  const v = VERSES[d.totalDeaths % VERSES.length];
  const card = (k, val, sub, c) => `<div class="card" style="--c:${c}"><div class="k">${k}</div><div class="cd">${val}</div>${sub ? `<div class="s">${sub}</div>` : ''}</div>`;
  const dtNice = (d.dt || '').replace(/^(\d+)\.(\d+)\.(\d+)-(\d+)\.(\d+)\.\d+$/, '$1 年 $2 月 $3 日 $4:$5');
  return `<!doctype html><html lang="zh-CN" data-theme="light"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>影之刃零 · 存档志</title>
<script>(function(){var t;try{t=localStorage.getItem('pbz.theme')}catch(e){}if(!t)t=matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light';document.documentElement.dataset.theme=t})()</script>
<style>
@font-face{font-family:"Songs Han";src:url(assets/wk-400.woff2) format("woff2");font-weight:400;font-display:swap}
@font-face{font-family:"Songs Han";src:url(assets/wk-500.woff2) format("woff2");font-weight:500 800;font-display:swap}
@font-face{font-family:"Songs Fell";src:url(assets/fell-r.woff2) format("woff2");font-style:normal;font-display:swap}
@font-face{font-family:"Songs Fell";src:url(assets/fell-i.woff2) format("woff2");font-style:italic;font-display:swap}
*{box-sizing:border-box;margin:0;padding:0}
:root{--sans:"Songs Han","LXGW WenKai","Kaiti SC","STKaiti","KaiTi",serif;--serif:"Songs Fell","IM Fell English",Georgia,serif;
  --hand:18px 7px 15px 9px / 9px 15px 7px 18px;--hand2:8px 16px 10px 18px / 16px 9px 18px 8px;--pill:255px 15px 225px 15px / 15px 225px 15px 255px}
[data-theme=light]{color-scheme:light;
  --sky-bg:linear-gradient(180deg,#A9C3CF 0%,#D7DDC2 30%,#EBDCA8 58%,#E6C9A6 100%);
  --washes:radial-gradient(45% 32% at 10% 4%,rgba(255,244,196,.95),transparent 70%),radial-gradient(55% 40% at 90% 10%,rgba(128,166,192,.55),transparent 70%),
    radial-gradient(45% 40% at 4% 82%,rgba(214,128,138,.30),transparent 70%),radial-gradient(60% 40% at 96% 94%,rgba(127,160,90,.40),transparent 70%);
  --bg2:#FBF5E3;--surface:rgba(251,245,227,.80);--surface2:rgba(255,250,236,.92);--edge:rgba(58,42,31,.40);
  --line:rgba(58,42,31,.20);--text:#3A2A1F;--muted:#6C5947;--faint:#9B8870;
  --accent:#3F6F95;--ochre:#A3562A;--f1:#B83A2C;--gt:#1F7A6A;--warn:#B8721C;
  --shadow:0 22px 44px -22px rgba(60,40,20,.45);--vine:#5D6F2C;--grain:.55}
[data-theme=dark]{color-scheme:dark;
  --sky-bg:linear-gradient(180deg,#121D33 0%,#1B2236 45%,#2B1F2A 75%,#3D2320 100%);
  --washes:radial-gradient(45% 26% at 50% 104%,rgba(232,118,46,.50),transparent 72%),radial-gradient(55% 36% at 8% 6%,rgba(58,92,146,.55),transparent 70%),
    radial-gradient(40% 36% at 94% 30%,rgba(104,52,84,.42),transparent 70%),radial-gradient(36% 22% at 82% 98%,rgba(200,70,40,.32),transparent 70%);
  --bg2:#1C1C29;--surface:rgba(20,21,31,.76);--surface2:rgba(34,33,48,.92);--edge:rgba(239,226,196,.28);
  --line:rgba(239,226,196,.16);--text:#EFE2C4;--muted:#C4B391;--faint:#8D8068;
  --accent:#9EC1E3;--ochre:#E8914A;--f1:#F0805F;--gt:#72CBB8;--warn:#E8A84A;
  --shadow:0 22px 44px -22px rgba(0,0,0,.7);--vine:#8E6C52;--grain:.35}
html{min-height:100%;background:var(--sky-bg)}
body{position:relative;min-height:100vh;color:var(--text);font-family:var(--sans);line-height:1.6;-webkit-font-smoothing:antialiased}
body::after{content:"";position:fixed;inset:0;z-index:-3;background:var(--washes),var(--sky-bg);pointer-events:none}
body::before{content:"";position:fixed;inset:0;background:url(assets/paper.svg);opacity:var(--grain);pointer-events:none;mix-blend-mode:multiply;z-index:-1}
[data-theme=dark] body::before{mix-blend-mode:screen}
button{font:inherit;color:inherit;background:none;border:0;cursor:pointer}
.defs{position:absolute;width:0;height:0}
.app{max-width:1000px;margin:0 auto;padding:56px 40px 40px}
.card,.panel{position:relative;isolation:isolate}
.card::after,.panel::after{content:"";position:absolute;inset:0;z-index:-1;border-radius:var(--hand);background:var(--surface);box-shadow:0 0 0 1.3px var(--edge),var(--shadow);filter:url(#wob);pointer-events:none}
.top{display:flex;align-items:flex-end;justify-content:space-between;gap:16px;margin-bottom:26px}
.motto{font-family:var(--serif);font-style:italic;font-size:19px;color:var(--ochre)}
.motto .bk{font-size:13px;color:var(--faint);margin-left:8px}
h1{font-size:46px;line-height:1.15;font-weight:500;letter-spacing:.06em}
h1 b{font-weight:500;color:var(--f1)}
.meta{margin-top:6px;color:var(--muted);font-size:15px}
.ibtn{height:38px;width:38px;border:1.3px solid var(--line);border-radius:var(--pill);background:var(--surface2);display:inline-flex;align-items:center;justify-content:center;color:var(--ochre);transition:transform .25s,border-color .2s}
.ibtn:hover{border-color:var(--edge);transform:rotate(-8deg)}
.cards{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:16px}
.card{padding:14px 16px 14px 24px}
.card::before{content:"";position:absolute;left:9px;top:15px;bottom:15px;width:5px;border-radius:5px 2px 6px 3px;background:var(--c,var(--accent));opacity:.75;filter:url(#wob)}
.card .k{font-size:13px;color:var(--muted)}
.card .cd{margin-top:4px;font-size:28px;font-weight:500;line-height:1.25;white-space:nowrap}
.card .cd small{font-size:14px;color:var(--muted);margin-left:2px}
.card .s{font-size:12.5px;color:var(--faint);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.card.big .cd{color:var(--f1)}
.note{position:relative;isolation:isolate;margin-top:22px;padding:14px 20px;font-size:15.5px}
.note::after{content:"";position:absolute;inset:0;z-index:-1;border-radius:var(--hand2);background:linear-gradient(160deg,rgba(214,96,70,.24),rgba(240,200,120,.14) 70%),var(--surface2);box-shadow:0 0 0 1.3px var(--edge);filter:url(#wob)}
.note b{color:var(--f1);font-weight:500}
.panel{margin-top:30px;padding:22px 24px}
.ph{display:flex;align-items:baseline;justify-content:space-between;gap:12px;margin-bottom:12px}
.ph h2{font-size:20px;font-weight:500}
.ph .en{font-family:var(--serif);font-style:italic;font-size:15px;color:var(--ochre)}
.boss{display:grid;grid-template-columns:minmax(0,1.6fr) 58px 58px 58px minmax(0,1.7fr);gap:12px;align-items:center;padding:13px 4px;border-top:1px dashed var(--line)}
.boss:first-of-type{border-top:0}
.bn .tt{display:flex;align-items:baseline;gap:8px;flex-wrap:wrap}
.bn .tt b{font-size:19px;font-weight:500}
.bn .ti{font-size:13px;padding:0 9px;border-radius:var(--pill);background:hsl(var(--h) 60% 55% / .16);color:hsl(var(--h) 45% 38%);border:1px solid hsl(var(--h) 45% 45% / .3)}
[data-theme=dark] .bn .ti{color:hsl(var(--h) 60% 74%)}
.bn .en{font-family:var(--serif);font-style:italic;font-size:14px;color:var(--faint);line-height:1.35}
.bn .nt{font-size:12px;color:var(--faint)}
.num{text-align:center;line-height:1.2}
.num b{display:block;font-size:22px;font-weight:500}
.num span{font-size:12px;color:var(--faint)}
.num.death b{color:var(--f1)}
.bar{height:11px;border-radius:7px 3px 8px 4px;background:var(--line);overflow:hidden}
.bar span{display:block;height:100%;border-radius:7px 3px 8px 4px;background:linear-gradient(90deg,var(--f1),var(--ochre));filter:url(#wob)}
.bar.gray span{background:var(--faint)}
.bc .sub{margin-top:5px;font-size:12.5px;color:var(--muted);display:flex;flex-wrap:wrap;column-gap:10px}
.bc .sub span{white-space:nowrap}
.boss.other .bn .tt b{color:var(--muted)}
.foot{margin-top:10px;font-size:12.5px;color:var(--faint)}
.chart{width:100%;height:auto;overflow:visible}
.chart .grid{stroke:var(--line);stroke-dasharray:2 5}
.chart .ax{fill:var(--faint);font-size:12px;font-family:var(--sans)}
.chart .line{fill:none;stroke:var(--text);stroke-width:2.2;stroke-linejoin:round;stroke-linecap:round}
.chart .dot{fill:var(--bg2);stroke:var(--text);stroke-width:1.3}
.chart .mark path:first-child{stroke:var(--f1);stroke-dasharray:3 4;stroke-width:1.2;opacity:.75}
.chart .star{fill:#E8BE55;stroke:var(--f1);stroke-width:1}
.chart .ml{fill:var(--f1);font-size:13px;font-family:var(--sans)}
table{width:100%;border-collapse:collapse;font-size:15px}
th{font-weight:500;font-size:13px;color:var(--faint);text-align:left;padding:4px 8px 8px;white-space:nowrap}
td{padding:9px 8px;border-top:1px dashed var(--line)}
td.n,th.n{text-align:right;white-space:nowrap}
tr.cur td{color:var(--text);background:rgba(232,190,85,.13)}
.htag{font-size:12px;padding:1px 9px;border-radius:var(--pill);background:rgba(214,128,138,.22);color:var(--f1);border:1px solid rgba(184,58,44,.25)}
.colophon{position:relative;isolation:isolate;margin:56px auto 20px;max-width:560px;text-align:center;font-family:var(--serif);font-style:italic;color:var(--muted)}
.colophon::before{content:"";position:absolute;inset:-26px -60px;z-index:-1;border-radius:50%;background:radial-gradient(closest-side,var(--bg2) 58%,transparent);opacity:.9;filter:url(#wob)}
.colophon .v{font-size:18.5px;line-height:1.7}
.colophon .src{margin-top:10px;font-size:13.5px;color:var(--faint)}
.colophon .fl{display:block;margin:0 auto 12px;color:var(--ochre);opacity:.75}
.path{margin-top:18px;text-align:center;font-size:12px;color:var(--faint);font-family:var(--sans);word-break:break-all}
@media (max-width:760px){
  .app{padding:34px 16px 30px}h1{font-size:34px}
  .cards{grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}
  .boss{grid-template-columns:repeat(3,1fr);gap:8px 6px}
  .boss .bn,.boss .bc{grid-column:1/-1}
  .panel{padding:18px 14px}
}
</style></head><body>
<svg class="defs" aria-hidden="true"><filter id="wob" x="-5%" y="-5%" width="110%" height="110%"><feTurbulence type="fractalNoise" baseFrequency=".014" numOctaves="2" seed="7"/><feDisplacementMap in="SourceGraphic" scale="4" xChannelSelector="R" yChannelSelector="G"/></filter></svg>
<div class="app">
<header class="top"><div>
  <div class="motto">Songs of Experience<span class="bk">· a ledger of the fallen</span></div>
  <h1>影之刃零 · <b>存档志</b></h1>
  <div class="meta">${esc(d.latestName)} · ${esc(dtNice)}${d.finished ? ' · 已通关' : ''}</div>
</div><button class="ibtn" id="themeBtn" title="天真 / 经验" aria-label="切换日间夜间">
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"><path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5Z"/></svg></button></header>

<section class="cards">
  ${card('总死亡', `${d.totalDeaths}<small>次</small>`, d.totalDeaths ? `平均 ${fmtTime(d.playTime / d.totalDeaths)} 一次` : '', 'var(--f1)').replace('class="card"', 'class="card big"')}
  ${card('游戏时长', fmtTime(d.playTime).replace('小时', '<small>时</small>').replace('分', '<small>分</small>').replace('秒', '<small>秒</small>'), `周目 ${d.cycle + 1} · 难度 ${esc(d.difficulty)}`, 'var(--accent)')}
  ${card('已击败 BOSS', `${d.bosses.filter((b) => b.kills).length}<small>位</small>`, `BOSS 战死亡 ${d.bossDeaths} 次`, 'var(--ochre)')}
  ${card('尘', esc(d.dust ?? '—'), `剩余 ${esc(d.days ?? '—')} 天 · 成就 ${d.achievements}`, 'var(--gt)')}
</section>
${hardest && hardest.deaths ? `<div class="note">最难缠的是${hardest.title ? `「${esc(hardest.title)}」` : ''}<b>${esc(hardest.name)}</b>：倒下 ${hardest.deaths} 次才斩落，占全部死亡的 ${Math.round(100 * hardest.deaths / Math.max(1, d.totalDeaths))}%。</div>` : ''}

<section class="panel"><div class="ph"><h2>BOSS 战绩</h2><span class="en">The Tyger &amp; the Lamb</span></div>
${rows}${other}
<div class="foot">死亡 = 尝试 − 击败（中途逃跑也算一次）。名字可在 names.json 里改。</div></section>

<section class="panel"><div class="ph"><h2>死亡曲线</h2><span class="en">the steps of the Sun</span></div>
${deathChart(d.timeline, d.bosses)}
<div class="foot">星标 = 首次击败该 BOSS 的时刻（悬停看详情）。来自主存档和 ${d.backupFiles} 个自动备份。</div></section>

<section class="panel"><div class="ph"><h2>存档位</h2><span class="en">Infant Joy</span></div>
<table><tr><th>存档位</th><th>保存时间</th><th class="n">时长</th><th class="n">死亡</th><th class="n">已斩 BOSS</th></tr>${slotRows}</table></section>

<footer class="colophon">
  <svg class="fl" width="120" height="22" viewBox="0 0 120 22" fill="none" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"><path d="M4 11C24 3 40 19 60 11S96 3 116 11"/><path d="M60 11c-4-6-1-9 0-10 1 1 4 4 0 10Z" fill="currentColor"/><circle cx="20" cy="9" r="1.6" fill="currentColor"/><circle cx="100" cy="9" r="1.6" fill="currentColor"/></svg>
  <div class="v">${v.slice(0, 4).map(esc).join('<br>')}</div>
  <div class="src">— William Blake, ${esc(v[4])}</div>
  <div class="path">只读分析，未改动存档 · ${esc(d.file)}</div>
</footer>
</div>
<script>document.getElementById('themeBtn').onclick=function(){var r=document.documentElement,t=r.dataset.theme==='dark'?'light':'dark';r.dataset.theme=t;try{localStorage.setItem('pbz.theme',t)}catch(e){}}</script>
</body></html>`;
}

try { main(); } catch (e) { console.error('出错：' + e.message); process.exit(1); }
