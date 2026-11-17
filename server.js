'use strict';
/* 毎朝5問｜理科・社会 — 公開Webアプリ版
   Node.js 標準機能のみ。データは JSON ファイルに保存する。
   画面: /(プレイヤー: 息子さん用) /admin(保護者用)
   連携: 毎朝の問題投入と毎晩の結果取得は x-agent-token ヘッダーで認証する。 */
const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const PORT = process.env.PORT || 8080;
const DATA_DIR = process.env.RAILWAY_VOLUME_MOUNT_PATH || process.env.DATA_DIR || __dirname;
const DATA_FILE = path.join(DATA_DIR, 'quiz-data.json');

/* ---------------- データ ---------------- */
function blankData() {
  return {
    adminPasswordHash: null,      // scrypt$hex$salt 形式
    playerPassHash: null,         // あいことば（プレイヤー用）
    agentTokenHash: null,         // 連携トークン（ハッシュで保存）
    playerTokens: [],             // プレイヤーのログイン済みトークン（ハッシュ）
    days: {},                     // 'YYYY-MM-DD': {questions:[], extraPool:[], answers:{}, extraSets:[[answers...]], extraUsed:0}
    tests: {},                    // weekStart 'YYYY-MM-DD': {attempts:[{date,correct,total,passed}], passed:false, lastPool:[qid...]}
  };
}
let data = blankData();
function loadData() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      const raw = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
      data = Object.assign(blankData(), raw);
    }
  } catch (e) { console.error('loadData error', e); }
}
function saveData() {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 1));
  } catch (e) { console.error('saveData error', e); }
}
loadData();

/* ---------------- 認証まわり ---------------- */
function hashSecret(secret) {
  const salt = crypto.randomBytes(16).toString('hex');
  const h = crypto.scryptSync(String(secret), salt, 32).toString('hex');
  return 'scrypt$' + h + '$' + salt;
}
function verifySecret(secret, stored) {
  if (!stored || typeof stored !== 'string') return false;
  const parts = stored.split('$');
  if (parts.length !== 3) return false;
  try {
    const h = crypto.scryptSync(String(secret), parts[2], 32).toString('hex');
    return crypto.timingSafeEqual(Buffer.from(h, 'hex'), Buffer.from(parts[1], 'hex'));
  } catch (e) { return false; }
}
function sha256(s) { return crypto.createHash('sha256').update(String(s)).digest('hex'); }
function newToken() { return crypto.randomBytes(24).toString('hex'); }

const adminSessions = new Map(); // token -> expiresAt
function isAdmin(req) {
  const t = (req.headers['authorization'] || '').replace(/^Bearer\s+/i, '');
  if (!t) return false;
  const exp = adminSessions.get(t);
  if (!exp || exp < Date.now()) { adminSessions.delete(t); return false; }
  return true;
}
function isAgent(req) {
  const t = req.headers['x-agent-token'];
  if (!t || !data.agentTokenHash) return false;
  return sha256(t) === data.agentTokenHash;
}
function isPlayer(req) {
  const t = (req.headers['authorization'] || '').replace(/^Bearer\s+/i, '');
  if (!t) return false;
  return data.playerTokens.includes(sha256(t));
}

/* ---------------- 日付（日本時間） ---------------- */
function jstNow() { return new Date(Date.now() + 9 * 3600 * 1000); }
function fmtDate(d) {
  const y = d.getUTCFullYear(), m = String(d.getUTCMonth() + 1).padStart(2, '0'), dd = String(d.getUTCDate()).padStart(2, '0');
  return y + '-' + m + '-' + dd;
}
function todayStr() { return fmtDate(jstNow()); }
function parseDate(s) { const p = s.split('-').map(Number); return new Date(Date.UTC(p[0], p[1] - 1, p[2])); }
function addDays(s, n) { const d = parseDate(s); d.setUTCDate(d.getUTCDate() + n); return fmtDate(d); }
function mondayOf(s) { const d = parseDate(s); const dow = (d.getUTCDay() + 6) % 7; d.setUTCDate(d.getUTCDate() - dow); return fmtDate(d); }
function lastSunday(s) { const d = parseDate(s); const dow = d.getUTCDay(); d.setUTCDate(d.getUTCDate() - dow); return fmtDate(d); } // 日曜なら当日
function validDateStr(s) { return /^\d{4}-\d{2}-\d{2}$/.test(s || ''); }

/* ---------------- 計算 ---------------- */
function dayOf(date) { return data.days[date] || null; }
function mainDone(day) {
  if (!day || !day.questions || day.questions.length === 0) return false;
  return day.questions.every((q) => day.answers && day.answers[q.id] != null);
}
function mainScore(day) {
  if (!day) return null;
  let c = 0, done = 0;
  (day.questions || []).forEach((q) => {
    const a = day.answers ? day.answers[q.id] : null;
    if (a != null) { done++; if (a === q.answer) c++; }
  });
  return { correct: c, answered: done, total: (day.questions || []).length };
}
function missedUnits(day) {
  if (!day) return [];
  const out = [];
  (day.questions || []).forEach((q) => {
    const a = day.answers ? day.answers[q.id] : null;
    if (a != null && a !== q.answer) out.push({ subject: q.subject, unit: q.unit });
  });
  return out;
}
function calcStreak() {
  let streak = 0;
  let d = todayStr();
  if (!mainDone(dayOf(d))) d = addDays(d, -1); // 今日が未実施なら昨日から数える
  while (mainDone(dayOf(d))) { streak++; d = addDays(d, -1); }
  return streak;
}
function unitStats() {
  const stats = {}; // key: subject|unit -> {subject, unit, attempts, correct}
  function add(q, chosen, include) {
    if (!include || chosen == null) return;
    const k = q.subject + '|' + q.unit;
    if (!stats[k]) stats[k] = { subject: q.subject, unit: q.unit, attempts: 0, correct: 0 };
    stats[k].attempts++;
    if (chosen === q.answer) stats[k].correct++;
  }
  Object.keys(data.days).forEach((date) => {
    const day = data.days[date];
    (day.questions || []).forEach((q) => add(q, day.answers ? day.answers[q.id] : null, true));
    (day.extraSets || []).forEach((set) => {
      (set.questions || []).forEach((q, i) => add(q, set.answers ? set.answers[i] : null, true));
    });
  });
  return Object.values(stats).sort((a, b) => (a.correct / a.attempts) - (b.correct / b.attempts));
}
function weeklyAccuracy() {
  const weeks = [];
  const thisMon = mondayOf(todayStr());
  for (let w = 0; w < 4; w++) {
    const mon = addDays(thisMon, -7 * w);
    let correct = 0;
    for (let i = 0; i < 7; i++) {
      const day = dayOf(addDays(mon, i));
      if (day) (day.questions || []).forEach((q) => {
        const a = day.answers ? day.answers[q.id] : null;
        if (a != null && a === q.answer) correct++;
      });
    }
    let days;
    if (w === 0) days = Math.floor((parseDate(todayStr()) - parseDate(mon)) / 86400000) + 1;
    else days = 7;
    weeks.push({ weekStart: mon, correct, days, rate: days > 0 ? correct / (days * 5) : 0 });
  }
  return weeks; // [今週, 先週, ...]
}
function recentMissedUnits(daysBack) {
  const out = {}; // unit -> {subject, unit, count, lastDate}
  const from = addDays(todayStr(), -daysBack);
  Object.keys(data.days).filter((d) => d >= from).forEach((date) => {
    missedUnits(data.days[date]).forEach((m) => {
      const k = m.subject + '|' + m.unit;
      if (!out[k]) out[k] = { subject: m.subject, unit: m.unit, count: 0, lastDate: date };
      out[k].count++; out[k].lastDate = date;
    });
  });
  return Object.values(out).sort((a, b) => b.count - a.count);
}
/* 週末テスト: 直近の日曜に終わる週（月〜日）が対象。日曜当日はその週。 */
function testWeek() {
  const sun = lastSunday(todayStr());
  const mon = addDays(sun, -6);
  return { weekStart: mon, weekEnd: sun };
}
function testPool(weekStart) {
  // その週の本編で間違えた問題（重複なし）
  const seen = {}, pool = [];
  for (let i = 0; i < 7; i++) {
    const day = dayOf(addDays(weekStart, i));
    if (!day) continue;
    (day.questions || []).forEach((q) => {
      const a = day.answers ? day.answers[q.id] : null;
      if (a != null && a !== q.answer && !seen[q.id]) { seen[q.id] = true; pool.push(q); }
    });
  }
  return pool;
}
function testState() {
  const { weekStart, weekEnd } = testWeek();
  const rec = data.tests[weekStart] || { attempts: [], passed: false, lastPool: null };
  let pool;
  if (rec.passed) pool = [];
  else if (rec.lastPool && rec.lastPool.length > 0) {
    const all = testPool(weekStart);
    pool = all.filter((q) => rec.lastPool.includes(q.id));
    if (pool.length === 0) pool = all;
  } else pool = testPool(weekStart);
  return { weekStart, weekEnd, available: pool.length > 0 && !rec.passed, passed: rec.passed, needless: testPool(weekStart).length === 0, pool, attempts: rec.attempts || [] };
}

/* ---------------- プレイヤー画面 ---------------- */
const PLAYER_HTML = `<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>毎朝5問｜理科・社会</title>
<style>
  * { box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
  body { margin:0; font-family: -apple-system, "Hiragino Kaku Gothic ProN", "Noto Sans JP", sans-serif; background:#f2f6f3; color:#21312a; }
  header { background:#1d9e4b; color:#fff; padding:14px 16px; position:sticky; top:0; z-index:5; }
  header .ttl { font-size:19px; font-weight:800; }
  header .sub { font-size:12.5px; opacity:.92; margin-top:2px; }
  main { max-width:640px; margin:0 auto; padding:14px 12px 40px; }
  .card { background:#fff; border-radius:14px; padding:16px; margin-bottom:14px; box-shadow:0 1px 3px rgba(0,0,0,.08); }
  .card h2 { font-size:16.5px; margin:0 0 10px; }
  button { font:inherit; border:none; border-radius:10px; padding:13px 18px; background:#1d9e4b; color:#fff; font-weight:700; font-size:16px; cursor:pointer; width:100%; }
  button.sub { background:#e8f3ec; color:#176b35; }
  button.ghost { background:#fff; color:#176b35; border:1.5px solid #bcd8c6; }
  button:disabled { opacity:.45; }
  .row { display:flex; gap:10px; } .row > * { flex:1; }
  .chip { display:inline-block; background:#e8f3ec; color:#176b35; border-radius:999px; padding:3px 11px; font-size:12.5px; font-weight:700; }
  .chip.fire { background:#fff3e0; color:#b26a00; }
  .tag { display:inline-block; font-size:12px; font-weight:700; border-radius:6px; padding:2px 8px; margin-right:6px; }
  .tag.sci { background:#e3f0ff; color:#1756a9; } .tag.soc { background:#ffeee0; color:#a3540a; }
  .qtext { font-size:17.5px; font-weight:700; line-height:1.65; margin:10px 0 14px; white-space:pre-wrap; }
  .choice { display:block; width:100%; text-align:left; background:#f4f8f5; color:#21312a; border:2px solid #d8e4dc; border-radius:12px; padding:14px; margin-bottom:10px; font-size:16px; font-weight:600; }
  .choice.correct { background:#e6f6ec; border-color:#1d9e4b; }
  .choice.wrong { background:#fdecec; border-color:#d64545; }
  .choice.dim { opacity:.55; }
  .explain { background:#fffbe8; border:1.5px solid #f0df9a; border-radius:12px; padding:14px; margin-top:12px; }
  .explain h3 { margin:0 0 8px; font-size:15px; }
  .explain .sec { margin-bottom:10px; line-height:1.7; font-size:14.5px; white-space:pre-wrap; }
  .explain .sec b { color:#176b35; }
  .explain svg { max-width:100%; height:auto; background:#fff; border-radius:8px; }
  .resultbig { font-size:34px; font-weight:800; text-align:center; margin:6px 0; }
  .center { text-align:center; }
  .hint { color:#6b7a72; font-size:13px; line-height:1.6; }
  .bar { background:#e6eee9; border-radius:999px; height:12px; overflow:hidden; }
  .bar > div { background:#1d9e4b; height:100%; }
  table { width:100%; border-collapse:collapse; font-size:14px; }
  th, td { padding:7px 6px; border-bottom:1px solid #e3eae6; text-align:left; }
  th { color:#5c6f66; font-size:12.5px; }
  .tabs { display:flex; gap:8px; margin-bottom:14px; }
  .tabs button { background:#fff; color:#40534a; box-shadow:0 1px 3px rgba(0,0,0,.08); padding:10px; font-size:15px; }
  .tabs button.on { background:#1d9e4b; color:#fff; }
  input.pass { width:100%; font:inherit; font-size:17px; padding:13px; border:2px solid #cfe0d6; border-radius:10px; margin-bottom:12px; }
  .miss { color:#c62828; font-weight:700; }
  .ok { color:#1d9e4b; font-weight:700; }
  .prog { font-size:13px; color:#6b7a72; font-weight:700; }
</style>
</head>
<body>
<header><div class="ttl">毎朝5問｜理科・社会</div><div class="sub" id="hdate"></div></header>
<main id="app"></main>
<script>
var token = localStorage.getItem('quiz_player_token') || '';
var S = null; // today state
var view = 'home';
var quiz = null; // {mode:'main'|'extra'|'test', list:[], idx, results:[], setIndex}

function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
function api(path, opts){
  opts = opts || {};
  opts.headers = Object.assign({'Content-Type':'application/json', 'Authorization':'Bearer '+token}, opts.headers||{});
  if (opts.body && typeof opts.body !== 'string') opts.body = JSON.stringify(opts.body);
  return fetch(path, opts).then(function(r){
    if (r.status === 401) { token=''; localStorage.removeItem('quiz_player_token'); renderGate('あいことばをもう一度入れてね'); throw new Error('auth'); }
    return r.json();
  });
}
function jstTodayLabel(){
  var d = new Date(Date.now() + 9*3600*1000);
  var w = ['日','月','火','水','木','金','土'][d.getUTCDay()];
  return d.getUTCFullYear()+'年'+(d.getUTCMonth()+1)+'月'+d.getUTCDate()+'日（'+w+'）';
}
document.getElementById('hdate').textContent = jstTodayLabel();

function renderGate(msg){
  view='gate';
  document.getElementById('app').innerHTML =
    '<div class="card"><h2>あいことばを入れてね</h2>' +
    (msg ? '<p class="hint">'+esc(msg)+'</p>' : '<p class="hint">おうちの人に聞いた「あいことば」を入力してください。</p>') +
    '<input class="pass" id="pass" type="text" autocomplete="off" placeholder="あいことば">' +
    '<button onclick="doLogin()">はじめる</button></div>';
}
function doLogin(){
  var p = document.getElementById('pass').value.trim();
  if (!p) return;
  fetch('/api/player/login', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({pass:p})})
    .then(function(r){ return r.json(); })
    .then(function(d){
      if (d && d.ok) { token = d.token; localStorage.setItem('quiz_player_token', token); loadToday(); }
      else renderGate('あいことばが違うみたい。もう一度確認してね');
    }).catch(function(){ renderGate('通信エラー。もう一度試してね'); });
}
function loadToday(){
  api('/api/player/today').then(function(d){ S = d; renderHome(); }).catch(function(e){ if (String(e)!=='Error: auth') document.getElementById('app').innerHTML='<div class="card">読み込みに失敗しました。電波のいいところでもう一度開いてね。</div>'; });
}

function tagHtml(q){ return '<span class="tag '+(q.subject==='理科'?'sci':'soc')+'">'+esc(q.subject)+'</span><span class="hint">'+esc(q.unit)+'</span>'; }

function renderHome(){
  view='home';
  var app = document.getElementById('app');
  if (!S) { app.innerHTML='<div class="card">読み込み中…</div>'; return; }
  var h = '';
  h += '<div class="tabs"><button class="on" onclick="renderHome()">今日</button><button onclick="renderRecords()">記録</button></div>';
  h += '<div class="card"><h2>今日の5問</h2>';
  h += '<p><span class="chip fire">🔥 '+S.streak+'日連続</span></p>';
  if (!S.hasQuestions) {
    h += '<p class="hint">今日の問題はまだ届いていません。朝6:30に用意されます。</p>';
  } else if (S.done) {
    h += '<div class="resultbig">'+S.score.correct+' / '+S.score.total+' 点</div>';
    if (S.missedUnits.length) h += '<p class="center">間違えた単元：'+S.missedUnits.map(function(m){return esc(m.subject)+'・'+esc(m.unit);}).join('、')+'</p>';
    else h += '<p class="center ok">全問正解！すごい！</p>';
    h += '<p><button class="sub" onclick="reviewMain()">解説を見直す</button></p>';
    h += '<p><button onclick="startExtra()">さらに続ける（追加5問）</button></p>';
    if (S.extra.setsDone>0) h += '<p class="hint center">追加問題は '+S.extra.setsDone+' セット解きました</p>';
  } else {
    var answered = S.questions.filter(function(q){return q.answered;}).length;
    h += '<p class="hint">'+(answered>0 ? ('途中まで解いています（'+answered+' / '+S.questions.length+' 問）') : '今日の入試レベル5問に挑戦しよう')+'</p>';
    h += '<p><button onclick="startMain()">'+(answered>0?'つづきから解く':'はじめる')+'</button></p>';
  }
  h += '</div>';
  if (S.test && (S.test.available || S.test.passed)) {
    h += '<div class="card"><h2>週末テスト</h2>';
    if (S.test.passed) h += '<p class="ok">✅ 合格済みです。よくがんばった！</p>';
    else h += '<p class="hint">先週間違えた問題のテストです（'+S.test.total+'問）。80%以上で合格！</p><p><button onclick="startTest()">テストを受ける</button></p>';
    h += '</div>';
  }
  app.innerHTML = h;
}

function startMain(){
  var list = S.questions.filter(function(q){return !q.answered;});
  if (list.length===0) { renderHome(); return; }
  quiz = {mode:'main', list:list, idx:0, results:[]};
  renderQuestion();
}
function reviewMain(){
  quiz = {mode:'review', list:S.questions, idx:0, results:[]};
  renderQuestion();
}
function startExtra(){
  api('/api/player/extra/start', {method:'POST', body:{}}).then(function(d){
    if (!d.ok) { alert(d.error || '追加問題はもうありません'); return; }
    quiz = {mode:'extra', list:d.questions, idx:0, results:[], setIndex:d.setIndex};
    renderQuestion();
  });
}
function startTest(){
  api('/api/player/test').then(function(d){
    if (!d.ok || !d.questions.length) { alert('テストは今ありません'); return; }
    quiz = {mode:'test', list:d.questions, idx:0, results:[]};
    renderQuestion();
  });
}

function renderQuestion(){
  var q = quiz.list[quiz.idx];
  var app = document.getElementById('app');
  var total = quiz.list.length;
  var h = '<div class="card">';
  h += '<div class="prog">'+(quiz.mode==='main'?'今日の5問':quiz.mode==='extra'?'追加問題':quiz.mode==='test'?'週末テスト':'見直し')+'　'+(quiz.idx+1)+' / '+total+' 問目</div>';
  h += '<div style="margin-top:8px">'+tagHtml(q)+'</div>';
  h += '<div class="qtext">'+esc(q.q)+'</div>';
  h += '<div id="choices">';
  q.choices.forEach(function(c,i){
    var cls = 'choice';
    if (q.answered) {
      if (i===q.answer) cls += ' correct';
      else if (i===q.chosen) cls += ' wrong';
      else cls += ' dim';
    }
    h += '<button class="'+cls+'" '+(q.answered?'disabled':'onclick="answer('+i+')"')+'>'+'①②③④'.charAt(i)+'　'+esc(c)+'</button>';
  });
  h += '</div><div id="card"></div>';
  if (q.answered) h += explainHtml(q);
  h += '</div>';
  app.innerHTML = h;
}
function explainHtml(q){
  var h = '<div class="explain"><h3>'+(q.chosen===q.answer ? '⭕ 正解！' : '❌ 正解は '+'①②③④'.charAt(q.answer))+'</h3>';
  h += '<div class="sec"><b>解説</b><br>'+esc(q.explanation)+'</div>';
  if (q.memoryTip) h += '<div class="sec"><b>覚え方ポイント</b><br>'+esc(q.memoryTip)+'</div>';
  if (q.diagram) h += '<div class="sec">'+q.diagram+'</div>';
  h += '<p style="margin:10px 0 0"><button onclick="nextQ()">'+(quiz.idx>=quiz.list.length-1?'結果を見る':'次の問題へ')+'</button></p></div>';
  return h;
}
function answer(i){
  var q = quiz.list[quiz.idx];
  var path = quiz.mode==='main' ? '/api/player/answer' : quiz.mode==='extra' ? '/api/player/extra/answer' : '/api/player/test/answer';
  var body = {qid:q.id, choice:i};
  if (quiz.mode==='extra') body.setIndex = quiz.setIndex;
  api(path, {method:'POST', body:body}).then(function(d){
    if (!d.ok) { alert(d.error||'エラー'); return; }
    q.answered = true; q.chosen = i; q.answer = d.answer; q.explanation = d.explanation; q.memoryTip = d.memoryTip; q.diagram = d.diagram;
    quiz.results.push({qid:q.id, choice:i, correct:d.correct});
    renderQuestion();
  });
}
function nextQ(){
  if (quiz.idx < quiz.list.length-1) { quiz.idx++; renderQuestion(); return; }
  if (quiz.mode==='main' || quiz.mode==='extra') {
    loadToday();
    return;
  }
  if (quiz.mode==='review') { loadToday(); return; }
  if (quiz.mode==='test') {
    api('/api/player/test/finish', {method:'POST', body:{results:quiz.results}}).then(function(d){
      var app = document.getElementById('app');
      var h = '<div class="card center"><h2>週末テスト結果</h2>';
      h += '<div class="resultbig">'+d.correct+' / '+d.total+'</div>';
      h += d.passed ? '<p class="ok" style="font-size:19px">🎉 合格！</p>' : '<p class="miss" style="font-size:17px">あと少し！80%で合格です</p><p class="hint">間違えた問題だけでもう一度テストします</p>';
      h += '<p><button onclick="loadToday()">ホームへ</button></p></div>';
      app.innerHTML = h;
    });
  }
}

function renderRecords(){
  view='records';
  var app = document.getElementById('app');
  var h = '<div class="tabs"><button onclick="renderHome()">今日</button><button class="on" onclick="renderRecords()">記録</button></div>';
  h += '<div class="card"><h2>週の正解率</h2>';
  S.week.forEach(function(w,i){
    var pct = Math.round(w.rate*100);
    h += '<p style="margin:8px 0 4px"><b>'+(i===0?'今週':w.weekStart.slice(5).replace('-','/')+'の週')+'</b>　'+pct+'%（'+w.correct+'問正解）</p>';
    h += '<div class="bar"><div style="width:'+pct+'%"></div></div>';
  });
  h += '<p class="hint">解かなかった日は0点で計算しています</p></div>';
  h += '<div class="card"><h2>単元ごとの正答率</h2>';
  if (!S.units.length) h += '<p class="hint">まだ記録がありません</p>';
  else {
    h += '<table><tr><th>単元</th><th>正答率</th><th>回数</th></tr>';
    S.units.forEach(function(u){
      var pct = Math.round(u.correct/u.attempts*100);
      h += '<tr><td>'+esc(u.subject)+'・'+esc(u.unit)+'</td><td>'+(pct<60?'<span class="miss">':'')+pct+'%'+(pct<60?'</span>':'')+'</td><td>'+u.correct+'/'+u.attempts+'</td></tr>';
    });
    h += '</table>';
  }
  h += '</div>';
  h += '<div class="card"><h2>これまでの結果</h2>';
  if (!S.history.length) h += '<p class="hint">まだ記録がありません</p>';
  else {
    h += '<table><tr><th>日付</th><th>スコア</th></tr>';
    S.history.forEach(function(dy){
      h += '<tr><td>'+dy.date.slice(5).replace('-','/')+'</td><td>'+(dy.done ? dy.correct+' / '+dy.total : '未実施')+'</td></tr>';
    });
    h += '</table>';
  }
  h += '</div>';
  app.innerHTML = h;
}

if (token) loadToday(); else renderGate('');
</script>
</body>
</html>`;

/* ---------------- 管理画面（保護者用） ---------------- */
const ADMIN_HTML = `<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>毎朝5問｜管理画面</title>
<style>
  body { margin:0; font-family:-apple-system,"Hiragino Kaku Gothic ProN","Noto Sans JP",sans-serif; background:#f2f6f3; color:#21312a; }
  main { max-width:680px; margin:0 auto; padding:16px 12px 40px; }
  .card { background:#fff; border-radius:14px; padding:16px; margin-bottom:14px; box-shadow:0 1px 3px rgba(0,0,0,.08); }
  h1 { font-size:20px; } h2 { font-size:16.5px; margin:0 0 10px; }
  button { font:inherit; border:none; border-radius:10px; padding:11px 16px; background:#1d9e4b; color:#fff; font-weight:700; cursor:pointer; }
  button.sub { background:#e8f3ec; color:#176b35; }
  input { width:100%; font:inherit; padding:11px; border:2px solid #cfe0d6; border-radius:10px; margin-bottom:10px; box-sizing:border-box; }
  table { width:100%; border-collapse:collapse; font-size:14px; }
  th, td { padding:7px 6px; border-bottom:1px solid #e3eae6; text-align:left; }
  th { color:#5c6f66; font-size:12.5px; }
  .hint { color:#6b7a72; font-size:13px; line-height:1.6; }
  .token { background:#fffbe8; border:1.5px solid #f0df9a; border-radius:10px; padding:12px; word-break:break-all; font-size:15px; font-weight:700; }
  .miss { color:#c62828; font-weight:700; } .ok { color:#1d9e4b; font-weight:700; }
</style>
</head>
<body>
<main id="app"></main>
<script>
var atoken = localStorage.getItem('quiz_admin_token') || '';
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
function api(path, opts){
  opts = opts || {};
  opts.headers = Object.assign({'Content-Type':'application/json','Authorization':'Bearer '+atoken}, opts.headers||{});
  if (opts.body && typeof opts.body !== 'string') opts.body = JSON.stringify(opts.body);
  return fetch(path, opts).then(function(r){ return r.json(); });
}
function renderAuth(mode, agentToken){
  var app = document.getElementById('app');
  var h = '<div class="card"><h1>毎朝5問｜管理画面</h1>';
  if (mode==='setup') h += '<p class="hint">最初に管理者パスワードを設定してください。</p><input type="password" id="pw" placeholder="パスワード"><button onclick="doSetup()">設定する</button>';
  else h += '<p class="hint">管理者パスワードを入力してください。</p><input type="password" id="pw" placeholder="パスワード"><button onclick="doLogin()">ログイン</button>';
  h += '</div>';
  if (agentToken) h += '<div class="card"><h2>イロ連携トークン（大切）</h2><p class="hint">このトークンをイロ（この管理画面ではなく、いつものチャット）に伝えてください。イロが毎朝の問題投入と毎晩の結果確認に使います。表示はこの1回だけです。</p><div class="token">'+esc(agentToken)+'</div></div>';
  app.innerHTML = h;
}
function doSetup(){
  var p = document.getElementById('pw').value;
  if (!p) return;
  fetch('/api/auth/setup', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({password:p})})
    .then(function(r){return r.json();}).then(function(d){
      if (d.ok) { atoken = d.token; localStorage.setItem('quiz_admin_token', atoken); renderDash(); showAgentToken(d.agentToken); }
      else alert(d.error||'エラー');
    });
}
function doLogin(){
  var p = document.getElementById('pw').value;
  fetch('/api/auth/login', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({password:p})})
    .then(function(r){return r.json();}).then(function(d){
      if (d.ok) { atoken = d.token; localStorage.setItem('quiz_admin_token', atoken); renderDash(); }
      else alert(d.error||'パスワードが違います');
    });
}
function showAgentToken(t){
  if (!t) return;
  var div = document.createElement('div');
  div.className = 'card';
  div.innerHTML = '<h2>イロ連携トークン（大切）</h2><p class="hint">このトークンをイロとのチャットで伝えてください。表示はこの1回だけです（忘れたら下の「再生成」で作り直せます）。</p><div class="token">'+esc(t)+'</div>';
  document.getElementById('app').prepend(div);
}
function renderDash(){
  api('/api/admin/state').then(function(d){
    if (!d.ok) { renderAuth('login'); return; }
    var app = document.getElementById('app');
    var h = '<div class="card"><h1>毎朝5問｜管理画面</h1>';
    var t = d.today;
    h += '<h2>今日（'+esc(t.date)+'）</h2>';
    if (!t.hasQuestions) h += '<p class="hint">今日の問題はまだ投入されていません（毎朝6:30にイロが入れます）。</p>';
    else if (t.done) h += '<p style="font-size:18px"><b>'+t.score.correct+' / '+t.score.total+' 点</b>　'+(t.missedUnits.length ? '間違えた単元：'+t.missedUnits.map(function(m){return esc(m.subject)+'・'+esc(m.unit);}).join('、') : '<span class="ok">全問正解</span>')+'</p>';
    else h += '<p class="hint">実施中または未実施です（'+t.score.answered+' / '+t.score.total+' 問回答済み）。</p>';
    h += '<p class="hint">連続実施：'+d.streak+'日</p></div>';
    h += '<div class="card"><h2>直近14日</h2><table><tr><th>日付</th><th>状態</th><th>スコア</th></tr>';
    d.history.forEach(function(x){ h += '<tr><td>'+x.date.slice(5).replace('-','/')+'</td><td>'+(x.done?'<span class="ok">実施済み</span>':(x.hasQuestions?'未実施':'問題なし'))+'</td><td>'+(x.done?x.correct+' / '+x.total:'-')+'</td></tr>'; });
    h += '</table></div>';
    h += '<div class="card"><h2>単元ごとの正答率</h2>';
    if (!d.units.length) h += '<p class="hint">まだ記録がありません</p>';
    else { h += '<table><tr><th>単元</th><th>正答率</th><th>回数</th></tr>';
      d.units.forEach(function(u){ var pct = Math.round(u.correct/u.attempts*100); h += '<tr><td>'+esc(u.subject)+'・'+esc(u.unit)+'</td><td>'+(pct<60?'<span class="miss">':'')+pct+'%'+(pct<60?'</span>':'')+'</td><td>'+u.correct+'/'+u.attempts+'</td></tr>'; });
      h += '</table>'; }
    h += '</div>';
    h += '<div class="card"><h2>週末テスト</h2>';
    if (!d.tests.length) h += '<p class="hint">まだ記録がありません</p>';
    d.tests.forEach(function(x){ h += '<p>'+x.weekStart.slice(5).replace('-','/')+'の週：'+(x.passed?'<span class="ok">合格</span>':'未合格')+'（'+x.attempts+'回受験）</p>'; });
    h += '</div>';
    h += '<div class="card"><h2>設定</h2>';
    h += '<p class="hint">あいことば（お子さんがアプリを開くときに入力する言葉）。現在：'+(d.settings.playerPassSet?'設定済み':'未設定')+'</p>';
    h += '<input type="text" id="newpass" placeholder="新しいあいことば"><button class="sub" onclick="setPass()">あいことばを設定する</button>';
    h += '<p class="hint" style="margin-top:14px">イロ連携トークンを作り直す（古いトークンは使えなくなります）</p><button class="sub" onclick="regen()">トークンを再生成する</button>';
    h += '</div>';
    app.innerHTML = h;
  });
}
function setPass(){
  var p = document.getElementById('newpass').value.trim();
  if (!p) return;
  api('/api/admin/settings', {method:'POST', body:{playerPass:p}}).then(function(d){
    if (d.ok) { alert('あいことばを設定しました。お子さんに伝えてください'); renderDash(); }
    else alert(d.error||'エラー');
  });
}
function regen(){
  if (!confirm('トークンを作り直します。新しいトークンをイロに伝えるまで、問題の自動投入と結果確認が止まります。よろしいですか？')) return;
  api('/api/admin/regen-token', {method:'POST', body:{}}).then(function(d){
    if (d.ok) { renderDash(); showAgentToken(d.agentToken); }
    else alert(d.error||'エラー');
  });
}
fetch('/api/auth/status').then(function(r){return r.json();}).then(function(d){
  if (!d.hasPassword) renderAuth('setup');
  else if (atoken) renderDash();
  else renderAuth('login');
});
</script>
</body>
</html>`;

/* ---------------- HTTP ---------------- */
function sendJson(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(body);
}
function sendHtml(res, html) {
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(html);
}
function readBody(req) {
  return new Promise((resolve) => {
    let b = '';
    req.on('data', (c) => { b += c; if (b.length > 2 * 1024 * 1024) req.destroy(); });
    req.on('end', () => { try { resolve(JSON.parse(b || '{}')); } catch (e) { resolve({}); } });
  });
}
function publicQuestion(q) { return { id: q.id, subject: q.subject, unit: q.unit, q: q.q, choices: q.choices }; }
function answeredQuestion(q, chosen) {
  const o = publicQuestion(q);
  o.answered = true; o.chosen = chosen; o.answer = q.answer;
  o.explanation = q.explanation; o.memoryTip = q.memoryTip; o.diagram = q.diagram || null;
  return o;
}
function cardOf(q, choice) {
  return { ok: true, correct: choice === q.answer, answer: q.answer, explanation: q.explanation, memoryTip: q.memoryTip, diagram: q.diagram || null };
}
function history14() {
  const out = [];
  for (let i = 0; i < 14; i++) {
    const date = addDays(todayStr(), -i);
    const day = dayOf(date);
    const sc = mainScore(day);
    out.push({ date, hasQuestions: !!(day && day.questions && day.questions.length), done: mainDone(day), correct: sc ? sc.correct : 0, total: sc ? sc.total : 0 });
  }
  return out;
}
function cleanDiagram(s) {
  if (typeof s !== 'string') return null;
  if (s.length > 8000) return null;
  const cleaned = s.replace(/<script[\s\S]*?<\/script>/gi, '').replace(/\son\w+\s*=\s*"[^"]*"/gi, '').replace(/\son\w+\s*=\s*'[^']*'/gi, '');
  return cleaned.trim() ? cleaned : null;
}
function validQuestion(q) {
  return q && (q.subject === '理科' || q.subject === '社会') && typeof q.unit === 'string' && q.unit.length > 0 &&
    typeof q.q === 'string' && q.q.length > 0 && Array.isArray(q.choices) && q.choices.length === 4 &&
    Number.isInteger(q.answer) && q.answer >= 0 && q.answer <= 3 &&
    typeof q.explanation === 'string' && q.explanation.length > 0 && typeof q.memoryTip === 'string';
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const p = url.pathname;
  try {
    if (req.method === 'GET' && p === '/') return sendHtml(res, PLAYER_HTML);
    if (req.method === 'GET' && p === '/admin') return sendHtml(res, ADMIN_HTML);

    /* ---- プレイヤー ---- */
    if (req.method === 'POST' && p === '/api/player/login') {
      const body = await readBody(req);
      if (!data.playerPassHash) return sendJson(res, 400, { ok: false, error: 'あいことばがまだ設定されていません' });
      if (!verifySecret(body.pass || '', data.playerPassHash)) return sendJson(res, 401, { ok: false, error: 'あいことばが違います' });
      const t = newToken();
      data.playerTokens.push(sha256(t));
      if (data.playerTokens.length > 10) data.playerTokens = data.playerTokens.slice(-10);
      saveData();
      return sendJson(res, 200, { ok: true, token: t });
    }
    if (p.startsWith('/api/player/') && !isPlayer(req)) return sendJson(res, 401, { ok: false, error: 'ログインが必要です' });

    if (req.method === 'GET' && p === '/api/player/today') {
      const date = todayStr();
      const day = dayOf(date);
      const ts = testState();
      const extraSets = day ? (day.extraSets || []) : [];
      const payload = {
        ok: true, date,
        hasQuestions: !!(day && day.questions && day.questions.length),
        questions: day ? day.questions.map((q) => {
          const a = day.answers ? day.answers[q.id] : null;
          return a != null ? answeredQuestion(q, a) : publicQuestion(q);
        }) : [],
        done: mainDone(day),
        score: mainScore(day) || { correct: 0, answered: 0, total: 0 },
        missedUnits: missedUnits(day),
        streak: calcStreak(),
        extra: { setsDone: extraSets.length },
        test: { available: ts.available, passed: ts.passed, needless: ts.needless, total: ts.pool.length, weekStart: ts.weekStart },
        week: weeklyAccuracy(),
        units: unitStats(),
        history: history14(),
      };
      return sendJson(res, 200, payload);
    }
    if (req.method === 'POST' && p === '/api/player/answer') {
      const body = await readBody(req);
      const day = dayOf(todayStr());
      if (!day) return sendJson(res, 404, { ok: false, error: '今日の問題がありません' });
      const q = (day.questions || []).find((x) => x.id === body.qid);
      if (!q) return sendJson(res, 404, { ok: false, error: '問題が見つかりません' });
      if (!Number.isInteger(body.choice) || body.choice < 0 || body.choice > 3) return sendJson(res, 400, { ok: false, error: '答えが不正です' });
      if (!day.answers) day.answers = {};
      if (day.answers[q.id] == null) {
        day.answers[q.id] = body.choice;
        if (!day.startedAt) day.startedAt = new Date().toISOString();
        if (mainDone(day)) day.finishedAt = new Date().toISOString();
        saveData();
      }
      const out = cardOf(q, day.answers[q.id]);
      out.done = mainDone(day); out.score = mainScore(day);
      return sendJson(res, 200, out);
    }
    if (req.method === 'POST' && p === '/api/player/extra/start') {
      const day = dayOf(todayStr());
      if (!day || !mainDone(day)) return sendJson(res, 400, { ok: false, error: 'まず今日の5問を解いてね' });
      if (!day.extraSets) day.extraSets = [];
      const used = day.extraSets.reduce((n, s) => n + (s.questions || []).length, 0);
      const next = (day.extraPool || []).slice(used, used + 5);
      if (next.length === 0) return sendJson(res, 200, { ok: false, error: '今日の追加問題はもうありません' });
      day.extraSets.push({ questions: next, answers: next.map(() => null) });
      saveData();
      return sendJson(res, 200, { ok: true, setIndex: day.extraSets.length - 1, questions: next.map(publicQuestion) });
    }
    if (req.method === 'POST' && p === '/api/player/extra/answer') {
      const body = await readBody(req);
      const day = dayOf(todayStr());
      if (!day || !day.extraSets || !day.extraSets[body.setIndex]) return sendJson(res, 404, { ok: false, error: 'セットが見つかりません' });
      const set = day.extraSets[body.setIndex];
      const ix = (set.questions || []).findIndex((x) => x.id === body.qid);
      if (ix < 0) return sendJson(res, 404, { ok: false, error: '問題が見つかりません' });
      if (!Number.isInteger(body.choice) || body.choice < 0 || body.choice > 3) return sendJson(res, 400, { ok: false, error: '答えが不正です' });
      if (set.answers[ix] == null) { set.answers[ix] = body.choice; saveData(); }
      return sendJson(res, 200, cardOf(set.questions[ix], set.answers[ix]));
    }
    if (req.method === 'GET' && p === '/api/player/test') {
      const ts = testState();
      return sendJson(res, 200, { ok: true, available: ts.available, passed: ts.passed, needless: ts.needless, questions: ts.pool.map(publicQuestion) });
    }
    if (req.method === 'POST' && p === '/api/player/test/answer') {
      const body = await readBody(req);
      const ts = testState();
      const q = ts.pool.find((x) => x.id === body.qid);
      if (!q) return sendJson(res, 404, { ok: false, error: '問題が見つかりません' });
      if (!Number.isInteger(body.choice) || body.choice < 0 || body.choice > 3) return sendJson(res, 400, { ok: false, error: '答えが不正です' });
      return sendJson(res, 200, cardOf(q, body.choice));
    }
    if (req.method === 'POST' && p === '/api/player/test/finish') {
      const body = await readBody(req);
      const ts = testState();
      if (!ts.available) return sendJson(res, 400, { ok: false, error: 'テストがありません' });
      const byId = {}; ts.pool.forEach((q) => { byId[q.id] = q; });
      let correct = 0; const missed = [];
      (body.results || []).forEach((r) => {
        const q = byId[r.qid];
        if (!q) return;
        if (r.choice === q.answer) correct++; else missed.push(r.qid);
      });
      const total = ts.pool.length;
      const passed = total > 0 && correct / total >= 0.8;
      if (!data.tests[ts.weekStart]) data.tests[ts.weekStart] = { attempts: [], passed: false, lastPool: null };
      const rec = data.tests[ts.weekStart];
      rec.attempts.push({ date: todayStr(), correct, total, passed });
      if (passed) { rec.passed = true; rec.lastPool = null; } else rec.lastPool = missed;
      saveData();
      return sendJson(res, 200, { ok: true, correct, total, passed });
    }

    /* ---- 認証（管理者） ---- */
    if (req.method === 'GET' && p === '/api/auth/status') {
      return sendJson(res, 200, { hasPassword: !!data.adminPasswordHash, authed: isAdmin(req) });
    }
    if (req.method === 'POST' && p === '/api/auth/setup') {
      if (data.adminPasswordHash) return sendJson(res, 400, { ok: false, error: 'すでに設定済みです' });
      const body = await readBody(req);
      if (!body.password || String(body.password).length < 4) return sendJson(res, 400, { ok: false, error: 'パスワードは4文字以上にしてください' });
      data.adminPasswordHash = hashSecret(body.password);
      const agentToken = newToken();
      data.agentTokenHash = sha256(agentToken);
      saveData();
      const t = newToken();
      adminSessions.set(t, Date.now() + 30 * 24 * 3600 * 1000);
      return sendJson(res, 200, { ok: true, token: t, agentToken });
    }
    if (req.method === 'POST' && p === '/api/auth/login') {
      const body = await readBody(req);
      if (!verifySecret(body.password || '', data.adminPasswordHash)) return sendJson(res, 401, { ok: false, error: 'パスワードが違います' });
      const t = newToken();
      adminSessions.set(t, Date.now() + 30 * 24 * 3600 * 1000);
      return sendJson(res, 200, { ok: true, token: t });
    }
    if (p.startsWith('/api/admin/') && !isAdmin(req)) return sendJson(res, 401, { ok: false, error: '認証が必要です' });

    if (req.method === 'GET' && p === '/api/admin/state') {
      const date = todayStr();
      const day = dayOf(date);
      const tests = Object.keys(data.tests).sort().map((ws) => ({ weekStart: ws, passed: !!data.tests[ws].passed, attempts: (data.tests[ws].attempts || []).length }));
      return sendJson(res, 200, {
        ok: true,
        today: { date, hasQuestions: !!(day && day.questions && day.questions.length), done: mainDone(day), score: mainScore(day) || { correct: 0, answered: 0, total: 0 }, missedUnits: missedUnits(day) },
        streak: calcStreak(),
        history: history14(),
        units: unitStats(),
        tests,
        settings: { playerPassSet: !!data.playerPassHash },
      });
    }
    if (req.method === 'POST' && p === '/api/admin/settings') {
      const body = await readBody(req);
      if (typeof body.playerPass === 'string' && body.playerPass.length >= 2) {
        data.playerPassHash = hashSecret(body.playerPass);
        data.playerTokens = [];
        saveData();
        return sendJson(res, 200, { ok: true });
      }
      return sendJson(res, 400, { ok: false, error: 'あいことばは2文字以上にしてください' });
    }
    if (req.method === 'POST' && p === '/api/admin/regen-token') {
      const agentToken = newToken();
      data.agentTokenHash = sha256(agentToken);
      saveData();
      return sendJson(res, 200, { ok: true, agentToken });
    }

    /* ---- 連携（イロ） ---- */
    if (p.startsWith('/api/agent/') && !isAgent(req)) return sendJson(res, 401, { ok: false, error: 'トークンが違います' });
    if (req.method === 'POST' && p === '/api/agent/questions') {
      const body = await readBody(req);
      const date = body.date;
      if (!validDateStr(date)) return sendJson(res, 400, { ok: false, error: 'date が不正です' });
      if (!Array.isArray(body.questions) || body.questions.length !== 5 || !body.questions.every(validQuestion)) {
        return sendJson(res, 400, { ok: false, error: 'questions は5問・形式チェックNG' });
      }
      const extra = Array.isArray(body.extraPool) ? body.extraPool : [];
      if (!extra.every(validQuestion)) return sendJson(res, 400, { ok: false, error: 'extraPool の形式が不正です' });
      const existing = dayOf(date);
      if (existing && existing.answers && Object.keys(existing.answers).length > 0 && !body.force) {
        return sendJson(res, 409, { ok: false, error: 'その日はすでに回答が記録されています' });
      }
      const qs = body.questions.map((q, i) => ({ id: date + '-m' + (i + 1), subject: q.subject, unit: q.unit, q: q.q, choices: q.choices, answer: q.answer, explanation: q.explanation, memoryTip: q.memoryTip, diagram: cleanDiagram(q.diagram) }));
      const xs = extra.map((q, i) => ({ id: date + '-x' + (i + 1), subject: q.subject, unit: q.unit, q: q.q, choices: q.choices, answer: q.answer, explanation: q.explanation, memoryTip: q.memoryTip, diagram: cleanDiagram(q.diagram) }));
      data.days[date] = { questions: qs, extraPool: xs, answers: {}, extraSets: [] };
      saveData();
      return sendJson(res, 200, { ok: true, date, count: qs.length, extraCount: xs.length });
    }
    if (req.method === 'GET' && p === '/api/agent/results') {
      const date = url.searchParams.get('date') || todayStr();
      const day = dayOf(date);
      const ts = testState();
      return sendJson(res, 200, {
        ok: true, date,
        hasQuestions: !!(day && day.questions && day.questions.length),
        done: mainDone(day),
        score: mainScore(day) || { correct: 0, answered: 0, total: 0 },
        missedUnits: missedUnits(day),
        extraSetsDone: day ? (day.extraSets || []).length : 0,
        finishedAt: day ? (day.finishedAt || null) : null,
        streak: calcStreak(),
        testToday: ts.attempts.filter((a) => a.date === date),
      });
    }
    if (req.method === 'GET' && p === '/api/agent/summary') {
      return sendJson(res, 200, {
        ok: true, today: todayStr(), streak: calcStreak(),
        recentMissed: recentMissedUnits(14),
        units: unitStats(),
        week: weeklyAccuracy(),
        test: (() => { const ts = testState(); return { weekStart: ts.weekStart, available: ts.available, passed: ts.passed, needless: ts.needless, poolSize: ts.pool.length }; })(),
        days: Object.keys(data.days).sort().slice(-14),
      });
    }

    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Not Found');
  } catch (e) {
    console.error(e);
    sendJson(res, 500, { ok: false, error: 'サーバーエラー' });
  }
});

if (require.main === module) {
  server.listen(PORT, () => {
    console.log('毎朝5問サーバー起動: http://localhost:' + PORT);
    console.log('  プレイヤー: /  管理: /admin  データ: ' + DATA_FILE);
  });
}
module.exports = { server };
