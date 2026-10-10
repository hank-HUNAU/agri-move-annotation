/* 语步标注平台（纯前端 · GitHub Pages）
 * 数据以 AES-256-GCM 密文随仓库发布，浏览器端用 WebCrypto 解密；
 * 答案与过程日志只存在本机浏览器（localStorage），提交后锁定，导出交回。 */
"use strict";

const $ = (id) => document.getElementById(id);
const now = () => Date.now();
const enc = new TextEncoder();

const ui = {
  gate: $("gate"), gateMsg: $("gateMsg"), gateForm: $("gateForm"), gateErr: $("gateErr"),
  pass: $("pass"), enterBtn: $("enterBtn"),
  trialDone: $("trialDone"), toMain: $("toMain"),
  work: $("work"), qPos: $("qPos"), qMeta: $("qMeta"), qText: $("qText"),
  labels: $("labels"), note: $("note"), noteReq: $("noteReq"),
  prevBtn: $("prevBtn"), nextBtn: $("nextBtn"), gateHint: $("gateHint"),
  ctxBody: $("ctxBody"), ctxToggle: $("ctxToggle"),
  finish: $("finish"), finishTitle: $("finishTitle"), finishMsg: $("finishMsg"),
  finishSum: $("finishSum"), submitBtn: $("submitBtn"), submitHint: $("submitHint"),
  export: $("export"), exportTitle: $("exportTitle"), exportSum: $("exportSum"),
  csvMain: $("csvMain"), csvTrial: $("csvTrial"), jsonLog: $("jsonLog"),
  wipeBtn: $("wipeBtn"),
  roleBadge: $("roleBadge"), phaseBadge: $("phaseBadge"),
  progressText: $("progressText"), progressBar: $("progressBar"),
  footVer: $("footVer"),
};

let payload = null;
let state = null;
let role = null;
let key = null;
let pass = "";
let tickTimer = null;

/* ------------------------------------------------------------------ 工具 */
function b64ToBuf(b64) {
  const bin = atob(b64);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf;
}
function hex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function sha256(text) {
  return hex(await crypto.subtle.digest("SHA-256", enc.encode(text)));
}
function fmtMs(ms) {
  const s = Math.max(0, Math.round(ms / 1000));
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), ss = s % 60;
  return (h ? h + " 小时 " : "") + (h || m ? m + " 分 " : "") + ss + " 秒";
}
function esc(t) {
  return String(t).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}
function csvCell(v) {
  const s = v === null || v === undefined ? "" : String(v);
  return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}
function download(name, text, mime) {
  const blob = new Blob([text], { type: mime || "text/plain;charset=utf-8" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = name;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 4000);
}
function stamp() {
  const d = new Date(), p = (n) => String(n).padStart(2, "0");
  return d.getFullYear() + p(d.getMonth() + 1) + p(d.getDate()) + "_" + p(d.getHours()) + p(d.getMinutes());
}
function parseFragment() {
  const o = {};
  location.hash.replace(/^#/, "").split("&").forEach((kv) => {
    if (!kv) return;
    const i = kv.indexOf("=");
    const k = decodeURIComponent(i < 0 ? kv : kv.slice(0, i));
    o[k] = i < 0 ? "" : decodeURIComponent(kv.slice(i + 1));
  });
  return o;
}

/* --------------------------------------------------------------- 解密题库 */
async function decrypt(payloadEnc, password) {
  if (!crypto.subtle) throw new Error("浏览器不支持 WebCrypto，请换用 Chrome / Edge / Safari 新版。");
  const base = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
  const k = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: b64ToBuf(payloadEnc.salt), iterations: payloadEnc.iter, hash: "SHA-256" },
    base, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64ToBuf(payloadEnc.iv) }, k, b64ToBuf(payloadEnc.ct));
  return JSON.parse(new TextDecoder().decode(pt));
}

/* ----------------------------------------------------------------- 状态 */
function storeKey() { return "anno_v103_" + role; }
function blankAns() {
  return { v: "", n: "", t0: 0, t1: 0, d: 0, nEnter: 0, c: 0, tr: [], ne: 0 };
}
function newState() {
  return { role, built: payload.built, startedAt: now(), trial: {}, main: {},
           trialDone: false, submitted: false, lockedAt: 0, exportedAt: 0 };
}
function loadState() {
  try {
    const raw = localStorage.getItem(storeKey());
    if (raw) {
      const s = JSON.parse(raw);
      if (s && s.role === role) return s;
    }
  } catch (e) { /* 忽略损坏的存档 */ }
  return newState();
}
let saveTimer = null;
function save(immediate) {
  clearTimeout(saveTimer);
  const go = () => { try { localStorage.setItem(storeKey(), JSON.stringify(state)); } catch (e) {} };
  immediate ? go() : (saveTimer = setTimeout(go, 400));
}

/* --------------------------------------------------------------- 上下文 */
function currentList() { return state.trialDone === false ? payload.trial : payload.sentences; }
function currentMap() { return state.trialDone === false ? state.trial : state.main; }
function isTrialPhase() { return !state.trialDone; }

function renderContext(rec) {
  const books = isTrialPhase() ? payload.trial_abstracts : payload.abstracts;
  const a = books[rec.aid];
  if (!a) { ui.ctxBody.textContent = "（未找到该篇摘要全文）"; return; }
  const head = '<span class="meta">' + esc(a.journal || "") + (a.year ? " · " + esc(a.year) : "") +
    (a.discipline ? " · " + esc(a.discipline) : "") + " · " + esc(a.group || "") + "</span>" +
    '<span class="meta">' + esc(a.title || "") + "</span>";
  const text = a.text || "";
  const i = rec.text ? text.indexOf(rec.text) : -1;
  let body;
  if (i >= 0) {
    body = esc(text.slice(0, i)) + "<mark>" + esc(text.slice(i, i + rec.text.length)) + "</mark>" +
      esc(text.slice(i + rec.text.length));
  } else {
    body = esc(text);
  }
  ui.ctxBody.innerHTML = head + body;
  const mark = ui.ctxBody.querySelector("mark");
  if (mark) mark.scrollIntoView({ block: "center" });
}

/* ----------------------------------------------------------------- 渲染 */
function renderTop() {
  ui.roleBadge.hidden = false;
  ui.roleBadge.textContent = "标注员 " + role;
  ui.phaseBadge.hidden = false;
  const list = currentList(), map = currentMap();
  const done = list.filter((r) => map[r.sid] && map[r.sid].v).length;
  ui.phaseBadge.textContent = isTrialPhase() ? "试标阶段（20 句）" : "正式标注（472 句）";
  ui.progressText.textContent = done + " / " + list.length;
  ui.progressBar.style.width = (list.length ? (done / list.length) * 100 : 0) + "%";
  ui.footVer.textContent = payload.dataset.name + " · 题库 " + payload.dataset.version;
}

let curIdx = 0;
function renderQuestion() {
  const list = currentList();
  const rec = list[curIdx];
  const ans = currentMap()[rec.sid] || (currentMap()[rec.sid] = blankAns());
  ans.t0 = ans.t0 || now();
  ans.t1 = now();
  ans.nEnter = (ans.nEnter || 0) + 1;

  ui.qPos.textContent = (isTrialPhase() ? "试标 " : "第 ") + (curIdx + 1) + " / " + list.length +
    (isTrialPhase() ? " 句" : " 句");
  ui.qMeta.textContent = [rec.journal, rec.year, rec.discipline, rec.group].filter(Boolean).join(" · ");
  ui.qText.textContent = rec.text;
  ui.note.value = ans.n || "";
  ui.noteReq.textContent = "";
  renderLabels(ans);
  renderContext(rec);
  updateNav();
  renderTop();
  save();
  focusNoteIfNeeded();
}

function renderLabels(ans) {
  ui.labels.innerHTML = "";
  payload.labels.forEach((L, i) => {
    const id = "lab" + i;
    const on = ans.v === L.code;
    const el = document.createElement("label");
    el.className = "lab" + (on ? " on" : "");
    el.htmlFor = id;
    el.innerHTML = '<input type="radio" id="' + id + '" name="lab" value="' + esc(L.code) + '"' +
      (on ? " checked" : "") + '><span><span class="code">' + (i + 1) + ". " + esc(L.code) +
      "</span><span class=\"desc\">" + esc(L.desc) + "</span></span>";
    ui.labels.appendChild(el);
  });
  ui.labels.querySelectorAll("input[name=lab]").forEach((inp) => {
    inp.addEventListener("change", () => onPick(inp.value));
  });
}

function focusNoteIfNeeded() {
  const ans = currentMap()[currentList()[curIdx].sid];
  if (ans && ans.v === "UN无法判定" && !(ans.n || "").trim()) ui.note.focus();
}

function onPick(code) {
  const rec = currentList()[curIdx];
  const ans = currentMap()[rec.sid];
  if (state.submitted) return;
  if (ans.v === code) return;
  if (ans.v) {
    ans.c = (ans.c || 0) + 1;
    ans.tr.push([now() - state.startedAt, ans.v, code]);
  }
  ans.v = code;
  ui.labels.querySelectorAll(".lab").forEach((el) => {
    const inp = el.querySelector("input");
    el.classList.toggle("on", inp.value === code);
  });
  renderTop();
  updateNav();
  save();
  if (code === "UN无法判定") ui.note.focus();
}

function noteChanged() {
  const ans = currentMap()[currentList()[curIdx].sid];
  if (!ans) return;
  if ((ans.n || "") !== ui.note.value) { ans.ne = (ans.ne || 0) + 1; ans.n = ui.note.value; }
  updateNav();
  save();
}

function unmet() {
  const ans = currentMap()[currentList()[curIdx].sid];
  if (!ans || !ans.v) return "请先选一个标签";
  if (ans.v === "UN无法判定" && !(ans.n || "").trim()) return "填「UN无法判定」时请在备注里写明为什么拿不准";
  return "";
}
function updateNav() {
  const why = unmet();
  ui.nextBtn.disabled = !!why;
  ui.gateHint.textContent = state.submitted ? "" : (why || "");
  ui.prevBtn.disabled = curIdx === 0;
  const last = curIdx === currentList().length - 1;
  ui.nextBtn.textContent = last ? (isTrialPhase() ? "完成试标 →" : "完成标注 →") : "下一句 →";
}

function leaveCurrent() {
  const a = currentMap()[currentList()[curIdx].sid];
  if (!a) return;
  a.t1 = now();
  if (a.enterAt) a.d = (a.d || 0) + (a.t1 - a.enterAt);
  a.enterAt = 0;
}
function enterCurrent() {
  const a = currentMap()[currentList()[curIdx].sid];
  if (a) a.enterAt = now();
}

function goNext() {
  if (unmet()) return;
  leaveCurrent();
  if (curIdx < currentList().length - 1) { curIdx++; applyPermalinkScroll(); }
  else if (isTrialPhase()) { finishTrial(); return; }
  else { finishMain(); return; }
  enterCurrent(); renderQuestion();
}
function goPrev() {
  if (curIdx === 0) return;
  leaveCurrent();
  curIdx--;
  enterCurrent();
  renderQuestion();
}

/* ----------------------------------------------------------- 试标 / 完成 */
function finishTrial() {
  state.trialDone = true;
  save(true);
  ui.work.hidden = true;
  ui.trialDone.hidden = false;
  renderTop();
}
function firstUnanswered(list, map) {
  for (let i = 0; i < list.length; i++) if (!(map[list[i].sid] && map[list[i].sid].v)) return i;
  return -1;
}
function startMain() {
  ui.trialDone.hidden = true;
  const i = firstUnanswered(payload.sentences, state.main);
  if (i < 0) { finishMain(); return; }   // 已全部答完 → 直接进提交页，不必重走 472 句
  ui.work.hidden = false;
  curIdx = i;
  enterCurrent();
  renderQuestion();
}
function finishMain() {
  const answered = payload.sentences.filter((r) => state.main[r.sid] && state.main[r.sid].v).length;
  ui.work.hidden = true;
  ui.finish.hidden = false;
  ui.export.hidden = true;
  ui.finishTitle.textContent = "472 句已全部标注完毕";
  ui.finishMsg.textContent = "请点下面的按钮提交。提交后答案会锁定，不能再修改。";
  ui.finishSum.innerHTML =
    row("已标注", answered + " / " + payload.sentences.length) +
    row("试标集", (state.trialDone ? "已完成 20 / 20" : "未完成")) +
    row("累计用时", fmtMs(now() - state.startedAt)) +
    row("本机存档", "答案只存在这台电脑的浏览器里");
  ui.submitBtn.hidden = false;
  ui.submitHint.hidden = false;
}
function row(k, v) { return "<div><span>" + esc(k) + "</span><b>" + esc(v) + "</b></div>"; }

function submit() {
  const answered = payload.sentences.filter((r) => state.main[r.sid] && state.main[r.sid].v).length;
  if (answered < payload.sentences.length) { alert("还有 " + (payload.sentences.length - answered) + " 句未标注。"); return; }
  if (!confirm("确认提交？提交后答案将锁定、不可再修改。")) return;
  state.submitted = true;
  state.lockedAt = now();
  save(true);
  renderExport();
}

/* --------------------------------------------------------------- 导出 */
function rowsFor(list, map, cols) {
  return list.map((r) => {
    const a = map[r.sid] || blankAns();
    const out = {
      "句子ID": r.sid, "试标ID": r.sid, "摘要编号": r.aid, "语言组": r.group,
      "期刊": r.journal, "年份": r.year, "学科": r.discipline, "题名": r.title,
      "句内序号": r.seq, "待标句子": r.text, "人工标注": a.v || "", "备注": a.n || "",
    };
    return cols.map((c) => out[c] === undefined ? "" : out[c]);
  });
}
function toCsv(cols, rows) {
  const lines = [cols.map(csvCell).join(",")];
  rows.forEach((r) => lines.push(r.map(csvCell).join(",")));
  return "\uFEFF" + lines.join("\r\n") + "\r\n";
}
const COLS_MAIN = ["句子ID", "摘要编号", "语言组", "期刊", "年份", "学科", "题名", "句内序号", "待标句子", "人工标注", "备注"];
const COLS_TRIAL = ["试标ID", "摘要编号", "语言组", "期刊", "题名", "句内序号", "待标句子", "人工标注", "备注"];

function logFor(list, map) {
  return list.map((r) => {
    const a = map[r.sid] || blankAns();
    if (a.enterAt) { a.t1 = now(); a.d = (a.d || 0) + (a.t1 - a.enterAt); a.enterAt = 0; }
    return {
      sid: r.sid, aid: r.aid, seq: r.seq, label: a.v || "", note: a.n || "",
      noteLength: (a.n || "").length, noteEdits: a.ne || 0,
      enterCount: a.nEnter || 0, changeCount: a.c || 0,
      dwellMs: a.d || 0, dwellSec: Math.round((a.d || 0) / 100) / 10,
      firstAt: a.t0 ? new Date(a.t0).toISOString() : null,
      lastAt: a.t1 ? new Date(a.t1).toISOString() : null,
      changes: (a.tr || []).map((x) => ({ atSec: Math.round(x[0] / 100) / 10, from: x[1], to: x[2] })),
    };
  });
}
async function exportBundle() {
  const mainCsv = toCsv(COLS_MAIN, rowsFor(payload.sentences, state.main, COLS_MAIN));
  const trialCsv = toCsv(COLS_TRIAL, rowsFor(payload.trial, state.trial, COLS_TRIAL));
  const mainSha = await sha256(mainCsv), trialSha = await sha256(trialCsv);
  const log = {
    schema: "agri-move-annotation-log/1",
    role: role,
    dataset: payload.dataset,
    session: {
      startedAt: new Date(state.startedAt).toISOString(),
      submittedAt: state.lockedAt ? new Date(state.lockedAt).toISOString() : null,
      exportAt: new Date().toISOString(),
      elapsedMs: now() - state.startedAt,
      trialDone: state.trialDone, locked: state.submitted,
      ua: navigator.userAgent, lang: navigator.language,
      timezone: (Intl.DateTimeFormat().resolvedOptions().timeZone || ""),
      screen: screen.width + "x" + screen.height,
      viewport: innerWidth + "x" + innerHeight,
      localTimeOffsetMin: new Date().getTimezoneOffset(),
    },
    counts: {
      trial: payload.trial.length, main: payload.sentences.length,
      mainAnswered: payload.sentences.filter((r) => state.main[r.sid] && state.main[r.sid].v).length,
      noteFilled: payload.sentences.filter((r) => state.main[r.sid] && (state.main[r.sid].n || "").trim()).length,
    },
    hashes: { mainCsvSha256: mainSha, trialCsvSha256: trialSha },
    trialLog: logFor(payload.trial, state.trial),
    mainLog: logFor(payload.sentences, state.main),
  };
  return { mainCsv, trialCsv, log, mainSha, trialSha };
}

function renderExport() {
  ui.work.hidden = true; ui.finish.hidden = true; ui.trialDone.hidden = true;
  ui.export.hidden = false;
  const answered = payload.sentences.filter((r) => state.main[r.sid] && state.main[r.sid].v).length;
  ui.exportTitle.textContent = "✅ 已提交并锁定";
  ui.exportSum.innerHTML =
    row("标注员", role) + row("正式标注", answered + " / " + payload.sentences.length) +
    row("试标集", state.trialDone ? "20 / 20" : "未完成") +
    row("锁定时长（自开始）", fmtMs(state.lockedAt - state.startedAt)) +
    row("题库版本", payload.dataset.version);
  renderTop();
}

async function doExport(kind) {
  try {
    const b = await exportBundle();
    state.exportedAt = now();
    save(true);
    const base = "效度验证_标注员" + role + "_" + stamp();
    if (kind === "main") download(base + "_正式标注.csv", b.mainCsv, "text/csv;charset=utf-8");
    else if (kind === "trial") download(base + "_试标集.csv", b.trialCsv, "text/csv;charset=utf-8");
    else download(base + "_过程日志.json", JSON.stringify(b.log, null, 1), "application/json;charset=utf-8");
  } catch (e) {
    alert("导出失败：" + (e && e.message ? e.message : e) + "\n请把这一页截图发给老师。");
  }
}

/* --------------------------------------------------------------- 启动 */
function show(el) { el.hidden = false; }
function hide(el) { el.hidden = true; }

function applyPermalinkScroll() { /* 预留：将来按 URL 定位到某句 */ }

async function boot() {
  const frag = parseFragment();
  role = (frag.role || "").toUpperCase() === "B" ? "B" : (frag.role ? "A" : "");
  pass = frag.k || "";

  if (role && frag.reset === "1") {
    localStorage.removeItem("anno_v103_" + role);
    ui.gateMsg.textContent = "已清空标注员 " + role + " 的本机数据，请重新进入。";
  }

  // 若链接里没带角色，等用户选
  if (!role) {
    ui.gateMsg.textContent = "请选择你的标注员编号，并输入老师给你的口令。";
    show(ui.gateForm);
    ui.pass.value = "";
    ui.enterBtn.disabled = true;
    let picked = "";
    document.querySelectorAll(".rolebtn").forEach((b) => {
      b.addEventListener("click", () => {
        picked = b.dataset.role;
        document.querySelectorAll(".rolebtn").forEach((x) => x.setAttribute("aria-pressed", x === b));
        ui.enterBtn.disabled = !(picked && ui.pass.value.trim());
      });
    });
    ui.pass.addEventListener("input", () => { ui.enterBtn.disabled = !(picked && ui.pass.value.trim()); });
    ui.enterBtn.addEventListener("click", () => { role = picked; pass = ui.pass.value.trim(); start(); });
    return;
  }
  if (pass) { ui.gateMsg.textContent = "正在解密题库…"; start(); return; }
  // 有角色但没口令
  ui.gateMsg.textContent = "链接里没有口令，请输入老师给你的口令。";
  show(ui.gateForm);
  document.querySelectorAll(".rolebtn").forEach((b) => {
    b.setAttribute("aria-pressed", b.dataset.role === role);
  });
  ui.enterBtn.disabled = true;
  ui.pass.addEventListener("input", () => { ui.enterBtn.disabled = !ui.pass.value.trim(); });
  ui.enterBtn.addEventListener("click", () => { pass = ui.pass.value.trim(); start(); });
}

async function start() {
  hide(ui.gateForm); ui.gateMsg.textContent = "正在解密题库…"; hide(ui.gateErr);
  try {
    const r = await fetch("data/enc_" + role.toLowerCase() + ".json", { cache: "no-cache" });
    if (!r.ok) throw new Error("题库文件读取失败（HTTP " + r.status + "）");
    const payloadEnc = await r.json();
    payload = await decrypt(payloadEnc, pass);
  } catch (e) {
    show(ui.gateErr);
    ui.gateErr.textContent = "口令不对或浏览器不支持：" + (e && e.message ? e.message : e) +
      "\n请确认口令没有多余空格；若仍不行，把这一页截图发给老师。";
    ui.gateMsg.textContent = "未能进入标注。";
    show(ui.gateForm);
    return;
  }
  hide(ui.gate);
  state = loadState();
  key = storeKey();
  bindOnce();
  if (state.submitted) { renderExport(); return; }
  if (!state.trialDone) { show(ui.work); const i = firstUnanswered(payload.trial, state.trial); curIdx = i < 0 ? 0 : i; enterCurrent(); renderQuestion(); return; }
  show(ui.work); startMain();
}

let bound = false;
function bindOnce() {
  if (bound) return;
  bound = true;
  ui.trialDone.hidden = true;
  ui.toMain.addEventListener("click", startMain);
  ui.nextBtn.addEventListener("click", goNext);
  ui.prevBtn.addEventListener("click", goPrev);
  ui.note.addEventListener("input", noteChanged);
  ui.submitBtn.addEventListener("click", submit);
  ui.csvMain.addEventListener("click", () => doExport("main"));
  ui.csvTrial.addEventListener("click", () => doExport("trial"));
  ui.jsonLog.addEventListener("click", () => doExport("log"));
  ui.ctxToggle.addEventListener("click", () => {
    const c = ui.ctxBody.classList.toggle("collapsed");
    ui.ctxToggle.textContent = c ? "展开" : "收起";
  });
  ui.wipeBtn.addEventListener("click", () => {
    if (!confirm("确定清空本机保存的全部标注数据？此操作不可撤销。")) return;
    localStorage.removeItem(storeKey());
    alert("已清空。请刷新页面重新开始。");
  });
  document.addEventListener("keydown", (e) => {
    if (ui.work.hidden || state.submitted) return;
    if (e.target && /INPUT|TEXTAREA/.test(e.target.tagName)) {
      if (e.key === "Enter" && e.target.tagName === "TEXTAREA" && (e.ctrlKey || e.metaKey)) { e.preventDefault(); goNext(); }
      return;
    }
    if (/^[1-7]$/.test(e.key)) {
      const L = payload.labels[Number(e.key) - 1];
      if (L) { const inp = ui.labels.querySelector('input[value="' + L.code + '"]'); if (inp) { inp.checked = true; onPick(L.code); } }
    } else if (e.key === "Enter" || e.key === "ArrowRight") { if (!ui.nextBtn.disabled) goNext(); }
    else if (e.key === "ArrowLeft" && !ui.prevBtn.disabled) goPrev();
  });
window.addEventListener("beforeunload", () => { leaveCurrent(); save(true); });
  setInterval(() => { if (!ui.work.hidden && !state.submitted) renderTop(); }, 30000);
}

// 从裸链接跳到带 #role=…&k=… 的链接时，浏览器只改 hash 不会重载页面；
// 这里补一个监听，免得学生粘贴链接后页面没反应。
window.addEventListener("hashchange", () => { if (!payload) boot(); });

boot();
