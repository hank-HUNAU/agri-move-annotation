/* 语步标注平台（纯前端 · GitHub Pages）
 * 三段式：① 试标 20 句（可改）→ ② 提交并锁定 → 解锁反馈页（你的判读／参考答案／手册依据）
 *          → 填写《校准记录》→ ③ 正式 472 句（独立完成）
 * 数据以 AES-256-GCM 密文随仓库发布，浏览器端 WebCrypto 解密；
 * 答案与过程日志只存本机（localStorage），提交后锁定，导出交回。 */
"use strict";
const $ = (id) => document.getElementById(id);
const now = () => Date.now();
const enc = new TextEncoder();
const ui = {
  gate: $("gate"), gateMsg: $("gateMsg"), gateForm: $("gateForm"), gateErr: $("gateErr"),
  pass: $("pass"), enterBtn: $("enterBtn"),
  trialSubmit: $("trialSubmit"), trialSum: $("trialSum"), lockTrial: $("lockTrial"),
  feedback: $("feedback"), keySource: $("keySource"), fbSum: $("fbSum"), fbTable: $("fbTable"),
  fbLead: $("fbLead"), fbDiffN: $("fbDiffN"), fbSameN: $("fbSameN"),
  fbScope: $("fbScope"), fbDiffBlock: $("fbDiffBlock"), fbAllBlock: $("fbAllBlock"), fbAll: $("fbAll"),
  calibRows: $("calibRows"), calibSummary: $("calibSummary"), calibBy: $("calibBy"),
  calibHint: $("calibHint"), toMain: $("toMain"),
  calibGather: $("calibGather"), calibGatherHint: $("calibGatherHint"),
  work: $("work"), qPos: $("qPos"), qMeta: $("qMeta"), qText: $("qText"),
  labels: $("labels"), note: $("note"), noteReq: $("noteReq"),
  prevBtn: $("prevBtn"), nextBtn: $("nextBtn"), gateHint: $("gateHint"),
  ctxBody: $("ctxBody"), ctxToggle: $("ctxToggle"),
  finish: $("finish"), finishTitle: $("finishTitle"), finishMsg: $("finishMsg"),
  finishSum: $("finishSum"), submitBtn: $("submitBtn"), submitHint: $("submitHint"),
  export: $("export"), exportTitle: $("exportTitle"), exportSum: $("exportSum"),
  csvMain: $("csvMain"), csvTrial: $("csvTrial"), jsonLog: $("jsonLog"), csvCalib: $("csvCalib"),
  wipeBtn: $("wipeBtn"),
  roleBadge: $("roleBadge"), phaseBadge: $("phaseBadge"),
  progressText: $("progressText"), progressBar: $("progressBar"), footVer: $("footVer"),
};
let payload = null, state = null, role = null, pass = "";
let phase = "trial";          // trial | feedback | main
let curIdx = 0;
let bound = false;
function b64ToBuf(b64) {
  const bin = atob(b64), buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf;
}
function hex(buf) { return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join(""); }
async function sha256(text) { return hex(await crypto.subtle.digest("SHA-256", enc.encode(text))); }
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
async function decrypt(payloadEnc, password) {
  if (!crypto.subtle) throw new Error("浏览器不支持 WebCrypto，请换用 Chrome / Edge / Safari 新版。");
  const base = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
  const k = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: b64ToBuf(payloadEnc.salt), iterations: payloadEnc.iter, hash: "SHA-256" },
    base, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64ToBuf(payloadEnc.iv) }, k, b64ToBuf(payloadEnc.ct));
  return JSON.parse(new TextDecoder().decode(pt));
}
function storeKey() { return "anno_v103_" + role; }
function blankAns() { return { v: "", n: "", t0: 0, t1: 0, d: 0, nEnter: 0, c: 0, tr: [], ne: 0 }; }
function newState() {
  return { role, built: payload.built, startedAt: now(),
           trial: {}, trialSubmitted: false, trialLockedAt: 0,
           calib: { rows: {}, summary: "", by: role || "", done: false, at: 0 },
           main: {}, submitted: false, lockedAt: 0, exportedAt: 0 };
}
function loadState() {
  try {
    const raw = localStorage.getItem(storeKey());
    if (raw) {
      const s = JSON.parse(raw);
      if (s && s.role === role) {
        s.calib = s.calib || { rows: {}, summary: "", by: role, done: false, at: 0 };
        s.calib.rows = s.calib.rows || {};
        s.trial = s.trial || {};
        s.main = s.main || {};
        return s;
      }
    }
  } catch (e) { /* 存档损坏则重来 */ }
  return newState();
}
let saveTimer = null;
function save(immediate) {
  clearTimeout(saveTimer);
  const go = () => { try { localStorage.setItem(storeKey(), JSON.stringify(state)); } catch (e) {} };
  immediate ? go() : (saveTimer = setTimeout(go, 400));
}
function currentList() { return phase === "trial" ? payload.trial : payload.sentences; }
function currentMap() { return phase === "trial" ? state.trial : state.main; }
function row(k, v) { return "<div><span>" + esc(k) + "</span><b>" + esc(v) + "</b></div>"; }
function show(el) { el.hidden = false; }
function hide(el) { el.hidden = true; }
function renderContext(rec) {
  const books = phase === "trial" ? payload.trial_abstracts : payload.abstracts;
  const a = books[rec.aid];
  if (!a) { ui.ctxBody.textContent = "（未找到该篇摘要全文）"; return; }
  const head = '<span class="meta">' + esc(a.journal || "") + (a.year ? " · " + esc(a.year) : "") +
    (a.discipline ? " · " + esc(a.discipline) : "") + " · " + esc(a.group || "") + "</span>" +
    '<span class="meta">' + esc(a.title || "") + "</span>";
  const text = a.text || "";
  const i = rec.text ? text.indexOf(rec.text) : -1;
  const body = i >= 0
    ? esc(text.slice(0, i)) + "<mark>" + esc(text.slice(i, i + rec.text.length)) + "</mark>" + esc(text.slice(i + rec.text.length))
    : esc(text);
  ui.ctxBody.innerHTML = head + body;
  const mk = ui.ctxBody.querySelector("mark");
  if (mk) mk.scrollIntoView({ block: "center" });
}
function renderTop() {
  ui.roleBadge.hidden = false;
  ui.roleBadge.textContent = "标注员 " + role;
  ui.phaseBadge.hidden = false;
  if (phase === "trial") {
    const done = payload.trial.filter((r) => state.trial[r.sid] && state.trial[r.sid].v).length;
    ui.phaseBadge.textContent = "试标阶段（20 句）";
    ui.progressText.textContent = done + " / " + payload.trial.length;
    ui.progressBar.style.width = (done / payload.trial.length * 100) + "%";
  } else if (phase === "feedback") {
    ui.phaseBadge.textContent = "试标反馈 · 校准记录";
    ui.progressText.textContent = "已锁定试标";
    ui.progressBar.style.width = "100%";
  } else {
    const list = payload.sentences, map = state.main;
    const done = list.filter((r) => map[r.sid] && map[r.sid].v).length;
    ui.phaseBadge.textContent = "正式标注（472 句）";
    ui.progressText.textContent = done + " / " + list.length;
    ui.progressBar.style.width = (done / list.length * 100) + "%";
  }
  ui.footVer.textContent = payload.dataset.name + " · 题库 " + payload.dataset.version;
}
function renderQuestion() {
  const list = currentList(), rec = list[curIdx];
  const map = currentMap();
  const ans = map[rec.sid] || (map[rec.sid] = blankAns());
  ans.t0 = ans.t0 || now();
  ans.t1 = now();
  ans.nEnter = (ans.nEnter || 0) + 1;
  ui.qPos.textContent = (phase === "trial" ? "试标 " : "第 ") + (curIdx + 1) + " / " + list.length + " 句";
  ui.qMeta.textContent = [rec.journal, rec.year, rec.discipline, rec.group].filter(Boolean).join(" · ");
  ui.qText.textContent = rec.text;
  ui.note.value = ans.n || "";
  ui.noteReq.textContent = "";
  renderLabels(ans);
  renderContext(rec);
  updateNav();
  renderTop();
  save();
  if (ans.v === "UN无法判定" && !(ans.n || "").trim()) ui.note.focus();
}
function renderLabels(ans) {
  ui.labels.innerHTML = "";
  const locked = phase === "trial" && state.trialSubmitted;
  payload.labels.forEach((L, i) => {
    const id = "lab" + i, on = ans.v === L.code;
    const el = document.createElement("label");
    el.className = "lab" + (on ? " on" : "");
    el.htmlFor = id;
    el.innerHTML = '<input type="radio" id="' + id + '" name="lab" value="' + esc(L.code) + '"' +
      (on ? " checked" : "") + (locked ? " disabled" : "") +
      '><span><span class="code">' + (i + 1) + ". " + esc(L.code) +
      '</span><span class="desc">' + esc(L.desc) + "</span></span>";
    ui.labels.appendChild(el);
  });
  ui.labels.querySelectorAll("input[name=lab]").forEach((inp) => {
    inp.addEventListener("change", () => onPick(inp.value));
  });
}
function onPick(code) {
  if (phase === "trial" && state.trialSubmitted) return;
  const rec = currentList()[curIdx], ans = currentMap()[rec.sid];
  if (!ans || ans.v === code) return;
  if (ans.v) { ans.c = (ans.c || 0) + 1; ans.tr.push([now() - state.startedAt, ans.v, code]); }
  ans.v = code;
  ui.labels.querySelectorAll(".lab").forEach((el) => {
    el.classList.toggle("on", el.querySelector("input").value === code);
  });
  renderTop(); updateNav(); save();
  if (code === "UN无法判定") ui.note.focus();
}
function noteChanged() {
  const ans = currentMap()[currentList()[curIdx].sid];
  if (!ans) return;
  if ((ans.n || "") !== ui.note.value) { ans.ne = (ans.ne || 0) + 1; ans.n = ui.note.value; }
  updateNav(); save();
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
  ui.gateHint.textContent = why || "";
  ui.prevBtn.disabled = curIdx === 0;
  const last = curIdx === currentList().length - 1;
  ui.nextBtn.textContent = last ? (phase === "trial" ? "完成试标 →" : "完成标注 →") : "下一句 →";
}
function leaveCurrent() {
  const a = currentMap()[currentList()[curIdx].sid];
  if (!a) return;
  a.t1 = now();
  if (a.enterAt) { a.d = (a.d || 0) + (a.t1 - a.enterAt); a.enterAt = 0; }
}
function enterCurrent() {
  const a = currentMap()[currentList()[curIdx].sid];
  if (a) a.enterAt = now();
}
function goNext() {
  if (unmet()) return;
  leaveCurrent();
  if (curIdx < currentList().length - 1) { curIdx++; enterCurrent(); renderQuestion(); return; }
  if (phase === "trial") { showTrialSubmit(); return; }
  finishMain();
}
function goPrev() {
  if (curIdx === 0) return;
  leaveCurrent(); curIdx--; enterCurrent(); renderQuestion();
}
function firstUnanswered(list, map) {
  for (let i = 0; i < list.length; i++) if (!(map[list[i].sid] && map[list[i].sid].v)) return i;
  return -1;
}
function showTrialSubmit() {
  hide(ui.work); hide(ui.feedback); hide(ui.finish); hide(ui.export);
  show(ui.trialSubmit);
  const done = payload.trial.filter((r) => state.trial[r.sid] && state.trial[r.sid].v).length;
  ui.trialSum.innerHTML = row("试标已答", done + " / " + payload.trial.length) +
    row("累计用时", fmtMs(now() - state.startedAt)) +
    row("提示", "提交后答案锁定，不能修改");
  ui.lockTrial.disabled = done < payload.trial.length;
  renderTop();
}
function lockTrial() {
  if (!confirm("提交并锁定试标答案？\n锁定后会立即显示参考答案与逐句反馈，答案不可再修改。")) return;
  state.trialSubmitted = true;
  state.trialLockedAt = now();
  save(true);
  showFeedback();
}
function trialCompare() {
  return payload.trial.map((r) => {
    const a = state.trial[r.sid] || blankAns();
    const ref = r.ref || "";
    return { sid: r.sid, aid: r.aid, text: r.text, seq: r.seq, mine: a.v || "", ref: ref,
             basis: r.basis || "", note: a.n || "", group: r.group || "", journal: r.journal || "",
             title: r.title || "", same: !!ref && a.v === ref };
  });
}
// 线索词高亮：词表取自《编码手册（第二版）》第四节"常见语言特征"
const CUES = [
  { move: "M1背景", ex: "近年／已有研究表明／然而／尚缺乏", re:
    /(In recent years|in recent years|has been reported|little is known|近年来|近年|已有研究表明|尚缺乏|研究较少|However|however)/g },
  { move: "M2目的", ex: "旨在／为探究／为…/本研究／aim／objective", re:
    /(旨在|为探究|为了解|为探讨|本研究|本文以|This study (?:was|aims|aimed)|was conducted to|we investigated|aims? to|objective)/g },
  { move: "M3方法", ex: "以…为材料／采用／随机区组／测定", re:
    /(以[^，。；]{0,12}为材料|采用|随机区组|测定|分离纯化|were determined by|was carried out|were measured|were analyzed|using)/g },
  { move: "M4结果", ex: "结果表明／显著高于／results showed", re:
    /(结果表明|结果显示|分析结果表明|显著高于|显著低于|分别达到|The results showed|the results showed|results showed|was significantly (?:higher|lower)|were significantly (?:higher|lower))/g },
  { move: "M5结论", ex: "表明／说明／可为…提供／suggest／indicate", re:
    /(阐明了|表明|说明|可为[^，。；]{0,12}提供|提供了|有望|有待进一步|Taken together|In conclusion|as a conclusion|suggest|indicate|provides? a)/g },
];
function markCues(text) {
  const t = String(text || "");
  const hits = [];
  CUES.forEach((c) => {
    c.re.lastIndex = 0;
    let m;
    while ((m = c.re.exec(t))) {
      if (!m[0]) break;
      hits.push({ s: m.index, e: m.index + m[0].length, move: c.move, ex: c.ex });
    }
  });
  hits.sort((a, b) => a.s - b.s || (b.e - b.s) - (a.e - a.s));
  let last = -1, out = "", pos = 0;
  hits.forEach((h) => {
    if (h.s < last) return;
    last = h.e;
    out += esc(t.slice(pos, h.s)) + '<mark class="cue" title="' + esc(h.move + " 线索：" + h.ex) +
      '">' + esc(t.slice(h.s, h.e)) + "</mark>";
    pos = h.e;
  });
  return out + esc(t.slice(pos));
}
let fbScope = "diff";                 // diff=只看分歧句 | all=逐句看全部
function fbCardHtml(r, withInput) {
  return '<div class="fbcard' + (r.same ? " ok" : "") + '" data-sid="' + esc(r.sid) + '">' +
    '<div class="fbc-head"><span class="mono sid">' + esc(r.sid) + "</span>" +
    '<span class="muted small">' + esc(r.group) + " ｜ " + esc(r.journal) + " ｜ 第 " +
    esc(String(r.seq)) + " 句</span>" +
    (r.same ? '<span class="chip ok">一致</span>' : '<span class="chip bad">不一致</span>') + "</div>" +
    '<p class="fbc-text">' + markCues(r.text) + "</p>" +
    '<div class="fbc-cmp">' +
    '<div class="cmpbox"><span class="lbl">你的判读</span><b>' + esc(r.mine || "（未填）") + "</b></div>" +
    '<div class="cmpbox ref"><span class="lbl">参考答案</span><b>' + esc(r.ref) + "</b></div></div>" +
    '<div class="fbc-basis"><span class="lbl">《编码手册》依据</span>' + esc(r.basis) + "</div>" +
    (r.note ? '<div class="fbc-note"><span class="lbl">你的备注</span>' + esc(r.note) + "</div>" : "") +
    (withInput
      ? '<label class="fbc-fix" for="calib-' + esc(r.sid) + '">这一句最后怎么定（一句话；不确定就写「仍存疑」）</label>' +
        '<input id="calib-' + esc(r.sid) + '" type="text" placeholder="' +
        "例：按语义重心判 M3方法（依据手册规则⑦）／仍存疑：两人读法不同" + '" value="' +
        esc(state.calib.rows[r.sid] || "") + '">'
      : "") + "</div>";
}
function wireCalibInputs(root) {
  root.querySelectorAll("input").forEach((inp) => {
    inp.addEventListener("input", () => {
      state.calib.rows[inp.id.replace("calib-", "")] = inp.value;
      calibChanged();
    });
  });
}
function renderFeedback() {
  const rows = trialCompare();
  const same = rows.filter((r) => r.same);
  const diff = rows.filter((r) => !r.same);
  ui.fbDiffN.textContent = String(diff.length);
  ui.fbSameN.textContent = String(same.length);
  ui.fbLead.innerHTML = diff.length
    ? "共 " + rows.length + " 句试标，你的判读与参考答案有 <strong>" + diff.length +
      " 句</strong>不同。下面默认只列这 " + diff.length + " 句（含句子全文与《编码手册》依据）；" +
      "要逐句过全部 " + rows.length + " 句，点上面的「逐句看全部」。"
    : "本次试标 " + rows.length + " 句全部一致，没有分歧句——直接写下面的《校准记录》即可进入正式标注。";
  // 两个视图只渲染其中一个，避免同名输入框重复
  if (fbScope === "all") {
    ui.fbAll.innerHTML = rows.map((r) => fbCardHtml(r, !r.same)).join("");
    ui.calibRows.innerHTML = "";
    ui.fbTable.innerHTML = "";
  } else {
    ui.calibRows.innerHTML = diff.length
      ? diff.map((r) => fbCardHtml(r, true)).join("")
      : '<p class="hint">本次试标全部一致，无分歧句。</p>';
    let h = "<thead><tr><th>试标ID</th><th>你的判读 ＝ 参考答案</th>" +
            "<th>《编码手册》依据</th></tr></thead><tbody>";
    same.forEach((r) => {
      h += '<tr class="same"><td class="mono">' + esc(r.sid) + "</td><td>" + esc(r.mine) +
        '</td><td class="small">' + esc(r.basis) + "</td></tr>";
    });
    ui.fbTable.innerHTML = h + "</tbody>";
    ui.fbAll.innerHTML = "";
  }
  wireCalibInputs(ui.calibRows);
  wireCalibInputs(ui.fbAll);
  ui.fbScope.querySelectorAll(".segbtn").forEach((b) => {
    b.classList.toggle("on", b.getAttribute("data-scope") === fbScope);
  });
  ui.fbDiffBlock.hidden = fbScope !== "diff";
  ui.fbAllBlock.hidden = fbScope !== "all";
}
function showFeedback() {
  phase = "feedback";
  hide(ui.work); hide(ui.trialSubmit); hide(ui.finish); hide(ui.export);
  show(ui.feedback);
  const rows = trialCompare();
  const same = rows.filter((r) => r.same);
  const diff = rows.filter((r) => !r.same);
  ui.keySource.textContent = "参考答案来源：" + (payload.trial_key_source || "研究者裁定") +
    "　（本页仅在提交并锁定试标后显示）";
  ui.fbSum.innerHTML = row("试标一致性", same.length + " / " + rows.length +
    "（" + Math.round(same.length / rows.length * 1000) / 10 + "%）") +
    row("需要讨论的不一致句", diff.length + " 句") +
    row("试标锁定时间", new Date(state.trialLockedAt).toLocaleString());
  renderFeedback();
  ui.calibSummary.value = state.calib.summary || "";
  ui.calibBy.value = state.calib.by || role || "";
  calibChanged();
  renderTop();
  save();
}
function calibChanged() {
  state.calib.summary = ui.calibSummary.value;
  state.calib.by = ui.calibBy.value;
  const ok = (state.calib.summary || "").trim().length >= 20;
  ui.toMain.disabled = !ok;
  ui.calibHint.textContent = ok ? "可以进入正式标注了" : "请先写下校准会谈定的规则（至少 20 字）";
  save();
}
const GATHER_MARK = "【逐句口径汇总，可继续改写】";
function gatherCalib() {
  const diff = trialCompare().filter((r) => !r.same);
  const parts = [];
  diff.forEach((r) => {
    const v = (state.calib.rows[r.sid] || "").trim();
    if (v) parts.push(r.sid + "：" + v);
  });
  if (!parts.length) {
    ui.calibGatherHint.textContent = diff.length
      ? "上面 " + diff.length + " 张卡还没填过口径——先各写一句，再点这里汇总。"
      : "本次试标全部一致，没有分歧句需要汇总。";
    return;
  }
  let prev = ui.calibSummary.value || "";
  const i = prev.indexOf(GATHER_MARK);
  if (i >= 0) prev = prev.slice(0, i).trimEnd();
  ui.calibSummary.value = (prev ? prev + "\n" : "") + GATHER_MARK + "\n" + parts.join("\n");
  calibChanged();
  ui.calibGatherHint.textContent = "已汇总 " + parts.length + " 句；请顺着改写成规则（再点会覆盖上一次的汇总部分）。";
}
function enterMain() {
  state.calib.done = true;
  state.calib.at = now();
  save(true);
  phase = "main";
  hide(ui.feedback);
  startMain();
}
function startMain() {
  phase = "main";
  const i = firstUnanswered(payload.sentences, state.main);
  if (i < 0) { finishMain(); return; }
  show(ui.work);
  curIdx = i;
  enterCurrent();
  renderQuestion();
}
function finishMain() {
  const answered = payload.sentences.filter((r) => state.main[r.sid] && state.main[r.sid].v).length;
  hide(ui.work); hide(ui.feedback); hide(ui.trialSubmit); hide(ui.export);
  show(ui.finish);
  ui.finishTitle.textContent = "472 句已全部标注完毕";
  ui.finishMsg.textContent = "请点下面的按钮提交。提交后答案会锁定，不能再修改。";
  ui.finishSum.innerHTML = row("已标注", answered + " / " + payload.sentences.length) +
    row("试标", state.trialSubmitted ? "已锁定并完成校准" : "未完成") +
    row("累计用时", fmtMs(now() - state.startedAt)) +
    row("本机存档", "答案只存在这台电脑的浏览器里");
  renderTop();
}
function submit() {
  const answered = payload.sentences.filter((r) => state.main[r.sid] && state.main[r.sid].v).length;
  if (answered < payload.sentences.length) { alert("还有 " + (payload.sentences.length - answered) + " 句未标注。"); return; }
  if (!confirm("确认提交？提交后答案将锁定、不可再修改。")) return;
  state.submitted = true;
  state.lockedAt = now();
  save(true);
  renderExport();
}
const COLS_MAIN = ["句子ID", "摘要编号", "语言组", "期刊", "年份", "学科", "题名", "句内序号", "待标句子", "人工标注", "备注"];
const COLS_TRIAL = ["试标ID", "摘要编号", "语言组", "期刊", "题名", "句内序号", "待标句子", "人工标注", "备注"];
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
function logFor(list, map) {
  return list.map((r) => {
    const a = map[r.sid] || blankAns();
    if (a.enterAt) { a.t1 = now(); a.d = (a.d || 0) + (a.t1 - a.enterAt); a.enterAt = 0; }
    return { sid: r.sid, aid: r.aid, seq: r.seq, label: a.v || "", note: a.n || "",
             noteLength: (a.n || "").length, noteEdits: a.ne || 0,
             enterCount: a.nEnter || 0, changeCount: a.c || 0,
             dwellMs: a.d || 0, dwellSec: Math.round((a.d || 0) / 100) / 10,
             firstAt: a.t0 ? new Date(a.t0).toISOString() : null,
             lastAt: a.t1 ? new Date(a.t1).toISOString() : null,
             changes: (a.tr || []).map((x) => ({ atSec: Math.round(x[0] / 100) / 10, from: x[1], to: x[2] })) };
  });
}
function calibMarkdown() {
  const rows = trialCompare();
  const same = rows.filter((r) => r.same).length;
  const L = ["# 试标校准记录", "",
    "- 标注员：" + (state.calib.by || role),
    "- 试标提交并锁定时间：" + new Date(state.trialLockedAt).toLocaleString(),
    "- 校准记录完成时间：" + (state.calib.at ? new Date(state.calib.at).toLocaleString() : ""),
    "- 试标一致性：" + same + " / " + rows.length + "（" + Math.round(same / rows.length * 1000) / 10 + "%）",
    "- 参考答案来源：" + (payload.trial_key_source || ""), "",
    "## 一、试标逐句对照", "",
    "| 试标ID | 你的判读 | 参考答案 | 是否一致 | 手册依据 | 谈定口径 |",
    "| --- | --- | --- | --- | --- | --- |"];
  rows.forEach((r) => {
    L.push("| " + r.sid + " | " + r.mine + " | " + r.ref + " | " + (r.same ? "一致" : "不一致") +
           " | " + r.basis + " | " + (state.calib.rows[r.sid] || "") + " |");
  });
  L.push("", "## 二、本次校准会谈定的规则", "", (state.calib.summary || "").trim(), "");
  return L.join("\n");
}
async function exportBundle() {
  const mainCsv = toCsv(COLS_MAIN, rowsFor(payload.sentences, state.main, COLS_MAIN));
  const trialCsv = toCsv(COLS_TRIAL, rowsFor(payload.trial, state.trial, COLS_TRIAL));
  const calibMd = calibMarkdown();
  const mainSha = await sha256(mainCsv), trialSha = await sha256(trialCsv);
  const log = {
    schema: "agri-move-annotation-log/2",
    role: role, dataset: payload.dataset,
    session: {
      startedAt: new Date(state.startedAt).toISOString(),
      trialLockedAt: state.trialLockedAt ? new Date(state.trialLockedAt).toISOString() : null,
      calibAt: state.calib.at ? new Date(state.calib.at).toISOString() : null,
      submittedAt: state.lockedAt ? new Date(state.lockedAt).toISOString() : null,
      exportAt: new Date().toISOString(),
      elapsedMs: now() - state.startedAt,
      ua: navigator.userAgent, lang: navigator.language,
      timezone: (Intl.DateTimeFormat().resolvedOptions().timeZone || ""),
      screen: screen.width + "x" + screen.height,
      viewport: innerWidth + "x" + innerHeight,
      localTimeOffsetMin: new Date().getTimezoneOffset(),
    },
    trial: { submitted: state.trialSubmitted, total: payload.trial.length,
             same: trialCompare().filter((r) => r.same).length },
    calibration: { summary: state.calib.summary, by: state.calib.by,
                   mismatchNotes: state.calib.rows, done: state.calib.done },
    counts: { main: payload.sentences.length,
              mainAnswered: payload.sentences.filter((r) => state.main[r.sid] && state.main[r.sid].v).length,
              noteFilled: payload.sentences.filter((r) => state.main[r.sid] && (state.main[r.sid].n || "").trim()).length },
    hashes: { mainCsvSha256: mainSha, trialCsvSha256: trialSha },
    trialLog: logFor(payload.trial, state.trial),
    mainLog: logFor(payload.sentences, state.main),
  };
  return { mainCsv, trialCsv, calibMd, log };
}
function renderExport() {
  phase = "done";
  hide(ui.work); hide(ui.finish); hide(ui.trialSubmit); hide(ui.feedback);
  show(ui.export);
  const answered = payload.sentences.filter((r) => state.main[r.sid] && state.main[r.sid].v).length;
  ui.exportTitle.textContent = "✅ 已提交并锁定";
  ui.exportSum.innerHTML = row("标注员", role) +
    row("正式标注", answered + " / " + payload.sentences.length) +
    row("试标", state.trialSubmitted ? "已锁定并完成校准" : "未完成") +
    row("锁定时长（自开始）", fmtMs(state.lockedAt - state.startedAt)) +
    row("题库版本", payload.dataset.version);
  renderTop();
}
async function doExport(kind) {
  try {
    const b = await exportBundle();
    state.exportedAt = now(); save(true);
    const base = "效度验证_标注员" + role + "_" + stamp();
    if (kind === "main") download(base + "_正式标注.csv", b.mainCsv, "text/csv;charset=utf-8");
    else if (kind === "trial") download(base + "_试标集.csv", b.trialCsv, "text/csv;charset=utf-8");
    else if (kind === "calib") download(base + "_校准记录.md", b.calibMd, "text/markdown;charset=utf-8");
    else download(base + "_过程日志.json", JSON.stringify(b.log, null, 1), "application/json;charset=utf-8");
  } catch (e) {
    alert("导出失败：" + (e && e.message ? e.message : e) + "\n请把这一页截图发给老师。");
  }
}
function bindOnce() {
  if (bound) return;
  bound = true;
  ui.lockTrial.addEventListener("click", lockTrial);
  ui.fbScope.addEventListener("click", (e) => {
    const b = e.target.closest(".segbtn");
    if (!b) return;
    fbScope = b.getAttribute("data-scope") || "diff";
    renderFeedback();
  });
  ui.toMain.addEventListener("click", enterMain);
  ui.calibSummary.addEventListener("input", calibChanged);
  ui.calibBy.addEventListener("input", calibChanged);
  ui.calibGather.addEventListener("click", gatherCalib);
  ui.nextBtn.addEventListener("click", goNext);
  ui.prevBtn.addEventListener("click", goPrev);
  ui.note.addEventListener("input", noteChanged);
  ui.submitBtn.addEventListener("click", submit);
  ui.csvMain.addEventListener("click", () => doExport("main"));
  ui.csvTrial.addEventListener("click", () => doExport("trial"));
  ui.jsonLog.addEventListener("click", () => doExport("log"));
  ui.csvCalib.addEventListener("click", () => doExport("calib"));
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
      if (e.key === "Enter" && e.target.tagName === "TEXTAREA" && (e.ctrlKey || e.metaKey)) {
        e.preventDefault(); goNext();
      }
      return;
    }
    if (/^[1-7]$/.test(e.key)) {
      const L = payload.labels[Number(e.key) - 1];
      if (L) { const inp = ui.labels.querySelector('input[value="' + L.code + '"]');
        if (inp && !inp.disabled) { inp.checked = true; onPick(L.code); } }
    } else if (e.key === "Enter" || e.key === "ArrowRight") { if (!ui.nextBtn.disabled) goNext(); }
    else if (e.key === "ArrowLeft" && !ui.prevBtn.disabled) goPrev();
  });
  window.addEventListener("beforeunload", () => { leaveCurrent(); save(true); });
  setInterval(() => { if (!ui.work.hidden && !state.submitted) renderTop(); }, 30000);
}
function start() {
  hide(ui.gateForm); ui.gateMsg.textContent = "正在解密题库…"; hide(ui.gateErr);
  fetch("data/enc_" + role.toLowerCase() + ".json", { cache: "no-cache" })
    .then((r) => { if (!r.ok) throw new Error("题库文件读取失败（HTTP " + r.status + "）"); return r.json(); })
    .then((pe) => decrypt(pe, pass))
    .then((p) => {
      payload = p;
      hide(ui.gate);
      state = loadState();
      bindOnce();
      if (state.submitted) { renderExport(); return; }
      if (!state.trialSubmitted) {
        const i = firstUnanswered(payload.trial, state.trial);
        phase = "trial";
        if (i < 0) { showTrialSubmit(); } else { show(ui.work); curIdx = i; enterCurrent(); renderQuestion(); }
        return;
      }
      if (!state.calib.done) { showFeedback(); return; }
      startMain();
    })
    .catch((e) => {
      show(ui.gateErr);
      ui.gateErr.textContent = "口令不对或浏览器不支持：" + (e && e.message ? e.message : e) +
        "\n请确认口令没有多余空格；若仍不行，把这一页截图发给老师。";
      ui.gateMsg.textContent = "未能进入标注。";
      show(ui.gateForm);
    });
}
function boot() {
  const frag = parseFragment();
  role = (frag.role || "").toUpperCase() === "B" ? "B" : (frag.role ? "A" : "");
  pass = frag.k || "";
  if (role && frag.reset === "1") {
    localStorage.removeItem("anno_v103_" + role);
    ui.gateMsg.textContent = "已清空标注员 " + role + " 的本机数据，请重新进入。";
  }
  if (!role) {
    ui.gateMsg.textContent = "请选择你的标注员编号，并输入老师给你的口令。";
    show(ui.gateForm);
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
  ui.gateMsg.textContent = "链接里没有口令，请输入老师给你的口令。";
  show(ui.gateForm);
  document.querySelectorAll(".rolebtn").forEach((b) => b.setAttribute("aria-pressed", b.dataset.role === role));
  ui.pass.addEventListener("input", () => { ui.enterBtn.disabled = !ui.pass.value.trim(); });
  ui.enterBtn.addEventListener("click", () => { pass = ui.pass.value.trim(); start(); });
}
window.addEventListener("hashchange", () => { if (!payload) boot(); });
boot();
