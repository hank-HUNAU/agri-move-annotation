/* 160-sentence retest. Answers and logs stay in this browser until export. */
"use strict";

const $ = (id) => document.getElementById(id);
const encoder = new TextEncoder();
const BATCH_ID = "retest160_v121_20261031";
const LABELS = ["M1背景", "M2目的", "M3方法", "M4结果", "M5结论", "UN"];
const STORE_PREFIX = "retest160_v121_";
const NOTE_SEP = "；";

let payload = null;
let state = null;
let role = "";
let pass = "";
let currentIndex = 0;
let activeSince = 0;
let saveTimer = null;
let sourceBankHash = "";
let renderToken = 0;

const ui = {
  roleBadge: $("roleBadge"),
  progressText: $("progressText"),
  saveText: $("saveText"),
  progressBar: $("progressBar"),
  gate: $("gate"),
  gateErr: $("gateErr"),
  gateMsg: $("gateMsg"),
  gateForm: $("gateForm"),
  password: $("password"),
  enterBtn: $("enterBtn"),
  rules: $("rules"),
  ruleCards: $("ruleCards"),
  rulesAck: $("rulesAck"),
  startBtn: $("startBtn"),
  work: $("work"),
  qIndex: $("qIndex"),
  qMeta: $("qMeta"),
  qText: $("qText"),
  labels: $("labels"),
  note: $("note"),
  noteChips: $("noteChips"),
  prevBtn: $("prevBtn"),
  nextBtn: $("nextBtn"),
  firstUnanswered: $("firstUnanswered"),
  abstractText: $("abstractText"),
  finish: $("finish"),
  finishSummary: $("finishSummary"),
  lockBtn: $("lockBtn"),
  export: $("export"),
  exportCsv: $("exportCsv"),
  exportLog: $("exportLog"),
  exportRules: $("exportRules"),
  exportManifest: $("exportManifest"),
  exportZip: $("exportZip"),
  exportSummary: $("exportSummary"),
  exportHint: $("exportHint"),
  toast: $("toast"),
  versionText: $("versionText"),
};

function now() {
  return Date.now();
}

function hide(element) {
  element.hidden = true;
}

function show(element) {
  element.hidden = false;
}

function showOnly(target) {
  [ui.gate, ui.rules, ui.work, ui.finish, ui.export].forEach(hide);
  show(target);
  window.scrollTo({ top: 0, behavior: "instant" });
}

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  }[character]));
}

function fmtDuration(ms) {
  const seconds = Math.max(0, Math.round(ms / 1000));
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const rest = seconds % 60;
  if (hours) return `${hours} 小时 ${minutes} 分`;
  if (minutes) return `${minutes} 分 ${rest} 秒`;
  return `${rest} 秒`;
}

function stamp() {
  const date = new Date();
  const pad = (number) => String(number).padStart(2, "0");
  return `${date.getFullYear()}${pad(date.getMonth() + 1)}${pad(date.getDate())}_${pad(date.getHours())}${pad(date.getMinutes())}`;
}

function toast(message) {
  ui.toast.textContent = message;
  ui.toast.hidden = false;
  window.clearTimeout(toast.timer);
  toast.timer = window.setTimeout(() => {
    ui.toast.hidden = true;
  }, 3200);
}

function parseFragment() {
  const result = {};
  location.hash.replace(/^#/, "").split("&").forEach((pair) => {
    if (!pair) return;
    const index = pair.indexOf("=");
    const key = decodeURIComponent(index < 0 ? pair : pair.slice(0, index));
    result[key] = index < 0 ? "" : decodeURIComponent(pair.slice(index + 1));
  });
  return result;
}

function b64ToBuffer(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function hex(buffer) {
  return [...new Uint8Array(buffer)]
    .map((value) => value.toString(16).padStart(2, "0"))
    .join("");
}

async function sha256(text) {
  return hex(await crypto.subtle.digest("SHA-256", encoder.encode(text)));
}

async function decryptBank(encrypted, password) {
  if (!crypto.subtle) {
    throw new Error("当前浏览器不支持 WebCrypto，请改用新版 Edge、Chrome 或 Safari。");
  }
  const base = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  const key = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: b64ToBuffer(encrypted.salt),
      iterations: encrypted.iter,
      hash: "SHA-256",
    },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );
  const clear = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64ToBuffer(encrypted.iv) },
    key,
    b64ToBuffer(encrypted.ct),
  );
  return JSON.parse(new TextDecoder().decode(clear));
}

function stateKey() {
  return STORE_PREFIX + role;
}

function blankAnswer() {
  return {
    v: "",
    n: "",
    activeMs: 0,
    enterCount: 0,
    revisions: 0,
    lastSeenAt: 0,
    transitions: [],
  };
}

function newState() {
  return {
    schema: "agri-retest160-state/1",
    batchId: BATCH_ID,
    role,
    questionIds: payload.questions.map((question) => question.sid),
    startedAt: now(),
    lastSeenAt: now(),
    rulesAck: false,
    rulesAckAt: 0,
    currentIndex: 0,
    answers: {},
    submitted: false,
    lockedAt: 0,
    exports: [],
    exportAt: 0,
  };
}

function loadState() {
  try {
    const stored = localStorage.getItem(stateKey());
    if (!stored) return newState();
    const loaded = JSON.parse(stored);
    if (
      loaded
      && loaded.schema === "agri-retest160-state/1"
      && loaded.batchId === BATCH_ID
      && loaded.role === role
      && Array.isArray(loaded.questionIds)
      && loaded.questionIds.length === payload.questions.length
    ) {
      loaded.answers = loaded.answers || {};
      loaded.exports = loaded.exports || [];
      return loaded;
    }
  } catch (error) {
    console.warn("Stored state ignored", error);
  }
  return newState();
}

function save(immediate = false) {
  window.clearTimeout(saveTimer);
  const action = () => {
    try {
      state.lastSeenAt = now();
      localStorage.setItem(stateKey(), JSON.stringify(state));
      ui.saveText.textContent = "已自动保存";
    } catch (error) {
      ui.saveText.textContent = "保存失败，请立即导出";
      console.error(error);
    }
  };
  if (immediate) action();
  else saveTimer = window.setTimeout(action, 180);
}

function answerFor(sid) {
  if (!state.answers[sid]) state.answers[sid] = blankAnswer();
  return state.answers[sid];
}

function currentQuestion() {
  return payload.questions[currentIndex] || null;
}

function answeredCount() {
  return payload.questions.filter((question) => {
    const answer = state.answers[question.sid];
    return answer && answer.v;
  }).length;
}

function firstUnansweredIndex() {
  const index = payload.questions.findIndex((question) => {
    const answer = state.answers[question.sid];
    return !answer || !answer.v;
  });
  return index < 0 ? payload.questions.length - 1 : index;
}

function flushActiveTime() {
  const question = currentQuestion();
  if (!question || !activeSince) return;
  const answer = answerFor(question.sid);
  answer.activeMs += Math.max(0, now() - activeSince);
  activeSince = 0;
}

function startActiveTime() {
  activeSince = now();
}

function updateGlobalProgress() {
  if (!payload) return;
  const done = answeredCount();
  const total = payload.questions.length;
  ui.progressText.textContent = `${done} / ${total}`;
  ui.progressBar.style.width = `${(done / total) * 100}%`;
}

function renderRules() {
  ui.ruleCards.innerHTML = payload.rules.map((rule) => `
    <div class="rule">
      <code>${esc(rule.label)}</code>
      <p>${esc(rule.text)}</p>
    </div>
  `).join("");
  ui.rulesAck.checked = false;
  ui.startBtn.disabled = true;
  showOnly(ui.rules);
}

function abstractHtml(abstractText, sentence) {
  const rawSentence = String(sentence || "");
  const candidates = [rawSentence, rawSentence.trim()];
  for (const candidate of candidates) {
    if (!candidate) continue;
    const index = abstractText.indexOf(candidate);
    if (index >= 0) {
      return esc(abstractText.slice(0, index))
        + "<mark>" + esc(candidate) + "</mark>"
        + esc(abstractText.slice(index + candidate.length));
    }
  }
  return esc(abstractText);
}

function renderQuestion() {
  flushActiveTime();
  updateGlobalProgress();
  const total = payload.questions.length;
  if (currentIndex >= total) {
    showFinish();
    return;
  }
  if (currentIndex < 0) currentIndex = 0;
  state.currentIndex = currentIndex;
  const question = payload.questions[currentIndex];
  const answer = answerFor(question.sid);
  answer.enterCount += 1;
  answer.lastSeenAt = now();
  startActiveTime();

  showOnly(ui.work);
  ui.qIndex.textContent = `第 ${currentIndex + 1} / ${total} 句`;
  ui.qMeta.textContent = `${question.journal}（${question.year}） · ${question.discipline}`;
  ui.qText.textContent = question.text;
  ui.note.value = answer.n || "";
  ui.prevBtn.disabled = currentIndex === 0;
  ui.nextBtn.textContent = currentIndex === total - 1 ? "完成最后一句 →" : "下一句 →";
  ui.nextBtn.disabled = false;

  ui.labels.innerHTML = LABELS.map((label) => `
    <button type="button"
      class="label-btn ${label === "UN" ? "un" : ""} ${answer.v === label ? "on" : ""}"
      data-label="${esc(label)}"
      aria-pressed="${answer.v === label ? "true" : "false"}">
      ${esc(label)}
    </button>
  `).join("");

  const abstract = payload.abstracts[question.aid];
  const abstractText = abstract ? abstract.text : question.title || "";
  ui.abstractText.innerHTML = abstractHtml(abstractText, question.text);
  save();
}

function selectLabel(label) {
  const question = currentQuestion();
  if (!question || !LABELS.includes(label)) return;
  const answer = answerFor(question.sid);
  if (answer.v !== label) {
    answer.v = label;
    answer.revisions += 1;
    answer.transitions.push({ at: now(), value: label });
  }
  save(true);
  renderQuestion();
}

function appendNote(text) {
  if (!currentQuestion()) return;
  const current = ui.note.value.trim();
  if (current.includes(text)) return;
  ui.note.value = current ? current + NOTE_SEP + text : text;
  const answer = answerFor(currentQuestion().sid);
  answer.n = ui.note.value;
  save();
  ui.note.focus();
}

function validateCurrent() {
  const question = currentQuestion();
  if (!question) return false;
  const answer = answerFor(question.sid);
  if (!answer.v) {
    toast("请先选择语步标签。");
    return false;
  }
  if (answer.v === "UN" && !String(answer.n || "").trim()) {
    toast("选择 UN无法判定 时必须在备注中说明原因。");
    ui.note.focus();
    return false;
  }
  return true;
}

function goNext() {
  if (!validateCurrent()) return;
  flushActiveTime();
  if (currentIndex >= payload.questions.length - 1) {
    currentIndex = payload.questions.length;
  } else {
    currentIndex += 1;
  }
  state.currentIndex = currentIndex;
  save(true);
  renderQuestion();
}

function goPrevious() {
  if (currentIndex <= 0) return;
  flushActiveTime();
  currentIndex -= 1;
  state.currentIndex = currentIndex;
  save(true);
  renderQuestion();
}

function goFirstUnanswered() {
  flushActiveTime();
  currentIndex = firstUnansweredIndex();
  state.currentIndex = currentIndex;
  save(true);
  renderQuestion();
}

function summaryHtml(items) {
  return items.map(([label, value]) => `
    <div class="summary-item">
      <span class="muted small">${esc(label)}</span>
      <b>${esc(value)}</b>
    </div>
  `).join("");
}

function invalidUnAnswers() {
  return payload.questions.filter((question) => {
    const answer = state.answers[question.sid];
    return answer && answer.v === "UN" && !String(answer.n || "").trim();
  }).map((question) => question.sid);
}

function showFinish() {
  flushActiveTime();
  updateGlobalProgress();
  showOnly(ui.finish);
  const done = answeredCount();
  const notes = payload.questions.filter((question) => {
    const answer = state.answers[question.sid];
    return answer && String(answer.n || "").trim();
  }).length;
  const invalid = invalidUnAnswers();
  ui.finishSummary.innerHTML = summaryHtml([
    ["已答", `${done} / ${payload.questions.length}`],
    ["有备注", `${notes} 句`],
    ["UN 缺备注", `${invalid.length} 句`],
    ["当前角色", role],
  ]);
  ui.lockBtn.disabled = done !== payload.questions.length || invalid.length > 0;
  if (invalid.length) {
    ui.lockBtn.textContent = `还有 ${invalid.length} 个 UN 未写备注`;
  } else {
    ui.lockBtn.textContent = "提交并锁定";
  }
}

function lockSubmission() {
  if (answeredCount() !== payload.questions.length) {
    toast("仍有未答题目。");
    return;
  }
  if (invalidUnAnswers().length) {
    toast("仍有 UN 未写备注。");
    return;
  }
  flushActiveTime();
  state.submitted = true;
  state.lockedAt = now();
  save(true);
  showExport();
}

function csvCell(value) {
  const text = value === null || value === undefined ? "" : String(value);
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

function buildCsv() {
  const headers = [
    "句子ID", "摘要编号", "语言组", "期刊", "年份", "学科",
    "题名", "句内序号", "待标句子", "人工标注", "备注",
  ];
  const lines = [headers.map(csvCell).join(",")];
  for (const question of payload.questions) {
    const answer = answerFor(question.sid);
    lines.push([
      question.sid,
      question.aid,
      question.group,
      question.journal,
      question.year,
      question.discipline,
      question.title,
      question.seq,
      question.text,
      answer.v,
      answer.n,
    ].map(csvCell).join(","));
  }
  return "\ufeff" + lines.join("\r\n") + "\r\n";
}

function buildRulesMd() {
  const lines = [
    "# 160 句补测 · 规则确认记录",
    "",
    `- 批次：${BATCH_ID}`,
    `- 标注员：${role}`,
    `- 规则确认时间：${state.rulesAckAt ? new Date(state.rulesAckAt).toISOString() : ""}`,
    `- 开始时间：${new Date(state.startedAt).toISOString()}`,
    "",
    "## 已阅读规则",
    "",
  ];
  for (const rule of payload.rules) {
    lines.push(`- **${rule.label}**：${rule.text}`);
  }
  lines.push(
    "",
    "## 确认",
    "",
    "本人已阅读判定规则，按要求独立完成 160 句补测；未查看或讨论另一名标注员的答案。",
    "",
  );
  return lines.join("\n");
}

function buildLogHashes() {
  return {
    datasetSourceCsvSha256: payload.dataset.source_csv_sha256,
    bankFileSha256: sourceBankHash,
  };
}

function buildLog() {
  const answers = payload.questions.map((question, index) => {
    const answer = answerFor(question.sid);
    return {
      position: index + 1,
      sid: question.sid,
      aid: question.aid,
      group: question.group,
      value: answer.v,
      note: answer.n,
      activeMs: Math.round(answer.activeMs),
      enterCount: answer.enterCount,
      revisions: answer.revisions,
      transitions: answer.transitions,
    };
  });
  return {
    schema: "agri-retest160-log/1",
    batchId: BATCH_ID,
    role,
    dataset: payload.dataset,
    rulesAcknowledgement: {
      acknowledged: !!state.rulesAck,
      at: state.rulesAckAt ? new Date(state.rulesAckAt).toISOString() : null,
      rules: payload.rules,
    },
    session: {
      startedAt: new Date(state.startedAt).toISOString(),
      submittedAt: state.lockedAt ? new Date(state.lockedAt).toISOString() : null,
      exportedAt: new Date().toISOString(),
      activeDurationMs: answers.reduce((sum, answer) => sum + answer.activeMs, 0),
    },
    counts: {
      total: payload.questions.length,
      answered: answeredCount(),
      noteFilled: answers.filter((answer) => answer.note.trim()).length,
      un: answers.filter((answer) => answer.value === "UN").length,
    },
    environment: {
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      userAgent: navigator.userAgent,
      language: navigator.language,
    },
    hashes: buildLogHashes(),
    answers,
    exports: state.exports,
  };
}

function buildManifest(csvHash, logHash, rulesHash) {
  return [
    "# 160 句补测 · 数据完整性清单",
    "",
    `- 批次：${BATCH_ID}`,
    `- 标注员：${role}`,
    `- 锁定时间：${state.lockedAt ? new Date(state.lockedAt).toISOString() : ""}`,
    `- 题量：${payload.questions.length}`,
    `- 语料版本：${payload.dataset.version}`,
    `- 题库来源 CSV SHA256：${payload.dataset.source_csv_sha256}`,
    `- 加密题库文件 SHA256：${sourceBankHash}`,
    "",
    "## 交回文件",
    "",
    `- 补测判定 CSV：${csvHash}`,
    `- 过程日志 JSON：${logHash}`,
    `- 规则确认记录 MD：${rulesHash}`,
    "",
    "> 可再用 SHA256 工具核对上述文件，确认交回后未被改动。",
    "",
  ].join("\n");
}

function download(name, text, type) {
  const blob = new Blob([text], { type: type || "text/plain;charset=utf-8" });
  const anchor = document.createElement("a");
  anchor.href = URL.createObjectURL(blob);
  anchor.download = name;
  document.body.appendChild(anchor);
  anchor.click();
  window.setTimeout(() => {
    URL.revokeObjectURL(anchor.href);
    anchor.remove();
  }, 4000);
}

function downloadBytes(name, bytes, type) {
  const blob = new Blob([bytes], { type: type || "application/octet-stream" });
  const anchor = document.createElement("a");
  anchor.href = URL.createObjectURL(blob);
  anchor.download = name;
  document.body.appendChild(anchor);
  anchor.click();
  window.setTimeout(() => {
    URL.revokeObjectURL(anchor.href);
    anchor.remove();
  }, 4000);
}

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let number = 0; number < 256; number += 1) {
    let value = number;
    for (let bit = 0; bit < 8; bit += 1) {
      value = value & 1 ? 0xEDB88320 ^ (value >>> 1) : value >>> 1;
    }
    table[number] = value >>> 0;
  }
  return table;
})();

function crc32(bytes) {
  let value = 0xFFFFFFFF;
  for (let index = 0; index < bytes.length; index += 1) {
    value = CRC_TABLE[(value ^ bytes[index]) & 0xFF] ^ (value >>> 8);
  }
  return (value ^ 0xFFFFFFFF) >>> 0;
}

async function deflateRaw(bytes) {
  if (typeof CompressionStream === "undefined") return null;
  try {
    const stream = new Blob([bytes])
      .stream()
      .pipeThrough(new CompressionStream("deflate-raw"));
    return new Uint8Array(await new Response(stream).arrayBuffer());
  } catch (error) {
    return null;
  }
}

async function makeZip(entries) {
  const date = new Date();
  const time = ((date.getHours() << 11) | (date.getMinutes() << 5) | (date.getSeconds() >> 1)) & 0xFFFF;
  const day = (((date.getFullYear() - 1980) << 9) | ((date.getMonth() + 1) << 5) | date.getDate()) & 0xFFFF;
  const parts = [];
  const central = [];
  let offset = 0;
  for (const entry of entries) {
    const name = encoder.encode(entry.name);
    const crc = crc32(entry.bytes);
    const compressed = await deflateRaw(entry.bytes);
    const useCompressed = compressed && compressed.length < entry.bytes.length;
    const data = useCompressed ? compressed : entry.bytes;
    const method = useCompressed ? 8 : 0;
    const local = new DataView(new ArrayBuffer(30));
    local.setUint32(0, 0x04034b50, true);
    local.setUint16(4, 20, true);
    local.setUint16(6, 0x0800, true);
    local.setUint16(8, method, true);
    local.setUint16(10, time, true);
    local.setUint16(12, day, true);
    local.setUint32(14, crc, true);
    local.setUint32(18, data.length, true);
    local.setUint32(22, entry.bytes.length, true);
    local.setUint16(26, name.length, true);
    local.setUint16(28, 0, true);
    parts.push(new Uint8Array(local.buffer), name, data);
    const header = new DataView(new ArrayBuffer(46));
    header.setUint32(0, 0x02014b50, true);
    header.setUint16(4, 20, true);
    header.setUint16(6, 20, true);
    header.setUint16(8, 0x0800, true);
    header.setUint16(10, method, true);
    header.setUint16(12, time, true);
    header.setUint16(14, day, true);
    header.setUint32(16, crc, true);
    header.setUint32(20, data.length, true);
    header.setUint32(24, entry.bytes.length, true);
    header.setUint16(28, name.length, true);
    header.setUint32(42, offset, true);
    central.push(new Uint8Array(header.buffer), name);
    offset += 30 + name.length + data.length;
  }
  const centralSize = central.reduce((sum, part) => sum + part.length, 0);
  const end = new DataView(new ArrayBuffer(22));
  end.setUint32(0, 0x06054b50, true);
  end.setUint16(8, entries.length, true);
  end.setUint16(10, entries.length, true);
  end.setUint32(12, centralSize, true);
  end.setUint32(16, offset, true);
  const chunks = [...parts, ...central, new Uint8Array(end.buffer)];
  const output = new Uint8Array(chunks.reduce((sum, part) => sum + part.length, 0));
  let position = 0;
  for (const part of chunks) {
    output.set(part, position);
    position += part.length;
  }
  return output;
}

async function exportBundle() {
  const csv = buildCsv();
  const rules = buildRulesMd();
  const csvHash = await sha256(csv);
  const rulesHash = await sha256(rules);
  const baseLog = buildLog();
  baseLog.hashes.csvSha256 = csvHash;
  baseLog.hashes.rulesSha256 = rulesHash;
  const logText = JSON.stringify(baseLog, null, 2);
  const logHash = await sha256(logText);
  const manifest = buildManifest(csvHash, logHash, rulesHash);
  const dashboard = JSON.stringify({
    schema: "agri-retest160-dashboard/1",
    batchId: BATCH_ID,
    role,
    dataset: payload.dataset,
    hashes: { csv: csvHash, log: logHash, rules: rulesHash },
  }, null, 2);
  return {
    csv,
    log: logText,
    rules,
    manifest,
    dashboard,
    csvHash,
    logHash,
    rulesHash,
  };
}

function exportName(suffix) {
  return `效度补测160_标注员${role}_${stamp()}_${suffix}`;
}

async function doExport(kind) {
  const bundle = await exportBundle();
  if (kind === "csv") {
    download(exportName("补测判定.csv"), bundle.csv, "text/csv;charset=utf-8");
  } else if (kind === "log") {
    download(exportName("过程日志.json"), bundle.log, "application/json;charset=utf-8");
  } else if (kind === "rules") {
    download(exportName("规则确认记录.md"), bundle.rules, "text/markdown;charset=utf-8");
  } else {
    download(exportName("数据完整性清单.md"), bundle.manifest, "text/markdown;charset=utf-8");
  }
  if (!state.exports.includes(kind)) state.exports.push(kind);
  state.exportAt = now();
  save(true);
  renderExport();
  toast("文件已生成。");
}

async function exportZip() {
  const bundle = await exportBundle();
  const base = `效度补测160_标注员${role}_${stamp()}`;
  const entries = [
    {
      name: `${base}_补测判定.csv`,
      bytes: encoder.encode(bundle.csv),
    },
    {
      name: `${base}_过程日志.json`,
      bytes: encoder.encode(bundle.log),
    },
    {
      name: `${base}_规则确认记录.md`,
      bytes: encoder.encode(bundle.rules),
    },
    {
      name: `${base}_数据完整性清单.md`,
      bytes: encoder.encode(bundle.manifest),
    },
  ];
  const zip = await makeZip(entries);
  downloadBytes(`${base}_交回包.zip`, zip, "application/zip");
  state.exports = ["csv", "log", "rules", "manifest", "zip"];
  state.exportAt = now();
  save(true);
  renderExport();
  toast("交回包已生成。");
}

function showExport() {
  showOnly(ui.export);
  renderExport();
}

function renderExport() {
  const done = answeredCount();
  const exported = new Set(state.exports);
  const completed = ["csv", "log", "rules", "manifest"].filter((item) => exported.has(item)).length;
  ui.exportSummary.innerHTML = summaryHtml([
    ["标注员", role],
    ["已锁定", `${done} / ${payload.questions.length}`],
    ["单独导出文件", `${completed} / 4`],
    ["ZIP 交回包", exported.has("zip") ? "已生成" : "未生成"],
  ]);
  ui.exportHint.textContent = exported.has("zip")
    ? "ZIP 已包含四份文件，把 ZIP 发回老师即可。"
    : "建议优先点击“一键导出交回包 ZIP”。";
}

async function start() {
  if (!role) {
    ui.gateErr.hidden = false;
    ui.gateErr.textContent = "请选择标注员。";
    return;
  }
  if (!pass) {
    ui.gateErr.hidden = false;
    ui.gateErr.textContent = "请输入访问口令。";
    return;
  }
  ui.gateErr.hidden = true;
  ui.gateForm.hidden = true;
  ui.gateMsg.textContent = "正在下载并解密题库…";
  try {
    const response = await fetch(`data/enc_retest160_${role.toLowerCase()}.json`, { cache: "no-store" });
    if (!response.ok) throw new Error(`题库下载失败（HTTP ${response.status}）`);
    const text = await response.text();
    sourceBankHash = await sha256(text);
    const encrypted = JSON.parse(text);
    payload = await decryptBank(encrypted, pass);
    if (payload.schema !== "agri-move-retest160-payload/1" || payload.batch_id !== BATCH_ID) {
      throw new Error("题库版本不匹配。");
    }
    if (payload.role !== role) throw new Error("口令与标注员身份不匹配。");
    state = loadState();
    ui.roleBadge.hidden = false;
    ui.roleBadge.textContent = `标注员 ${role}`;
    ui.versionText.textContent = `${payload.dataset.version} · ${payload.questions.length} 句`;
    currentIndex = Math.max(0, Math.min(state.currentIndex || 0, payload.questions.length));
    if (state.submitted) {
      showExport();
      return;
    }
    if (!state.rulesAck) {
      renderRules();
      return;
    }
    showWork();
  } catch (error) {
    console.error(error);
    ui.gateForm.hidden = false;
    ui.gateErr.hidden = false;
    ui.gateErr.textContent = error && error.name === "OperationError"
      ? "口令不正确，或该口令不属于所选标注员。"
      : (error.message || String(error));
    ui.gateMsg.textContent = "题库加载失败，请检查网络后重试。";
  }
}

function showWork() {
  if (currentIndex >= payload.questions.length) {
    showFinish();
  } else {
    renderQuestion();
  }
  updateGlobalProgress();
}

function acknowledgeRules() {
  state.rulesAck = true;
  state.rulesAckAt = now();
  currentIndex = firstUnansweredIndex();
  state.currentIndex = currentIndex;
  save(true);
  showWork();
}

function bindEvents() {
  document.querySelectorAll(".role-btn").forEach((button) => {
    button.addEventListener("click", () => {
      role = button.dataset.role;
      document.querySelectorAll(".role-btn").forEach((other) => {
        const selected = other === button;
        other.classList.toggle("on", selected);
        other.setAttribute("aria-pressed", selected ? "true" : "false");
      });
      ui.enterBtn.disabled = !(role && pass);
    });
  });
  ui.password.addEventListener("input", () => {
    pass = ui.password.value.trim();
    ui.enterBtn.disabled = !(role && pass);
  });
  ui.password.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !ui.enterBtn.disabled) start();
  });
  ui.enterBtn.addEventListener("click", start);
  ui.rulesAck.addEventListener("change", () => {
    ui.startBtn.disabled = !ui.rulesAck.checked;
  });
  ui.startBtn.addEventListener("click", acknowledgeRules);
  ui.labels.addEventListener("click", (event) => {
    const button = event.target.closest("[data-label]");
    if (button) selectLabel(button.dataset.label);
  });
  ui.noteChips.addEventListener("click", (event) => {
    const button = event.target.closest("[data-note]");
    if (button) appendNote(button.dataset.note);
  });
  ui.note.addEventListener("input", () => {
    const question = currentQuestion();
    if (!question) return;
    answerFor(question.sid).n = ui.note.value;
    save();
  });
  ui.prevBtn.addEventListener("click", goPrevious);
  ui.nextBtn.addEventListener("click", goNext);
  ui.firstUnanswered.addEventListener("click", goFirstUnanswered);
  ui.lockBtn.addEventListener("click", lockSubmission);
  ui.exportCsv.addEventListener("click", () => doExport("csv"));
  ui.exportLog.addEventListener("click", () => doExport("log"));
  ui.exportRules.addEventListener("click", () => doExport("rules"));
  ui.exportManifest.addEventListener("click", () => doExport("manifest"));
  ui.exportZip.addEventListener("click", exportZip);
  document.addEventListener("keydown", (event) => {
    if (ui.work.hidden || event.ctrlKey || event.metaKey || event.altKey) return;
    if (["INPUT", "TEXTAREA", "SELECT"].includes(event.target.tagName)) return;
    const number = Number(event.key);
    if (number >= 1 && number <= 6) {
      selectLabel(LABELS[number - 1]);
      event.preventDefault();
    } else if (event.key === "Enter") {
      goNext();
      event.preventDefault();
    }
  });
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) {
      flushActiveTime();
      save(true);
    } else if (!ui.work.hidden) {
      startActiveTime();
    }
  });
  window.addEventListener("beforeunload", () => {
    flushActiveTime();
    save(true);
  });
}

function initializeGate() {
  bindEvents();
  const fragment = parseFragment();
  role = (fragment.role || "").toUpperCase() === "B"
    ? "B"
    : (fragment.role || "").toUpperCase() === "A" ? "A" : "";
  pass = fragment.k || "";
  if (role) {
    document.querySelectorAll(".role-btn").forEach((button) => {
      const selected = button.dataset.role === role;
      button.classList.toggle("on", selected);
      button.setAttribute("aria-pressed", selected ? "true" : "false");
    });
  }
  if (pass) ui.password.value = pass;
  if (role && pass) {
    start();
    return;
  }
  ui.gateMsg.textContent = role
    ? "请输入访问口令后进入。"
    : "请选择标注员并输入访问口令。";
  ui.gateForm.hidden = false;
  ui.enterBtn.disabled = !(role && pass);
}

initializeGate();
