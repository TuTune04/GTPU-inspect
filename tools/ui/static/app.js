"use strict";

/* ================= tiện ích ================= */

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmtN = (n) => (n ?? 0).toLocaleString("vi-VN");
const hex32 = (t) => (t == null ? "–" : "0x" + t.toString(16).padStart(8, "0"));
const dash = (v) => (v == null ? "–" : v);

const store = {
  get(k, d) { try { const v = localStorage.getItem("gtpu." + k); return v == null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { localStorage.setItem("gtpu." + k, JSON.stringify(v)); } catch { /* bỏ qua */ } },
};

async function api(path, body, raw) {
  const opt = body === undefined ? {} : {
    method: "POST",
    headers: { "X-GTPU-UI": "1", ...(raw ? {} : { "Content-Type": "application/json" }) },
    body: raw ? body : JSON.stringify(body),
  };
  const r = await fetch(path, opt);
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.detail || `HTTP ${r.status}`);
  return data;
}
const q = (o) => new URLSearchParams(o).toString();

const LAYER_NAME = { eth: "Ethernet", ip: "IPv4", udp: "UDP", gtp: "GTP-U", ext: "Extension", inner: "IP bên trong", payload: "Payload" };
const layerColor = (k) => `var(--${k})`;

const WHY = {
  eth_truncated: "Chưa đủ 14 byte header Ethernet.",
  ip_truncated: "Thiếu byte trong header IPv4 (cần 20 byte, hoặc IHL × 4).",
  ip_bad_ihl: "IHL nhỏ hơn 5: header IPv4 không thể ngắn hơn 20 byte.",
  ip_bad_version: "EtherType báo IPv4 nhưng trường Version khác 4.",
  ip_len_mismatch: "Total length không khớp với số byte thật sự có.",
  udp_truncated: "Chưa đủ 8 byte header UDP.",
  udp_len_mismatch: "UDP length nhỏ hơn 8 hoặc vượt quá phần payload IP.",
  gtp_truncated: "Chưa đủ 8 byte header GTP-U bắt buộc.",
  gtp_bad_version: "Version khác 1, không phải GTPv1-U.",
  gtp_bad_pt: "PT = 0 là GTP' (tính cước), không phải GTP.",
  gtp_len_mismatch: "8 + Length không bằng độ dài payload UDP.",
  gtp_opt_truncated: "Cờ E/S/PN bật nhưng thiếu 4 byte trường tùy chọn.",
  gtp_ext_bad_len: "Extension có length = 0: spec cấm, đi tiếp sẽ lặp vô hạn.",
  gtp_ext_truncated: "Extension header vượt quá cuối gói.",
  gtp_ext_too_many: "Chuỗi extension dài hơn giới hạn của parser.",
  inner_truncated: "IP bên trong ngắn hơn 20 byte.",
  inner_bad_ihl: "IP bên trong có IHL < 5 hoặc version sai.",
  not_ipv4: "EtherType không phải IPv4 (0x0800).",
  not_udp: "IPv4 protocol không phải UDP (17).",
  not_gtpu_port: "Cổng UDP đích không phải 2152.",
  ip_fragment: "IPv4 bị phân mảnh, parser không ghép mảnh.",
};

const vClass = (v) => (v === "ok" ? "v-ok" : String(v).startsWith("ignored") ? "v-ign" : "v-err");
const vHtml = (v) => (v == null ? '<span class="dim">–</span>' : `<span class="verdict ${vClass(v)}">${esc(v)}</span>`);
const vOrder = (v) => (v === "ok" ? 0 : String(v).startsWith("ignored") ? 1 : 2);

/* ================= trạng thái ================= */

const S = {
  file: store.get("file", "tests/data/gtpu_5g_ext.pcap"),
  tab: store.get("tab", "analyze"),
  analysis: null,
  sel: 0,
  filter: null,
  status: null,
};

/* ================= vẽ một gói: dải byte + lưới octet + hex ================= */

const MAX_ROWS = 40;

function renderPacket(el, d, verdict, head) {
  if (!d) { el.innerHTML = '<p class="detail-empty">Chọn một gói để xem từng byte.</p>'; return; }
  const blame = d.blame || {};
  const keys = d.layers.map((l) => l.key);
  if (!el._layer || !keys.includes(el._layer) || el._lastVerdict !== verdict) {
    el._layer = keys.includes(blame.layer) ? blame.layer
      : keys.includes("gtp") ? "gtp" : (keys.filter((k) => k !== "payload").pop() || keys[0]);
  }
  el._lastVerdict = verdict;
  el._d = d;

  if (!el.querySelector(".strip")) {
    el.innerHTML = `<div class="detail-head"></div>
      <div class="strip" role="group" aria-label="Các lớp của gói, rộng theo số byte"></div>
      <div class="ruler"><span>0</span><span class="r-end"></span></div>
      <div class="layer"></div>
      <div class="hex" aria-label="Byte của gói"></div>`;
  }
  $(".detail-head", el).innerHTML = head || "";

  // dải byte: tái dùng phần tử theo key để chuyển động co giãn
  const strip = $(".strip", el);
  const gtp = d.layers.find((l) => l.key === "gtp");
  const scale = Math.max(d.len, gtp ? gtp.declared_end : 0, 1);
  const seen = new Set();
  for (const l of d.layers) {
    seen.add(l.key);
    let seg = strip.querySelector(`.seg[data-key="${l.key}"]`);
    if (!seg) {
      seg = document.createElement("button");
      seg.className = `seg k-${l.key}`;
      seg.dataset.key = l.key;
      seg.dataset.term = "layer." + l.key;
      seg.dataset.noopen = "Bấm để xem lưới octet của lớp này";
      seg.style.setProperty("--k", layerColor(l.key));
      seg.style.left = (l.start / scale) * 100 + "%";
      seg.style.width = "0";
      seg.addEventListener("click", () => { el._layer = l.key; renderPacket(el, el._d, el._lastVerdict, $(".detail-head", el).innerHTML); });
      strip.append(seg);
    }
    const n = l.end - l.start;
    seg.innerHTML = `<b>${esc(l.name)}</b><span>${n}</span>`;
    seg.setAttribute("aria-label", `${l.name}, ${n} byte`);
    seg.setAttribute("aria-pressed", String(l.key === el._layer));
    seg.classList.toggle("blamed", l.key === blame.layer && vClass(verdict) === "v-err");
    requestAnimationFrame(() => {
      seg.style.left = (l.start / scale) * 100 + "%";
      seg.style.width = `max(${(n / scale) * 100}%, 3px)`;
    });
  }
  $$(".seg", strip).forEach((s) => { if (!seen.has(s.dataset.key)) s.remove(); });
  let ghost = $(".ghost", strip);
  if (gtp && gtp.declared_end > d.len) {
    if (!ghost) { ghost = document.createElement("div"); ghost.className = "ghost"; strip.append(ghost); }
    ghost.style.left = (d.len / scale) * 100 + "%";
    ghost.style.width = ((gtp.declared_end - d.len) / scale) * 100 + "%";
    ghost.textContent = `GTP length cần thêm ${gtp.declared_end - d.len} byte`;
    ghost.title = ghost.textContent;
  } else if (ghost) ghost.remove();
  $(".r-end", el).textContent = `${d.len} byte`;

  renderLayer($(".layer", el), d, el._layer, blame, verdict, el);
  renderHex($(".hex", el), d);
}

function fieldBytes(f) {
  const n = Math.ceil((f.bit + f.bits) / 8);
  return [f.off, f.off + n - 1];
}

function renderLayer(box, d, key, blame, verdict, host) {
  const layer = d.layers.find((l) => l.key === key);
  if (!layer) { box.innerHTML = ""; return; }
  const title = `<div class="layer-title" style="--k:${layerColor(key)}"><span class="swatch"></span><h3>${esc(layer.name)}</h3>
    <span class="hint">byte ${layer.start}–${Math.max(layer.start, layer.end - 1)}</span>
    <button type="button" class="info-btn" data-term="layer.${key}">${esc(layer.name)} là gì?</button></div>`;
  const vc = vClass(verdict);
  const reason = String(verdict || "").split(":")[1];
  let note = "";
  if (verdict === "ok") note = `<p class="blame-note ok">Parser chấp nhận gói này.</p>`;
  else if (verdict && WHY[reason]) {
    const where = blame.layer ? ` Parser dừng ở lớp ${LAYER_NAME[blame.layer]}${blame.field ? `, trường ${blame.field}` : ""}.` : "";
    note = `<p class="blame-note">${esc(WHY[reason])}${esc(where)}</p>`;
  }

  if (!layer.fields.length) {
    box.innerHTML = title + `<p class="hint">Phần payload không có header để vẽ; xem byte ở khung hex bên dưới.</p>` + note;
    return;
  }

  // trường bị trỏ tới
  let blamedIdx = -1;
  if (vc !== "v-ok" && blame.layer === key) {
    blamedIdx = layer.fields.findIndex((f) => blame.field && (f.name === blame.field || f.name.endsWith(" " + blame.field)));
    if (blamedIdx < 0 && vc === "v-err") blamedIdx = layer.fields.findIndex((f) => f.missing);
  }

  let rows = 0;
  for (const f of layer.fields) rows = Math.max(rows, fieldBytes(f)[1] - layer.start + 1);
  const cap = host._expanded === key ? rows : Math.min(rows, MAX_ROWS);

  const cells = [`<div class="oct-bit" style="grid-column:1;grid-row:1">octet</div>`];
  for (let b = 0; b < 8; b++) cells.push(`<div class="oct-bit" style="grid-column:${b + 2};grid-row:1">${8 - b}</div>`);
  for (let r = 0; r < cap; r++) cells.push(`<div class="oct-num" style="grid-column:1;grid-row:${r + 2}">${r + 1}</div>`);

  layer.fields.forEach((f, i) => {
    const pieces = [];
    let pos = (f.off - layer.start) * 8 + f.bit, rem = f.bits;
    while (rem > 0) {
      const row = Math.floor(pos / 8), col = pos % 8;
      if (col === 0 && rem >= 8) {
        const h = Math.floor(rem / 8);
        pieces.push({ row, col: 0, w: 8, h }); pos += h * 8; rem -= h * 8;
      } else {
        const w = Math.min(8 - col, rem);
        pieces.push({ row, col, w, h: 1 }); pos += w; rem -= w;
      }
    }
    const main = pieces.reduce((a, p) => (p.w * p.h > a.w * a.h ? p : a), pieces[0]);
    const [b0, b1] = fieldBytes(f);
    const val = f.missing ? "thiếu" : esc(f.text);
    const ctx = esc(JSON.stringify({ layer: key, layerName: layer.name, val: f.missing ? null : f.text,
      b0, b1, o0: b0 - layer.start + 1, o1: b1 - layer.start + 1, bits: f.bits, note: f.note }));
    for (const p of pieces) {
      if (p.row >= cap) continue;
      const h = Math.min(p.h, cap - p.row);
      const cls = ["field", p === main ? "" : "cont", f.missing ? "missing" : "", i === blamedIdx ? "blamed" : ""].join(" ");
      cells.push(`<div class="${cls}" data-b0="${b0}" data-b1="${b1}" data-term="${esc(glossaryKey(key, f.name))}" data-ctx="${ctx}"
        tabindex="${p === main ? 0 : -1}" role="button" aria-label="${esc(f.name)}: ${f.missing ? "thiếu byte" : esc(f.text)}"
        style="--k:${layerColor(key)};grid-column:${p.col + 2} / span ${p.w};grid-row:${p.row + 2} / span ${h}">
        <span class="fn">${esc(f.name)}</span><span class="fv">${p === main ? val : "…"}</span></div>`);
    }
  });
  if (cap < rows) {
    cells.push(`<div class="oct-more" style="grid-row:${cap + 2}">Còn ${rows - cap} octet nữa. <button type="button" data-more>Hiện hết</button></div>`);
  }
  box.innerHTML = title + `<div class="octets" role="img" aria-label="Lưới octet của lớp ${esc(layer.name)}">${cells.join("")}</div>` + note;
  const more = $("[data-more]", box);
  if (more) more.onclick = () => { host._expanded = key; renderLayer(box, d, key, blame, verdict, host); };
  $$(".field", box).forEach((c) => {
    c.addEventListener("mouseenter", () => hlHex(host, +c.dataset.b0, +c.dataset.b1));
    c.addEventListener("mouseleave", () => hlHex(host, -1, -2));
  });
}

const HEX_CAP = 2048;
function renderHex(box, d) {
  const n = Math.min(d.len, HEX_CAP);
  const keyAt = new Array(n);
  for (const l of d.layers) for (let i = l.start; i < Math.min(l.end, n); i++) keyAt[i] = l.key;
  const out = [];
  for (let i = 0; i < n; i++) {
    if (i % 16 === 0) out.push(`<span class="off">${i.toString(16).padStart(4, "0")}</span>`);
    const k = keyAt[i] || "payload";
    out.push(`<span data-i="${i}" data-k="${k}" style="--k:${layerColor(k === "payload" ? "ink-3" : k)}">${d.hex.substr(i * 2, 2)}</span>`);
  }
  if (d.len > n) out.push(`<span style="grid-column:1/-1" class="dim">… còn ${d.len - n} byte</span>`);
  box.innerHTML = out.join("");
}

function hlHex(host, b0, b1) {
  $$(".hex span.hl", host).forEach((s) => s.classList.remove("hl"));
  for (let i = b0; i <= b1; i++) { const s = $(`.hex span[data-i="${i}"]`, host); if (s) s.classList.add("hl"); }
}

/* ================= chú giải: tooltip + ngăn 5W1H ================= */

const T = (key, text) => `<span class="term" tabindex="0" role="button" data-term="${esc(key)}">${esc(text)}</span>`;
const W5 = [["what", "Là gì", "What"], ["why", "Tại sao cần", "Why"], ["who", "Ai dùng", "Who"],
  ["when", "Khi nào", "When"], ["where", "Ở đâu", "Where"], ["how", "Thế nào", "How"]];
const KEY_LAYER = { eth: "eth", ip: "ip", udp: "udp", gtp: "gtp", ext: "ext", layer: null, term: null };

function termLayer(key, ctx) {
  if (ctx?.layer) return ctx.layer;
  if (GLOSSARY[key]?.layer) return GLOSSARY[key].layer;
  const [head, rest] = key.split(/\.(.*)/s);
  return head === "layer" ? rest : KEY_LAYER[head] ?? null;
}
function readCtx(el) {
  try { return el.dataset.ctx ? JSON.parse(el.dataset.ctx) : null; } catch { return null; }
}

const tip = $("#tip");
let tipTimer = 0, tipFor = null;
function showTip(el) {
  const g = GLOSSARY[el.dataset.term];
  if (!g) return;
  const ctx = readCtx(el);
  tip.innerHTML = `<b>${esc(g.t)}</b>${esc(g.s)}`
    + (ctx ? `<div class="tip-val">Giá trị ${ctx.val == null ? "thiếu" : esc(ctx.val)} (octet ${ctx.o0}${ctx.o1 > ctx.o0 ? "–" + ctx.o1 : ""})</div>` : "")
    + `<div class="tip-more">${esc(el.dataset.noopen || "Bấm để xem chi tiết 5W1H")}</div>`;
  tip.hidden = false;
  const r = el.getBoundingClientRect(), t = tip.getBoundingClientRect();
  let top = r.bottom + 8;
  if (top + t.height > innerHeight - 8) top = r.top - t.height - 8;
  const left = Math.min(Math.max(8, r.left + r.width / 2 - t.width / 2), innerWidth - t.width - 8);
  tip.style.top = Math.max(8, top) + "px";
  tip.style.left = left + "px";
}
function hideTip() { clearTimeout(tipTimer); tipFor = null; tip.hidden = true; }

document.addEventListener("mouseover", (e) => {
  const el = e.target.closest("[data-term]");
  if (el === tipFor) return;
  hideTip();
  if (!el) return;
  tipFor = el;
  tipTimer = setTimeout(() => showTip(el), 220);
});
document.addEventListener("focusin", (e) => {
  const el = e.target.closest("[data-term]");
  hideTip();
  if (el && el.matches(":focus-visible")) { tipFor = el; showTip(el); }
});
document.addEventListener("focusout", hideTip);
addEventListener("scroll", hideTip, true);

let glossOpener = null;
function openGloss(key, ctx, opener) {
  hideTip();
  const g = GLOSSARY[key], box = $("#gloss"), body = $("#gloss-body");
  const lk = termLayer(key, ctx);
  box.style.setProperty("--k", lk ? layerColor(lk) : "var(--ink)");
  $("#gloss-layer").textContent = lk ? `Lớp ${LAYER_NAME[lk]}` : "Khái niệm";
  $("#gloss-title").textContent = g ? g.t : key;
  if (!g) {
    body.innerHTML = `<p class="gloss-lede">Chưa có chú giải cho mục này.</p><p class="hint">Thêm khóa <code>${esc(key)}</code> vào <code>tools/ui/static/glossary.js</code>.</p>`;
  } else {
    let live = "";
    if (ctx) {
      live = `<div class="gloss-live">Trong gói đang xem: <span class="mono">${ctx.val == null ? "thiếu byte" : esc(ctx.val)}</span><br>
        Octet ${ctx.o0}${ctx.o1 > ctx.o0 ? "–" + ctx.o1 : ""} của lớp ${esc(ctx.layerName)}, tức byte ${ctx.b0}${ctx.b1 > ctx.b0 ? "–" + ctx.b1 : ""} của frame, dài ${ctx.bits} bit.`
        + (ctx.layer === "inner" ? "<br>Đây là header IP của gói người dùng, nằm bên trong tunnel." : "")
        + (ctx.note ? `<br>Ghi chú: ${esc(ctx.note)}.` : "") + `</div>`;
    }
    body.innerHTML = `<p class="gloss-lede">${esc(g.s)}</p>${live}
      <dl class="w5">${W5.filter(([k]) => g[k]).map(([k, vi, en]) => `<dt>${vi}<small>${en}</small></dt><dd>${esc(g[k])}</dd>`).join("")}</dl>
      ${g.proj ? `<div class="gloss-proj"><h3>Trong dự án này</h3>${esc(g.proj)}</div>` : ""}
      ${g.spec ? `<p class="gloss-spec">Tài liệu: ${esc(g.spec)}</p>` : ""}
      ${g.see?.length ? `<div class="gloss-see"><h3>Liên quan</h3><ul>${g.see.filter((k) => GLOSSARY[k]).map((k) =>
        `<li><button type="button" data-see="${esc(k)}">${esc(GLOSSARY[k].t)}</button></li>`).join("")}</ul></div>` : ""}`;
    body.scrollTop = 0;
  }
  if (box.hidden) glossOpener = opener || document.activeElement;
  box.hidden = false;
  $("#gloss-close").focus({ preventScroll: true });
}
function closeGloss() {
  const box = $("#gloss");
  if (box.hidden) return;
  box.hidden = true;
  if (glossOpener?.isConnected) glossOpener.focus({ preventScroll: true });
  glossOpener = null;
}
$("#gloss-close").addEventListener("click", closeGloss);
$("#gloss-body").addEventListener("click", (e) => {
  const b = e.target.closest("[data-see]");
  if (b) openGloss(b.dataset.see, null);
});
document.addEventListener("click", (e) => {
  const el = e.target.closest("[data-term]");
  if (!el || el.dataset.noopen) return;
  e.preventDefault(); // thuật ngữ nằm trong <label>: không bật checkbox/focus input
  openGloss(el.dataset.term, readCtx(el), el);
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") { hideTip(); closeGloss(); return; }
  const el = e.target.closest?.("[data-term][role=button]");
  if (el && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); openGloss(el.dataset.term, readCtx(el), el); }
});

/* ================= sidebar ================= */

async function loadStatus() {
  try { S.status = await api("/api/status"); } catch { S.status = null; }
  const st = S.status, el = $("#status");
  if (!st) { el.innerHTML = '<span class="warn">Không gọi được server.</span>'; return; }
  if (!st.binary) { el.innerHTML = '<span class="warn">Chưa có build/gtpu-inspect.</span> Build ở tab Build &amp; test.'; return; }
  const t = new Date(st.binary_mtime * 1000).toLocaleTimeString("vi-VN", { hour: "2-digit", minute: "2-digit" });
  el.innerHTML = `Binary build lúc <b>${t}</b>. Đọc output ${st.json ? "<b>-j</b> (JSON)" : "<b>-v</b> (text); thêm -j để có QFI từng gói"}.`
    + (st.tshark ? "" : ' <span class="warn">Thiếu tshark.</span>');
}

async function loadFiles() {
  const groups = await api("/api/files");
  $("#files").innerHTML = groups.map((g) => `<div><h2>${esc(g.title)}</h2><ul>${g.files.map((f) =>
    `<li><button data-path="${esc(f.path)}" title="${esc(f.path)}"${f.path === S.file ? ' aria-current="true"' : ""}>
      <span>${esc(f.name)}</span><small>${f.size < 10240 ? f.size + " B" : Math.round(f.size / 1024) + " kB"}</small></button></li>`).join("")}</ul></div>`).join("");
}

$("#files").addEventListener("click", (e) => {
  const b = e.target.closest("button[data-path]");
  if (b) selectFile(b.dataset.path);
});

$("#upload").addEventListener("change", async (e) => {
  const f = e.target.files[0];
  if (!f) return;
  const r = await api("/api/upload?" + q({ name: f.name }), f, true);
  e.target.value = "";
  await loadFiles();
  selectFile(r.path);
});

$("#path-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const p = $("#path-input").value.trim();
  if (p) selectFile(p);
});

// URL luôn chỉ đúng file và tab đang xem: tải lại trang hay chép link đều ra đúng chỗ.
function syncUrl() {
  history.replaceState(null, "", location.pathname + (S.file ? "?" + q({ file: S.file }) : "") + "#" + (S.tab || "analyze"));
}

function selectFile(path) {
  S.file = path; store.set("file", path);
  syncUrl();
  S.sel = 0; S.filter = null;
  $$("#files button").forEach((b) => (b.dataset.path === path
    ? b.setAttribute("aria-current", "true") : b.removeAttribute("aria-current")));
  if (S.tab === "compare") loadCompare();
  if (S.tab === "build") showTab("analyze"); else loadAnalysis();
}

/* ================= tabs ================= */

const TABS = ["analyze", "build", "compare", "test"];
function showTab(name) {
  S.tab = name; store.set("tab", name);
  syncUrl();
  for (const t of TABS) {
    const on = t === name;
    const btn = $("#tab-" + t);
    btn.setAttribute("aria-selected", String(on));
    btn.tabIndex = on ? 0 : -1;
    $("#panel-" + t).hidden = !on;
  }
  if (name === "analyze") loadAnalysis();
  if (name === "compare") loadCompare();
  if (name === "build") previewSoon(0);
  if (name === "test") loadTests();
}
$(".tabs").addEventListener("click", (e) => {
  const b = e.target.closest("[role=tab]");
  if (b) showTab(b.id.slice(4));
});
$(".tabs").addEventListener("keydown", (e) => {
  if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
  const i = TABS.indexOf(S.tab) + (e.key === "ArrowRight" ? 1 : -1);
  showTab(TABS[(i + TABS.length) % TABS.length]);
  $("#tab-" + S.tab).focus();
});

/* ================= tab phân tích ================= */

function noBinary(box) {
  box.innerHTML = `<div class="empty"><h2>Chưa có binary để chạy</h2>
    <p>Giao diện gọi <code>build/gtpu-inspect</code>, file này chưa tồn tại. Build một lần là dùng được.</p>
    <button class="btn" type="button" onclick="showTab('test')">Mở Build &amp; test</button></div>`;
}

// Xóa bảng, chi tiết, chân trang: không để lại gói của file trước khi file mới lỗi.
function clearAnalysis(lede) {
  S.analysis = null;
  $("#an-lede").textContent = lede;
  for (const id of ["#an-verdicts", "#an-table tbody", "#an-detail", "#an-foot"]) $(id).innerHTML = "";
  $("#an-filter-note").hidden = true;
}

let anSeq = 0;
async function loadAnalysis() {
  const seq = ++anSeq;
  $("#an-title").textContent = S.file.split("/").pop();
  let res;
  try { res = await api("/api/analyze?" + q({ path: S.file, top: $("#an-top").value || 10 })); }
  catch (e) {
    if (seq === anSeq) clearAnalysis(e.message);
    return;
  }
  if (seq !== anSeq) return;
  if (res.error === "no_binary") {
    clearAnalysis("");
    noBinary($("#an-detail"));
    return;
  }
  if (res.error) {
    clearAnalysis("");
    $("#an-verdicts").innerHTML = `<div class="err-box">Không đọc được output của binary: ${esc(res.detail)}<pre>${esc(res.stdout?.slice(0, 2000))}</pre></div>`;
    return;
  }
  S.analysis = res;
  const pk = res.packets, sm = res.summary || {};
  const cnt = { ok: 0, ign: 0, err: 0 };
  for (const p of pk) cnt[vClass(p.result).slice(2)]++;
  $("#an-lede").innerHTML = pk.length || sm.packets
    ? `${fmtN(sm.packets ?? pk.length)} gói, ${fmtN(sm.bytes)} byte: ${fmtN(cnt.ok)} được chấp nhận, ${fmtN(cnt.ign)} bị bỏ qua, ${fmtN(cnt.err)} lỗi.`
    : "File không có gói nào.";

  let html = "";
  if (res.rc !== 0 && res.stderr) html += `<div class="err-box">Binary thoát với mã ${res.rc}.<pre>${esc(res.stderr.trim())}</pre></div>`;
  const results = Object.entries(sm.results || {}).sort((a, b) => vOrder(a[0]) - vOrder(b[0]) || b[1] - a[1]);
  const total = results.reduce((s, [, n]) => s + n, 0) || 1;
  if (results.length) {
    const col = (v) => `var(--${vClass(v) === "v-ok" ? "good" : vClass(v) === "v-ign" ? "ign" : "bad"})`;
    html += `<div class="vbar" aria-hidden="true">${results.map(([v, n]) => `<i style="--c:${col(v)};flex:${n / total}" title="${esc(v)}: ${n}"></i>`).join("")}</div>
      <div class="vchips" role="group" aria-label="Lọc theo verdict">${results.map(([v, n]) =>
        `<button class="vchip" data-v="${esc(v)}" aria-pressed="${S.filter === v}" style="--c:${col(v)}">${esc(v)} <b>${fmtN(n)}</b></button>`).join("")}</div>`;
  }
  $("#an-verdicts").innerHTML = html;
  renderTable();
  renderFoot(sm);
}

$("#an-verdicts").addEventListener("click", (e) => {
  const c = e.target.closest(".vchip");
  if (!c) return;
  S.filter = S.filter === c.dataset.v ? null : c.dataset.v;
  $$(".vchip").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.v === S.filter)));
  renderTable();
});

const TABLE_CAP = 3000;
function visiblePackets() {
  const pk = S.analysis?.packets || [];
  return S.filter ? pk.filter((p) => p.result === S.filter) : pk;
}

function renderTable() {
  const vis = visiblePackets();
  const note = $("#an-filter-note");
  const cut = S.analysis?.truncated;
  note.hidden = !S.filter && !cut && vis.length <= TABLE_CAP;
  note.innerHTML = (S.filter ? `Đang lọc <b>${esc(S.filter)}</b>: ${fmtN(vis.length)} gói. <button type="button" id="clear-filter">Bỏ lọc</button> ` : "")
    + (cut ? `Chi tiết chỉ có cho ${fmtN(S.analysis.packets.length)} gói đầu trên tổng ${fmtN(S.analysis.summary.packets)}; thanh verdict và bảng phiên tính trên cả file.`
      : vis.length > TABLE_CAP ? `Chỉ hiện ${fmtN(TABLE_CAP)} gói đầu.` : "");
  const cf = $("#clear-filter");
  if (cf) cf.onclick = () => { S.filter = null; $$(".vchip").forEach((b) => b.setAttribute("aria-pressed", "false")); renderTable(); };
  if (vis.length && !vis.some((p) => p.idx === S.sel)) S.sel = vis[0].idx;
  $("#an-table tbody").innerHTML = vis.slice(0, TABLE_CAP).map((p) => `<tr data-idx="${p.idx}" aria-selected="${p.idx === S.sel}">
    <td class="num mono">${p.idx}</td><td>${vHtml(p.result)}</td><td class="mono">${p.teid == null ? '<span class="dim">–</span>' : hex32(p.teid)}</td>
    <td>${p.msg_name ? esc(p.msg_name) : '<span class="dim">–</span>'}</td><td class="num mono">${dash(p.qfi)}</td>
    <td class="mono">${p.inner_src ? `${esc(p.inner_src)} → ${esc(p.inner_dst)}` : '<span class="dim">–</span>'}</td></tr>`).join("")
    || `<tr><td colspan="6" class="dim">Không có gói.</td></tr>`;
  loadPacket();
}

$("#an-table").addEventListener("click", (e) => {
  const tr = e.target.closest("tr[data-idx]");
  if (tr) { S.sel = +tr.dataset.idx; markSel(); loadPacket(); }
});
$("#an-table-scroll").addEventListener("keydown", (e) => {
  if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
  e.preventDefault();
  const vis = visiblePackets().slice(0, TABLE_CAP);
  const i = vis.findIndex((p) => p.idx === S.sel) + (e.key === "ArrowDown" ? 1 : -1);
  if (i < 0 || i >= vis.length) return;
  S.sel = vis[i].idx; markSel(); loadPacket();
});
function markSel() {
  $$("#an-table tbody tr").forEach((tr) => {
    const on = +tr.dataset.idx === S.sel;
    tr.setAttribute("aria-selected", String(on));
    if (on) tr.scrollIntoView({ block: "nearest" });
  });
}

let pkSeq = 0;
async function loadPacket() {
  const seq = ++pkSeq;
  const p = (S.analysis?.packets || []).find((x) => x.idx === S.sel);
  const box = $("#an-detail");
  if (!p) { renderPacket(box, null); return; }
  try {
    const d = await api("/api/packet?" + q({ path: S.file, idx: p.idx, verdict: p.result }));
    if (seq !== pkSeq) return;
    renderPacket(box, d, p.result, `<h2>Gói #${p.idx}</h2>${vHtml(p.result)}`);
  } catch (e) {
    if (seq === pkSeq) box.innerHTML = `<p class="detail-empty">${esc(e.message)}</p>`;
  }
}

function bars(entries, label, color) {
  const max = Math.max(1, ...entries.map((e) => e[1]));
  return `<div class="bars">${entries.map(([k, n]) => `<div><span>${esc(label(k))}<span class="bar" style="width:${(n / max) * 100}%;--k:${color}"></span></span><span class="n">${fmtN(n)}</span></div>`).join("")}</div>`;
}

function renderFoot(sm) {
  const names = { 1: "Echo Request", 2: "Echo Response", 26: "Error Indication", 254: "End Marker", 255: "G-PDU" };
  const ts = sm.top_sessions || [];
  const mt = Object.entries(sm.msg_types || {});
  const qf = Object.entries(sm.qfi || {}).sort((a, b) => a[0] - b[0]);
  $("#an-foot").innerHTML = `
    <div class="card"><h3>Phiên nhiều byte nhất</h3>${ts.length ? `<table><thead><tr><th>${T("gtp.TEID", "TEID")}</th><th>${T("term.endpoint", "Endpoint")}</th><th class="num">Gói</th><th class="num">Byte</th><th class="num">Flow</th><th class="num">${T("ext.QFI", "QFI")}</th></tr></thead>
      <tbody>${ts.map((s) => `<tr><td class="mono">${hex32(s.teid)}</td><td class="mono">${esc(s.endpoint)}</td><td class="num mono">${fmtN(s.packets)}</td><td class="num mono">${fmtN(s.bytes)}</td><td class="num mono">${dash(s.flows)}</td><td class="num mono">${dash(s.qfi)}</td></tr>`).join("")}</tbody></table>`
      : '<p class="hint">Không có phiên G-PDU nào.</p>'}</div>
    <div class="card"><h3>${T("gtp.Message type", "Message type")}</h3>${mt.length ? bars(mt, (k) => `${names[k] || "Unknown"} (${k})`, "var(--gtp)") : '<p class="hint">Không có gói GTP-U hợp lệ.</p>'}</div>
    <div class="card"><h3>${T("ext.QFI", "QFI")}</h3>${qf.length ? bars(qf, (k) => `QFI ${k}`, "var(--ext)") : '<p class="hint">Không gói nào có PDU Session Container.</p>'}</div>`;
}

$("#an-run").addEventListener("click", loadAnalysis);
$("#an-top").addEventListener("change", loadAnalysis);
$("#an-ws").addEventListener("click", () => openWireshark(S.file));

async function openWireshark(path) {
  try { await api("/api/wireshark", { path }); } catch (e) { flash(e.message); }
}
let toastTimer = 0;
function flash(msg) {
  const el = $("#toast");
  el.textContent = msg;
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.hidden = true; }, 6000);
}

/* ================= tab tạo gói ================= */

const DEFAULT_SPEC = () => ({
  outer: {}, gtp: { teid: "0x5001", msg_type: "255", ext: [{ type: "pdu_ul", qfi: 9 }] },
  inner: { proto: "udp" }, corrupt: {},
});
const B = store.get("builder", null) || { packets: [DEFAULT_SPEC()], cur: 0 };
if (!B.packets?.length) { B.packets = [DEFAULT_SPEC()]; B.cur = 0; }
const cur = () => B.packets[B.cur];
const EXT_LABEL = { pdu_ul: "PDU Session UL", pdu_dl: "PDU Session DL", udp_port: "UDP Port" };

function fillForm() {
  const sp = cur();
  for (const el of $$("#bform [name]")) {
    const [a, b] = el.name.split(".");
    const v = sp[a]?.[b];
    if (el.type === "checkbox") el.checked = !!v;
    else el.value = v ?? (el.tagName === "SELECT" ? el.options[0].value : "");
  }
  renderExts();
  renderPList();
}

function readForm() {
  const sp = cur();
  for (const el of $$("#bform [name]")) {
    const [a, b] = el.name.split(".");
    sp[a] = sp[a] || {};
    sp[a][b] = el.type === "checkbox" ? el.checked : el.value.trim();
  }
  store.set("builder", B);
}

function renderExts() {
  const exts = cur().gtp.ext || (cur().gtp.ext = []);
  $("#exts").innerHTML = exts.map((x, i) => {
    let f = "";
    if (x.type === "udp_port") f = `<label>Port <input data-ei="${i}" data-ek="port" value="${esc(x.port ?? 2152)}" inputmode="numeric"></label>`;
    else {
      f = `<label><span class="term" tabindex="0" role="button" data-term="ext.QFI">QFI</span> <input data-ei="${i}" data-ek="qfi" value="${esc(x.qfi ?? 9)}" inputmode="numeric"></label>`;
      if (x.type === "pdu_dl") f += `<label><input type="checkbox" data-ei="${i}" data-ek="rqi"${x.rqi ? " checked" : ""}> <span class="term" tabindex="0" role="button" data-term="ext.RQI">RQI</span></label>`;
    }
    return `<li><span class="ext-name term" tabindex="0" role="button" data-term="${x.type === "udp_port" ? "term.ext_udp_port" : "term.pdu_container"}">${EXT_LABEL[x.type]}</span>${f}<button type="button" class="btn btn-quiet x" data-del-ext="${i}">Bỏ</button></li>`;
  }).join("") || `<li class="empty-ext">Không có extension, cờ E tắt.</li>`;
}

function renderPList() {
  $("#plist").innerHTML = B.packets.map((_, i) =>
    `<button type="button" class="btn btn-quiet" data-p="${i}"${i === B.cur ? ' aria-current="true"' : ""}>Gói ${i + 1}</button>`).join("")
    + `<button type="button" class="btn btn-quiet" data-p-dup>+ Nhân bản gói này</button>`
    + (B.packets.length > 1 ? `<button type="button" class="btn btn-quiet" data-p-del>Xóa gói ${B.cur + 1}</button>` : "");
}

$("#bform").addEventListener("input", (e) => {
  const ei = e.target.dataset.ei;
  if (ei !== undefined) {
    const x = cur().gtp.ext[+ei];
    x[e.target.dataset.ek] = e.target.type === "checkbox" ? (e.target.checked ? 1 : 0) : e.target.value.trim();
  }
  readForm();
  previewSoon();
});
$("#bform").addEventListener("submit", (e) => e.preventDefault());
$("#bform").addEventListener("click", (e) => {
  const t = e.target.closest("button");
  if (!t) return;
  if (t.dataset.addExt) {
    const x = { type: t.dataset.addExt };
    if (x.type === "udp_port") x.port = 40000; else x.qfi = 9;
    cur().gtp.ext.push(x);
  } else if (t.dataset.delExt !== undefined) {
    cur().gtp.ext.splice(+t.dataset.delExt, 1);
  } else if (t.dataset.p !== undefined) {
    B.cur = +t.dataset.p;
  } else if (t.hasAttribute("data-p-dup")) {
    B.packets.splice(B.cur + 1, 0, structuredClone(cur())); B.cur++;
  } else if (t.hasAttribute("data-p-del")) {
    B.packets.splice(B.cur, 1); B.cur = Math.max(0, B.cur - 1);
  } else return;
  store.set("builder", B);
  fillForm();
  previewSoon(0);
});

let pvTimer = 0, pvSeq = 0;
function previewSoon(delay = 160) {
  clearTimeout(pvTimer);
  pvTimer = setTimeout(preview, delay);
}
async function preview() {
  const seq = ++pvSeq;
  const box = $("#b-detail");
  let d;
  try { d = await api("/api/build", { packets: B.packets, index: B.cur }); }
  catch (e) { box.innerHTML = `<div class="err-box">${esc(e.message)}</div>`; return; }
  if (seq !== pvSeq) return;
  if (d.error) { box.innerHTML = `<div class="err-box">Chưa dựng được gói: ${esc(d.error)}</div>`; box._layer = null; return; }
  const head = d.binary_error === "no_binary"
    ? `<div class="answer"><span class="who">Chưa build binary nên chỉ xem được byte.</span></div>`
    : `<div class="answer"><span class="who">gtpu-inspect trả lời</span>${vHtml(d.verdict)}</div>`;
  renderPacket(box, d, d.verdict, head + `<h2>Gói ${B.cur + 1} / ${B.packets.length}</h2>`);
}

async function savePcap() {
  const name = $("#b-name").value.trim() || "my_case";
  const r = await api("/api/save", { name, packets: B.packets });
  $("#b-saved").textContent = `Đã ghi ${r.path} (${B.packets.length} gói).`;
  await loadFiles();
  return r.path;
}
$("#b-save").addEventListener("click", () => savePcap().catch((e) => flash(e.message)));
$("#b-analyze").addEventListener("click", async () => {
  try { const p = await savePcap(); selectFile(p); showTab("analyze"); } catch (e) { flash(e.message); }
});
$("#b-ws").addEventListener("click", async () => {
  try { await openWireshark(await savePcap()); } catch (e) { flash(e.message); }
});
$("#b-code").addEventListener("click", async () => {
  try {
    const r = await api("/api/fixture", { name: $("#b-name").value.trim(), packets: B.packets });
    $("#code-out").textContent = r.code;
    $("#code-dlg").showModal();
  } catch (e) { flash(e.message); }
});
$("#code-copy").addEventListener("click", async () => {
  try { await navigator.clipboard.writeText($("#code-out").textContent); $("#code-copy").textContent = "Đã chép"; }
  catch { $("#code-copy").textContent = "Không chép được, hãy bôi đen và chép tay"; }
  setTimeout(() => { $("#code-copy").textContent = "Chép code"; }, 1800);
});

/* ================= tab so sánh ================= */

let cmpSeq = 0, CMP = null;
async function loadCompare() {
  const seq = ++cmpSeq;
  $("#cmp-title").textContent = "So sánh: " + S.file.split("/").pop();
  $("#cmp-body").innerHTML = '<p class="hint">Đang chạy gtpu-inspect và tshark…</p>';
  try { CMP = await api("/api/compare?" + q({ path: S.file })); }
  catch (e) { $("#cmp-body").innerHTML = `<div class="err-box">${esc(e.message)}</div>`; return; }
  if (seq !== cmpSeq) return;
  renderCompare();
}

function renderCompare() {
  const c = CMP, body = $("#cmp-body");
  if (c.ours_error === "no_binary") { noBinary(body); return; }
  if (c.file) {
    const ours = c.ours_rc === 0 ? "ok" : (c.ours_stderr || "").trim() || `exit ${c.ours_rc}`;
    const okMatch = (c.file.verdict === "ok") === (c.ours_rc === 0);
    const nMatch = c.file.packets === c.rows.filter((r) => r.ours).length;
    body.innerHTML = `<div class="cmp-sum"><span class="big">${okMatch && nMatch ? "Khớp" : "Lệch"}</span>
      <span class="hint">File này kiểm tra pcap reader: so lỗi cấp file và số gói đọc được trước khi dừng.</span></div>
      <dl class="file-cmp">
        <dt>.expected</dt><dd>${esc(c.file.verdict)}, ${c.file.packets} gói${c.file.note ? `<br><span class="hint">${esc(c.file.note)}</span>` : ""}</dd>
        <dt>gtpu-inspect</dt><dd${okMatch && nMatch ? "" : ' class="v-err verdict"'}>${esc(ours)}, ${c.rows.filter((r) => r.ours).length} gói</dd>
      </dl>`;
    return;
  }
  const n = c.rows.length, bad = c.mismatches;
  const notes = [];
  if (!c.has_expected) notes.push("File này không có .expected, chỉ so với tshark.");
  if (c.format === "text") notes.push("Binary chưa có -j nên chưa so QFI từng gói.");
  if (c.tshark_error) notes.push("Không chạy được tshark.");
  if (c.truncated) notes.push(`Chỉ so ${fmtN(n)} gói đầu.`);
  notes.push("tshark chỉ được so ở gói mà parser của bạn chấp nhận.");
  const only = $("#cmp-only").checked;
  const rows = c.rows.filter((r) => !only || r.diff.length);
  const d = (r, k) => ` class="${r.diff.includes(k) ? "diff " : ""}mono${/msg_type|qfi/.test(k) ? " num" : ""}"`;
  const dv = (r, k) => (r.diff.includes(k) ? ' class="diff"' : "");
  body.innerHTML = `<div class="cmp-sum"><span class="big">${fmtN(n - bad)}/${fmtN(n)} gói khớp</span><span class="hint">${esc(notes.join(" "))}</span></div>
  <div class="table-scroll cmp"><table>
    <thead><tr><th></th><th class="grp" colspan="4">gtpu-inspect</th><th class="grp sep" colspan="5">.expected</th><th class="grp sep" colspan="4">tshark</th></tr>
    <tr><th class="num">#</th><th>${T("term.verdict", "Verdict")}</th><th>${T("gtp.TEID", "TEID")}</th><th class="num">${T("gtp.Message type", "Msg")}</th><th class="num">${T("ext.QFI", "QFI")}</th>
      <th class="sep">Verdict</th><th>TEID</th><th class="num">Msg</th><th class="num">QFI</th><th>Ghi chú</th>
      <th class="sep">TEID</th><th class="num">Msg</th><th class="num">QFI</th><th>Cảnh báo</th></tr></thead>
    <tbody>${rows.map((r) => {
      const o = r.ours || {}, e = r.expected, t = r.tshark;
      return `<tr data-idx="${r.idx}" title="Mở gói #${r.idx} ở tab Phân tích">
        <td class="num mono">${r.idx}</td><td${dv(r, "result")}>${vHtml(o.result)}</td>
        <td${d(r, "teid")}>${hex32(o.teid)}</td><td${d(r, "msg_type")}>${dash(o.msg_type)}</td><td${d(r, "qfi")}>${dash(o.qfi)}</td>
        ${e ? `<td class="sep">${vHtml(e.result)}</td><td class="mono">${hex32(e.teid)}</td><td class="num mono">${dash(e.msg_type)}</td><td class="num mono">${dash(e.qfi)}</td><td class="note">${esc(e.note)}</td>`
          : '<td class="sep dim" colspan="5">–</td>'}
        ${t ? `<td class="sep${r.diff.includes("ts_teid") ? " diff" : ""} mono">${hex32(t.teid)}</td><td${d(r, "ts_msg_type")}>${dash(t.msg_type)}</td><td${d(r, "ts_qfi")}>${dash(t.qfi)}</td><td class="expert">${esc(t.expert || "")}</td>`
          : '<td class="sep dim" colspan="4">–</td>'}</tr>`;
    }).join("") || `<tr><td colspan="14" class="dim">${only ? "Không có dòng lệch." : "Không có gói."}</td></tr>`}</tbody></table></div>`;
}

$("#cmp-run").addEventListener("click", loadCompare);
$("#cmp-only").addEventListener("change", () => CMP && renderCompare());
$("#cmp-body").addEventListener("click", (e) => {
  const tr = e.target.closest("tr[data-idx]");
  if (!tr) return;
  S.sel = +tr.dataset.idx; S.filter = null;
  showTab("analyze");
});

/* ================= tab build & test ================= */

let running = false, lastFailed = [];
const log = $("#t-log");

async function runStep(step, filter) {
  const r = await fetch("/api/run", {
    method: "POST",
    headers: { "X-GTPU-UI": "1", "Content-Type": "application/json" },
    body: JSON.stringify({ step, sanitize: $("#t-san").checked, filter }),
  });
  if (!r.ok) {
    const d = await r.json().catch(() => ({}));
    log.textContent += `\n${d.detail || "HTTP " + r.status}\n`;
    return 1;
  }
  const reader = r.body.getReader(), dec = new TextDecoder();
  let text = "";
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    const chunk = dec.decode(value, { stream: true });
    text += chunk;
    log.textContent = (log.textContent + chunk).slice(-200000);
    log.scrollTop = log.scrollHeight;
  }
  const m = text.match(/\[exit (-?\d+)\]\s*$/);
  return m ? +m[1] : 1;
}

async function runSteps(steps, filter) {
  if (running) return;
  running = true;
  $$("#panel-test button").forEach((b) => (b.disabled = true));
  log.textContent = "";
  try {
    for (const s of steps) {
      const rc = await runStep(s, filter);
      if (s === "build" || s === "configure") await loadStatus();
      if (s === "test") await loadTests();
      if (rc !== 0 && s !== "test") { log.textContent += `\nDừng: bước ${s} lỗi.\n`; break; }
    }
  } finally {
    running = false;
    $$("#panel-test button").forEach((b) => (b.disabled = false));
    $("#t-rerun").disabled = !lastFailed.length;
  }
}

$("#panel-test").addEventListener("click", (e) => {
  const b = e.target.closest("[data-step]");
  if (!b) return;
  const s = b.dataset.step;
  runSteps(s === "all" ? ["configure", "build", "test"] : s === "test" ? ["test"] : [s]);
});
$("#t-rerun").addEventListener("click", () => {
  const re = lastFailed.map((n) => "^" + n.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "$").join("|");
  runSteps(["build", "test"], re);
});

let TESTS = [];
async function loadTests() {
  try { TESTS = (await api("/api/tests")).tests; } catch { TESTS = []; }
  lastFailed = TESTS.filter((t) => t.status === "fail").map((t) => t.name);
  $("#t-rerun").disabled = running || !lastFailed.length;
  renderTests();
}
function renderTests() {
  const c = { pass: 0, fail: 0, skip: 0 };
  TESTS.forEach((t) => c[t.status]++);
  $("#t-summary").innerHTML = TESTS.length
    ? `<span><b>${c.pass}</b> qua</span><span${c.fail ? ' class="v-err verdict"' : ""}><b>${c.fail}</b> lỗi</span><span><b>${c.skip}</b> bỏ qua</span>`
    : '<span class="hint">Chưa có kết quả test. Bấm "Build và chạy test".</span>';
  const order = { fail: 0, skip: 2, pass: 1 };
  $("#t-grid").innerHTML = [...TESTS].sort((a, b) => order[a.status] - order[b.status])
    .map((t) => `<i class="t-${t.status}" title="${esc(t.name)}: ${t.status}"></i>`).join("");
  const f = $("#t-filter").value.trim().toLowerCase();
  $("#t-list").innerHTML = TESTS.filter((t) => !f || t.name.toLowerCase().includes(f))
    .sort((a, b) => order[a.status] - order[b.status] || a.name.localeCompare(b.name))
    .map((t) => `<li class="t-${t.status}" title="${esc(t.name)}"><span>${esc(t.name)}</span><small>${t.status === "skip" ? "bỏ qua" : t.status === "fail" ? "lỗi" : t.time.toFixed(2) + " s"}</small></li>`).join("");
}
$("#t-filter").addEventListener("input", renderTests);

/* ================= khởi động ================= */

(async function init() {
  // link dạng /?file=tests/data/malformed.pcap&idx=14#analyze
  const url = new URLSearchParams(location.search);
  if (url.get("file")) { S.file = url.get("file"); store.set("file", S.file); }
  if (url.get("idx")) S.sel = +url.get("idx");
  const hash = location.hash.slice(1);
  if (TABS.includes(hash)) S.tab = hash;
  $$(".term").forEach((t) => { t.tabIndex = 0; t.setAttribute("role", "button"); });
  await Promise.all([loadStatus(), loadFiles()]);
  fillForm();
  showTab(TABS.includes(S.tab) ? S.tab : "analyze");
})();
