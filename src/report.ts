import * as vscode from 'vscode';
import * as path from 'node:path';

type Sev = 'info'|'low'|'medium'|'high'|'critical';

export type UIItem = {
  fingerprint: string;
  ruleId: string;
  severity: Sev;
  file: string;
  relFile: string;
  range: { start: { line: number; col: number }, end: { line: number; col: number } };
  message: string;
  cwe?: string|null;
  owasp?: string|null;
  snippet?: string;
  explanation_md: string;
  unified_diff: string|null;
  calibrated: ('none'|'low'|'medium'|'high'|'critical')|null;
  confidence: number|null;
  references: string[];
  tests: string[];
};

const IGNORED_KEY = 'vulnscan/ignored';
const SEV_ORDER: Sev[] = ['critical','high','medium','low','info'];

export function openSecurityReport(
  ctx: vscode.ExtensionContext,
  workspaceRoot: string,
  items: UIItem[],
  meta?: { targetRoot: string; configs: string[]; timestamp: string }
) {
  const panel = vscode.window.createWebviewPanel(
    'secReport',
    'Security Report',
    vscode.ViewColumn.Two,
    { enableScripts: true, retainContextWhenHidden: true }
  );

  const ignored = new Set(ctx.workspaceState.get<string[]>(IGNORED_KEY, []));
  const visible = items.filter(i => !ignored.has(i.fingerprint));
  panel.webview.html = renderHTML(panel.webview, workspaceRoot, visible, meta);

  panel.webview.onDidReceiveMessage(async (msg) => {
    try {
      switch (msg.type) {
        case 'openFile': {
          const uri = vscode.Uri.file(msg.file as string);
          const doc = await vscode.workspace.openTextDocument(uri);
          const editor = await vscode.window.showTextDocument(doc, { preview: false });
          const line = Math.max(0, Number(msg.line || 0));
          const pos = new vscode.Position(line, 0);
          editor.selection = new vscode.Selection(pos, pos);
          editor.revealRange(new vscode.Range(pos, pos), vscode.TextEditorRevealType.InCenter);
          break;
        }
        case 'copyDiff': {
          await vscode.env.clipboard.writeText(String(msg.diff || ''));
          vscode.window.showInformationMessage('Diff copiado al portapapeles.');
          break;
        }
        case 'applyDiff': {
          const fp: string = msg.fingerprint;
          const it = items.find(x => x.fingerprint === fp);
          if (!it || !it.unified_diff) { vscode.window.showWarningMessage('No hay diff aplicable.'); break; }
          const ok = await tryApplyUnifiedDiff(it.file, it.unified_diff, it.snippet);
          panel.webview.postMessage({ type: 'applyDiff:result', ok, fp });
          vscode.window.showInformationMessage(ok ? 'Parche aplicado.' : 'No se pudo aplicar automáticamente.');
          break;
        }
        case 'toggleIgnore': {
          const fp: string = msg.fingerprint;
          const arr = ctx.workspaceState.get<string[]>(IGNORED_KEY, []);
          const s = new Set(arr);
          if (s.has(fp)) s.delete(fp); else s.add(fp);
          await ctx.workspaceState.update(IGNORED_KEY, [...s]);
          panel.webview.postMessage({ type: 'toggleIgnore:result', ok: true, fp, ignored: s.has(fp) });
          break;
        }
        case 'openExternal': {
          const url: string = msg.url;
          if (url && /^https?:\/\//i.test(url)) vscode.env.openExternal(vscode.Uri.parse(url));
          break;
        }
        case 'createIssue': {
          const it = items.find(x => x.fingerprint === msg.fingerprint);
          if (!it) break;
          const url = await buildGitHubIssueURL(workspaceRoot, it);
          if (url) vscode.env.openExternal(vscode.Uri.parse(url));
          else vscode.window.showInformationMessage('No se detectó remoto GitHub.');
          break;
        }
        case 'exportMd': vscode.commands.executeCommand('sec.exportReport'); break;
        case 'exportJson': vscode.commands.executeCommand('sec.exportJSON'); break;
        case 'rescan': vscode.commands.executeCommand('sec.scan'); break;
      }
    } catch (e: any) {
      vscode.window.showErrorMessage(`Report action failed: ${e?.message || e}`);
    }
  });
}

/*  HTML/UI  */

function renderHTML(webview: vscode.Webview, root: string, items: UIItem[], meta?: any) {
  const nonce = Array.from({ length: 16 }, () => Math.random().toString(36)[2]).join('');
  const counts = countBySeverity(items);
  const total = items.length;
  const chips = SEV_ORDER.map(s => chip(s, counts[s] || 0)).join('');
  const metaLine = [
    meta?.targetRoot ? `target: ${escapeHtml(path.relative(root, meta.targetRoot) || '.')}` : '',
    meta?.configs?.length ? `configs: ${meta.configs.join(', ')}` : '',
    meta?.timestamp ? `date: ${new Date(meta.timestamp).toLocaleString()}` : ''
  ].filter(Boolean).join(' · ');
  const cards = items.map(renderCard).join('');

  return `<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta http-equiv="Content-Security-Policy"
  content="default-src 'none'; img-src ${webview.cspSource} https:;
           style-src ${webview.cspSource} 'unsafe-inline';
           script-src 'nonce-${nonce}';">
<meta name="color-scheme" content="dark light">
<title>Security Report</title>
<style>
  :root{
    --bg:#0f1115; --panel:#12151c; --card:#151a22; --ink:#e8eaed; --muted:#9aa0a6; --border:#212735;
    --ring:#5b9dff;
    --crit:#ff3b5b; --high:#ff6a3d; --med:#ffbf38; --low:#3aa3ff; --info:#7f8ea3; --ok:#60d394;
    --pad: clamp(10px, 2vw, 16px);
    --radius: 14px;
    --chip-h: 34px;
  }
  @media (prefers-color-scheme: light){
    :root{
      --bg:#f5f7fb; --panel:#ffffff; --card:#ffffff; --ink:#10131a; --muted:#5c667a; --border:#e5e9f2;
      --ring:#2b6fff;
    }
  }

  *{box-sizing:border-box}
  html,body{height:100%}
  body{
    margin:0; padding:0;
    background:
      radial-gradient(80rem 40rem at 10% -10%, rgba(61,126,255,.06), transparent 60%),
      radial-gradient(60rem 30rem at 90% -20%, rgba(255,123,61,.05), transparent 60%),
      var(--bg);
    color:var(--ink);
    font: 13px/1.5 ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Arial;
    -webkit-font-smoothing: antialiased; text-rendering: optimizeLegibility;
  }

  /* ===== Topbar / Toolbar ===== */
  .topbar{
    position:sticky; top:0; z-index:10;
    backdrop-filter:saturate(140%) blur(6px);
    background: linear-gradient(180deg, color-mix(in oklab, var(--panel) 92%, transparent), color-mix(in oklab, var(--panel) 75%, transparent));
    border-bottom:1px solid var(--border);
  }
  .wrap{max-width:1200px; margin:0 auto; padding:var(--pad);}
  .top{ display:grid; grid-template-columns: 1fr auto; gap:12px; align-items:center; }
  @media (max-width: 900px){
    .top{ grid-template-columns: 1fr; gap:10px; }
  }

  /* Chips: carrusel en móvil */
  .chips{
    display:flex; align-items:center; gap:8px; flex-wrap:wrap;
    scroll-snap-type: x mandatory;
    overflow:auto; padding-bottom:2px;
    -webkit-overflow-scrolling: touch;
  }
  @media (max-width: 680px){
    .chips{ flex-wrap:nowrap; }
  }
  .chips::-webkit-scrollbar{ height:6px }
  .chips::-webkit-scrollbar-thumb{ background: color-mix(in oklab, var(--muted) 25%, transparent); border-radius:999px }

  .chip{
    display:inline-flex; align-items:center; gap:6px; height: var(--chip-h);
    padding:0 10px; border-radius:999px; font-weight:700; font-size:12px; cursor:pointer; user-select:none;
    border:1px solid color-mix(in oklab, var(--border) 80%, transparent);
    background: color-mix(in oklab, var(--panel) 85%, transparent);
    transition:transform .12s ease, background-color .15s ease, border-color .15s ease, box-shadow .15s ease;
    scroll-snap-align: start;
  }
  .chip[data-active="true"]{ box-shadow: 0 0 0 2px color-mix(in oklab, var(--ring) 50%, transparent) inset }
  .chip:hover{ transform:translateY(-1px) }
  .chip.critical{ background: color-mix(in oklab, var(--crit) 18%, transparent); border-color: color-mix(in oklab, var(--crit) 35%, transparent) }
  .chip.high{ background: color-mix(in oklab, var(--high) 18%, transparent); border-color: color-mix(in oklab, var(--high) 35%, transparent) }
  .chip.medium{ background: color-mix(in oklab, var(--med) 18%, transparent); border-color: color-mix(in oklab, var(--med) 35%, transparent) }
  .chip.low{ background: color-mix(in oklab, var(--low) 18%, transparent); border-color: color-mix(in oklab, var(--low) 35%, transparent) }
  .chip.info{ background: color-mix(in oklab, var(--info) 18%, transparent); border-color: color-mix(in oklab, var(--info) 35%, transparent) }
  .chip .dot{width:8px; height:8px; border-radius:999px; display:inline-block}
  .chip.critical .dot{background:var(--crit)} .chip.high .dot{background:var(--high)}
  .chip.medium .dot{background:var(--med)} .chip.low .dot{background:var(--low)} .chip.info .dot{background:var(--info)}
  .muted{ color:var(--muted) }

  .toolbar{
    display:flex; flex-wrap:wrap; gap:8px; align-items:center; justify-content:flex-end;
  }
  @media (max-width: 900px){
    .toolbar{ justify-content:space-between; }
  }
  .btn{
    display:inline-flex; align-items:center; gap:6px; padding:8px 11px; border-radius:10px;
    border:1px solid var(--border); background:linear-gradient(180deg, color-mix(in oklab, var(--panel) 90%, black 6%), color-mix(in oklab, var(--panel) 80%, black 12%));
    color:inherit; cursor:pointer; transition:transform .12s ease, box-shadow .2s ease, border-color .15s ease, background .2s ease;
    user-select:none; min-height:34px;
  }
  .btn:hover{ transform:translateY(-1px) }
  .btn:focus-visible{ outline:2px solid var(--ring); outline-offset:2px }
  .btn.ghost{ background:transparent }

  input[type="search"], select{
    background: color-mix(in oklab, var(--panel) 78%, black 14%); color:inherit;
    border:1px solid var(--border); border-radius:10px; padding:8px 10px; min-height:34px;
  }
  input[type="search"]::placeholder{color: color-mix(in oklab, var(--muted) 80%, transparent)}
  @media (max-width: 680px){
    input[type="search"]{ flex:1; min-width: 0; }
  }

  /* Menú colapsable "Más" en móvil */
  .more{ display:none }
  @media (max-width: 680px){
    .more{ display:inline-block }
    .toolbar .btn[data-role="export"], .toolbar .btn[data-role="expand"], .toolbar .btn[data-role="collapse"]{ display:none }
    .more summary{
      list-style:none; cursor:pointer; border:1px solid var(--border); border-radius:10px; padding:8px 11px;
      background:linear-gradient(180deg, color-mix(in oklab, var(--panel) 90%, black 6%), color-mix(in oklab, var(--panel) 80%, black 12%));
    }
    .more summary::-webkit-details-marker{ display:none }
    .more .menu{
      margin-top:6px; padding:6px; background:var(--panel); border:1px solid var(--border); border-radius:10px; display:grid; gap:6px;
    }
  }

  /* ===== List & Cards ===== */
  .list{ max-width:1200px; margin:12px auto; padding:0 var(--pad); display:flex; flex-direction:column; gap:10px; }

  details.card{
    border:1px solid var(--border); border-radius:var(--radius);
    background:linear-gradient(180deg, color-mix(in oklab, var(--card) 92%, transparent), color-mix(in oklab, var(--card) 82%, transparent));
    overflow:hidden; transition:border-color .2s ease, background .25s ease;
  }
  details.card[open]{ background:linear-gradient(180deg, color-mix(in oklab, var(--card) 96%, transparent), color-mix(in oklab, var(--card) 88%, transparent)) }
  details.card:focus-within{ outline:2px solid var(--ring); outline-offset:2px }

  .card-summary{
    list-style:none; display:flex; gap:12px; align-items:center; justify-content:space-between; padding:12px 14px; cursor:pointer;
  }
  .card-summary::-webkit-details-marker{ display:none }
  .head-left{ display:flex; align-items:center; gap:10px; min-width:0 }
  .file{ font-weight:700; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
  .rule{ color:var(--muted) }

  .sev{ font-size:11px; font-weight:800; padding:4px 8px; border-radius:8px; text-transform:uppercase; letter-spacing:.02em; color:#0b0b0c }
  @media (prefers-color-scheme: dark){
    .sev{ color:#fff }
  }
  .sev.critical{ background:var(--crit) } .sev.high{ background:var(--high) } .sev.medium{ background:var(--med) }
  .sev.low{ background:var(--low) } .sev.info{ background:var(--info) }

  .head-actions{ display:flex; gap:8px; align-items:center; flex-wrap:wrap }
  .tag{ background: color-mix(in oklab, var(--panel) 80%, black 10%); border:1px solid color-mix(in oklab, var(--border) 70%, transparent); padding:3px 8px; border-radius:999px; font-size:12px; color:inherit }

  .chev{ width:12px; height:12px; transform:rotate(-90deg); transition:transform .2s ease; opacity:.85 }
  details[open] .chev{ transform:rotate(0) }

  /* Animación de contenido */
  .card-content{ overflow:hidden; height:0; transition:height .22s ease; }
  details[open] .card-content{ height:auto }
  .card-inner{ padding:10px 14px 14px 14px; display:grid; gap:10px }

  .msg{ color: color-mix(in oklab, #cfe0ff 90%, transparent) }

  details.block{ margin-top:4px; border:1px solid color-mix(in oklab, var(--border) 70%, transparent); border-radius:10px; overflow:hidden }
  details.block summary{ padding:8px 10px; cursor:pointer; background: color-mix(in oklab, var(--panel) 86%, transparent); color:inherit; list-style:none }
  details.block summary::-webkit-details-marker{ display:none }
  details.block[open]{ background: color-mix(in oklab, var(--panel) 92%, transparent) }
  pre{
    background: color-mix(in oklab, var(--panel) 76%, black 10%); border-top:1px solid color-mix(in oklab, var(--border) 70%, transparent);
    margin:0; padding:10px; border-radius:0 0 10px 10px; overflow:auto;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace; font-size:12px;
  }
  ul.refs{ margin:8px 0 0 18px; padding:0 }
  a.ref{ color:#2b89ff; text-decoration:none }
  a.ref:focus-visible{ outline:2px solid var(--ring); outline-offset:2px }

  /* Visual feedback */
  .flash-ok{ box-shadow: 0 0 0 2px var(--ok) inset }
  .flash-bad{ box-shadow: 0 0 0 2px #ef5350 inset }

  /* Metadata en summary */
  .meta{ display:flex; align-items:center; gap:8px; color: color-mix(in oklab, var(--muted) 90%, transparent); flex-wrap:wrap }

  /* Accesibilidad */
  .sr-only{ position:absolute; width:1px; height:1px; padding:0; margin:-1px; overflow:hidden; clip:rect(0,0,0,0); white-space:nowrap; border:0 }

  /* Responsive tweaks */
  @media (max-width: 900px){
    .head-actions .btn{ padding:7px 9px }
    .file{ max-width: 40vw }
  }
  @media (max-width: 680px){
    .card-summary{ align-items:flex-start; gap:10px }
    .head-left{ flex-wrap:wrap }
    .file{ max-width: 70vw }
    .head-actions{ width:100%; justify-content: flex-start }
    .tag{ font-size:11px }
  }

  /* Reduced motion */
  @media (prefers-reduced-motion: reduce){
    *{ animation: none !important; transition: none !important; }
  }
</style>
</head>
<body>
  <div class="topbar">
    <div class="wrap">
      <div class="top" role="region" aria-label="Security Report toolbar">
        <div>
          <div class="chips" id="chips">
            <div class="chip" id="chip-total" data-sev="total" title="Total">
              <span class="dot" style="background:#9fb2d2"></span><strong>Total</strong><span id="count-total">${total}</span>
            </div>
            ${chips}
          </div>
          <div class="muted" id="meta" style="margin-top:6px">${escapeHtml(metaLine)}</div>
        </div>

        <div class="toolbar">
          <input id="search" type="search" placeholder="Buscar…" aria-label="Buscar" />
          <select id="sort" aria-label="Ordenar">
            <option value="sev">Ordenar: severidad</option>
            <option value="file">Ordenar: archivo</option>
            <option value="rule">Ordenar: regla</option>
          </select>

          <button id="btnExpand" class="btn" data-role="expand" title="Expandir todo (E)">Expandir</button>
          <button id="btnCollapse" class="btn ghost" data-role="collapse" title="Contraer todo (C)">Contraer</button>

          <details class="more">
            <summary>Más</summary>
            <div class="menu">
              <button id="btnExportMd_m" class="btn" data-role="export">Export MD</button>
              <button id="btnExportJson_m" class="btn" data-role="export">Export JSON</button>
              <button id="btnClear_m" class="btn">Limpiar filtros</button>
              <button id="btnRescan_m" class="btn">Rescan</button>
            </div>
          </details>

          <button id="btnRescan" class="btn" title="Re-escanear">Rescan</button>
          <button id="btnExportMd" class="btn" data-role="export">Export MD</button>
          <button id="btnExportJson" class="btn" data-role="export">Export JSON</button>
          <button id="btnClear" class="btn ghost" title="Limpiar filtros (L)">Limpiar</button>
        </div>
      </div>
    </div>
  </div>

  <div id="list" class="list" role="list">${cards}</div>

<script nonce="${nonce}">
  const vscode = acquireVsCodeApi();
  const $ = (sel, root=document) => root.querySelector(sel);
  const $$ = (sel, root=document) => Array.from(root.querySelectorAll(sel));
  const LS = {
    filters: 'vulnscan.filters',
    sort: 'vulnscan.sort',
    open: 'vulnscan.open',
  };

  const state = {
    filters: new Set(JSON.parse(localStorage.getItem(LS.filters)||'[]')),
    open: new Set(JSON.parse(localStorage.getItem(LS.open)||'[]')),
    sort: localStorage.getItem(LS.sort) || 'sev',
  };

  /* ===== Chips interactivas ===== */
  $$('#chips .chip').forEach(ch => {
    const sev = ch.dataset.sev;
    if (sev && sev !== 'total') ch.dataset.active = state.filters.has(sev);
    ch.addEventListener('click', () => {
      const s = ch.dataset.sev;
      if (s === 'total') return;
      if (state.filters.has(s)) state.filters.delete(s); else state.filters.add(s);
      localStorage.setItem(LS.filters, JSON.stringify([...state.filters]));
      ch.dataset.active = state.filters.has(s);
      applyFilters();
      recount();
    });
  });

  /* ===== Ordenar ===== */
  $('#sort').value = state.sort;
  $('#sort').addEventListener('change', () => {
    state.sort = $('#sort').value;
    localStorage.setItem(LS.sort, state.sort);
    sortCards();
  });

  /* ===== Búsqueda con debounce ===== */
  let tkSearch;
  $('#search').addEventListener('input', () => {
    clearTimeout(tkSearch);
    tkSearch = setTimeout(() => applyFilters(), 80);
  });

  /* ===== Acciones generales ===== */
  const bind = (id, fn) => { const el = document.getElementById(id); if (el) el.onclick = fn; };

  bind('btnRescan', () => vscode.postMessage({ type: 'rescan' }));
  bind('btnExportMd', () => vscode.postMessage({ type: 'exportMd' }));
  bind('btnExportJson', () => vscode.postMessage({ type: 'exportJson' }));
  bind('btnExpand', () => toggleAll(true));
  bind('btnCollapse', () => toggleAll(false));
  bind('btnClear', () => clearFilters());

  // Menú móvil
  bind('btnRescan_m', () => vscode.postMessage({ type: 'rescan' }));
  bind('btnExportMd_m', () => vscode.postMessage({ type: 'exportMd' }));
  bind('btnExportJson_m', () => vscode.postMessage({ type: 'exportJson' }));
  bind('btnClear_m', () => clearFilters());

  function clearFilters(){
    state.filters.clear();
    localStorage.setItem(LS.filters,'[]');
    $$('#chips .chip').forEach(c=>c.dataset.active = false);
    $('#search').value = '';
    applyFilters(); recount();
  }

  /* ===== Atajos ===== */
  window.addEventListener('keydown', (e) => {
    if (e.key === 'E' && !e.metaKey && !e.ctrlKey) { e.preventDefault(); toggleAll(true); }
    if (e.key === 'C' && !e.metaKey && !e.ctrlKey) { e.preventDefault(); toggleAll(false); }
    if (e.key === 'L' && !e.metaKey && !e.ctrlKey) { e.preventDefault(); clearFilters(); }
    if (e.key === '/' && !e.metaKey && !e.ctrlKey) { e.preventDefault(); $('#search').focus(); }
  });

  /* ===== Delegación de eventos en lista ===== */
  $('#list').addEventListener('click', (e) => {
    const t = e.target;
    if (!(t instanceof Element)) return;

    const btnOpen = t.closest('[data-open]');
    if (btnOpen) {
      vscode.postMessage({ type: 'openFile', file: btnOpen.getAttribute('data-open'), line: Number(btnOpen.getAttribute('data-line')||'0') });
      return;
    }
    const btnCopy = t.closest('[data-copy]');
    if (btnCopy) {
      vscode.postMessage({ type: 'copyDiff', diff: btnCopy.getAttribute('data-copy') });
      return;
    }
    const btnApply = t.closest('[data-apply]');
    if (btnApply) {
      vscode.postMessage({ type: 'applyDiff', fingerprint: btnApply.getAttribute('data-apply') });
      return;
    }
    const btnIgnore = t.closest('[data-ignore]');
    if (btnIgnore) {
      vscode.postMessage({ type: 'toggleIgnore', fingerprint: btnIgnore.getAttribute('data-ignore') });
      return;
    }
    const btnIssue = t.closest('[data-issue]');
    if (btnIssue) {
      vscode.postMessage({ type: 'createIssue', fingerprint: btnIssue.getAttribute('data-issue') });
      return;
    }
    const ref = t.closest('a.ref');
    if (ref) {
      e.preventDefault();
      vscode.postMessage({ type: 'openExternal', url: ref.getAttribute('data-href') });
      return;
    }
  });

  /* ===== Cards <details> con persistencia ===== */
  $$('#list details.card').forEach(d => {
    const fp = d.dataset.fp;
    const summary = $('.card-summary', d);
    const content = $('.card-content', d);

    // Abierta si estaba guardada o viene en hash
    const hashOpen = new URLSearchParams(location.hash.replace(/^#/, '')).get('fp') === fp;
    if (state.open.has(fp) || hashOpen) d.setAttribute('open','');

    // Animación de altura (medida una sola vez para evitar thrash)
    const setHeight = (h) => { content.style.height = h + 'px'; };
    const openAnim = () => { content.style.height = 'auto'; const h = content.offsetHeight; content.style.height = '0px'; requestAnimationFrame(()=> setHeight(h)); };
    const closeAnim = () => { setHeight(content.offsetHeight); requestAnimationFrame(()=> setHeight(0)); };

    d.addEventListener('toggle', () => {
      if (d.open) {
        openAnim();
        state.open.add(fp);
        summary?.setAttribute('aria-expanded','true');
        history.replaceState(null, '', '#fp='+encodeURIComponent(fp));
      } else {
        closeAnim();
        state.open.delete(fp);
        summary?.setAttribute('aria-expanded','false');
        const p = new URLSearchParams(location.hash.replace(/^#/, '')); if (p.get('fp') === fp) history.replaceState(null,'','#');
      }
      localStorage.setItem(LS.open, JSON.stringify([...state.open]));
    });

    // Teclado accesible
    summary.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); d.open = !d.open; }
      if (e.key === 'ArrowRight' && !d.open) { d.open = true; }
      if (e.key === 'ArrowLeft' && d.open) { d.open = false; }
    });

    if (d.open) { requestAnimationFrame(()=> { content.style.height = 'auto'; }); }
  });

  /* ===== Mensajes del host ===== */
  window.addEventListener('message', ev => {
    const m = ev.data;
    if (m.type === 'toggleIgnore:result' && m.ok) {
      const card = document.querySelector('details.card[data-fp="'+m.fp+'"]');
      if (card) {
        card.classList.add('flash-ok');
        setTimeout(()=>card.remove(), 140);
        recount();
      }
    }
    if (m.type === 'applyDiff:result') {
      const card = document.querySelector('details.card[data-fp="'+m.fp+'"]');
      if (card) {
        card.classList.add(m.ok ? 'flash-ok' : 'flash-bad');
        setTimeout(()=>card.classList.remove('flash-ok','flash-bad'), 600);
      }
    }
  });

  /* ===== Init ===== */
  sortCards();
  applyFilters();
  recount();

  const p = new URLSearchParams(location.hash.replace(/^#/, ''));
  const target = p.get('fp');
  if (target) {
    const el = document.querySelector('details.card[data-fp="'+target+'"]');
    if (el) { el.scrollIntoView({block:'center'}); el.querySelector('.card-summary')?.focus({preventScroll:true}); }
  }

  function toggleAll(open){
    $$('#list details.card').forEach(d => { d.open = open; });
  }

  function sortCards(){
    const list = $('#list');
    const nodes = Array.from(list.children);
    nodes.sort((a,b) => {
      const A = a.dataset, B = b.dataset;
      if (state.sort === 'file') return (A.rel||'').localeCompare(B.rel||'');
      if (state.sort === 'rule') return (A.rule||'').localeCompare(B.rule||'');
      const ord = ['critical','high','medium','low','info'];
      return ord.indexOf(A.sev||'') - ord.indexOf(B.sev||'');
    });
    list.replaceChildren(...nodes);
  }

  function applyFilters(){
    const q = ($('#search').value || '').toLowerCase();
    const active = state.filters;
    let visible = 0;
    $$('#list details.card').forEach(card => {
      const sev = card.dataset.sev;
      const matchesSev = !active.size || active.has(sev);
      const text = (card.innerText || '').toLowerCase();
      const matchesQ = !q || text.includes(q);
      const show = matchesSev && matchesQ;
      card.style.display = show ? '' : 'none';
      if (show) visible++;
    });
    $('#count-total').textContent = String(visible);
  }

  function recount(){
    const q = ($('#search').value || '').trim();
    for (const sev of ['critical','high','medium','low','info']){
      const chip = $('.chip.'+sev); if (!chip) continue;
      let num = $$('#list details.card[data-sev="'+sev+'"]').length;
      if (q) num = $$('#list details.card[data-sev="'+sev+'"]').filter(el => el.style.display !== 'none').length;
      const old = chip.querySelector('strong + span'); if (old) old.remove();
      chip.appendChild(Object.assign(document.createElement('span'), {textContent: String(num)}));
    }
    $('#count-total').textContent = String($$('#list details.card').filter(el => el.style.display !== 'none').length);
  }
</script>
</body>
</html>`;
}

function renderCard(it: UIItem) {
  const sev = it.severity.toLowerCase();
  const sevCls = `sev ${sev}`;
  const ai = (it.calibrated && it.calibrated !== 'none') ? `<span class="tag">AI: ${escapeHtml(it.calibrated)}</span>` : '';
  const conf = (typeof it.confidence === 'number') ? `<span class="tag">confidence: ${Math.round(it.confidence * 100)}%</span>` : '';
  const cwe = it.cwe ? `<span class="tag">CWE: ${escapeHtml(it.cwe)}</span>` : '';
  const owasp = it.owasp ? `<span class="tag">OWASP: ${escapeHtml(it.owasp)}</span>` : '';

  const expl = it.explanation_md ? `
    <details class="block" open>
      <summary>Explicación</summary>
      <div class="card-inner"><div>${mdToHtml(it.explanation_md)}</div></div>
    </details>` : '';

  const snip = it.snippet ? `
    <details class="block">
      <summary>Snippet</summary>
      <pre>${escapeHtml(it.snippet)}</pre>
    </details>` : '';

  const diff = it.unified_diff ? `
    <details class="block">
      <summary>Propuesta de fix (diff)</summary>
      <div class="card-inner" style="gap:8px">
        <div class="meta">
          <button class="btn" data-copy="${escapeAttr(it.unified_diff)}">Copy diff</button>
          <button class="btn" data-apply="${escapeAttr(it.fingerprint)}">Try patch</button>
        </div>
        <pre>${escapeHtml(it.unified_diff)}</pre>
      </div>
    </details>` : '';

  const tests = (it.tests || []).length ? `
    <details class="block">
      <summary>Tests sugeridos</summary>
      <div class="card-inner"><ul>${it.tests.map(t => `<li>${escapeHtml(t)}</li>`).join('')}</ul></div>
    </details>` : '';

  const refs = (it.references || []).length ? `
    <details class="block">
      <summary>Referencias</summary>
      <div class="card-inner"><ul class="refs">${it.references.map(r => refItem(r)).join('')}</ul></div>
    </details>` : '';

  return `
  <details class="card" role="listitem"
    data-sev="${escapeAttr(sev)}"
    data-rel="${escapeAttr(it.relFile)}"
    data-rule="${escapeAttr(it.ruleId)}"
    data-fp="${escapeAttr(it.fingerprint)}">
    <summary class="card-summary" tabindex="0" aria-expanded="false" aria-controls="cnt-${escapeAttr(it.fingerprint)}">
      <div class="head-left">
        <span class="${sevCls}">${sev.toUpperCase()}</span>
        <div class="file" title="${escapeAttr(it.relFile)}">${escapeHtml(it.relFile)}</div>
        <div class="rule">· ${escapeHtml(it.ruleId)}</div>
      </div>
      <div class="head-actions">
        ${ai}${conf}${cwe}${owasp}
        <button class="btn" data-open="${escapeAttr(it.file)}" data-line="${it.range.start.line}">Open</button>
        <button class="btn" data-ignore="${escapeAttr(it.fingerprint)}" title="Marcar como FP">False Positive</button>
        <button class="btn" data-issue="${escapeAttr(it.fingerprint)}">Create Issue</button>
        <svg class="chev" viewBox="0 0 24 24" aria-hidden="true"><path d="M8.1 9.3a1 1 0 0 1 1.4 0L12 11.8l2.5-2.5a1 1 0 1 1 1.4 1.4l-3.2 3.2a1.5 1.5 0 0 1-2.1 0L8.1 10.7a1 1 0 0 1 0-1.4z" fill="currentColor"/></svg>
      </div>
    </summary>
    <div id="cnt-${escapeAttr(it.fingerprint)}" class="card-content" role="region" aria-label="Contenido de vulnerabilidad">
      <div class="card-inner">
        <div class="msg">${escapeHtml(it.message || '')}</div>
        ${expl}
        ${snip}
        ${diff}
        ${tests}
        ${refs}
      </div>
    </div>
  </details>`;
}

function chip(sev: string, n: number) {
  const cls = `chip ${sev}`;
  const label = sev[0].toUpperCase() + sev.slice(1);
  return `<div class="${cls}" data-sev="${sev}" data-active="false" title="${label}">
    <span class="dot"></span><strong>${label}</strong><span>${n}</span>
  </div>`;
}

function countBySeverity(items: UIItem[]) {
  const map: Record<Sev, number> = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  for (const it of items) map[it.severity] = (map[it.severity] || 0) + 1;
  return map;
}

/* ---------- helpers seguro para HTML/MD ---------- */
function escapeHtml(s: string) {
  return String(s).replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[m]!);
}
function escapeAttr(s: string) { return escapeHtml(s).replace(/\n/g,'\\n'); }
function mdToHtml(md: string) {
  // protege bloques ``` ```
  const fenced = md.replace(/```([\s\S]*?)```/g, (_m, code) => `<pre>${escapeHtml(code)}</pre>`);
  // párrafos (sin permitir HTML crudo)
  return fenced.split(/\n{2,}/).map(p => `<p>${escapeHtml(p).replace(/\n/g,'<br>')}</p>`).join('\n');
}
function refItem(r: string) {
  const url = String(r).trim();
  const safe = /^https?:\/\//i.test(url) ? url : '';
  const label = safe ? url.replace(/^https?:\/\//, '') : url;

  return safe
    ? `<li><a class="ref" data-href="${escapeAttr(safe)}">${escapeHtml(label)}</a></li>`
    : `<li>${escapeHtml(url)}</li>`;
}

/* ---------- Aplicador de patch simple ---------- */
async function tryApplyUnifiedDiff(file: string, diff: string, snippet?: string): Promise<boolean> {
  try {
    const uri = vscode.Uri.file(file);
    const doc = await vscode.workspace.openTextDocument(uri);
    let text = doc.getText();

    // Fast path: single hunk replace using snippet
    if (snippet && /^---[\s\S]*?\n\+\+\+[\s\S]*?@@/m.test(diff)) {
      const blocks = extractHunks(diff);
      if (blocks.length === 1) {
        const h = blocks[0];
        const original = h.lines.filter(l => l.kind !== '+').map(l => l.txt).join('\n');
        const added = h.lines.filter(l => l.kind !== '-').map(l => l.txt).join('\n');
        if (snippet.includes(original.trim()) || text.includes(original.trim())) {
          const newText = text.replace(original, added);
          if (newText !== text) {
            const edit = new vscode.WorkspaceEdit();
            const range = new vscode.Range(doc.positionAt(0), doc.positionAt(text.length));
            edit.replace(uri, range, newText);
            const ok = await vscode.workspace.applyEdit(edit); if (ok) {await doc.save();} return ok;
          }
        }
      }
    }

    const hunks = extractHunks(diff);
    let offset = 0;
    for (const h of hunks) {
      const start = h.oldStart - 1 + offset;
      const end = start + h.oldLines;
      const before = doc.lineAt(Math.max(0, start)).range.start;
      const after = doc.lineAt(Math.min(doc.lineCount - 1, end - 1)).range.end;
      const oldBlock = doc.getText(new vscode.Range(before, after));
      const newBlock = h.lines.filter(l => l.kind !== '-').map(l => l.txt).join('\n');
      if (!oldBlock.trim()) {return false;}
      const edit = new vscode.WorkspaceEdit();
      edit.replace(uri, new vscode.Range(before, after), newBlock);
      const ok = await vscode.workspace.applyEdit(edit); if (!ok) {return false;}
      offset += (h.newLines - h.oldLines);
    }
    await doc.save();
    return true;
  } catch { return false; }
}

function extractHunks(diff: string) {
  const lines = diff.split('\n');
  type L = { kind: ' '|'+'|'-'; txt: string };
  type H = { oldStart: number; oldLines: number; newStart: number; newLines: number; lines: L[] };
  const hunks: H[] = [];
  let i = 0;
  while (i < lines.length) {
    const m = /^@@ -(\d+),?(\d+)? \+(\d+),?(\d+)? @@/.exec(lines[i]);
    if (!m) { i++; continue; }
    let h: H = {
      oldStart: parseInt(m[1],10), oldLines: parseInt(m[2]||'1',10),
      newStart: parseInt(m[3],10), newLines: parseInt(m[4]||'1',10), lines: []
    };
    i++;
    while (i < lines.length && !lines[i].startsWith('@@')) {
      const ch = lines[i][0]; const txt = lines[i].slice(1);
      if (ch === '+' || ch === '-' || ch === ' ') {h.lines.push({ kind: ch as any, txt });}
      i++;
    }
    hunks.push(h);
  }
  return hunks;
}

/* -------------------------- Export (Markdown) -------------------------- */
export function renderMarkdown(items: UIItem[]) {
  const rows = items.map(it => {
    const header = `### [${it.severity.toUpperCase()}] ${it.relFile} — ${it.ruleId}`;
    const cwe = it.cwe ? `\n- CWE: ${it.cwe}` : '';
    const owasp = it.owasp ? `\n- OWASP: ${it.owasp}` : '';
    const conf = (typeof it.confidence === 'number') ? `\n- Confidence: ${Math.round(it.confidence*100)}%` : '';
    const cal = it.calibrated ? `\n- Calibrated: ${it.calibrated}` : '';
    const expl = it.explanation_md ? `\n\n${it.explanation_md}\n` : '';
    const snip = it.snippet ? `\n**Snippet**:\n\n\`\`\`\n${it.snippet}\n\`\`\`\n` : '';
    const diff = it.unified_diff ? `\n**Propuesta de fix (diff)**:\n\n\`\`\`diff\n${it.unified_diff}\n\`\`\`\n` : '';
    const tests = (it.tests||[]).length ? `\n**Tests sugeridos**:\n${it.tests.map(t => `- ${t}`).join('\n')}\n` : '';
    const refs = (it.references||[]).length ? `\n**Referencias**:\n${it.references.map(r => `- ${r}`).join('\n')}\n` : '';
    return `${header}\n- File: ${it.relFile}:${it.range.start.line+1}${cwe}${owasp}${conf}${cal}${expl}${snip}${diff}${tests}${refs}`;
  }).join('\n\n');

  const totals = countBySeverity(items as any);
  const head = `# Security Report

**Totals:** Critical: ${totals.critical} · High: ${totals.high} · Medium: ${totals.medium} · Low: ${totals.low} · Info: ${totals.info}

`;

  return head + rows + '\n';
}

async function buildGitHubIssueURL(root: string, it: UIItem): Promise<string | null> {
  try {
    const { execSync } = await import('node:child_process');
    const remote = String(execSync('git config --get remote.origin.url', { cwd: root })).trim();

    // Match "owner/repo" desde URLs SSH o HTTPS
    // ejemplos: git@github.com:owner/repo.git  |  https://github.com/owner/repo.git
    const m = /github\.com[:/](.+?)(?:\.git)?$/.exec(remote);
    if (!m) return null;

    const repo = m[1];
    const title = encodeURIComponent(`[${it.severity.toUpperCase()}] ${it.ruleId} — ${it.relFile}`);
    const body = encodeURIComponent(renderMarkdown([it]));

    return `https://github.com/${repo}/issues/new?title=${title}&body=${body}`;
  } catch {
    return null;
  }
}
