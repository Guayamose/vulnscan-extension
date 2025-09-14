// src/report.ts
import * as vscode from 'vscode';
import * as path from 'node:path';

type Sev = 'info'|'low'|'medium'|'high'|'critical';

export type UIItem = {
  fingerprint: string;
  ruleId: string;
  severity: Sev;
  file: string;
  relFile: string;
  // ⇩⇩⇩ aquí el tipo corregido (col en vez de character)
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
          if (!it || !it.unified_diff) {
            vscode.window.showWarningMessage('No hay diff aplicable.');
            break;
          }
          const ok = await tryApplyUnifiedDiff(it.file, it.unified_diff, it.snippet);
          panel.webview.postMessage({ type: 'applyDiff:result', ok, fp });
          vscode.window.showInformationMessage(ok ? 'Parche aplicado.' : 'No se pudo aplicar el parche automáticamente.');
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
          else vscode.window.showInformationMessage('No se detectó remoto GitHub. Diff copiado en portapapeles.');
          break;
        }
      }
    } catch (e: any) {
      vscode.window.showErrorMessage(`Report action failed: ${e?.message || e}`);
    }
  });
}

/* ------------------------------ HTML/UI ------------------------------ */

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
<html>
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy"
  content="default-src 'none'; img-src ${webview.cspSource} https:;
           style-src ${webview.cspSource} 'unsafe-inline';
           script-src 'nonce-${nonce}';">
<style>
  :root {
    --bg: #1e1e1e; --card:#232323; --muted:#9aa0a6; --ink:#eaeaea; --border:#333;
    --crit:#b00020; --high:#d32f2f; --med:#f57c00; --low:#0288d1; --info:#757575; --ok:#80e27e;
  }
  body { background:var(--bg); color:var(--ink); font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Arial; padding:14px; }
  h1 { margin: 0 0 10px 0; }
  .top { display:flex; align-items:center; gap:12px; flex-wrap:wrap; }
  .chip { padding:4px 10px; border-radius:999px; font-weight:600; font-size:12px; cursor:pointer; user-select:none; }
  .chip.total { background:#2f3b2f; }
  .chip.critical { background:var(--crit); } .chip.high { background:var(--high); }
  .chip.medium { background:var(--med); } .chip.low { background:var(--low); } .chip.info { background:var(--info); }
  .muted { color:var(--muted); }
  .toolbar { display:flex; gap:10px; align-items:center; margin:10px 0 6px 0; }
  input[type="search"], select { background:#121212; color:#eee; border:1px solid #2a2a2a; border-radius:8px; padding:8px; }
  .grid { display:flex; flex-direction:column; gap:12px; }
  .card { background:var(--card); border:1px solid var(--border); border-radius:10px; padding:12px; }
  .header { display:flex; justify-content:space-between; gap:10px; align-items:center; }
  .badge { font-size:12px; font-weight:700; padding:4px 8px; border-radius:6px; }
  .sev.medium { background:var(--med); } .sev.high { background:var(--high); } .sev.critical { background:var(--crit); }
  .sev.low { background:var(--low); } .sev.info { background:var(--info); }
  .ai { background:#394b39; }
  .row { display:flex; gap:8px; align-items:center; flex-wrap:wrap; margin-top:6px; }
  .btn { background:#0e639c; color:#fff; border:none; padding:6px 10px; border-radius:6px; cursor:pointer; }
  .btn.gray { background:#3a3a3a; }
  .tag { background:#2f2f2f; padding:3px 8px; border-radius:999px; font-size:12px; }
  details { margin-top:8px; }
  pre { background:#111; border:1px solid #2a2a2a; padding:10px; border-radius:8px; overflow:auto; }
  a.ref { color:#9ecbff; text-decoration: none; cursor:pointer; }
</style>
</head>
<body>
  <h1>Security Report</h1>

  <div class="top">
    <div class="chip total">Total: ${total}</div>
    ${chips}
    <span class="muted">${escapeHtml(metaLine)}</span>
  </div>

  <div class="toolbar">
    <input id="search" type="search" placeholder="Buscar archivo / regla / texto…" />
    <select id="sort">
      <option value="sev">Sort: severity</option>
      <option value="file">Sort: file</option>
      <option value="rule">Sort: rule</option>
    </select>
  </div>

  <div id="list" class="grid">${cards}</div>

<script nonce="${nonce}">
  const vscode = acquireVsCodeApi();
  const state = { filters: new Set(JSON.parse(localStorage.getItem('vulnscan.filters')||'[]')) };

  document.querySelectorAll('.chip[data-sev]').forEach(el => {
    el.addEventListener('click', () => {
      const sev = el.getAttribute('data-sev');
      if (state.filters.has(sev)) state.filters.delete(sev); else state.filters.add(sev);
      localStorage.setItem('vulnscan.filters', JSON.stringify([...state.filters]));
      filter();
    });
  });

  document.getElementById('search').addEventListener('input', filter);
  document.getElementById('sort').addEventListener('change', sort);

  function sort() {
    const how = document.getElementById('sort').value;
    const list = document.getElementById('list');
    const nodes = [...list.children];
    nodes.sort((a,b) => {
      if (how === 'file') return a.dataset.rel.localeCompare(b.dataset.rel);
      if (how === 'rule') return a.dataset.rule.localeCompare(b.dataset.rule);
      const ord = ['critical','high','medium','low','info'];
      return ord.indexOf(a.dataset.sev) - ord.indexOf(b.dataset.sev);
    });
    list.replaceChildren(...nodes);
  }

  function filter() {
    const q = (document.getElementById('search').value || '').toLowerCase();
    const active = state.filters;
    [...document.querySelectorAll('.card')].forEach(card => {
      const sev = card.dataset.sev;
      const hay = !active.size || active.has(sev);
      const text = (card.innerText || '').toLowerCase();
      const okQ = !q || text.includes(q);
      card.style.display = (hay && okQ) ? '' : 'none';
    });
  }

  // botones
  document.querySelectorAll('[data-open]').forEach(btn => btn.addEventListener('click', e => {
    const file = e.currentTarget.getAttribute('data-open');
    const line = Number(e.currentTarget.getAttribute('data-line') || '0');
    vscode.postMessage({ type: 'openFile', file, line });
  }));
  document.querySelectorAll('[data-copy]').forEach(btn => btn.addEventListener('click', e => {
    vscode.postMessage({ type: 'copyDiff', diff: e.currentTarget.getAttribute('data-copy') });
  }));
  document.querySelectorAll('[data-apply]').forEach(btn => btn.addEventListener('click', e => {
    vscode.postMessage({ type: 'applyDiff', fingerprint: e.currentTarget.getAttribute('data-apply') });
  }));
  document.querySelectorAll('[data-ignore]').forEach(btn => btn.addEventListener('click', e => {
    vscode.postMessage({ type: 'toggleIgnore', fingerprint: e.currentTarget.getAttribute('data-ignore') });
  }));
  document.querySelectorAll('a.ref').forEach(a => a.addEventListener('click', e => {
    e.preventDefault();
    vscode.postMessage({ type: 'openExternal', url: e.currentTarget.getAttribute('data-href') });
  }));
  document.querySelectorAll('[data-issue]').forEach(btn => btn.addEventListener('click', e => {
    vscode.postMessage({ type: 'createIssue', fingerprint: e.currentTarget.getAttribute('data-issue') });
  }));

  // mensajes de vuelta
  window.addEventListener('message', ev => {
    const m = ev.data;
    if (m.type === 'toggleIgnore:result' && m.ok) {
      const card = document.querySelector('.card[data-fp="'+m.fp+'"]');
      if (card) card.remove();
    }
    if (m.type === 'applyDiff:result') {
      if (m.ok) {
        const card = document.querySelector('.card[data-fp="'+m.fp+'"]');
        if (card) card.style.outline = '2px solid #80e27e';
      }
    }
  });

  filter(); sort();
</script>
</body>
</html>`;
}

function renderCard(it: UIItem) {
  const sev = it.severity.toLowerCase();
  const sevCls = `badge sev ${sev}`;
  const ai = (it.calibrated && it.calibrated !== 'none') ? `<span class="badge ai">AI: ${escapeHtml(it.calibrated)}</span>` : '';
  const conf = (typeof it.confidence === 'number') ? `<span class="tag">confidence: ${Math.round(it.confidence * 100)}%</span>` : '';
  const cwe = it.cwe ? `<span class="tag">CWE: ${escapeHtml(it.cwe)}</span>` : '';
  const owasp = it.owasp ? `<span class="tag">OWASP: ${escapeHtml(it.owasp)}</span>` : '';

  const expl = it.explanation_md ? `<details open><summary>Explicación</summary><div>${mdToHtml(it.explanation_md)}</div></details>` : '';
  const snip = it.snippet ? `<details><summary>Snippet</summary><pre>${escapeHtml(it.snippet)}</pre></details>` : '';
  const diff = it.unified_diff ? `<details><summary>Propuesta de fix (diff)</summary><div class="row"><button class="btn" data-copy="${escapeAttr(it.unified_diff)}">Copy diff</button><button class="btn gray" data-apply="${escapeAttr(it.fingerprint)}">Try apply patch</button></div><pre>${escapeHtml(it.unified_diff)}</pre></details>` : '';

  const tests = (it.tests || []).length ? `<details><summary>Tests sugeridos</summary><ul>${it.tests.map(t => `<li>${escapeHtml(t)}</li>`).join('')}</ul></details>` : '';
  const refs = (it.references || []).length ? `<details><summary>Referencias</summary><ul>${it.references.map(r => refItem(r)).join('')}</ul></details>` : '';

  return `
  <div class="card" data-sev="${escapeAttr(sev)}" data-rel="${escapeAttr(it.relFile)}" data-rule="${escapeAttr(it.ruleId)}" data-fp="${escapeAttr(it.fingerprint)}">
    <div class="header">
      <div>
        <span class="${sevCls}">${sev.toUpperCase()}</span>
        <strong style="margin-left:8px">${escapeHtml(it.relFile)}</strong>
        <span class="muted">· ${escapeHtml(it.ruleId)}</span>
      </div>
      <div class="row">
        ${ai}${conf}${cwe}${owasp}
        <button class="btn" data-open="${escapeAttr(it.file)}" data-line="${it.range.start.line}">Abrir en editor</button>
        <button class="btn gray" data-ignore="${escapeAttr(it.fingerprint)}">False Positive</button>
        <button class="btn gray" data-issue="${escapeAttr(it.fingerprint)}">Create Issue</button>
      </div>
    </div>
    <div class="muted" style="margin-top:6px">${escapeHtml(it.message || '')}</div>
    ${expl}
    ${snip}
    ${diff}
    ${tests}
    ${refs}
  </div>`;
}

function chip(sev: string, n: number) {
  const cls = `chip ${sev}`;
  const label = sev[0].toUpperCase() + sev.slice(1);
  return `<div class="${cls}" data-sev="${sev}">${label}: ${n}</div>`;
}

function countBySeverity(items: UIItem[]) {
  const map: Record<Sev, number> = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  for (const it of items) map[it.severity] = (map[it.severity] || 0) + 1;
  return map;
}

function escapeHtml(s: string) {
  return String(s).replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[m]!);
}
function escapeAttr(s: string) { return escapeHtml(s).replace(/\n/g,'\\n'); }

function mdToHtml(md: string) {
  const fenced = md.replace(/```([\s\S]*?)```/g, (_m, code) => `<pre>${escapeHtml(code)}</pre>`);
  const lines = fenced.split(/\n{2,}/).map(p => `<p>${escapeHtml(p).replace(/\n/g,'<br>')}</p>`);
  return lines.join('\n');
}

function refItem(r: string) {
  const url = String(r).trim();
  const safe = /^https?:\/\//i.test(url) ? url : '';
  const label = safe ? url.replace(/^https?:\/\//,'') : url;
  if (!safe) return `<li>${escapeHtml(url)}</li>`;
  return `<li><a class="ref" data-href="${escapeAttr(safe)}">${escapeHtml(label)}</a></li>`;
}

/* --------------------------- Apply unified diff --------------------------- */
async function tryApplyUnifiedDiff(file: string, diff: string, snippet?: string): Promise<boolean> {
  try {
    const uri = vscode.Uri.file(file);
    const doc = await vscode.workspace.openTextDocument(uri);
    let text = doc.getText();

    if (snippet && /^---[\s\S]*?\n\+\+\+[\s\S]*?@@/m.test(diff)) {
      const blocks = extractHunks(diff).map(h => h);
      if (blocks.length === 1) {
        const h = blocks[0];
        const original = h.lines.filter(l => l.kind !== '+').map(l => l.txt).join('\n');
        const added = h.lines.filter(l => l.kind !== '-').map(l => l.txt).join('\n');
        if (snippet.includes(original.trim()) || text.includes(original.trim())) {
          const newText = text.replace(original, added);
          if (newText !== text) {
            const edit = new vscode.WorkspaceEdit();
            const full = new vscode.Range(doc.positionAt(0), doc.positionAt(text.length));
            edit.replace(uri, full, newText);
            const ok = await vscode.workspace.applyEdit(edit);
            if (ok) await doc.save();
            return ok;
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

      const newBlock = h.lines
        .filter(l => l.kind !== '-')
        .map(l => l.txt)
        .join('\n');

      if (!oldBlock.trim()) return false;

      const edit = new vscode.WorkspaceEdit();
      edit.replace(uri, new vscode.Range(before, after), newBlock);
      const ok = await vscode.workspace.applyEdit(edit);
      if (!ok) return false;

      offset += (h.newLines - h.oldLines);
    }
    await doc.save();
    return true;
  } catch {
    return false;
  }
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
      oldStart: parseInt(m[1],10),
      oldLines: parseInt(m[2]||'1',10),
      newStart: parseInt(m[3],10),
      newLines: parseInt(m[4]||'1',10),
      lines: []
    };
    i++;
    while (i < lines.length && !lines[i].startsWith('@@')) {
      const ch = lines[i][0];
      const txt = lines[i].slice(1);
      if (ch === '+' || ch === '-' || ch === ' ') h.lines.push({ kind: ch as any, txt });
      i++;
    }
    hunks.push(h);
  }
  return hunks;
}

/* -------------------------- Exporter (Markdown) -------------------------- */
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

  const totals = countBySeverity(items);
  const head = `# Security Report

**Totals:** Critical: ${totals.critical} · High: ${totals.high} · Medium: ${totals.medium} · Low: ${totals.low} · Info: ${totals.info}

`;

  return head + rows + '\n';
}

/* ------------------------------- GitHub URL ------------------------------- */
async function buildGitHubIssueURL(root: string, it: UIItem): Promise<string | null> {
  try {
    const { execSync } = await import('node:child_process');
    const remote = String(execSync('git config --get remote.origin.url', { cwd: root })).trim();
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
