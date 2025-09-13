import * as vscode from 'vscode';
import * as path from 'node:path';

type RangeLike = { start: { line: number, col: number }, end: { line: number, col: number } };
export type UIItem = {
  fingerprint: string;
  ruleId: string;
  severity: 'critical'|'high'|'medium'|'low'|'info';
  file: string;
  relFile: string;
  range: RangeLike;
  message: string;
  cwe?: string|null;
  owasp?: string|null;
  snippet?: string;
  explanation_md?: string;
  unified_diff?: string|null;
};

export function openSecurityReport(
  ctx: vscode.ExtensionContext,
  workspaceRoot: string,
  items: UIItem[],
) {
  const panel = vscode.window.createWebviewPanel(
    'secReport',
    'Security Report',
    vscode.ViewColumn.Active,
    { enableScripts: true, retainContextWhenHidden: true }
  );

  const byFile = groupByFile(items);
  const total = items.length;
  const stats = countSev(items);

  panel.webview.html = htmlReport(byFile, stats, total);

  panel.webview.onDidReceiveMessage(async (msg) => {
    if (msg.type === 'open') {
      const abs = path.isAbsolute(msg.file)
        ? msg.file
        : path.join(workspaceRoot, msg.file);
      const doc = await vscode.workspace.openTextDocument(abs);
      const editor = await vscode.window.showTextDocument(doc, { preview: false });
      const line = Math.max(0, Number(msg.line) || 0);
      const col = Math.max(0, Number(msg.col) || 0);
      const pos = new vscode.Position(line, col);
      editor.selection = new vscode.Selection(pos, pos);
      editor.revealRange(new vscode.Range(pos, pos), vscode.TextEditorRevealType.InCenter);
    }
  });
}

export function renderMarkdown(items: UIItem[]): string {
  const byFile = groupByFile(items);
  const stats = countSev(items);
  const total = items.length;

  const header =
`# Security Report

**Total:** ${total}
**Critical:** ${stats.critical} · **High:** ${stats.high} · **Medium:** ${stats.medium} · **Low:** ${stats.low} · **Info:** ${stats.info}

---

`;

  const blocks = Array.from(byFile.entries()).map(([file, arr]) => {
    const entries = arr.map(i => {
      const line = i.range.start.line + 1;
      const chips = [
        i.cwe ? `CWE: ${i.cwe}` : null,
        i.owasp ? `OWASP: ${i.owasp}` : null,
      ].filter(Boolean).join(' · ');
      const exp = i.explanation_md ? `\n\n**Explanation**\n\n${i.explanation_md}` : '';
      const snip = i.snippet ? `\n\n**Snippet**\n\n\`\`\`\n${i.snippet}\n\`\`\`\n` : '';
      const diff = i.unified_diff ? `\n\n**Fix (diff)**\n\n\`\`\`diff\n${i.unified_diff}\n\`\`\`\n` : '';
      return `### [${i.severity.toUpperCase()}] ${i.ruleId}\n**Location:** \`${file}:${line}\`\n\n${i.message}\n\n${chips}${exp}${snip}${diff}`;
    }).join('\n\n---\n\n');

    return `## ${file}  \n_${arr.length} findings_\n\n${entries}`;
  }).join('\n\n---\n\n');

  return header + blocks + '\n';
}

/* ---------- helpers (privados) ---------- */

function groupByFile(items: UIItem[]) {
  const byFile = new Map<string, UIItem[]>();
  for (const it of items) {
    const arr = byFile.get(it.relFile) ?? [];
    arr.push(it);
    byFile.set(it.relFile, arr);
  }
  return byFile;
}

function countSev(items: UIItem[]) {
  const sev = (s: UIItem['severity']) => items.filter(i => i.severity === s).length;
  return {
    critical: sev('critical'),
    high: sev('high'),
    medium: sev('medium'),
    low: sev('low'),
    info: sev('info')
  };
}

function colorFor(sev: UIItem['severity']) {
  switch (sev) {
    case 'critical': return '#B00020';
    case 'high': return '#D32F2F';
    case 'medium': return '#ED6C02';
    case 'low': return '#0288D1';
    default: return '#616161';
  }
}

function escapeHtml(s: string) {
  return s.replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]!));
}

function htmlReport(byFile: Map<string, UIItem[]>, stats: any, total: number) {
  const fileBlocks = Array.from(byFile.entries()).map(([file, arr]) => {
    const rows = arr.map((i) => {
      const sevColor = colorFor(i.severity);
      const cwe = i.cwe ? `<span class="chip">CWE: ${escapeHtml(i.cwe)}</span>` : '';
      const owasp = i.owasp ? `<span class="chip">OWASP: ${escapeHtml(i.owasp)}</span>` : '';
      const diff = i.unified_diff ? `<details><summary>Propuesta de fix (diff)</summary><pre>${escapeHtml(i.unified_diff)}</pre></details>` : '';
      const snippet = i.snippet ? `<details><summary>Snippet</summary><pre>${escapeHtml(i.snippet)}</pre></details>` : '';

      return `
        <div class="finding">
          <div class="finding-head">
            <span class="sev" style="background:${sevColor}">${i.severity.toUpperCase()}</span>
            <span class="rule">${escapeHtml(i.ruleId)}</span>
            <button class="open" data-file="${escapeHtml(i.file)}" data-line="${i.range.start.line}" data-col="${i.range.start.col}">Abrir en editor</button>
          </div>
          <div class="msg">${escapeHtml(i.message)}</div>
          <div class="chips">${cwe} ${owasp}</div>
          ${i.explanation_md ? `<details open><summary>Explicación</summary><div class="md">${escapeHtml(i.explanation_md)}</div></details>` : ''}
          ${snippet}
          ${diff}
        </div>
      `;
    }).join('\n');

    return `
      <section class="file">
        <h3>${escapeHtml(file)} <span class="count">${arr.length}</span></h3>
        ${rows}
      </section>
    `;
  }).join('\n');

  return `<!DOCTYPE html>
  <html>
  <head>
    <meta charset="UTF-8" />
    <style>
      body { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, Arial; margin: 0; padding: 16px; color: #eee; background: #1e1e1e; }
      h1 { margin: 0 0 12px 0; font-size: 18px; }
      .summary { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 16px; }
      .badge { padding: 6px 10px; border-radius: 999px; font-weight: 600; }
      .badge.total { background: #2e7d32; }
      .badge.critical { background: ${colorFor('critical')} }
      .badge.high { background: ${colorFor('high')} }
      .badge.medium { background: ${colorFor('medium')} }
      .badge.low { background: ${colorFor('low')} }
      .badge.info { background: ${colorFor('info')} }
      .file { background: #232323; border: 1px solid #333; border-radius: 10px; margin-bottom: 14px; padding: 10px; }
      .file h3 { font-size: 14px; margin: 0 0 8px 0; display:flex; align-items:center; gap:8px; }
      .file .count { color: #bbb; font-weight: 600; }
      .finding { border-top: 1px solid #333; padding: 10px 0; }
      .finding:first-child { border-top: none; }
      .finding-head { display: flex; gap: 8px; align-items: center; margin-bottom: 6px; }
      .sev { color: #fff; font-weight: 700; font-size: 11px; padding: 4px 8px; border-radius: 6px; }
      .rule { color: #ddd; font-weight: 600; font-size: 12px; }
      .open { margin-left: auto; background: #0e639c; color: white; border: none; padding: 6px 10px; border-radius: 6px; cursor: pointer; }
      .open:hover { filter: brightness(1.1); }
      .msg { color: #ddd; margin: 6px 0; }
      .chips { display: flex; gap: 6px; flex-wrap: wrap; margin: 6px 0; }
      .chip { background: #2b2b2b; color: #ccc; padding: 3px 8px; border-radius: 999px; font-size: 11px; border: 1px solid #3a3a3a; }
      details { margin: 6px 0; }
      pre { background: #111; color: #ddd; padding: 8px; border-radius: 8px; overflow: auto; border: 1px solid #2a2a2a; }
      .md { white-space: pre-wrap; line-height: 1.45; }
      header { display:flex; align-items:center; gap:12px; margin-bottom: 8px; }
    </style>
  </head>
  <body>
    <header>
      <h1>Security Report</h1>
      <span class="badge total">Total: ${total}</span>
      <div class="summary">
        <span class="badge critical">Critical: ${stats.critical}</span>
        <span class="badge high">High: ${stats.high}</span>
        <span class="badge medium">Medium: ${stats.medium}</span>
        <span class="badge low">Low: ${stats.low}</span>
        <span class="badge info">Info: ${stats.info}</span>
      </div>
    </header>

    ${fileBlocks}

    <script>
      const vscode = acquireVsCodeApi();
      document.querySelectorAll('.open').forEach(btn => {
        btn.addEventListener('click', () => {
          vscode.postMessage({
            type: 'open',
            file: btn.dataset.file,
            line: btn.dataset.line,
            col: btn.dataset.col
          });
        });
      });
    </script>
  </body>
  </html>`;
}
