// src/ui/resultsView.ts
import * as vscode from 'vscode';

type Row = {
  file: string;
  uri: vscode.Uri;
  items: {
    message: string;
    ruleId?: string;
    severity: 'error' | 'warning' | 'info';
    line0: number;
    col0: number;
  }[];
  counts: { error: number; warning: number; info: number };
};

export class ResultsViewProvider implements vscode.WebviewViewProvider {
  public static readonly viewId = 'oryon.resultsView';
  private disposables: vscode.Disposable[] = [];

  constructor(private readonly ctx: vscode.ExtensionContext) {}

  resolveWebviewView(view: vscode.WebviewView) {
    const webview = view.webview;
    webview.options = { enableScripts: true };
    webview.html = this.renderHtml();

    const pushData = async () => {
      const rows = this.collect();
      webview.postMessage({ type: 'data', payload: rows.map(r => ({
        file: r.file,
        items: r.items.map(i => ({
          message: i.message,
          ruleId: i.ruleId,
          severity: i.severity,
          line1: i.line0 + 1,
          col1: i.col0 + 1
        })),
        counts: r.counts
      })) });
    };

    this.disposables.push(
      vscode.languages.onDidChangeDiagnostics(() => pushData())
    );

    webview.onDidReceiveMessage(async (msg) => {
      if (msg?.type === 'open' && msg?.file && typeof msg.line1 === 'number' && typeof msg.col1 === 'number') {
        const uri = vscode.Uri.file(msg.file);
        const pos = new vscode.Position(Math.max(0, msg.line1 - 1), Math.max(0, msg.col1 - 1));
        const sel = new vscode.Selection(pos, pos);
        const doc = await vscode.workspace.openTextDocument(uri);
        const editor = await vscode.window.showTextDocument(doc, { preview: true });
        editor.selection = sel;
        editor.revealRange(new vscode.Range(pos, pos), vscode.TextEditorRevealType.InCenterIfOutsideViewport);
      } else if (msg?.type === 'scan') {
        await vscode.commands.executeCommand('sec.scan');
      }
    });

    pushData();
  }

  private collect(): Row[] {
    const out: Map<string, Row> = new Map();
    const all = vscode.languages.getDiagnostics();
    for (const [uri, diags] of all) {
      const ours = diags.filter(d => (d.source || '').toLowerCase() === 'oryon');
      if (!ours.length) continue;
      const key = uri.fsPath;
      if (!out.has(key)) {
        out.set(key, {
          file: key,
          uri,
          items: [],
          counts: { error: 0, warning: 0, info: 0 }
        });
      }
      const row = out.get(key)!;
      for (const d of ours) {
        const sev = d.severity === vscode.DiagnosticSeverity.Error ? 'error'
                 : d.severity === vscode.DiagnosticSeverity.Warning ? 'warning'
                 : 'info';
        row.items.push({
          message: d.message,
          ruleId: (d.code as any)?.value ?? (typeof d.code === 'string' ? d.code : undefined),
          severity: sev,
          line0: d.range.start.line,
          col0: d.range.start.character
        });
        row.counts[sev]++;
      }
    }

    const arr = Array.from(out.values());
    arr.sort((a, b) => {
      const sa = a.counts.error * 100 + a.counts.warning * 10 + a.counts.info;
      const sb = b.counts.error * 100 + b.counts.warning * 10 + b.counts.info;
      if (sa !== sb) return sb - sa;
      return a.file.localeCompare(b.file);
    });
    return arr;
  }

  private renderHtml(): string {
    const nonce = String(Math.random()).slice(2);
    const csp = [
      "default-src 'none'",
      "style-src 'unsafe-inline'",
      `script-src 'nonce-${nonce}'`
    ].join(';');

    return `<!doctype html>
<html>
<head>
<meta charset="utf-8" />
<meta http-equiv="Content-Security-Policy" content="${csp}">
<style>
  body { font-family: var(--vscode-font-family); padding: 8px; }
  .hdr { display:flex; align-items:center; gap:8px; margin-bottom:8px; }
  .btn { padding:4px 8px; border:1px solid var(--vscode-editorWidget-border); border-radius:6px; background:transparent; cursor:pointer; }
  .empty { opacity:.7; margin: 8px 0; }
  .row { border:1px solid var(--vscode-editorWidget-border); border-radius:8px; margin-bottom:8px; }
  .rowHead { display:flex; justify-content:space-between; padding:8px; background:var(--vscode-editorWidget-background); border-bottom:1px solid var(--vscode-editorWidget-border); }
  .path { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Courier New', monospace; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .badges { display:flex; gap:6px; }
  .badge { font-size:11px; padding:2px 6px; border-radius:999px; border:1px solid var(--vscode-editorWidget-border); }
  .b-error { border-color:var(--vscode-errorForeground); }
  .items { padding:6px 8px; }
  .item { display:flex; gap:8px; padding:4px 0; align-items:center; cursor:pointer; }
  .sev { width:10px; height:10px; border-radius:50%; display:inline-block; }
  .sev-error { background: var(--vscode-errorForeground); }
  .sev-warning { background: var(--vscode-inputValidation-warningBorder); }
  .sev-info { background: var(--vscode-badge-foreground); opacity:.6; }
  .msg { flex:1 1 auto; }
  .pos, .rule { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Courier New', monospace; opacity:.8; }
</style>
</head>
<body>
  <div class="hdr">
    <strong>Security Findings</strong>
    <div style="flex:1"></div>
    <button class="btn" id="scanBtn">Scan Workspace</button>
  </div>
  <div id="list"></div>

<script nonce="${nonce}">
  const vscode = acquireVsCodeApi();

  function render(rows) {
    const list = document.getElementById('list');
    if (!rows || !rows.length) {
      list.innerHTML = '<div class="empty">No hay findings aún. Lanza un scan o guarda un archivo para ver el live-scan.</div>';
      return;
    }
    const frag = document.createDocumentFragment();
    rows.forEach(r => {
      const wrap = document.createElement('div');
      wrap.className = 'row';

      const head = document.createElement('div');
      head.className = 'rowHead';
      head.innerHTML = \`
        <div class="path" title="\${r.file}">\${r.file}</div>
        <div class="badges">
          <span class="badge b-error">E: \${r.counts.error}</span>
          <span class="badge">W: \${r.counts.warning}</span>
          <span class="badge">I: \${r.counts.info}</span>
        </div>
      \`;
      wrap.appendChild(head);

      const items = document.createElement('div');
      items.className = 'items';
      r.items.forEach(it => {
        const el = document.createElement('div');
        el.className = 'item';
        el.innerHTML = \`
          <span class="sev sev-\${it.severity}"></span>
          <div class="msg">\${it.message.replace(/</g,'&lt;')}</div>
          <div class="rule">\${it.ruleId ? '['+it.ruleId+']' : ''}</div>
          <div class="pos">L\${it.line1}:\${it.col1}</div>
        \`;
        el.addEventListener('click', () => {
          vscode.postMessage({ type: 'open', file: r.file, line1: it.line1, col1: it.col1 });
        });
        items.appendChild(el);
      });
      wrap.appendChild(items);
      frag.appendChild(wrap);
    });
    list.replaceChildren(frag);
  }

  window.addEventListener('message', (e) => {
    const msg = e.data;
    if (msg?.type === 'data') render(msg.payload || []);
  });

  document.getElementById('scanBtn').addEventListener('click', () => {
    vscode.postMessage({ type: 'scan' });
  });
</script>
</body>
</html>`;
  }
}
