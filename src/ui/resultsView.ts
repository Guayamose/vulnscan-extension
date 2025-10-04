// src/ui/resultsView.ts
import * as vscode from 'vscode';

export class ResultsViewProvider implements vscode.WebviewViewProvider {
  public static readonly viewId = 'oryon.resultsView';
  private view?: vscode.WebviewView;

  constructor(private readonly ctx: vscode.ExtensionContext) {}

  resolveWebviewView(webviewView: vscode.WebviewView) {
    this.view = webviewView;
    const webview = webviewView.webview;
    webview.options = { enableScripts: true };

    const nonce = String(Math.random()).slice(2);
    const csp = [
      "default-src 'none'",
      "img-src https: data:",
      "style-src 'unsafe-inline'",
      `script-src 'nonce-${nonce}'`,
    ].join(';');

    webview.html = `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta http-equiv="Content-Security-Policy" content="${csp}">
  <style>
    :root { --gap: 8px; }
    body { font-family: var(--vscode-font-family); padding: 10px; }
    h3 { margin: 0 0 10px; }
    .row { margin: 8px 0; }
    .box { border: 1px solid var(--vscode-editorWidget-border); padding: 10px; border-radius: 6px; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace; }
    button { padding: 6px 10px; }
    .muted { opacity: .8; }
    .pill { display:inline-block; padding:2px 8px; border-radius:999px; border:1px solid var(--vscode-editorWidget-border); margin-right:6px; }
  </style>
</head>
<body>
  <h3>Oryon — Resultados</h3>

  <div class="box">
    <div class="row">Resumen de findings (basado en diagnósticos actuales).</div>
    <div class="row">
      <span class="pill" id="countAll">Total: 0</span>
      <span class="pill" id="countHigh">High+: 0</span>
      <span class="pill" id="countMed">Medium: 0</span>
      <span class="pill" id="countLow">Low/Info: 0</span>
    </div>
    <div class="row muted mono" id="status">Esperando análisis…</div>
    <div class="row">
      <button id="scan">Scan Workspace</button>
      <button id="clear">Clear diagnostics</button>
      <button id="openSettings">Open settings</button>
    </div>
  </div>

  <script nonce="${nonce}">
    const vscode = acquireVsCodeApi();
    function setText(id, v){ const el=document.getElementById(id); if(el) el.textContent=v; }

    document.getElementById('scan').addEventListener('click', () => vscode.postMessage({ type: 'scan' }));
    document.getElementById('clear').addEventListener('click', () => vscode.postMessage({ type: 'clear' }));
    document.getElementById('openSettings').addEventListener('click', () => vscode.postMessage({ type: 'openSettings' }));

    window.addEventListener('message', (e) => {
      const msg = e.data;
      if (msg?.type === 'summary') {
        const s = msg.payload || {};
        setText('countAll',  'Total: ' + (s.total ?? 0));
        setText('countHigh', 'High+: ' + (s.high ?? 0));
        setText('countMed',  'Medium: ' + (s.medium ?? 0));
        setText('countLow',  'Low/Info: ' + (s.low ?? 0));
        document.getElementById('status').textContent = s.message || '';
      }
    });

    vscode.postMessage({ type: 'requestSummary' });
  </script>
</body>
</html>`;

    // Mensajes desde el Webview hacia la extensión
    webview.onDidReceiveMessage(async (msg) => {
      switch (msg?.type) {
        case 'scan':
          await vscode.commands.executeCommand('sec.scan');
          break;
        case 'clear':
          await vscode.commands.executeCommand('oryon.clearDiagnostics');
          break;
        case 'openSettings':
          await vscode.commands.executeCommand('workbench.action.openSettings', 'oryon');
          break;
        case 'requestSummary':
          this.postSummary();
          break;
      }
    });
  }

  public postSummary(payload?: {
    total?: number; high?: number; medium?: number; low?: number; message?: string;
  }) {
    try {
      this.view?.webview.postMessage({
        type: 'summary',
        payload:
          payload ?? { total: 0, high: 0, medium: 0, low: 0, message: 'Sin datos aún.' },
      });
    } catch { /* noop */ }
  }
}
