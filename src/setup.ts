// src/setup.ts
import * as vscode from 'vscode';
import { execFile } from 'node:child_process';
import * as os from 'node:os';
import * as path from 'node:path';

const TOKEN_KEY = 'vulnscan/apiKey';

function detectSemgrep(): Promise<{ ok: boolean; version?: string; note?: string }> {
  const candidates = [
    'semgrep',
    path.join(os.homedir(), '.local', 'bin', 'semgrep'),
    path.join(os.homedir(), '.local', 'share', 'pipx', 'venvs', 'semgrep', 'bin', 'semgrep')
  ];
  return new Promise((resolve) => {
    let idx = 0;
    const tryNext = () => {
      if (idx >= candidates.length) return resolve({ ok: false, note: 'No encontrado en PATH ni rutas comunes.' });
      const bin = candidates[idx++];
      execFile(bin, ['--version'], { timeout: 5000 }, (err, stdout) => {
        if (!err && stdout) return resolve({ ok: true, version: stdout.trim() });
        tryNext();
      });
    };
    tryNext();
  });
}

export async function openSetupWizard(ctx: vscode.ExtensionContext) {
  const panel = vscode.window.createWebviewPanel(
    'vulnscanSetup',
    'VulnScan — Setup Wizard',
    vscode.ViewColumn.Active,
    { enableScripts: true, retainContextWhenHidden: true }
  );

  const cfg = vscode.workspace.getConfiguration('vulnscan');
  const currentMin = cfg.get<string>('minSeverity', 'low')!;
  const currentTarget = cfg.get<string>('targetDirectory', 'auto')!;
  const currentLang = cfg.get<string>('enrich.language', 'es')!;

  panel.webview.html = html(panel.webview, currentMin, currentTarget, currentLang);

  panel.webview.onDidReceiveMessage(async (msg) => {
    switch (msg.type) {
      case 'checkSemgrep': {
        const res = await detectSemgrep();
        panel.webview.postMessage({ type: 'checkSemgrep:result', ...res });
        break;
      }
      case 'installSemgrep': {
        const term = vscode.window.createTerminal({ name: 'Install Semgrep' });
        term.show();
        term.sendText('pipx install semgrep');
        vscode.window.showInformationMessage('Abierto terminal para instalar Semgrep con pipx. Cuando termine, pulsa "Recheck".');
        break;
      }
      case 'saveApiKey': {
        const key = String(msg.key || '').trim();
        if (!key) { vscode.window.showWarningMessage('Introduce una API key válida.'); break; }
        await ctx.secrets.store(TOKEN_KEY, key);
        if (!process.env.OPENAI_API_KEY) process.env.OPENAI_API_KEY = key;
        vscode.window.showInformationMessage('OPENAI_API_KEY guardada en VS Code Secrets.');
        break;
      }
      case 'testAi': {
        try {
          // Sin dependencias: basta con comprobar que hay API key
          const ok = !!process.env.OPENAI_API_KEY;
          panel.webview.postMessage({ type: 'testAi:result', ok, err: ok ? '' : 'API key no configurada' });
        } catch (e: any) {
          panel.webview.postMessage({ type: 'testAi:result', ok: false, err: e?.message || String(e) });
        }
        break;
      }
      case 'setConfig': {
        const { key, value } = msg;
        await vscode.workspace.getConfiguration('vulnscan').update(key, value, vscode.ConfigurationTarget.Workspace);
        vscode.window.showInformationMessage(`VulnScan: ${key} = ${value}`);
        break;
      }
      case 'scanNow': {
        vscode.commands.executeCommand('sec.scan');
        break;
      }
    }
  });
}

function nonce() { return Array.from({ length: 32 }, () => Math.random().toString(36)[2]).join(''); }

function html(webview: vscode.Webview, minSev: string, targetDir: string, analysisLang: string) {
  const n = nonce();
  return `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8" />
<meta http-equiv="Content-Security-Policy"
  content="default-src 'none'; img-src ${webview.cspSource} https:;
           style-src ${webview.cspSource} 'unsafe-inline';
           script-src 'nonce-${n}';">
<style>
  body { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Arial; color: #eaeaea; background: #1e1e1e; margin: 0; padding: 16px; }
  h1 { margin: 0 0 12px 0; font-size: 18px; }
  .grid { display: grid; gap: 16px; grid-template-columns: 1fr 1fr; }
  .card { background: #232323; border: 1px solid #333; border-radius: 10px; padding: 14px; }
  .row { display:flex; gap:8px; align-items:center; margin: 8px 0; }
  .btn { background: #0e639c; color: #fff; border: none; padding: 8px 12px; border-radius: 6px; cursor: pointer; }
  .btn.secondary { background: #3a3a3a; }
  input[type="password"], select { background:#111; color:#eee; border:1px solid #2a2a2a; border-radius:6px; padding:8px; width:100%; }
  .footer { margin-top:16px; display:flex; gap:10px; }
</style>
</head>
<body>
  <h1>VulnScan — Setup Wizard</h1>
  <div class="grid">
    <div class="card">
      <h3>1) Semgrep</h3>
      <div id="semgrepStatus" class="row">Estado: <span id="sgLabel">Checking…</span></div>
      <div class="row">
        <button class="btn" onclick="recheck()">Recheck</button>
        <button class="btn secondary" onclick="install()">Install via pipx</button>
      </div>
    </div>

    <div class="card">
      <h3>2) OpenAI API Key</h3>
      <div class="row"><input id="apiKey" type="password" placeholder="sk-..." /></div>
      <div class="row">
        <button class="btn" onclick="saveKey()">Save</button>
        <button class="btn secondary" onclick="testAi()">Test</button>
        <span id="aiRes"></span>
      </div>
    </div>

    <div class="card">
      <h3>3) Preferencias rápidas</h3>
      <div class="row">
        <label style="min-width:160px">Minimum severity</label>
        <select id="minSev">
          <option value="info">info</option>
          <option value="low">low</option>
          <option value="medium">medium</option>
          <option value="high">high</option>
          <option value="critical">critical</option>
        </select>
      </div>
      <div class="row">
        <label style="min-width:160px">Target directory</label>
        <select id="targetDir">
          <option value="auto">auto</option>
          <option value="app">app</option>
          <option value="root">root</option>
        </select>
      </div>
      <div class="row">
        <label style="min-width:160px">Language of analysis</label>
        <select id="analysisLang">
          <option value="auto">auto</option>
          <option value="es">es</option>
          <option value="en">en</option>
          <option value="fr">fr</option>
          <option value="de">de</option>
          <option value="it">it</option>
          <option value="pt">pt</option>
          <option value="ja">ja</option>
          <option value="ko">ko</option>
          <option value="zh">zh</option>
        </select>
      </div>
    </div>

    <div class="card">
      <h3>4) ¡Listo!</h3>
      <p>Pulsa para ejecutar tu primer escaneo del workspace.</p>
      <button class="btn" onclick="scanNow()">Run first scan</button>
    </div>
  </div>

  <div class="footer">
    <small>También puedes abrir este asistente desde la paleta: “VulnScan: Setup Wizard”.</small>
  </div>

<script nonce="${n}">
  const vscode = acquireVsCodeApi();

  function recheck() {
    document.getElementById('sgLabel').textContent = 'Checking…';
    vscode.postMessage({ type: 'checkSemgrep' });
  }
  function install() { vscode.postMessage({ type: 'installSemgrep' }); }
  function saveKey() {
    const key = document.getElementById('apiKey').value;
    vscode.postMessage({ type: 'saveApiKey', key });
  }
  function testAi() {
    document.getElementById('aiRes').textContent = 'Testing…';
    vscode.postMessage({ type: 'testAi' });
  }
  function scanNow() { vscode.postMessage({ type: 'scanNow' }); }
  function setConfig(key, value) { vscode.postMessage({ type: 'setConfig', key, value }); }

  // init values
  document.getElementById('minSev').value = "${minSev}";
  document.getElementById('targetDir').value = "${targetDir}";
  document.getElementById('analysisLang').value = "${analysisLang}";

  document.getElementById('minSev').addEventListener('change', e => setConfig('vulnscan.minSeverity', e.target.value));
  document.getElementById('targetDir').addEventListener('change', e => setConfig('vulnscan.targetDirectory', e.target.value));
  document.getElementById('analysisLang').addEventListener('change', e => setConfig('vulnscan.enrich.language', e.target.value));

  // first checks
  recheck();

  window.addEventListener('message', (ev) => {
    const msg = ev.data;
    if (msg.type === 'checkSemgrep:result') {
      const el = document.getElementById('sgLabel');
      if (msg.ok) el.innerHTML = '<span style="color:#80e27e;font-weight:600">Found</span> — ' + (msg.version || '');
      else el.innerHTML = '<span style="color:#ff6659;font-weight:600">Not found</span> — ' + (msg.note || '');
    }
    if (msg.type === 'testAi:result') {
      const el = document.getElementById('aiRes');
      if (msg.ok) el.innerHTML = '<span style="color:#80e27e;font-weight:600">OK</span>';
      else el.innerHTML = '<span style="color:#ff6659;font-weight:600">Fail</span> — ' + (msg.err || '');
    }
  });
</script>
</body>
</html>`;
}
