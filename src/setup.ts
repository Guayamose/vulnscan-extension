import * as vscode from 'vscode';
import { exec, execFile } from 'node:child_process';
import * as path from 'node:path';

const TOKEN_KEY = 'vulnscan/apiKey';

export async function openSetupWizard(ctx: vscode.ExtensionContext) {
  const panel = vscode.window.createWebviewPanel(
    'vulnscanSetup',
    'VulnScan — Setup Wizard',
    vscode.ViewColumn.One,
    { enableScripts: true, retainContextWhenHidden: true }
  );

  const cfg = vscode.workspace.getConfiguration('vulnscan');
  const minSeverity = cfg.get<'info'|'low'|'medium'|'high'|'critical'>('minSeverity', 'low');
  const targetDirectory = cfg.get<'auto'|'root'|'app'>('targetDirectory', 'auto');
  const analysisLang = cfg.get<string>('enrich.language', 'es');

  const nonce = makeNonce();
  panel.webview.html = getHtml(nonce, {
    apiKey: (await ctx.secrets.get(TOKEN_KEY)) ? '***' : '',
    minSeverity, targetDirectory, analysisLang
  });

  // ——— helpers ———
  const post = (msg: any) => panel.webview.postMessage(msg);

  async function checkSemgrep(): Promise<{ ok: boolean; version?: string; err?: string }> {
    try {
      const version = await runVersion('semgrep');
      return { ok: true, version };
    } catch (e: any) {
      try {
        // prueba ruta típica pipx
        const v2 = await runCmd('~/.local/bin/semgrep --version');
        return { ok: true, version: v2.trim() };
      } catch (err: any) {
        return { ok: false, err: String(err?.message || err) };
      }
    }
  }

  async function installSemgrep(): Promise<{ ok: boolean; out?: string; err?: string }> {
    try {
      const result = await runCmd('pipx install semgrep -q');
      return { ok: true, out: result };
    } catch (e: any) {
      return { ok: false, err: String(e?.message || e) };
    }
  }

  async function savePrefs(p: any) {
    if (p.minSeverity) await cfg.update('minSeverity', p.minSeverity, vscode.ConfigurationTarget.Workspace);
    if (p.targetDirectory) await cfg.update('targetDirectory', p.targetDirectory, vscode.ConfigurationTarget.Workspace);
    if (p.analysisLang) await cfg.update('enrich.language', p.analysisLang, vscode.ConfigurationTarget.Workspace);
  }

  async function testKey(k?: string) {
    const key = k || (await ctx.secrets.get(TOKEN_KEY));
    if (!key) return { ok: false, err: 'No API key' };
    try {
      // Node 18+ trae fetch nativo
      const res = await fetch('https://api.openai.com/v1/models', {
        headers: { Authorization: `Bearer ${key}` }
      });
      if (res.ok) return { ok: true };
      const body = await res.text();
      return { ok: false, err: `${res.status} ${res.statusText} ${body.slice(0, 120)}` };
    } catch (e: any) {
      return { ok: false, err: String(e?.message || e) };
    }
  }

  // ——— mensajes desde WebView ———
  panel.webview.onDidReceiveMessage(async (m) => {
    switch (m.type) {
      case 'recheck': {
        post({ type: 'semgrep:status', state: 'checking' });
        const res = await checkSemgrep();
        post({ type: 'semgrep:status', state: res.ok ? 'ok' : 'missing', version: res.version, err: res.err });
        break;
      }
      case 'install': {
        post({ type: 'semgrep:install', state: 'running' });
        const res = await installSemgrep();
        const stat = await checkSemgrep();
        post({ type: 'semgrep:install', state: res.ok ? 'done' : 'error', out: res.out, err: res.err, version: stat.version });
        break;
      }
      case 'saveKey': {
        const key = String(m.key || '').trim();
        if (!key) { vscode.window.showWarningMessage('Introduce una API key'); break; }
        await ctx.secrets.store(TOKEN_KEY, key);
        process.env.OPENAI_API_KEY = key;
        vscode.window.showInformationMessage('OpenAI API key guardada.');
        post({ type: 'key:saved' });
        break;
      }
      case 'testKey': {
        const key = String(m.key || '').trim() || (await ctx.secrets.get(TOKEN_KEY)) || '';
        const res = await testKey(key);
        post({ type: 'key:test', ok: res.ok, err: res.err });
        break;
      }
      case 'savePrefs': {
        await savePrefs(m.prefs || {});
        vscode.window.showInformationMessage('Preferencias guardadas.');
        break;
      }
      case 'run': {
        await savePrefs(m.prefs || {});
        vscode.commands.executeCommand('sec.scan');
        break;
      }
      case 'exportMd': {
        vscode.commands.executeCommand('sec.exportReport');
        break;
      }
      case 'exportJson': {
        vscode.commands.executeCommand('sec.exportJSON');
        break;
      }
    }
  });

  // auto-chequeo al abrir
  setTimeout(() => post({ type: 'semgrep:auto' }), 300);
}

/* ----------------------------- utils ----------------------------- */

function makeNonce() {
  return Array.from({ length: 16 }, () => Math.random().toString(36)[2]).join('');
}

function runVersion(bin: string): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(bin, ['--version'], { timeout: 15000 }, (err, stdout, stderr) => {
      if (err) return reject(err);
      resolve((stdout || stderr || '').trim());
    });
  });
}

function runCmd(cmd: string): Promise<string> {
  return new Promise((resolve, reject) => {
    exec(cmd, { shell: '/bin/bash' }, (err, stdout, stderr) => {
      if (err) return reject(stderr || stdout || err);
      resolve(stdout || '');
    });
  });
}

/* ----------------------------- HTML ----------------------------- */

function getHtml(nonce: string, init: {
  apiKey: string; minSeverity: string; targetDirectory: string; analysisLang: string;
}) {
  return `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy"
  content="default-src 'none'; img-src https:; style-src 'unsafe-inline'; script-src 'nonce-${nonce}';">
<style>
  :root { --bg:#1e1e1e; --card:#232323; --ink:#eaeaea; --muted:#9aa0a6; --ok:#80e27e; --bad:#ef5350; --btn:#0e639c; }
  html,body { background:var(--bg); color:var(--ink); font-family: system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Arial; }
  .wrap { padding: 16px; max-width: 980px; }
  h1 { margin: 0 0 16px; }
  .grid { display:grid; grid-template-columns: repeat(auto-fit, minmax(280px,1fr)); gap:16px; }
  .card { background:var(--card); border:1px solid #333; border-radius:12px; padding:14px; }
  .title { font-weight:700; margin-bottom:6px; }
  .row { display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
  .btn { background:var(--btn); color:#fff; border:none; border-radius:8px; padding:8px 10px; cursor:pointer; }
  .muted { color:var(--muted); font-size:12px; }
  input, select { width:100%; background:#121212; color:#eee; border:1px solid #2a2a2a; border-radius:8px; padding:8px; }
  .ok { color: var(--ok); font-weight:600; }
  .bad { color: var(--bad); font-weight:600; }
  .actions { display:flex; gap:8px; margin-top:10px; flex-wrap:wrap; }
</style>
</head>
<body>
<div class="wrap">
  <h1>VulnScan — Setup Wizard</h1>

  <div class="grid">
    <div class="card">
      <div class="title">1) Semgrep</div>
      <div class="row"><div id="sgStatus" class="muted">Estado: <span>checking…</span></div></div>
      <div class="actions">
        <button id="btnRecheck" class="btn">Recheck</button>
        <button id="btnInstall" class="btn">Instalar via pipx</button>
      </div>
    </div>

    <div class="card">
      <div class="title">2) OpenAI API Key</div>
      <input id="key" type="password" placeholder="sk-..." value="${init.apiKey ? '' : ''}" />
      <div class="actions">
        <button id="btnSaveKey" class="btn">Save</button>
        <button id="btnTestKey" class="btn">Test</button>
      </div>
      <div id="keyStatus" class="muted"></div>
    </div>

    <div class="card">
      <div class="title">3) Preferencias rápidas</div>
      <label class="muted">Minimum severity</label>
      <select id="minSeverity">
        ${['info','low','medium','high','critical'].map(s => `<option value="${s}" ${s===init.minSeverity?'selected':''}>${s}</option>`).join('')}
      </select>
      <label class="muted" style="margin-top:8px; display:block">Target directory</label>
      <select id="targetDirectory">
        ${['auto','root','app'].map(s => `<option value="${s}" ${s===init.targetDirectory?'selected':''}>${s}</option>`).join('')}
      </select>
      <label class="muted" style="margin-top:8px; display:block">Analysis language</label>
      <select id="analysisLang">
        ${['auto','en','es','fr','de','pt','it'].map(s => `<option value="${s}" ${s===init.analysisLang?'selected':''}>${s}</option>`).join('')}
      </select>
      <div class="actions">
        <button id="btnSavePrefs" class="btn">Guardar preferencias</button>
      </div>
    </div>

    <div class="card">
      <div class="title">4) ¡Listo!</div>
      <p class="muted">Pulsa para ejecutar tu primer escaneo del workspace.</p>
      <div class="actions">
        <button id="btnRun" class="btn">Run first scan</button>
        <button id="btnExportMd" class="btn">Export MD</button>
        <button id="btnExportJson" class="btn">Export JSON</button>
      </div>
    </div>
  </div>

  <p class="muted" style="margin-top:12px">También puedes abrir este asistente desde la paleta: “VulnScan: Setup Wizard”.</p>
</div>

<script nonce="${nonce}">
  const vscode = acquireVsCodeApi();

  const $ = (id) => document.getElementById(id);

  function prefs() {
    return {
      minSeverity: $('minSeverity').value,
      targetDirectory: $('targetDirectory').value,
      analysisLang: $('analysisLang').value
    };
  }

  $('btnRecheck').onclick = () => vscode.postMessage({ type: 'recheck' });
  $('btnInstall').onclick = () => vscode.postMessage({ type: 'install' });
  $('btnSaveKey').onclick = () => vscode.postMessage({ type: 'saveKey', key: $('key').value.trim() });
  $('btnTestKey').onclick = () => vscode.postMessage({ type: 'testKey', key: $('key').value.trim() });
  $('btnSavePrefs').onclick = () => vscode.postMessage({ type: 'savePrefs', prefs: prefs() });
  $('btnRun').onclick = () => vscode.postMessage({ type: 'run', prefs: prefs() });
  $('btnExportMd').onclick = () => vscode.postMessage({ type: 'exportMd' });
  $('btnExportJson').onclick = () => vscode.postMessage({ type: 'exportJson' });

  window.addEventListener('message', (e) => {
    const m = e.data;
    if (m.type === 'semgrep:auto') vscode.postMessage({ type: 'recheck' });

    if (m.type === 'semgrep:status') {
      const el = $('sgStatus');
      if (m.state === 'checking') el.innerHTML = 'Estado: <span>checking…</span>';
      else if (m.state === 'ok') el.innerHTML = 'Estado: <span class="ok">Found</span> — <span>' + (m.version || '') + '</span>';
      else el.innerHTML = 'Estado: <span class="bad">Not found</span>';
    }
    if (m.type === 'semgrep:install') {
      const el = $('sgStatus');
      if (m.state === 'running') el.innerHTML = 'Estado: <span>installing…</span>';
      else if (m.state === 'done') el.innerHTML = 'Estado: <span class="ok">Installed</span> — <span>' + (m.version || '') + '</span>';
      else if (m.state === 'error') el.innerHTML = 'Estado: <span class="bad">Install failed</span>';
    }
    if (m.type === 'key:test') {
      $('keyStatus').innerText = m.ok ? 'OK' : ('Error: ' + (m.err||''));
      $('keyStatus').className = m.ok ? 'ok' : 'bad';
    }
    if (m.type === 'key:saved') {
      $('key').value = '';
    }
  });
</script>
</body>
</html>`;
}
