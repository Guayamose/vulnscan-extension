// src/ui/authView.ts
import * as vscode from 'vscode';
import { AuthManager } from '../auth/auth-manager';

type Me = { sub?: number|string|null; user_id?: number|string|null; org?: string|null; role?: string|null; scope?: string|null };

export class AuthViewProvider implements vscode.WebviewViewProvider {
  public static readonly viewId = 'oryon.authView';

  constructor(private ctx: vscode.ExtensionContext, private auth: AuthManager) {}

  resolveWebviewView(webviewView: vscode.WebviewView) {
    const webview = webviewView.webview;
    webview.options = { enableScripts: true };
    webview.html = this.renderHtml();

    const pushState = async () => {
      try {
        const me = await this.auth.whoami();
        const loggedIn = !!(me && (me.sub ?? (me as any).user_id));
        await vscode.commands.executeCommand('setContext', 'oryon:isLoggedIn', loggedIn);
        const cfg = vscode.workspace.getConfiguration('oryon');
        const payload = {
          me,
          cfg: {
            baseUrl:        cfg.get<string>('backend.baseUrl'),
            targetDirectory:cfg.get<string>('targetDirectory'),
            minSeverity:    cfg.get<string>('minSeverity'),
            batchSize:      cfg.get<number>('batchSize'),
            timeoutSec:     cfg.get<number>('timeoutSec'),
            maxFileSizeKb:  cfg.get<number>('scan.maxFileSizeKb'),
            excludeGlobs:   cfg.get<string[]>('scan.excludeGlobs'),
            allowedExtensions: cfg.get<string[]>('allowedExtensions'),
            semgrepBin:     cfg.get<string>('semgrepBin'),
            autoScanOnSave: cfg.get<boolean>('autoScanOnSave'),
            semgrepConfigs: cfg.get<string[]>('semgrep.configs')
          }
        };
        webview.postMessage({ type: 'state', payload });
        if (loggedIn) {
          // abre Results en cuanto te logueas
          vscode.commands.executeCommand('workbench.view.extension.oryon');
          vscode.commands.executeCommand('workbench.view.extension.oryon.resultsView');
        }
      } catch (e: any) {
        await vscode.commands.executeCommand('setContext', 'oryon:isLoggedIn', false);
        webview.postMessage({ type: 'state', payload: { me: {}, cfg: {} } });
      }
    };

    webview.onDidReceiveMessage(async (msg) => {
      try {
        switch (msg?.type) {
          case 'login': {
            await this.auth.login(msg.username, msg.password);
            vscode.window.showInformationMessage('Sesión iniciada.');
            await pushState();
            break;
          }
          case 'logout': {
            await this.auth.logout();
            vscode.window.showInformationMessage('Sesión cerrada.');
            await pushState();
            break;
          }
          case 'whoami': await pushState(); break;
          case 'openSettings': await vscode.commands.executeCommand('workbench.action.openSettings', 'oryon'); break;
          case 'saveQuickConfig': {
            const cfg = vscode.workspace.getConfiguration('oryon');
            const w = vscode.ConfigurationTarget.Workspace;
            const p = msg.payload || {};
            if (p.baseUrl        != null) await cfg.update('backend.baseUrl',      String(p.baseUrl),        w);
            if (p.targetDirectory!= null) await cfg.update('targetDirectory',     String(p.targetDirectory), w);
            if (p.minSeverity    != null) await cfg.update('minSeverity',         String(p.minSeverity),     w);
            if (p.batchSize      != null) await cfg.update('batchSize',           Number(p.batchSize),       w);
            if (p.timeoutSec     != null) await cfg.update('timeoutSec',          Number(p.timeoutSec),      w);
            if (p.maxFileSizeKb  != null) await cfg.update('scan.maxFileSizeKb',  Number(p.maxFileSizeKb),   w);
            if (p.excludeGlobs   != null) await cfg.update('scan.excludeGlobs',   p.excludeGlobs,            w);
            if (p.allowedExtensions != null) await cfg.update('allowedExtensions', p.allowedExtensions,      w);
            if (p.semgrepBin     != null) await cfg.update('semgrepBin',          String(p.semgrepBin),      w);
            if (p.autoScanOnSave != null) await cfg.update('autoScanOnSave',      !!p.autoScanOnSave,        w);
            vscode.window.showInformationMessage('Oryon: configuración guardada en este workspace.');
            await pushState();
            break;
          }
          case 'scanWorkspace': await vscode.commands.executeCommand('sec.scan'); break;
        }
      } catch (e: any) {
        webview.postMessage({ type: 'error', payload: e?.message || String(e) });
        vscode.window.showErrorMessage('Oryon: ' + (e?.message || e));
      }
    });

    pushState();
  }

    private renderHtml(): string {
    const nonce = String(Math.random()).slice(2);
    const csp = [
      "default-src 'none'",
      "img-src https: data:",
      "style-src 'unsafe-inline'",
      `script-src 'nonce-${nonce}'`,
    ].join(';');

    return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta http-equiv="Content-Security-Policy" content="${csp}">
  <style>
    :root { --gap: 8px; }
    body { font-family: var(--vscode-font-family); padding: 10px; }
    h3 { margin: 0 0 10px; }
    h4 { margin: 16px 0 8px; }
    .row { margin-bottom: var(--gap); }
    input, select, textarea { width: 100%; padding: 6px; }
    button { padding: 6px 10px; }
    .muted { opacity: .8; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono','Courier New', monospace; }
    .box { border: 1px solid var(--vscode-editorWidget-border); padding: 10px; border-radius: 6px; }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: var(--gap); }
    .grid .cell { display: flex; flex-direction: column; gap: 6px; }
    .cta { display: flex; gap: 8px; align-items: center; }
    .tag { display:inline-block; padding:2px 6px; border:1px solid var(--vscode-editorWidget-border); border-radius:999px; margin:2px 4px 0 0; font-size: 12px; }
    .list { max-height: 96px; overflow:auto; border:1px dashed var(--vscode-editorWidget-border); padding:6px; border-radius:6px; }
    .sep { height:1px; background: var(--vscode-editorWidget-border); margin:10px 0; }
    .center { display:flex; align-items:center; gap:8px; }
  </style>
</head>
<body>
  <h3>Oryon — Login / Setup</h3>

  <div class="box" id="statusBox">
    <div><strong>Usuario:</strong> <span id="user">desconocido</span></div>
    <div><strong>Org:</strong> <span id="org" class="mono">n/a</span></div>
    <div><strong>Role:</strong> <span id="role">n/a</span></div>
    <div class="row muted mono" id="raw"></div>
    <div class="row">
      <button id="refresh">Who am I</button>
      <button id="logout">Logout</button>
    </div>
  </div>

  <h4 id="loginTitle">Login</h4>
  <div class="box" id="loginBox">
    <div class="row"><input id="email" type="text" placeholder="email / username" /></div>
    <div class="row"><input id="password" type="password" placeholder="password" /></div>
    <div class="row"><button id="login">Login</button></div>
  </div>

  <h4 id="wizTitle" style="display:none;">Setup wizard</h4>
  <div class="box" id="wizBox" style="display:none;">
    <div class="grid">
      <div class="cell">
        <label>Backend Base URL</label>
        <input id="cfg_baseUrl" type="text" />
      </div>
      <div class="cell">
        <label>Target directory</label>
        <select id="cfg_targetDirectory">
          <option value="auto">auto</option>
          <option value="app">app</option>
          <option value="root">root</option>
        </select>
      </div>

      <div class="cell">
        <label>Min severity</label>
        <select id="cfg_minSeverity">
          <option value="info">info</option>
          <option value="low">low</option>
          <option value="medium">medium</option>
          <option value="high">high</option>
          <option value="critical">critical</option>
        </select>
      </div>
      <div class="cell">
        <label>Timeout (s)</label>
        <input id="cfg_timeoutSec" type="number" min="10" />
      </div>

      <div class="cell">
        <label>Batch size</label>
        <input id="cfg_batchSize" type="number" min="10" />
      </div>
      <div class="cell">
        <label>Max file size (KB)</label>
        <input id="cfg_maxFileSizeKb" type="number" min="1" />
      </div>

      <div class="cell">
        <label>Allowed extensions (coma/separadas)</label>
        <input id="cfg_allowedExtensions" type="text" placeholder=".rb,.py,.js,.jsx,.ts,.tsx" />
      </div>
      <div class="cell">
        <label>Exclude globs (uno por línea)</label>
        <textarea id="cfg_excludeGlobs" rows="4" class="mono"></textarea>
      </div>

      <div class="cell">
        <label>Semgrep bin (opcional)</label>
        <input id="cfg_semgrepBin" type="text" placeholder="/ruta/a/semgrep" />
      </div>
      <div class="cell center">
        <input id="cfg_autoScanOnSave" type="checkbox" />
        <label for="cfg_autoScanOnSave">Live scan al guardar (autoScanOnSave)</label>
      </div>
    </div>

    <div class="sep"></div>

    <div class="row">
      <div class="muted">Semgrep configs (solo lectura, se mantienen tal cual):</div>
      <div id="cfg_semgrepConfigs" class="list mono"></div>
    </div>

    <div class="row cta">
      <button id="save">Guardar</button>
      <button id="openSettings">Abrir configuración completa</button>
      <div style="flex:1"></div>
      <button id="scanNow">Scan Workspace</button>
    </div>
  </div>

  <script nonce="${nonce}">
    const vscode = acquireVsCodeApi();
    const loginBtn = document.getElementById('login');
    const emailEl  = document.getElementById('email');
    const passEl   = document.getElementById('password');

    function setText(id, v) { const el = document.getElementById(id); if (el) el.textContent = v ?? ''; }

    function fillCfg(cfg) {
      document.getElementById('cfg_baseUrl').value         = cfg?.baseUrl ?? '';
      document.getElementById('cfg_targetDirectory').value = cfg?.targetDirectory ?? 'auto';
      document.getElementById('cfg_minSeverity').value     = cfg?.minSeverity ?? 'low';
      document.getElementById('cfg_batchSize').value       = cfg?.batchSize ?? 60;
      document.getElementById('cfg_timeoutSec').value      = cfg?.timeoutSec ?? 60;
      document.getElementById('cfg_maxFileSizeKb').value   = cfg?.maxFileSizeKb ?? 1024;
      document.getElementById('cfg_allowedExtensions').value = (cfg?.allowedExtensions ?? []).join(',');
      document.getElementById('cfg_excludeGlobs').value    = (cfg?.excludeGlobs ?? []).join('\\n');
      document.getElementById('cfg_semgrepBin').value      = cfg?.semgrepBin ?? '';
      document.getElementById('cfg_autoScanOnSave').checked = !!cfg?.autoScanOnSave;
      const list = document.getElementById('cfg_semgrepConfigs');
      list.innerHTML = '';
      (cfg?.semgrepConfigs ?? []).forEach(x => {
        const span = document.createElement('span'); span.className = 'tag'; span.textContent = x; list.appendChild(span);
      });
    }

    function updateUI(payload) {
      const me = payload?.me || {};
      const cfg = payload?.cfg || {};

      const user = (me && (me.sub ?? me.user_id)) ? (me.sub ?? me.user_id) : 'desconocido';
      setText('user', String(user));
      setText('org',  me?.org ?? 'n/a');
      setText('role', me?.role ?? me?.scope ?? 'n/a');
      setText('raw',  JSON.stringify(me || {}));

      const loggedIn = !!(me && (me.sub ?? me.user_id));
      document.getElementById('loginTitle').style.display = loggedIn ? 'none' : '';
      document.getElementById('loginBox').style.display   = loggedIn ? 'none' : '';
      document.getElementById('wizTitle').style.display   = loggedIn ? '' : 'none';
      document.getElementById('wizBox').style.display     = loggedIn ? '' : 'none';

      if (loggedIn) fillCfg(cfg);
    }

    window.addEventListener('message', (e) => {
      const msg = e.data;
      if (msg?.type === 'state') updateUI(msg.payload);
      if (msg?.type === 'state' || msg?.type === 'error') {
        loginBtn.disabled = false; loginBtn.textContent = 'Login';
      }
    });

    function doLogin() {
      const username = emailEl.value;
      const password = passEl.value;
      loginBtn.disabled = true; loginBtn.textContent = 'Accediendo…';
      vscode.postMessage({ type: 'login', username, password });
    }

    loginBtn.addEventListener('click', doLogin);
    passEl.addEventListener('keydown', (e) => { if (e.key === 'Enter') doLogin(); });

    document.getElementById('logout').addEventListener('click', () => vscode.postMessage({ type: 'logout' }));
    document.getElementById('refresh').addEventListener('click', () => vscode.postMessage({ type: 'whoami' }));

    document.getElementById('openSettings').addEventListener('click', () => vscode.postMessage({ type: 'openSettings' }));

    document.getElementById('save').addEventListener('click', () => {
      const payload = {
        baseUrl:        document.getElementById('cfg_baseUrl').value,
        targetDirectory:document.getElementById('cfg_targetDirectory').value,
        minSeverity:    document.getElementById('cfg_minSeverity').value,
        batchSize:      Number(document.getElementById('cfg_batchSize').value),
        timeoutSec:     Number(document.getElementById('cfg_timeoutSec').value),
        maxFileSizeKb:  Number(document.getElementById('cfg_maxFileSizeKb').value),
        allowedExtensions: document.getElementById('cfg_allowedExtensions').value.split(',').map(s => s.trim()).filter(Boolean),
        excludeGlobs:   document.getElementById('cfg_excludeGlobs').value.split('\\n').map(s => s.trim()).filter(Boolean),
        semgrepBin:     document.getElementById('cfg_semgrepBin').value,
        autoScanOnSave: document.getElementById('cfg_autoScanOnSave').checked
      };
      vscode.postMessage({ type: 'saveQuickConfig', payload });
    });

    document.getElementById('scanNow').addEventListener('click', () => {
      vscode.postMessage({ type: 'scanWorkspace' });
    });

    vscode.postMessage({ type: 'whoami' });
  </script>
</body>
</html>`;
  }

}
