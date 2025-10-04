// src/extension.ts
import * as vscode from 'vscode';
import { runSemgrepOnFiles } from './scanners/semgrep';
import { fromSemgrep, Finding } from './normalize';
import { publishFindings, clearDiagnostics } from './diagnostics';
import { AuthManager } from './auth/auth-manager';
import { OryonApi } from './auth/api';
import { Uploader } from './ingest/uploader';
import { LiveScanner } from './live/live-scanner';
import { runSetupWizard } from './setup';
import { AuthViewProvider } from './ui/authView';
import { ResultsViewProvider } from './ui/resultsView';

export async function activate(context: vscode.ExtensionContext) {
  const out = vscode.window.createOutputChannel('Oryon');
  context.subscriptions.push(out);
  out.appendLine('[oryon] activate()');

  try {
    const cfg = vscode.workspace.getConfiguration('oryon');
    const baseUrl =
      (cfg.get('backend.baseUrl') as string) ??
      'https://vulnscan-mock-df9c85d690d0.herokuapp.com';

    // ⚠️ IMPORTANTE: crear AuthManager y REGISTRAR VISTAS ANTES DE CUALQUIER await
    const auth = new AuthManager(context, baseUrl);

    // 1) Registrar vistas inmediatamente (sin esperar a init)
    const authProvider = new AuthViewProvider(context, auth);
    context.subscriptions.push(
      vscode.window.registerWebviewViewProvider(AuthViewProvider.viewId, authProvider)
    );

    const resultsProvider = new ResultsViewProvider(context);
    context.subscriptions.push(
      vscode.window.registerWebviewViewProvider(ResultsViewProvider.viewId, resultsProvider)
    );
    out.appendLine('[oryon] webview providers registered');

    // 2) Lanzar init en background (no bloquear el registro de vistas)
    auth.init().catch((e: any) => {
      out.appendLine('[oryon] auth.init() failed: ' + (e?.message || e));
      vscode.commands.executeCommand('setContext', 'oryon:isLoggedIn', false);
    });

    // Helper: requiere login
    function requireAuth<T extends any[]>(fn: (...a: T) => any) {
      return async (...a: T) => {
        if (!(await auth.isLoggedIn())) {
          vscode.window.showWarningMessage(
            'Debes iniciar sesión en el panel Oryon (barra lateral) para usar estas funciones.'
          );
          await vscode.commands.executeCommand('workbench.view.extension.oryon');
          return;
        }
        return fn(...a);
      };
    }

    async function pickTargetFolder(): Promise<vscode.Uri | null> {
      const mode = (cfg.get('targetDirectory') as 'auto' | 'app' | 'root') ?? 'auto';
      const ws = vscode.workspace.workspaceFolders?.[0];
      if (!ws) return null;
      if (mode === 'root') return ws.uri;
      if (mode === 'app') return vscode.Uri.joinPath(ws.uri, 'app');
      const app = vscode.Uri.joinPath(ws.uri, 'app');
      try { const stat = await vscode.workspace.fs.stat(app); if (stat) return app; } catch {}
      return ws.uri;
    }

    async function collectFiles(root: vscode.Uri): Promise<string[]> {
      const allowed = new Set(((cfg.get('allowedExtensions') as string[]) ?? ['.rb','.py','.js','.jsx','.ts','.tsx']).map(s => s.toLowerCase()));
      const excludes = (cfg.get('scan.excludeGlobs') as string[]) ?? [];
      const maxKb = (cfg.get('scan.maxFileSizeKb') as number) ?? 1024;

      const files = await vscode.workspace.findFiles(
        new vscode.RelativePattern(root, '**/*'),
        excludes.length ? `{${excludes.join(',')}}` : undefined
      );

      const kept: string[] = [];
      for (const u of files) {
        const path = u.fsPath;
        const dot = path.lastIndexOf('.');
        const ext = (dot >= 0 ? path.slice(dot) : '').toLowerCase();
        if (!allowed.has(ext)) continue;
        try {
          const stat = await vscode.workspace.fs.stat(u);
          if (stat.size > maxKb * 1024) continue;
          kept.push(path);
        } catch {}
      }
      return kept;
    }

    async function scanWorkspaceAndUpload() {
      clearDiagnostics();

      const target = await pickTargetFolder();
      if (!target) { vscode.window.showWarningMessage('No hay workspace abierto.'); return; }

      const files = await collectFiles(target);
      if (!files.length) {
        vscode.window.showInformationMessage('No hay archivos que coincidan con los filtros.');
        return;
      }

      const startedAt = new Date();
      const configs = (cfg.get('semgrep.configs') as string[]) ?? ['p/owasp-top-ten', 'p/secrets'];
      const timeoutSec = (cfg.get('timeoutSec') as number) ?? 60;
      const batchSize  = (cfg.get('batchSize')  as number) ?? 60;

      const results: any[] = [];
      for (let i = 0; i < files.length; i += batchSize) {
        const chunk = files.slice(i, i + batchSize);
        const r = await runSemgrepOnFiles(chunk, configs, {
          timeoutSec,
          onDebug: m => out.appendLine(m)
        });
        results.push(...r);
        vscode.window.setStatusBarMessage(
          `Oryon: Analizando… ${Math.min(i + batchSize, files.length)}/${files.length}`,
          1500
        );
      }

      const findings: Finding[] = results.map(fromSemgrep);
      publishFindings(findings);

      const access = await auth.getAccessToken();
      if (!access) {
        const dbg = await auth.debugTokens();
        out.appendLine('No access token; estado: ' + JSON.stringify(dbg));
        vscode.window.showWarningMessage('Resultados listos. Inicia sesión para subirlos.');
        return;
      }

      let org = 'org_unknown';
      let userRef: string | number = 'user_unknown';
      try {
        const me = await auth.whoami();
        org = me?.org ?? org;
        userRef = (me?.sub as any) ?? userRef;
      } catch (e: any) {
        out.appendLine('whoami durante upload falló: ' + (e?.message || e));
      }

      const api = new OryonApi(baseUrl);
      const uploader = new Uploader(api, access);
      const finishedAt = new Date();
      const idem = OryonApi.newIdemKey();

      const scanPayload = {
        org,
        user_ref: userRef,
        project_slug: vscode.workspace.workspaceFolders?.[0]?.name || 'workspace',
        scan_type: 'workspace' as const,
        started_at: startedAt.toISOString().replace(/\.\d{3}Z$/, 'Z'),
        finished_at: finishedAt.toISOString().replace(/\.\d{3}Z$/, 'Z'),
        findings_ingested: findings.length,
        deduped: 0,
        status: 'completed' as const,
        idempotency_key: idem
      };

      try {
        const { id: scanId } = await uploader.createOrUpdateScan(scanPayload, idem);
        await uploader.uploadFindings(scanId, findings);
        vscode.window.showInformationMessage(`Oryon: Scan subido (${findings.length} findings).`);
      } catch (e: any) {
        out.appendLine('Upload FAILED: ' + (e?.message || e));
        vscode.window.showErrorMessage(`Error subiendo a la plataforma: ${e?.message || e}`);
      }
    }

    // Comandos
    context.subscriptions.push(
      vscode.commands.registerCommand('oryon.login', async () => {
        const username = await vscode.window.showInputBox({ prompt: 'Email/username' }); if (!username) return;
        const password = await vscode.window.showInputBox({ prompt: 'Password', password: true }); if (!password) return;
        try { await auth.login(username, password); vscode.window.showInformationMessage('Sesión iniciada.'); }
        catch (e: any) { vscode.window.showErrorMessage('Login failed: ' + (e?.message || e)); }
      }),
      vscode.commands.registerCommand('oryon.logout', async () => { await auth.logout(); vscode.window.showInformationMessage('Sesión cerrada.'); }),
      vscode.commands.registerCommand('oryon.whoami', async () => {
        const me = await auth.whoami();
        vscode.window.showInformationMessage('Conectado como: ' + JSON.stringify(me));
      }),

      vscode.commands.registerCommand('sec.scan', requireAuth(scanWorkspaceAndUpload)),
      vscode.commands.registerCommand('sec.exportReport', requireAuth(() => vscode.window.showInformationMessage('Export report TODO'))),
      vscode.commands.registerCommand('sec.toggleSeverity', requireAuth(() => vscode.window.showInformationMessage('Toggle severity TODO'))),
      vscode.commands.registerCommand('sec.setup', async () => { await runSetupWizard(context, auth, out); })
    );

    // Live scanner (siempre activo)
    const live = new LiveScanner({
      configs: (cfg.get('semgrep.configs') as string[]) ?? ['p/owasp-top-ten', 'p/secrets'],
      timeoutSec: (cfg.get('timeoutSec') as number) ?? 60,
      onDebug: (m) => out.appendLine(m)
    });
    live.bind(context);

    out.appendLine('[oryon] activate() done');
  } catch (e: any) {
    console.error('[oryon] activate() failed:', e?.message || e);
    vscode.window.showErrorMessage('Oryon: error durante la activación. Revisa la Consola del Desarrollador.');
  }
}

export function deactivate() { clearDiagnostics(); }
