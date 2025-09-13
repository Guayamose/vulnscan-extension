import * as vscode from 'vscode';
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';
import dotenv from 'dotenv';

import { runSemgrepOnFiles } from './scanners/semgrep.js';
import { fromSemgrep, Finding } from './normalize.js';
import { getSnippet } from './snippet.js';
import { publishFindings, clearDiagnostics } from './diagnostics.js';
import { enrichFinding } from './openai/enrich.js';
import { openSecurityReport, UIItem } from './report.js';

const SEMGREP_CONFIGS = ['p/owasp-top-ten']; // añade 'p/ruby' si quieres más señal en models
const BATCH_SIZE = 60;                        // archivos por lote
const ALLOWED_EXT = new Set(['.rb', '.py', '.js', '.jsx', '.ts', '.tsx']);
const DEFAULT_EXCLUDES = [
  'node_modules', 'vendor', 'tmp', 'log', 'public',
  'storage', 'dist', 'build', 'coverage', '.git'
];

export function activate(ctx: vscode.ExtensionContext) {
  console.log('[vulnscan] activated');

  // Cargar .env desde la carpeta de la extensión (no desde el workspace abierto)
  try {
    const envPath = path.join(ctx.extensionPath, '.env');
    if (fs.existsSync(envPath)) dotenv.config({ path: envPath });
  } catch {}

  const hasKey = !!process.env.OPENAI_API_KEY;
  if (!hasKey) {
    vscode.window.showWarningMessage('VulnScan: OPENAI_API_KEY no configurada — se omite la capa IA.');
  }

  const scanCmd = vscode.commands.registerCommand('sec.scan', async () => {
    const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
    if (!workspaceRoot) { return vscode.window.showErrorMessage('Open a folder first.'); }

    // Preferir app/ si existe (común en Rails); si no, la raíz
    const appDir = path.join(workspaceRoot, 'app');
    const targetRoot = fs.existsSync(appDir) ? appDir : workspaceRoot;

    await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: `VulnScan: scanning ${path.basename(targetRoot)}/ …`,
        cancellable: true
      },
      async (progress, token) => {
        try {
          clearDiagnostics();
          progress.report({ message: 'indexing files…', increment: 0 });

          // 1) Enumerar archivos objetivo (respetando excludes) y filtrar por extensión
          const allFiles = await enumerateFiles(targetRoot, DEFAULT_EXCLUDES, token);
          const targetFiles = allFiles.filter(f => ALLOWED_EXT.has(path.extname(f)));
          if (token.isCancellationRequested) return;

          if (targetFiles.length === 0) {
            vscode.window.showInformationMessage('VulnScan: no target files found.');
            return;
          }

          // 2) Escanear por lotes con progreso real
          const findings: Finding[] = [];
          const total = targetFiles.length;
          let done = 0;

          for (let i = 0; i < total; i += BATCH_SIZE) {
            if (token.isCancellationRequested) break;

            const batch = targetFiles.slice(i, i + BATCH_SIZE);
            const aborter = new AbortController();
            token.onCancellationRequested(() => aborter.abort());

            progress.report({ message: `scanning ${done}/${total}…` });

            const raw = await runSemgrepOnFiles(batch, SEMGREP_CONFIGS, { timeoutSec: 60, signal: aborter.signal });
            const mapped: Finding[] = raw.map(fromSemgrep);

            // Preparar snippets y publicar incrementales
            for (const f of mapped) {
              f.snippet = await getSnippet(f.file, f.range);
              findings.push(f);
            }
            publishFindings(findings);

            done += batch.length;
            const pct = Math.min(100, Math.round((done / total) * 100));
            progress.report({ message: `scanned ${done}/${total} files`, increment: pct });
          }

          // 3) Enriquecimiento IA (opcional) + construir datos para el reporte
          const reportItems: UIItem[] = [];
          const out = vscode.window.createOutputChannel('Security');
          out.clear();
          out.appendLine(`Findings: ${findings.length}`);

          if (hasKey && findings.length > 0 && !token.isCancellationRequested) {
            for (let i = 0; i < findings.length; i++) {
              if (token.isCancellationRequested) break;
              const f = findings[i];
              const loc = `${f.file}:${f.range.start.line + 1}`;
              out.appendLine(`\n[${i + 1}/${findings.length}] Enriching ${f.ruleId} @ ${loc} …`);
              try {
                const enriched = await enrichFinding(detectLang(f.file), f);
                out.appendLine(enriched?.explanation_md || '(no explanation)');

                reportItems.push({
                  fingerprint: f.fingerprint,
                  ruleId: f.ruleId,
                  severity: f.severity,
                  file: f.file,
                  relFile: vscode.workspace.asRelativePath(f.file),
                  range: f.range,
                  message: f.message,
                  cwe: enriched?.cwe ?? f.cwe ?? null,
                  owasp: enriched?.owasp ?? f.owasp ?? null,
                  snippet: f.snippet,
                  explanation_md: enriched?.explanation_md ?? '',
                  unified_diff: enriched?.fix?.unified_diff ?? null
                });
              } catch (e: any) {
                out.appendLine(`❌ AI enrich error: ${e?.message || e}`);
                reportItems.push({
                  fingerprint: f.fingerprint,
                  ruleId: f.ruleId,
                  severity: f.severity,
                  file: f.file,
                  relFile: vscode.workspace.asRelativePath(f.file),
                  range: f.range,
                  message: f.message,
                  cwe: f.cwe ?? null,
                  owasp: f.owasp ?? null,
                  snippet: f.snippet,
                  explanation_md: '',
                  unified_diff: null
                });
              }
            }
            out.show(true);
          } else {
            // sin IA: solo datos básicos
            for (const f of findings) {
              reportItems.push({
                fingerprint: f.fingerprint,
                ruleId: f.ruleId,
                severity: f.severity,
                file: f.file,
                relFile: vscode.workspace.asRelativePath(f.file),
                range: f.range,
                message: f.message,
                cwe: f.cwe ?? null,
                owasp: f.owasp ?? null,
                snippet: f.snippet,
                explanation_md: '',
                unified_diff: null
              });
            }
          }

          // 4) Abrir reporte visual (webview)
          if (!token.isCancellationRequested) {
            openSecurityReport(ctx, workspaceRoot, reportItems);
            vscode.window.showInformationMessage(`VulnScan: done (${findings.length} findings).`);
          } else {
            vscode.window.showWarningMessage('VulnScan: cancelled.');
          }
        } catch (e: any) {
          vscode.window.showErrorMessage(`Scan failed: ${e?.message || e}`);
        }
      }
    );
  });

  ctx.subscriptions.push(scanCmd);
}

function detectLang(file: string) {
  if (file.endsWith('.rb')) return 'ruby';
  if (file.endsWith('.py')) return 'python';
  if (file.endsWith('.ts') || file.endsWith('.tsx')) return 'typescript';
  if (file.endsWith('.js') || file.endsWith('.jsx')) return 'javascript';
  return 'unknown';
}

// Recorrido recursivo con excludes, cancelable
async function enumerateFiles(root: string, excludes: string[], token: vscode.CancellationToken): Promise<string[]> {
  const files: string[] = [];
  const skipWithinRoot = new Set(excludes.map(e => path.resolve(root, e)));

  async function walk(dir: string) {
    if (token.isCancellationRequested) return;
    let entries: fs.Dirent[];
    try {
      entries = await fsp.readdir(dir, { withFileTypes: true });
    } catch {
      return; // permisos o enlaces rotos
    }
    for (const ent of entries) {
      if (token.isCancellationRequested) return;
      const p = path.join(dir, ent.name);
      if (ent.isDirectory()) {
        if (skipWithinRoot.has(p)) continue;
        await walk(p);
      } else {
        files.push(p);
      }
    }
  }

  await walk(root);
  return files;
}

export function deactivate() {}
