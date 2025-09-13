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
import { openSecurityReport, UIItem, renderMarkdown } from './report.js';

const SEV_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 } as const;

let lastReportItems: UIItem[] = [];

export function activate(ctx: vscode.ExtensionContext) {
  console.log('[vulnscan] activated');

  // .env desde la carpeta de la extensión
  try {
    const envPath = path.join(ctx.extensionPath, '.env');
    if (fs.existsSync(envPath)) dotenv.config({ path: envPath });
  } catch {}

  const hasKey = !!process.env.OPENAI_API_KEY;
  if (!hasKey) {
    vscode.window.showWarningMessage('VulnScan: OPENAI_API_KEY no configurada — se omite la capa IA.');
  }

  // Comando principal
  const scanCmd = vscode.commands.registerCommand('sec.scan', async () => {
    const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
    if (!workspaceRoot) { return vscode.window.showErrorMessage('Open a folder first.'); }

    // Carga de settings
    const cfg = vscode.workspace.getConfiguration('vulnscan');
    const targetDirectory = cfg.get<string>('targetDirectory', 'auto');
    const minSeverity = cfg.get<'info'|'low'|'medium'|'high'|'critical'>('minSeverity', 'low');
    const semgrepConfigs = cfg.get<string[]>('semgrep.configs', ['p/owasp-top-ten', 'p/ruby']);
    const batchSize = Math.max(10, cfg.get<number>('batchSize', 60));
    const timeoutSec = Math.max(10, cfg.get<number>('timeoutSec', 60));
    const allowedExtensions = new Set(cfg.get<string[]>('allowedExtensions', [".rb", ".py", ".js", ".jsx", ".ts", ".tsx"]));
    const enrichConcurrency = Math.min(8, Math.max(1, cfg.get<number>('enrich.concurrency', 3)));

    // Dir objetivo
    const appDir = path.join(workspaceRoot, 'app');
    const targetRoot =
      targetDirectory === 'app' ? appDir :
      targetDirectory === 'root' ? workspaceRoot :
      (fs.existsSync(appDir) ? appDir : workspaceRoot);

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

          // 1) Enumerar archivos y filtrar por extensión
          const allFiles = await enumerateFiles(targetRoot, defaultExcludes(), token);
          const targetFiles = allFiles.filter(f => allowedExtensions.has(path.extname(f)));
          if (token.isCancellationRequested) return;

          if (targetFiles.length === 0) {
            vscode.window.showInformationMessage('VulnScan: no target files found.');
            return;
          }

          // 2) Escanear por lotes con progreso real
          const findingsRaw: any[] = [];
          const total = targetFiles.length;
          let done = 0;

          for (let i = 0; i < total; i += batchSize) {
            if (token.isCancellationRequested) break;

            const batch = targetFiles.slice(i, i + batchSize);
            const aborter = new AbortController();
            token.onCancellationRequested(() => aborter.abort());

            progress.report({ message: `scanning ${done}/${total}…` });

            const raw = await runSemgrepOnFiles(batch, semgrepConfigs, { timeoutSec, signal: aborter.signal });
            findingsRaw.push(...raw);

            done += batch.length;
            const pct = Math.min(100, Math.round((done / total) * 100));
            progress.report({ message: `scanned ${done}/${total} files`, increment: pct });
          }

          // 3) Normalizar, filtrar por severidad mínima y publicar diagnostics
          const mapped: Finding[] = findingsRaw.map(fromSemgrep);
          const findings = mapped.filter(f => SEV_RANK[f.severity] >= SEV_RANK[minSeverity]);
          for (const f of findings) { f.snippet = await getSnippet(f.file, f.range); }
          publishFindings(findings);

          // 4) Enriquecimiento (concurrencia limitada) + preparar reporte
          const out = vscode.window.createOutputChannel('Security');
          out.clear();
          out.appendLine(`Findings (>= ${minSeverity}): ${findings.length}`);

          const reportItems: UIItem[] = [];

          if (hasKey && findings.length > 0 && !token.isCancellationRequested) {
            await pLimit(enrichConcurrency, findings.map((f, idx) => async () => {
              if (token.isCancellationRequested) return;
              const loc = `${f.file}:${f.range.start.line + 1}`;
              out.appendLine(`\n[${idx + 1}/${findings.length}] Enriching ${f.ruleId} @ ${loc} …`);
              try {
                const enriched = await enrichFinding(detectLang(f.file), f);
                out.appendLine(enriched?.explanation_md || '(no explanation)');
                reportItems.push(toUIItem(f, enriched?.explanation_md ?? '', enriched?.fix?.unified_diff ?? null, enriched?.cwe ?? f.cwe, enriched?.owasp ?? f.owasp));
              } catch (e: any) {
                out.appendLine(`❌ AI enrich error: ${e?.message || e}`);
                reportItems.push(toUIItem(f, '', null, f.cwe, f.owasp));
              }
            }));
            out.show(true);
          } else {
            for (const f of findings) reportItems.push(toUIItem(f, '', null, f.cwe, f.owasp));
          }

          // 5) Abrir reporte visual y guardar últimos resultados (para export)
          if (!token.isCancellationRequested) {
            lastReportItems = reportItems.sort((a, b) =>
              a.relFile.localeCompare(b.relFile) || SEV_RANK[b.severity] - SEV_RANK[a.severity]
            );
            openSecurityReport(ctx, workspaceRoot, lastReportItems);
            vscode.window.showInformationMessage(`VulnScan: done (${findings.length} findings >= ${minSeverity}).`);
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

  // Comando de export a Markdown
  const exportCmd = vscode.commands.registerCommand('sec.exportReport', async () => {
    if (!lastReportItems.length) {
      return vscode.window.showWarningMessage('No hay un reporte reciente para exportar. Ejecuta "Security: Scan Workspace" primero.');
    }
    const uri = await vscode.window.showSaveDialog({
      filters: { Markdown: ['md'] },
      saveLabel: 'Export'
    });
    if (!uri) return;
    const md = renderMarkdown(lastReportItems);
    await vscode.workspace.fs.writeFile(uri, Buffer.from(md, 'utf8'));
    vscode.window.showInformationMessage(`Reporte exportado a ${uri.fsPath}`);
  });
  ctx.subscriptions.push(exportCmd);
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
      return;
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

function defaultExcludes() {
  return ['node_modules', 'vendor', 'tmp', 'log', 'public', 'storage', 'dist', 'build', 'coverage', '.git'];
}

// Concurrencia limitada estilo p-limit
async function pLimit<T>(limit: number, tasks: Array<() => Promise<T>>): Promise<void> {
  let i = 0;
  const workers = Array.from({ length: Math.min(limit, tasks.length) }, async () => {
    while (i < tasks.length) {
      const idx = i++;
      await tasks[idx]();
    }
  });
  await Promise.all(workers);
}

function toUIItem(
  f: Finding,
  explanation_md: string,
  unified_diff: string|null,
  cwe?: string|null,
  owasp?: string|null
): UIItem {
  return {
    fingerprint: f.fingerprint,
    ruleId: f.ruleId,
    severity: f.severity,
    file: f.file,
    relFile: vscode.workspace.asRelativePath(f.file),
    range: f.range,
    message: f.message,
    cwe: cwe ?? null,
    owasp: owasp ?? null,
    snippet: f.snippet,
    explanation_md,
    unified_diff
  };
}

export function deactivate() {}
