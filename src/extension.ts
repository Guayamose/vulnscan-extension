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
import { openSetupWizard } from './setup.js';

const TOKEN_KEY = 'vulnscan/apiKey';
const IGNORED_KEY = 'vulnscan/ignored';
const SEV_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 } as const;

let lastReportItems: UIItem[] = [];
let statusScan: vscode.StatusBarItem;
let statusSev: vscode.StatusBarItem;

export async function activate(ctx: vscode.ExtensionContext) {
  console.log('[vulnscan] activated');

  try {
    const envPath = path.join(ctx.extensionPath, '.env');
    if (fs.existsSync(envPath)) dotenv.config({ path: envPath });
  } catch {}
  const secretKey = await ctx.secrets.get(TOKEN_KEY);
  if (secretKey && !process.env.OPENAI_API_KEY) process.env.OPENAI_API_KEY = secretKey;

  statusScan = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusScan.text = '$(shield) Scan';
  statusScan.tooltip = 'Security: Scan Workspace';
  statusScan.command = 'sec.scan';
  statusScan.show();
  ctx.subscriptions.push(statusScan);

  statusSev = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 99);
  statusSev.command = 'sec.toggleSeverity';
  updateSevStatus();
  statusSev.show();
  ctx.subscriptions.push(statusSev);

  ctx.subscriptions.push(vscode.commands.registerCommand('sec.setup', () => openSetupWizard(ctx)));
  ctx.subscriptions.push(vscode.commands.registerCommand('sec.toggleSeverity', setMinSeverity));
  ctx.subscriptions.push(vscode.commands.registerCommand('sec.exportReport', exportReport));
  ctx.subscriptions.push(vscode.commands.registerCommand('sec.scan', () => scanWorkspace(ctx)));

  const dispSave = vscode.workspace.onDidSaveTextDocument(async () => {
    const cfg = vscode.workspace.getConfiguration('vulnscan');
    if (cfg.get<boolean>('autoScanOnSave', false)) {
      await scanWorkspace(ctx, { silentIfRunning: true });
    }
  });
  ctx.subscriptions.push(dispSave);

  void maybeShowSetup();
}

async function maybeShowSetup() {
  const hasKey = !!process.env.OPENAI_API_KEY;
  if (!hasKey) setTimeout(() => vscode.commands.executeCommand('sec.setup'), 500);
}

async function setMinSeverity() {
  const cfg = vscode.workspace.getConfiguration('vulnscan');
  const current = cfg.get<'info'|'low'|'medium'|'high'|'critical'>('minSeverity', 'low');
  const pick = await vscode.window.showQuickPick(['info','low','medium','high','critical'], {
    title: 'Minimum severity',
    placeHolder: current
  });
  if (!pick) return;
  await cfg.update('minSeverity', pick, vscode.ConfigurationTarget.Workspace);
  updateSevStatus();
}

function updateSevStatus() {
  const cfg = vscode.workspace.getConfiguration('vulnscan');
  const sev = cfg.get<string>('minSeverity', 'low');
  const mapIcon: Record<string,string> = { critical: '$(flame)', high: '$(circle-filled)', medium: '$(warning)', low: '$(info)', info: '$(circle-outline)' };
  statusSev.text = `${mapIcon[sev] || '$(info)'} ${sev}`;
  statusSev.tooltip = 'VulnScan: Set Minimum Severity';
}

async function exportReport() {
  if (!lastReportItems.length) {
    return vscode.window.showWarningMessage('No hay un reporte reciente para exportar. Ejecuta "Security: Scan Workspace" primero.');
  }
  const uri = await vscode.window.showSaveDialog({ filters: { Markdown: ['md'] }, saveLabel: 'Export' });
  if (!uri) return;
  const md = renderMarkdown(lastReportItems);
  await vscode.workspace.fs.writeFile(uri, Buffer.from(md, 'utf8'));
  vscode.window.showInformationMessage(`Reporte exportado a ${uri.fsPath}`);
}

type Sev = 'info'|'low'|'medium'|'high'|'critical';
function normalizeSeverity(s: unknown): Sev {
  const u = String(s ?? '').toUpperCase();
  switch (u) {
    case 'INFO': return 'info';
    case 'WARNING': return 'medium'; // cámbialo a 'low' si lo prefieres
    case 'ERROR': return 'high';
    case 'LOW': return 'low';
    case 'MEDIUM': return 'medium';
    case 'HIGH': return 'high';
    case 'CRITICAL': return 'critical';
    default: return 'info';
  }
}

async function scanWorkspace(ctx: vscode.ExtensionContext, _opts?: { silentIfRunning?: boolean }) {
  const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  if (!workspaceRoot) { return vscode.window.showErrorMessage('Open a folder first.'); }

  const cfg = vscode.workspace.getConfiguration('vulnscan');
  const targetDirectory = cfg.get<string>('targetDirectory', 'auto');
  const minSeverity = cfg.get<'info'|'low'|'medium'|'high'|'critical'>('minSeverity', 'low');
  const semgrepConfigs = cfg.get<string[]>('semgrep.configs', ['p/owasp-top-ten', 'p/ruby']);
  const batchSize = Math.max(10, cfg.get<number>('batchSize', 60));
  const timeoutSec = Math.max(10, cfg.get<number>('timeoutSec', 60));
  const allowedExtensions = new Set(cfg.get<string[]>('allowedExtensions', [".rb", ".py", ".js", ".jsx", ".ts", ".tsx"]));
  const enrichConcurrency = Math.min(8, Math.max(1, cfg.get<number>('enrich.concurrency', 3)));
  const hasKey = !!process.env.OPENAI_API_KEY;

  let analysisLanguage = cfg.get<string>('enrich.language', 'es')!;
  if (analysisLanguage === 'auto') analysisLanguage = (vscode.env.language || 'en').slice(0, 2);

  const appDir = path.join(workspaceRoot, 'app');
  const out = vscode.window.createOutputChannel('Security');
  out.clear();

  let targetRoot: string;
  if (targetDirectory === 'app') {
    if (fs.existsSync(appDir)) {
      targetRoot = appDir;
    } else {
      targetRoot = workspaceRoot;
      vscode.window.showWarningMessage(`VulnScan: "app" no existe en ${workspaceRoot}. Escaneando raíz en su lugar.`);
    }
  } else if (targetDirectory === 'root') {
    targetRoot = workspaceRoot;
  } else {
    targetRoot = fs.existsSync(appDir) ? appDir : workspaceRoot;
  }

  out.appendLine(`WorkspaceRoot: ${workspaceRoot}`);
  out.appendLine(`TargetDirectory setting: ${targetDirectory}`);
  out.appendLine(`Resolved targetRoot: ${targetRoot}`);
  out.appendLine(`Configs: ${semgrepConfigs.join(', ')}`);
  out.show(true);

  await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: `VulnScan: scanning ${path.basename(targetRoot)}/ …`, cancellable: true },
    async (progress, token) => {
      try {
        clearDiagnostics();
        statusScan.text = '$(sync~spin) Scanning…';
        progress.report({ message: 'indexing files…', increment: 0 });

        const allFiles = await enumerateFiles(targetRoot, defaultExcludes(), token);
        const targetFiles = allFiles.filter(f => allowedExtensions.has(path.extname(f)));
        if (token.isCancellationRequested) return;

        out.appendLine(`Enumerated files: ${allFiles.length}`);
        out.appendLine(`Target files (by extension): ${targetFiles.length}`);

        if (targetFiles.length === 0) {
          vscode.window.showInformationMessage('VulnScan: no target files found.');
          return;
        }

        const findingsRaw: any[] = [];
        const total = targetFiles.length;
        let done = 0;

        for (let i = 0; i < total; i += batchSize) {
          if (token.isCancellationRequested) break;
          const batch = targetFiles.slice(i, i + batchSize);
          const aborter = new AbortController();
          token.onCancellationRequested(() => aborter.abort());

          progress.report({ message: `scanning ${done}/${total}…` });

          const raw = await runSemgrepOnFiles(batch, semgrepConfigs, {
            timeoutSec,
            signal: aborter.signal,
            onDebug: (m) => out.appendLine(m)
          });
          findingsRaw.push(...raw);
          done += batch.length;

          out.appendLine(`Batch ${Math.floor(i / batchSize) + 1}: files=${batch.length}, semgrepResults=${raw.length}`);
          const pct = Math.min(100, Math.round((done / total) * 100));
          progress.report({ message: `scanned ${done}/${total} files`, increment: pct });
        }

        const mapped: Finding[] = findingsRaw.map(fromSemgrep).map(f => ({
          ...f,
          severity: normalizeSeverity((f as any).severity)
        }));

        // Aplicar ignore list
        const ignored = new Set(ctx.workspaceState.get<string[]>(IGNORED_KEY, []));
        const filteredForDiagnostics = mapped.filter(f => !ignored.has(f.fingerprint));
        const hist: Record<string, number> = {};
        for (const m of filteredForDiagnostics) hist[m.severity] = (hist[m.severity] || 0) + 1;
        out.appendLine(`Severities after map (ignored filtered out): ${Object.entries(hist).map(([k,v]) => `${k}:${v}`).join(', ') || 'none'}`);

        const findings = filteredForDiagnostics.filter(f => SEV_RANK[f.severity] >= SEV_RANK[minSeverity]);
        for (const f of findings) { f.snippet = await getSnippet(f.file, f.range); }
        publishFindings(findings);

        out.appendLine(`Findings (>= ${minSeverity}): ${findings.length}`);

        const reportItems: UIItem[] = [];
        if (hasKey && findings.length > 0 && !token.isCancellationRequested) {
          await pLimit(enrichConcurrency, findings.map((f, idx) => async () => {
            if (token.isCancellationRequested) return;
            const loc = `${f.file}:${f.range.start.line + 1}`;
            out.appendLine(`\n[${idx + 1}/${findings.length}] Enriching ${f.ruleId} @ ${loc} …`);
            try {
              const enriched = await enrichFinding(detectLang(f.file), f, analysisLanguage);
              reportItems.push(toUIItem(f, {
                explanation_md: enriched?.explanation_md ?? '',
                unified_diff: enriched?.fix?.unified_diff ?? null,
                calibrated: enriched?.severity_calibrated ?? null,
                confidence: typeof enriched?.confidence === 'number' ? enriched.confidence : null,
                references: Array.isArray(enriched?.references) ? enriched.references : [],
                tests: Array.isArray(enriched?.tests_suggested) ? enriched.tests_suggested : [],
                cwe: enriched?.cwe ?? f.cwe,
                owasp: enriched?.owasp ?? f.owasp
              }));
            } catch (e: any) {
              out.appendLine(`❌ AI enrich error: ${e?.message || e}`);
              reportItems.push(toUIItem(f, {
                explanation_md: '',
                unified_diff: null,
                calibrated: null,
                confidence: null,
                references: [],
                tests: [],
                cwe: f.cwe, owasp: f.owasp
              }));
            }
          }));
          out.show(true);
        } else {
          for (const f of findings) reportItems.push(toUIItem(f, { explanation_md: '', unified_diff: null, calibrated: null, confidence: null, references: [], tests: [], cwe: f.cwe, owasp: f.owasp }));
        }

        if (!token.isCancellationRequested) {
          lastReportItems = reportItems.sort((a, b) =>
            a.relFile.localeCompare(b.relFile) || SEV_RANK[b.severity] - SEV_RANK[a.severity]
          );
          openSecurityReport(ctx, workspaceRoot, lastReportItems, {
            targetRoot,
            configs: semgrepConfigs,
            timestamp: new Date().toISOString()
          });
          vscode.window.showInformationMessage(`VulnScan: done (${lastReportItems.length} findings >= ${minSeverity}).`);
        } else {
          vscode.window.showWarningMessage('VulnScan: cancelled.');
        }
      } catch (e: any) {
        vscode.window.showErrorMessage(`Scan failed: ${e?.message || e}`);
      } finally {
        statusScan.text = '$(shield) Scan';
      }
    }
  );
}

function detectLang(file: string) {
  if (file.endsWith('.rb')) return 'ruby';
  if (file.endsWith('.py')) return 'python';
  if (file.endsWith('.ts') || file.endsWith('.tsx')) return 'typescript';
  if (file.endsWith('.js') || file.endsWith('.jsx')) return 'javascript';
  return 'unknown';
}

async function enumerateFiles(root: string, excludes: string[], token: vscode.CancellationToken): Promise<string[]> {
  const files: string[] = [];
  const skipWithinRoot = new Set(excludes.map(e => path.resolve(root, e)));
  async function walk(dir: string) {
    if (token.isCancellationRequested) return;
    let entries: fs.Dirent[];
    try { entries = await fsp.readdir(dir, { withFileTypes: true }); } catch { return; }
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
  extra: {
    explanation_md: string;
    unified_diff: string | null;
    calibrated: 'none'|'low'|'medium'|'high'|'critical'|null;
    confidence: number | null;
    references: string[];
    tests: string[];
    cwe?: string|null;
    owasp?: string|null;
  }
): UIItem {
  return {
    fingerprint: f.fingerprint,
    ruleId: f.ruleId,
    severity: f.severity,
    file: f.file,
    relFile: vscode.workspace.asRelativePath(f.file),
    range: f.range,
    message: f.message,
    cwe: extra.cwe ?? null,
    owasp: extra.owasp ?? null,
    snippet: f.snippet,
    explanation_md: extra.explanation_md,
    unified_diff: extra.unified_diff,
    calibrated: extra.calibrated ?? null,
    confidence: extra.confidence ?? null,
    references: extra.references,
    tests: extra.tests
  };
}

export function deactivate() {}
