// src/live/live-scanner.ts
import * as vscode from 'vscode';
import { runSemgrepOnFiles } from '../scanners/semgrep';
import { fromSemgrep, Finding } from '../normalize';
import { publishFindings, clearDiagnostics } from '../diagnostics';

export interface LiveScannerOptions {
  configs: string[];
  timeoutSec: number;
  onDebug?: (msg: string) => void;
}

export class LiveScanner {
  private timer: NodeJS.Timeout | undefined;

  constructor(private opts: LiveScannerOptions) {}

  bind(context: vscode.ExtensionContext) {
    context.subscriptions.push(
      vscode.workspace.onDidChangeTextDocument((e) => {
        if (e.document.uri.scheme !== 'file') return;
        this.debounceScan(e.document);
      }),
      vscode.workspace.onDidSaveTextDocument((doc) => {
        if (doc.uri.scheme !== 'file') return;
        this.debounceScan(doc, 300);
      }),
      vscode.workspace.onDidCloseTextDocument((doc) => {
        if (doc.uri.scheme !== 'file') return;
        clearDiagnostics(doc.uri.fsPath);
      })
    );
  }

  private debounceScan(doc: vscode.TextDocument, delay = 800) {
    if (this.timer) clearTimeout(this.timer);
    this.timer = setTimeout(() => this.scanDocument(doc), delay);
  }

  private async scanDocument(doc: vscode.TextDocument) {
    const path = doc.uri.fsPath;
    const ext = path.split('.').pop() || '';
    const allowed = ['rb','py','js','jsx','ts','tsx'];
    if (!allowed.includes(ext)) return;

    try {
      const results = await runSemgrepOnFiles([path], this.opts.configs, {
        timeoutSec: this.opts.timeoutSec,
        onDebug: this.opts.onDebug,
      });

      const findings: Finding[] = results
        .map(fromSemgrep)
        .filter(f => f.file === path);

      clearDiagnostics(path);
      publishFindings(findings);
    } catch (e: any) {
      this.opts.onDebug?.(`[live] scan error: ${e?.message || e}`);
    }
  }
}
