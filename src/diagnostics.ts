// src/diagnostics.ts
import * as vscode from 'vscode';
import type { Finding } from './normalize';

const COLLECTION_NAME = 'oryon';
const collection = vscode.languages.createDiagnosticCollection(COLLECTION_NAME);

export function publishFindings(findings: Finding[]) {
  const byFile = new Map<string, vscode.Diagnostic[]>();

  for (const f of findings) {
    const start = new vscode.Position(f.range.start.line, f.range.start.col);
    const end   = new vscode.Position(f.range.end.line,   f.range.end.col);
    const sev: vscode.DiagnosticSeverity =
      (f.severity === 'critical' || f.severity === 'high') ? vscode.DiagnosticSeverity.Error
      : (f.severity === 'medium') ? vscode.DiagnosticSeverity.Warning
      : vscode.DiagnosticSeverity.Information;

    const d = new vscode.Diagnostic(new vscode.Range(start, end), f.message, sev);
    d.source = 'oryon';
    d.code = f.ruleId ? f.ruleId : undefined;

    const arr = byFile.get(f.file) ?? [];
    arr.push(d);
    byFile.set(f.file, arr);
  }

  const entries: [vscode.Uri, vscode.Diagnostic[]][] = [];
  for (const [file, diags] of byFile) {
    entries.push([vscode.Uri.file(file), diags]);
  }
  collection.clear();
  collection.set(entries);
}

export function clearDiagnostics(filePath?: string) {
  if (filePath) collection.delete(vscode.Uri.file(filePath));
  else collection.clear();
}
