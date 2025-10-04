// src/diagnostics.ts
import * as vscode from 'vscode';
import type { Finding } from './normalize';

const collection = vscode.languages.createDiagnosticCollection('oryon');

export function clearDiagnostics() {
  collection.clear();
}

export function publishFindings(findings: Finding[]) {
  const byFile = new Map<string, vscode.Diagnostic[]>();

  for (const f of findings) {
    const uri = vscode.Uri.file(f.file);
    const start = new vscode.Position(f.range.start.line, f.range.start.col);
    const end   = new vscode.Position(f.range.end.line,   f.range.end.col);

    const diag = new vscode.Diagnostic(
      new vscode.Range(start, end),
      f.message,
      f.severity === 'critical' || f.severity === 'high'
        ? vscode.DiagnosticSeverity.Error
        : f.severity === 'medium'
        ? vscode.DiagnosticSeverity.Warning
        : vscode.DiagnosticSeverity.Information
    );

    diag.source = 'oryon';

    // Diagnostic.code puede ser string|number|{ value; target? }
    if (f.ruleId) {
      diag.code = f.ruleId;   // Asignar solo el string si no hay target
    }

    const arr = byFile.get(uri.fsPath) || [];
    arr.push(diag);
    byFile.set(uri.fsPath, arr);
  }

  collection.clear();
  for (const [file, ds] of byFile) {
    collection.set(vscode.Uri.file(file), ds);
  }
}
