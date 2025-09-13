import * as vscode from 'vscode';
import { Finding } from './normalize.js';

const collection = vscode.languages.createDiagnosticCollection('sec');

export function clearDiagnostics() { collection.clear(); }

export function publishFindings(findings: Finding[]) {
  const perFile = new Map<string, vscode.Diagnostic[]>();
  for (const f of findings) {
    const uri = vscode.Uri.file(f.file);
    const range = new vscode.Range(
      new vscode.Position(f.range.start.line, f.range.start.col),
      new vscode.Position(f.range.end.line,   f.range.end.col)
    );
    const diag = new vscode.Diagnostic(range, `[${f.engine}] ${f.message}`, mapSeverity(f.severity));
    diag.code = f.ruleId;
    const arr = perFile.get(uri.fsPath) ?? [];
    arr.push(diag);
    perFile.set(uri.fsPath, arr);
  }
  collection.clear();
  for (const [file, diags] of perFile) {
    collection.set(vscode.Uri.file(file), diags);
  }
}

function mapSeverity(s:string) {
  if (s === 'critical' || s === 'high') return vscode.DiagnosticSeverity.Error;
  if (s === 'medium') return vscode.DiagnosticSeverity.Warning;
  return vscode.DiagnosticSeverity.Information;
}
