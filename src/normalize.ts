// src/normalize.ts
import * as crypto from 'node:crypto';
import * as path from 'node:path';
import * as vscode from 'vscode';

export type Sev = 'info'|'low'|'medium'|'high'|'critical';

export type Finding = {
  fingerprint: string;
  ruleId: string;
  severity: Sev;
  file: string;
  relFile: string;
  range: { start:{ line:number; col:number }, end:{ line:number; col:number } };
  message: string;
  engine: string;
  cwe?: string|null;
  owasp?: string|null;
  snippet?: string;
  // IA:
  calibrated?: 'none'|'low'|'medium'|'high'|'critical'|null;
  confidence?: number|null;
  explanation_md?: string;
  unified_diff?: string|null;
  tests?: string[];
  references?: string[];
  meta?: Record<string, any>;
};

function mapSeverity(s: string): Sev {
  const t = (s||'').toLowerCase();
  if (t.includes('crit')) return 'critical';
  if (t.startsWith('h')) return 'high';
  if (t.startsWith('m')) return 'medium';
  if (t.startsWith('l')) return 'low';
  return 'info';
}

function wsRoot(): string {
  return vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || '';
}

export function fromSemgrep(r: any): Finding {
  const root = wsRoot();
  const abs = r.path || r.extra?.path || '';
  const rel = root && abs.startsWith(root) ? path.relative(root, abs) : (r.path || '');
  const ruleId = r.check_id || r.extra?.rule?.id || r.rule_id || 'unknown';
  const sev = mapSeverity(r.severity || r.extra?.metadata?.severity || 'low');
  const msg = r.extra?.message || r.message || '';
  const start = { line: (r.start?.line ?? r.extra?.start?.line ?? 1) - 1, col: (r.start?.col ?? r.extra?.start?.col ?? 1) - 1 };
  const end   = { line: (r.end?.line ?? r.extra?.end?.line ?? start.line+1) - 1, col: (r.end?.col ?? r.extra?.end?.col ?? 1) - 1 };
  const cwe = r.extra?.metadata?.cwe || null;
  const owasp = r.extra?.metadata?.owasp || null;

  const fpRaw = `${abs}:${ruleId}:${start.line+1}:${msg}`;
  const fingerprint = crypto.createHash('sha1').update(fpRaw).digest('hex');

  return {
    fingerprint,
    ruleId,
    severity: sev,
    file: abs,
    relFile: rel || abs,
    range: { start, end },
    message: msg,
    engine: `semgrep@${r?.extra?.version || 'unknown'}`,
    cwe: cwe || null,
    owasp: owasp || null,
    meta: {
      lang: r?.lang || r?.extra?.engine || r?.extra?.metadata?.language || null,
      rule_kind: r?.extra?.metadata?.mode || r?.extra?.rule?.mode || null
    }
  };
}
