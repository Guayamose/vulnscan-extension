export type Finding = {
  engine: 'semgrep';
  ruleId: string;
  severity: 'critical'|'high'|'medium'|'low'|'info';
  file: string;
  range: { start:{line:number,col:number}, end:{line:number,col:number} };
  message: string;
  snippet?: string;
  cwe?: string|null;
  owasp?: string|null;
  fingerprint: string;
};

export function fromSemgrep(r:any): Finding {
  return {
    engine: 'semgrep',
    ruleId: r.check_id,
    severity: (r.extra?.severity || 'LOW').toLowerCase(),
    file: r.path,
    range: {
      start: { line: r.start.line - 1, col: r.start.col - 1 },
      end:   { line: r.end.line   - 1, col: r.end.col   - 1 }
    },
    message: r.extra?.message ?? 'Security issue',
    cwe: r.extra?.metadata?.cwe ?? null,
    owasp: r.extra?.metadata?.owasp ?? null,
    fingerprint: `${r.path}:${r.check_id}:${r.start.line}:${r.start.col}`
  };
}
