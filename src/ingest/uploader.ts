// src/ingest/uploader.ts
import * as vscode from 'vscode';
import { OryonApi } from '../auth/api';
import type { Finding } from '../normalize';

type FindingWire = {
  fingerprint: string;
  rule_id: string;
  severity: string;
  path: string;
  line: number;
  col: number;
  end_line: number;
  end_col: number;
  message: string;
  engine: string;
  cwe: string[];
  owasp: string[];
  scan_id?: string; // compat
};

export class Uploader {
  constructor(private api: OryonApi, private accessToken: string) {}

  async createOrUpdateScan(
    scanPayload: any,
    idem: string
  ): Promise<{ id: string | number }> {
    const body = {
      ...scanPayload,
      scan: scanPayload, // compat
      idempotency_key: idem,
    };
    const res = await this.api.createOrUpdateScan(this.accessToken, body);
    if (!res?.id) throw new Error('API /scans no devolvió id');
    return res;
  }

  private workspaceRoot(): string | null {
    const ws = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
    return ws ?? null;
  }

  private toRelativePath(p: string): string {
    if (!p) return p;
    const root = this.workspaceRoot();
    if (root && (p.startsWith(root) || p.startsWith(root.replace(/\\/g, '/')))) {
      let rel = p.slice(root.length);
      if (rel.startsWith('/') || rel.startsWith('\\')) rel = rel.slice(1);
      return rel;
    }
    return p.replace(/^[.\/\\]+/, '');
  }

  private toWire(f: Finding): FindingWire {
    const startLine = Number((f as any).range?.start?.line ?? (f as any).line ?? 0);
    const startCol  = Number((f as any).range?.start?.column ?? (f as any).col ?? 0);
    const endLine   = Number((f as any).range?.end?.line ?? (f as any).endLine ?? startLine);
    const endCol    = Number((f as any).range?.end?.column ?? (f as any).endCol ?? startCol);

    const rawPath = (f as any).path ?? (f as any).file ?? (f as any).abs_path ?? '';
    const path = this.toRelativePath(String(rawPath));

    return {
      fingerprint: String((f as any).fingerprint || ''),
      rule_id: String((f as any).ruleId ?? (f as any).rule_id ?? ''),
      severity: String((f as any).severity || 'low'),
      path,
      line: Number.isFinite(startLine) ? startLine : 0,
      col: Number.isFinite(startCol) ? startCol : 0,
      end_line: Number.isFinite(endLine) ? endLine : 0,
      end_col: Number.isFinite(endCol) ? endCol : 0,
      message: String((f as any).message ?? ''),
      engine: String((f as any).engine ?? 'semgrep@unknown'),
      cwe: Array.isArray((f as any).cwe) ? (f as any).cwe : [],
      owasp: Array.isArray((f as any).owasp) ? (f as any).owasp : [],
    };
  }

  /**
   * Sube findings soportando ambos contratos:
   *  - BULK:   { scan_id, items:[{... scan_id }...] }
   *  - SINGLE: { scan_id, finding:{... scan_id } }
   *  Si el BULK devuelve 4xx, intenta ONE-BY-ONE.
   */
  async uploadFindings(scanIdIn: string | number, findings: Finding[]): Promise<void> {
    const scan_id = String(scanIdIn ?? '');
    if (!scan_id || scan_id === 'undefined') {
      throw new Error('scan_id no válido al subir findings');
    }
    if (!findings?.length) return;

    const items = findings.map((f) => {
      const w = this.toWire(f);
      return { ...w, scan_id };
    });

    const bulkRes = await this.api.postFindings(this.accessToken, { scan_id, items });

    if (bulkRes.status >= 200 && bulkRes.status < 300) return;

    // fallback uno a uno
    for (const item of items) {
      const res = await this.api.postFindings(this.accessToken, { scan_id, finding: item });
      if (res.status >= 200 && res.status < 300) continue;

      try {
        const body = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);
        console.error('[uploader] finding failed', res.status, body);
      } catch {
        console.error('[uploader] finding failed', res.status, res.data);
      }
    }
  }
}
