// src/ingest/uploader.ts
import { OryonApi } from '../auth/api';
import { Finding } from '../normalize';

export interface ScanPayload {
  org: string;
  user_ref: string | number;
  project_slug: string;
  scan_type: 'workspace' | 'file' | 'pipeline';
  commit_sha?: string;
  started_at: string;
  finished_at: string;
  findings_ingested: number;
  deduped: number;
  status: 'running' | 'completed' | 'failed';
  idempotency_key: string;
}

export class Uploader {
  constructor(private api: OryonApi, private access: string) {}

  async createOrUpdateScan(p: ScanPayload, idemKey: string): Promise<{ id: string }> {
    return await this.api.postWithAuth<{ id: string }>(
      '/api/v1/scans',
      this.access,
      p,
      { 'Idempotency-Key': idemKey }
    );
  }

  async uploadFindings(scanId: string, findings: Finding[]) {
    const concurrency = 8;
    let i = 0;

    const worker = async () => {
      while (i < findings.length) {
        const f = findings[i++];
        const body = {
          scan_id: scanId,
          rule_id: f.ruleId,
          severity: f.severity.toUpperCase(),
          file_path: f.file,
          line: f.range.start.line + 1,
          message: f.message,
          fingerprint_hint: f.fingerprint
        };
        await this.api.postWithAuth('/api/v1/findings', this.access, body);
      }
    };

    await Promise.all(
      Array.from({ length: Math.min(concurrency, findings.length || 1) }, worker)
    );
  }
}
