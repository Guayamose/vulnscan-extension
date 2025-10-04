// src/auth/api.ts
import axios, { AxiosInstance } from 'axios';

export class OryonApi {
  private http: AxiosInstance;

  constructor(baseUrl: string) {
    this.http = axios.create({
      baseURL: baseUrl.replace(/\/+$/, ''),
      timeout: 15000,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  static newIdemKey() {
    return cryptoRandom(16);
  }

  // ===== Auth =====
  async passwordLogin(username: string, password: string) {
    const { data } = await this.http.post('/api/v1/auth/password_login', {
      username,
      password,
    });
    return data as { access: string; refresh: string; expires_in?: number };
  }

  async whoami(access: string) {
    const { data } = await this.http.get('/api/v1/auth/whoami', {
      headers: { Authorization: `Bearer ${access}` },
      params: { 'token[access]': access }, // compat
    });
    return data;
  }

  async refresh(refresh: string) {
    const { data } = await this.http.post('/api/v1/auth/refresh', { refresh });
    return data as { access: string; refresh?: string; expires_in?: number };
  }

  async revoke(refresh: string) {
    await this.http.post('/api/v1/auth/revoke', { refresh });
  }

  // ===== Scans & Findings =====
  async createOrUpdateScan(access: string, body: any) {
    const { data } = await this.http.post('/api/v1/scans', body, {
      headers: {
        Authorization: `Bearer ${access}`,
        // tu API acepta header o body; mandamos ambos
        'Idempotency-Key': body?.idempotency_key ?? body?.scan?.idempotency_key ?? ''
      },
      validateStatus: () => true
    });

    if (!data || (data.status && (data.status < 200 || data.status >= 400))) {
      throw new Error('API /scans devolvió error');
    }

    const id = data.id ?? data.scan_id;
    if (!id) throw new Error('API /scans no devolvió id');

    return { id, status: data.status ?? 'created' } as { id: string | number; status: string };
  }

  /** Post findings devolviendo status+data aunque sea 4xx (para ver el error del server). */
  async postFindings(access: string, payload: any) {
    const res = await this.http.post('/api/v1/findings', payload, {
      headers: { Authorization: `Bearer ${access}` },
      validateStatus: () => true,
    });
    return { status: res.status, data: res.data };
  }
}

function cryptoRandom(n = 16) {
  const buf = new Uint8Array(n);
  if (typeof crypto !== 'undefined' && (crypto as any).getRandomValues) {
    (crypto as any).getRandomValues(buf);
  } else {
    const nodeCrypto = require('node:crypto');
    const b = nodeCrypto.randomBytes(n);
    b.copy(buf as any, 0, 0, n);
  }
  return Array.from(buf).map((b) => b.toString(16).padStart(2, '0')).join('');
}
