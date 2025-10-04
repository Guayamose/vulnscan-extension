// src/auth/api.ts
import axios, { AxiosInstance, type AxiosRequestConfig } from 'axios';

export interface Tokens { access: string; refresh: string; expires_in?: number; }
export interface WhoAmI {
  sub?: number | string | null;
  user_id?: number | string | null; // compat
  org?: string | null;
  role?: string | null;
  scope?: string | null;
}

export class OryonApi {
  private http: AxiosInstance;

  constructor(private baseUrl: string) {
    this.http = axios.create({
      baseURL: baseUrl.replace(/\/+$/, ''),
      timeout: 15000,
      headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      responseType: 'json',
      validateStatus: (s) => s >= 200 && s < 400,
    });
  }

  static newIdemKey(): string {
    const bytes = new Uint8Array(16);
    // @ts-ignore
    if (globalThis.crypto?.getRandomValues) globalThis.crypto.getRandomValues(bytes);
    else for (let i = 0; i < 16; i++) bytes[i] = Math.floor(Math.random() * 256);
    bytes[6] = (bytes[6] & 0x0f) | 0x40; // v4
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant
    const hex = Array.from(bytes, x => x.toString(16).padStart(2,'0')).join('');
    return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
  }

  // ---------- AUTH ----------
  async passwordLogin(username: string, password: string): Promise<Tokens> {
    const { data } = await this.http.post('/api/v1/auth/password_login', { username, password });
    return data as Tokens;
  }

  async refresh(refresh: string): Promise<Tokens> {
    const { data } = await this.http.post('/api/v1/auth/refresh', { refresh });
    return data as Tokens;
  }

  async revoke(refresh: string): Promise<void> {
    // aceptamos ambas variantes por compat
    await this.http.post('/api/v1/auth/revoke', { refresh, token: { refresh } });
  }

  /**
   * whoami con compat total:
   * - Header Authorization: Bearer <access>
   * - Query EXACTA: token[access]=<access>  (no usar objetos anidados en axios)
   */
  async whoami(access: string): Promise<WhoAmI> {
    const qs = new URLSearchParams({ 'token[access]': access }).toString();
    const url = `/api/v1/auth/whoami?${qs}`;

    const cfg: AxiosRequestConfig = {
      headers: { Authorization: `Bearer ${access}` },
    };

    const res = await this.http.get(url, cfg);

    let data: any = res.data;
    if (typeof data === 'string') {
      try { data = JSON.parse(data); } catch { data = {}; }
    }
    if (!data || typeof data !== 'object') data = {};

    // Normalización robusta
    const sub   = data.sub   ?? data.user_id ?? null;
    const role  = data.role  ?? data.scope   ?? null;
    const org   = data.org   ?? null;

    // Devolvemos ambas claves para compat con toda la extensión
    return {
      sub,
      user_id: data.user_id ?? (sub as any),
      org,
      role,
      scope: data.scope ?? (role as any),
    };
  }

  // ---------- helpers ----------
  async getWithAuth<T>(path: string, access: string, headers?: AxiosRequestConfig['headers']): Promise<T> {
    const { data } = await this.http.get(path, { headers: { Authorization: `Bearer ${access}`, ...(headers||{}) } });
    return data as T;
  }

  async postWithAuth<T>(path: string, access: string, body: any, headers?: AxiosRequestConfig['headers']): Promise<T> {
    const { data } = await this.http.post(path, body, { headers: { Authorization: `Bearer ${access}`, ...(headers||{}) } });
    return data as T;
  }
}
