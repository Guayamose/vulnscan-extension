// src/auth/auth-manager.ts
import * as vscode from 'vscode';
import { OryonApi } from './api';

type Tokens = { access?: string; refresh?: string; expires_at?: number };

const K = {
  ACCESS: 'oryon/access',
  REFRESH: 'oryon/refresh',
  EXPIRES: 'oryon/expires'
};

export class AuthManager {
  private api: OryonApi;
  constructor(private ctx: vscode.ExtensionContext, baseUrl: string) {
    this.api = new OryonApi(baseUrl);
  }

  async init() {
    const access = await this.getAccessToken();
    const ok = !!access;
    await vscode.commands.executeCommand('setContext', 'oryon:isLoggedIn', ok);
  }

  async isLoggedIn() {
    const a = await this.getAccessToken();
    return !!a;
  }

  async login(username: string, password: string) {
    const res = await this.api.passwordLogin(username, password);
    const now = Math.floor(Date.now()/1000);
    await this.ctx.secrets.store(K.ACCESS, res.access || '');
    await this.ctx.secrets.store(K.REFRESH, res.refresh || '');
    await this.ctx.secrets.store(K.EXPIRES, String(now + (res.expires_in || 900) - 30));
    await vscode.commands.executeCommand('setContext', 'oryon:isLoggedIn', true);
  }

  async logout() {
    try {
      const r = await this.ctx.secrets.get(K.REFRESH);
      if (r) await this.api.revoke(r);
    } catch {}
    await this.ctx.secrets.delete(K.ACCESS);
    await this.ctx.secrets.delete(K.REFRESH);
    await this.ctx.secrets.delete(K.EXPIRES);
    await vscode.commands.executeCommand('setContext', 'oryon:isLoggedIn', false);
  }

  async getAccessToken(): Promise<string | null> {
    const access = await this.ctx.secrets.get(K.ACCESS);
    const exp = Number(await this.ctx.secrets.get(K.EXPIRES) || '0');
    const now = Math.floor(Date.now()/1000);
    if (access && now < exp) return access;
    // refresh
    const refresh = await this.ctx.secrets.get(K.REFRESH);
    if (!refresh) return null;
    try {
      const res = await this.api.refresh(refresh);
      const nnow = Math.floor(Date.now()/1000);
      await this.ctx.secrets.store(K.ACCESS, res.access || '');
      await this.ctx.secrets.store(K.REFRESH, res.refresh || refresh);
      await this.ctx.secrets.store(K.EXPIRES, String(nnow + (res.expires_in || 900) - 30));
      return res.access || null;
    } catch {
      await this.logout();
      return null;
    }
  }

  async whoami() {
    const a = await this.getAccessToken();
    if (!a) return null;
    return this.api.whoami(a);
  }

  async debugTokens() {
    return {
      has_access: !!(await this.ctx.secrets.get(K.ACCESS)),
      has_refresh: !!(await this.ctx.secrets.get(K.REFRESH)),
      exp: await this.ctx.secrets.get(K.EXPIRES)
    };
  }
}
