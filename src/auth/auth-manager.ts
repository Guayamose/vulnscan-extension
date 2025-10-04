// src/auth/auth-manager.ts
import * as vscode from 'vscode';
import { OryonApi, Tokens, WhoAmI } from './api';

const ACCESS_KEY  = 'oryon/auth/access';
const REFRESH_KEY = 'oryon/auth/refresh';
const EXP_KEY     = 'oryon/auth/expiresAt';
export const LOGIN_CONTEXT_KEY = 'oryon:isLoggedIn';

export class AuthManager {
  private api: OryonApi;

  constructor(private ctx: vscode.ExtensionContext, baseUrl: string) {
    this.api = new OryonApi(baseUrl);
  }

  setBaseUrl(baseUrl: string) { this.api = new OryonApi(baseUrl); }
  get apiClient() { return this.api; }

  async init() {
    const ok = !!(await this.getAccessTokenSafe());
    await vscode.commands.executeCommand('setContext', LOGIN_CONTEXT_KEY, ok);
  }

  async isLoggedIn(): Promise<boolean> {
    return !!(await this.ctx.secrets.get(ACCESS_KEY));
  }

  async login(username: string, password: string) {
    const t = await this.api.passwordLogin(username, password);
    await this.saveTokens(t);
    await vscode.commands.executeCommand('setContext', LOGIN_CONTEXT_KEY, true);
  }

  async logout() {
    const refresh = await this.ctx.secrets.get(REFRESH_KEY);
    if (refresh) { try { await this.api.revoke(refresh); } catch { /* noop */ } }
    await this.clear();
    await vscode.commands.executeCommand('setContext', LOGIN_CONTEXT_KEY, false);
  }

  async whoami(): Promise<WhoAmI> {
    const access = await this.getAccessTokenSafe();
    if (!access) {
      await vscode.commands.executeCommand('setContext', LOGIN_CONTEXT_KEY, false);
      return {};
    }
    const me = await this.api.whoami(access);

    // Refleja claves para máxima compatibilidad en el resto de la extensión
    const both: WhoAmI = {
      ...me,
      sub: (me.sub ?? me.user_id) ?? null,
      user_id: (me.user_id ?? me.sub) ?? null,
      role: me.role ?? me.scope ?? null,
    };

    const ok = !!(both.sub != null);
    await vscode.commands.executeCommand('setContext', LOGIN_CONTEXT_KEY, ok);
    return both;
  }

  async getAccessToken(): Promise<string | null> {
    const access = await this.ctx.secrets.get(ACCESS_KEY);
    const refresh = await this.ctx.secrets.get(REFRESH_KEY);
    const expStr  = await this.ctx.secrets.get(EXP_KEY);
    if (!access || !refresh || !expStr) return null;

    const exp = Number(expStr);
    if (Number.isNaN(exp)) { await this.clear(); return null; }

    const now = Math.floor(Date.now()/1000);
    if (now >= (exp - 30)) {
      try {
        const t = await this.api.refresh(refresh);
        await this.saveTokens(t);
        return t.access;
      } catch {
        await this.clear();
        return null;
      }
    }
    return access;
  }

  private async getAccessTokenSafe(): Promise<string | null> {
    const access = await this.ctx.secrets.get(ACCESS_KEY);
    if (!access) return null;
    const expStr = await this.ctx.secrets.get(EXP_KEY);
    const refresh = await this.ctx.secrets.get(REFRESH_KEY);
    const exp = expStr ? Number(expStr) : NaN;
    const now = Math.floor(Date.now()/1000);
    if (!Number.isNaN(exp) && now < (exp - 30)) return access;
    if (!refresh) return access;
    try {
      const t = await this.api.refresh(refresh);
      await this.saveTokens(t);
      await vscode.commands.executeCommand('setContext', LOGIN_CONTEXT_KEY, true);
      return t.access;
    } catch {
      await this.clear();
      await vscode.commands.executeCommand('setContext', LOGIN_CONTEXT_KEY, false);
      return null;
    }
  }

  private async saveTokens(t: Tokens) {
    const expiresAt = Math.floor(Date.now()/1000) + (t.expires_in ?? 900);
    await this.ctx.secrets.store(ACCESS_KEY, t.access);
    await this.ctx.secrets.store(REFRESH_KEY, t.refresh);
    await this.ctx.secrets.store(EXP_KEY, String(expiresAt));
  }

  private async clear() {
    await this.ctx.secrets.delete(ACCESS_KEY);
    await this.ctx.secrets.delete(REFRESH_KEY);
    await this.ctx.secrets.delete(EXP_KEY);
  }

  async debugTokens() {
    const access  = !!(await this.ctx.secrets.get(ACCESS_KEY));
    const refresh = !!(await this.ctx.secrets.get(REFRESH_KEY));
    const expStr  = await this.ctx.secrets.get(EXP_KEY);
    const exp = expStr ? Number(expStr) : null;
    const now = Math.floor(Date.now()/1000);
    return {
      hasAccess: access, hasRefresh: refresh, expiresAt: exp, now,
      expiredOrNear: exp != null ? now >= (exp - 30) : true
    };
  }
}
