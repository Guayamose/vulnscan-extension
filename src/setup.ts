// src/setup.ts
import * as vscode from 'vscode';
import { AuthManager } from './auth/auth-manager';

export async function runSetupWizard(context: vscode.ExtensionContext, auth: AuthManager, out: vscode.OutputChannel) {
  out.appendLine('=== Oryon Setup Wizard ===');

  // 1) Base URL
  const cfg = vscode.workspace.getConfiguration('oryon');
  const currentBase = cfg.get<string>('backend.baseUrl', 'https://vulnscan-mock-df9c85d690d0.herokuapp.com');

  const baseUrl = await vscode.window.showInputBox({
    title: 'Oryon — Backend Base URL',
    value: currentBase,
    prompt: 'Introduce la URL base del backend (mock o prod).',
    ignoreFocusOut: true
  });
  if (!baseUrl) { out.appendLine('Setup cancelado (sin baseUrl)'); return; }

  await cfg.update('backend.baseUrl', baseUrl, vscode.ConfigurationTarget.Global);
  auth.setBaseUrl(baseUrl);
  out.appendLine(`Base URL guardada: ${baseUrl}`);

  // 2) Credenciales
  const username = await vscode.window.showInputBox({
    title: 'Login — Usuario/Email',
    prompt: 'Introduce tu usuario/email',
    ignoreFocusOut: true
  });
  if (!username) { out.appendLine('Setup cancelado (sin username)'); return; }

  const password = await vscode.window.showInputBox({
    title: 'Login — Contraseña',
    prompt: 'Introduce tu contraseña',
    password: true,
    ignoreFocusOut: true
  });
  if (!password) { out.appendLine('Setup cancelado (sin password)'); return; }

  // 3) Login
  try {
    out.appendLine('Haciendo login...');
    await auth.login(username, password);
    out.appendLine('Login OK. Tokens guardados en SecretStorage.');
  } catch (e: any) {
    out.appendLine('Login FAILED: ' + (e?.message || e));
    vscode.window.showErrorMessage('Login fallido: ' + (e?.message || e));
    return;
  }

  // 4) Validar sesión (whoami)
  try {
    out.appendLine('Invocando whoami...');
    const me = await auth.whoami();
    out.appendLine('whoami OK: ' + JSON.stringify(me));
    vscode.window.showInformationMessage(`Oryon listo. Usuario: ${(me?.sub ?? me?.user_id ?? 'desconocido')} (org: ${me?.org ?? 'n/a'})`);
  } catch (e: any) {
    const dbg = await auth.debugTokens();
    out.appendLine('whoami FAILED: ' + (e?.message || e));
    out.appendLine('Estado de tokens: ' + JSON.stringify(dbg));
    vscode.window.showErrorMessage('No se pudo validar la sesión (whoami). Revisa la URL o las credenciales.');
  }
}
