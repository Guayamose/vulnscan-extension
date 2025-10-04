// src/setup.ts
import * as vscode from 'vscode';
import { AuthManager } from './auth/auth-manager';

export async function runSetupWizard(_ctx: vscode.ExtensionContext, _auth: AuthManager, out: vscode.OutputChannel) {
  const cfg = vscode.workspace.getConfiguration('oryon');

  const baseUrl = await vscode.window.showInputBox({
    prompt: 'Backend Base URL',
    value: (cfg.get('backend.baseUrl') as string) || 'https://vulnscan-mock-df9c85d690d0.herokuapp.com'
  });
  if (baseUrl) await cfg.update('backend.baseUrl', baseUrl, vscode.ConfigurationTarget.Workspace);

  const bin = await vscode.window.showInputBox({
    prompt: 'Ruta a semgrep (opcional). Dejar vacío para autodetectar o usar npx.',
    value: (cfg.get('semgrepBin') as string) || ''
  });
  if (bin !== undefined) await cfg.update('semgrepBin', bin, vscode.ConfigurationTarget.Workspace);

  const min = await vscode.window.showQuickPick(['info','low','medium','high','critical'], {
    placeHolder: 'Severidad mínima para IA y panel'
  });
  if (min) await cfg.update('minSeverity', min, vscode.ConfigurationTarget.Workspace);

  vscode.window.showInformationMessage('Oryon: Setup actualizado.');
  out.appendLine('[oryon] setup wizard done');
}
