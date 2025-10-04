// src/scanners/semgrep.ts
import * as vscode from 'vscode';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
const execFileAsync = promisify(execFile);

export type RunOpts = {
  timeoutSec?: number;
  signal?: AbortSignal;
  onDebug?: (m: string) => void;
};

async function resolveSemgrepBin(): Promise<string> {
  // 1) env override
  if (process.env.ORYON_SEMGREP_BIN) return process.env.ORYON_SEMGREP_BIN;
  // 2) setting
  const cfg = vscode.workspace.getConfiguration('oryon');
  const s = cfg.get<string>('semgrepBin', '');
  if (s && s.trim()) return s.trim();
  // 3) fallback: PATH
  return 'semgrep';
}

export async function runSemgrepOnFiles(
  files: string[],
  configs: string[],
  opts: RunOpts = {}
): Promise<any[]> {
  if (!files.length) return [];

  const bin = await resolveSemgrepBin();
  const timeoutSec = Math.max(10, opts.timeoutSec ?? 60);

  const args: string[] = ['--json', '--quiet', `--timeout=${timeoutSec}`, '--metrics=off'];
  for (const c of configs) args.push('--config', c);
  args.push(...files);

  const env = { ...process.env, PYTHONWARNINGS: 'ignore::UserWarning' };
  opts.onDebug?.(`[semgrep] exec: ${bin} ${args.join(' ')}`);

  const { stdout } = await execFileAsync(bin, args, { signal: opts.signal, env });
  let parsed: any;
  try { parsed = JSON.parse(stdout || '{}'); } catch { parsed = {}; }
  const results: any[] = Array.isArray(parsed.results) ? parsed.results : [];
  opts.onDebug?.(`[semgrep] results: ${results.length}`);
  return results;
}
