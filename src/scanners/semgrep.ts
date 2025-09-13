// src/scanners/semgrep.ts
import { execFile } from 'node:child_process';
import * as os from 'node:os';
import * as path from 'node:path';

export type RunOpts = {
  timeoutSec?: number;
  signal?: AbortSignal;
  onDebug?: (msg: string) => void;
};

/** Ejecuta Semgrep sobre una lista de archivos (absolutos). Devuelve "results" del JSON. */
export async function runSemgrepOnFiles(
  files: string[],
  configs: string[],
  opts: RunOpts = {}
): Promise<any[]> {
  if (!files.length) {
    return [];
  }
  const bin = await resolveSemgrepBin();
  const timeoutSec = Math.max(10, opts.timeoutSec ?? 60);

  const args: string[] = [
    '--json',
    '--quiet',
    `--timeout=${timeoutSec}`,
    '--metrics=off',
  ];
  for (const c of configs) {
    args.push('--config', c);
  }
  args.push(...files);

  opts.onDebug?.(`[semgrep] exec: ${bin} ${args.join(' ')}`);

  const { stdout } = await execFileAsync(bin, args, { signal: opts.signal });
  let parsed: any;
  try {
    parsed = JSON.parse(stdout || '{}');
  } catch {
    parsed = {};
  }
  const results: any[] = Array.isArray(parsed.results) ? parsed.results : [];
  opts.onDebug?.(`[semgrep] results: ${results.length}`);
  return results;
}

/* ---------- helpers ---------- */

function toText(x: unknown): string {
  if (typeof x === 'string') return x;
  try {
    // Buffer u otros objetos con toString
    return (x as any)?.toString?.('utf8') ?? '';
  } catch {
    return '';
  }
}

function execFileAsync(
  cmd: string,
  args: string[],
  opt: { signal?: AbortSignal }
): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const cp = execFile(
      cmd,
      args,
      { maxBuffer: 50 * 1024 * 1024 },
      (err, stdout, stderr) => {
        if (err) {
          const msg = toText(stderr) || (err as any)?.message || String(err);
          return reject(new Error(msg));
        }
        resolve({ stdout: toText(stdout), stderr: toText(stderr) });
      }
    );

    if (opt?.signal) {
      opt.signal.addEventListener(
        'abort',
        () => {
          cp.kill('SIGTERM');
        },
        { once: true }
      );
    }
  });
}

async function resolveSemgrepBin(): Promise<string> {
  const candidates = [
    'semgrep',
    path.join(os.homedir(), '.local', 'bin', 'semgrep'),
    path.join(
      os.homedir(),
      '.local',
      'share',
      'pipx',
      'venvs',
      'semgrep',
      'bin',
      'semgrep'
    ),
  ];
  for (const c of candidates) {
    try {
      await execFileAsync(c, ['--version'], {});
      return c;
    } catch {
      // sigue probando
    }
  }
  throw new Error(
    'Semgrep no encontrado. Instálalo con `pipx install semgrep` o añade al PATH.'
  );
}
