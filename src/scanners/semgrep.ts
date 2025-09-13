import { execFile } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

function candidateSemgrepBins() {
  const home = os.homedir();
  return [
    'semgrep',
    path.join(home, '.local', 'bin', 'semgrep'),
    path.join(home, '.local', 'share', 'pipx', 'venvs', 'semgrep', 'bin', 'semgrep'),
  ];
}

type RunOpts = {
  timeoutSec?: number;      // límite por ejecución
  signal?: AbortSignal;     // para cancelar desde fuera
};

// (A) Escaneo de un directorio completo (compat)
export async function runSemgrep(
  targetDir: string,
  config: string | string[] = 'p/owasp-top-ten',
  opts: RunOpts = {}
): Promise<any[]> {
  const bins = candidateSemgrepBins().filter(p => p === 'semgrep' || fs.existsSync(p));
  const cfgs = Array.isArray(config) ? config : [config];
  const tryOne = (bin: string) =>
    new Promise<any[]>((resolve, reject) => {
      const args = [
        ...cfgs.flatMap(c => ['--config', c]),
        '--metrics', 'off',
        '--json',
        targetDir
      ];
      execFile(
        bin,
        args,
        { maxBuffer: 100_000_000, timeout: (opts.timeoutSec ?? 60) * 1000, signal: opts.signal },
        (err, stdout, stderr) => {
          if (err && !stdout) return reject(new Error((stderr || err.message || 'semgrep failed').toString()));
          try { resolve((JSON.parse(stdout || '{}').results) || []); }
          catch { reject(new Error('Failed to parse semgrep JSON')); }
        }
      );
    });

  let lastErr: any;
  for (const bin of bins) { try { return await tryOne(bin); } catch (e) { lastErr = e; } }
  throw lastErr ?? new Error('Unable to execute semgrep (not found in PATH)');
}

// (B) Escaneo por LOTES de archivos concretos (para progreso real)
export async function runSemgrepOnFiles(
  files: string[],
  config: string | string[] = 'p/owasp-top-ten',
  opts: RunOpts = {}
): Promise<any[]> {
  if (!files.length) return [];
  const bins = candidateSemgrepBins().filter(p => p === 'semgrep' || fs.existsSync(p));
  const cfgs = Array.isArray(config) ? config : [config];

  const tryOne = (bin: string) =>
    new Promise<any[]>((resolve, reject) => {
      const args = [
        ...cfgs.flatMap(c => ['--config', c]),
        '--metrics', 'off',
        '--json',
        ...files
      ];
      execFile(
        bin,
        args,
        { maxBuffer: 100_000_000, timeout: (opts.timeoutSec ?? 60) * 1000, signal: opts.signal },
        (err, stdout, stderr) => {
          if (err && !stdout) return reject(new Error((stderr || err.message || 'semgrep failed').toString()));
          try { resolve((JSON.parse(stdout || '{}').results) || []); }
          catch { reject(new Error('Failed to parse semgrep JSON')); }
        }
      );
    });

  let lastErr: any;
  for (const bin of bins) { try { return await tryOne(bin); } catch (e) { lastErr = e; } }
  throw lastErr ?? new Error('Unable to execute semgrep (not found in PATH)');
}
