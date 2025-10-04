// src/scanners/semgrep.ts
import { execFile } from 'node:child_process';
import * as util from 'node:util';

const execFileAsync = util.promisify(execFile);

export type SemgrepFindingRaw = {
  check_id?: string;
  extra?: {
    severity?: string;
    message?: string;
    metadata?: Record<string, any>;
  };
  path?: string;
  start?: { line: number; col: number; offset?: number };
  end?:   { line: number; col: number; offset?: number };
};

export type SemgrepJson = {
  results?: SemgrepFindingRaw[];
};

export type SemgrepOptions = {
  timeoutSec: number;
  semgrepBin?: string;           // opcional, si viene se usa tal cual
  onDebug?: (msg: string) => void;
};

function buildArgs(files: string[], configs: string[], timeoutSec: number) {
  const base = [
    '--json',
    '--quiet',
    `--timeout=${timeoutSec}`,
    '--metrics=off',
  ];

  const cfgs = configs.flatMap(c => ['--config', c]);

  // semgrep permite pasar los paths al final
  return [...base, ...cfgs, ...files];
}

async function detectSemgrepBin(explicit?: string): Promise<{cmd: string; argsPrefix: string[]}> {
  if (explicit && explicit.trim()) {
    return { cmd: explicit.trim(), argsPrefix: [] };
  }
  // intentamos usar semgrep local; si no, npx
  try {
    await execFileAsync('semgrep', ['--version'], { timeout: 3000 });
    return { cmd: 'semgrep', argsPrefix: [] };
  } catch {
    return { cmd: 'npx', argsPrefix: ['-y', 'semgrep'] };
  }
}

async function runOnce(cmd: string, args: string[], opt: SemgrepOptions): Promise<SemgrepJson> {
  opt.onDebug?.(`[semgrep] ${cmd} ${args.join(' ')}`);
  const { stdout } = await execFileAsync(cmd, args, {
    timeout: opt.timeoutSec * 1000,
    maxBuffer: 64 * 1024 * 1024,
  });
  let json: SemgrepJson;
  try {
    json = JSON.parse(stdout || '{}');
  } catch {
    json = { results: [] };
  }
  return json;
}

/**
 * Ejecuta semgrep sobre un conjunto de archivos.
 * - Si falla por reglas/packs, reintenta con un set mínimo (owasp-top-ten, secrets, ruby, javascript).
 */
export async function runSemgrepOnFiles(
  files: string[],
  configs: string[],
  opt: SemgrepOptions
): Promise<SemgrepFindingRaw[]> {
  const bin = await detectSemgrepBin(opt.semgrepBin);
  const args = [...bin.argsPrefix, ...buildArgs(files, configs, opt.timeoutSec)];

  try {
    const json = await runOnce(bin.cmd, args, opt);
    return Array.isArray(json.results) ? json.results : [];
  } catch (e: any) {
    // retry con set mínimo
    if (configs.length > 6) {
      const min = ['p/owasp-top-ten', 'p/secrets', 'p/ruby', 'p/javascript'];
      try {
        opt.onDebug?.('[semgrep] retry with reduced ruleset');
        const args2 = [...bin.argsPrefix, ...buildArgs(files, min, opt.timeoutSec)];
        const json2 = await runOnce(bin.cmd, args2, opt);
        return Array.isArray(json2.results) ? json2.results : [];
      } catch (e2: any) {
        opt.onDebug?.('[semgrep] retry failed: ' + (e2?.message || e2));
        throw e2;
      }
    }
    throw e;
  }
}
