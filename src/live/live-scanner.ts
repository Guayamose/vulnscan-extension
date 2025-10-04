// src/live/live-scanner.ts
import * as vscode from 'vscode';
import { runSemgrepOnFiles } from '../scanners/semgrep';
import { fromSemgrep, Finding } from '../normalize';
import { publishFindings } from '../diagnostics';

type Opts = { configs: string[]; timeoutSec: number; onDebug?: (m: string) => void };

export class LiveScanner {
  private last: NodeJS.Timeout | null = null;
  private cache: Map<string, Finding[]> = new Map();

  constructor(private opt: Opts) {}

  bind(ctx: vscode.ExtensionContext) {
    ctx.subscriptions.push(
      vscode.workspace.onDidSaveTextDocument(doc => {
        const fsPath = doc.uri.fsPath;
        this.debounce(async () => {
          try {
            const res = await runSemgrepOnFiles([fsPath], this.opt.configs, {
              timeoutSec: this.opt.timeoutSec,
              onDebug: this.opt.onDebug
            });
            const fnds = (res || []).map(fromSemgrep);
            this.cache.set(fsPath, fnds);
            this.pushAll();
          } catch (e: any) {
            // ignora
          }
        }, 250);
      })
    );
  }

  private pushAll() {
    const all: Finding[] = [];
    for (const arr of this.cache.values()) all.push(...arr);
    publishFindings(all);
  }

  private debounce(fn: () => void, ms: number) {
    if (this.last) clearTimeout(this.last);
    this.last = setTimeout(fn, ms);
  }
}
