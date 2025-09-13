import * as fs from 'node:fs';

export async function getSnippet(
  file:string,
  range:{start:{line:number}, end:{line:number}},
  pad=80
){
  try {
    const text = await fs.promises.readFile(file,'utf8');
    const lines = text.split('\n');
    const s = Math.max(0, range.start.line - Math.floor(pad/2));
    const e = Math.min(lines.length-1, range.end.line + Math.floor(pad/2));
    return lines.slice(s, e+1).join('\n');
  } catch {
    return '';
  }
}
