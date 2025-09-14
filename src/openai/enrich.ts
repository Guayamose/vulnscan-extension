// src/openai/enrich.ts
import { getOpenAI } from './client.js';
import type { Finding } from '../normalize.js';

/* ------------------ JSON Schema de salida (Responses API) ------------------ */
const SCHEMA_NAME = 'EnrichedFinding';
const SCHEMA_OBJECT = {
  type: 'object',
  additionalProperties: false,
  properties: {
    rule_id: { type: 'string' },
    cwe: { type: ['string', 'null'] },
    owasp: { type: ['string', 'null'] },
    severity_calibrated: { enum: ['none', 'low', 'medium', 'high', 'critical'] },
    confidence: { type: 'number', minimum: 0, maximum: 1 },
    explanation_md: { type: 'string' },
    fix: {
      type: 'object',
      additionalProperties: false,
      properties: {
        type: { enum: ['none', 'diff'] },
        unified_diff: { type: ['string', 'null'] }
      },
      required: ['type', 'unified_diff']
    },
    tests_suggested: { type: 'array', items: { type: 'string' } },
    references: { type: 'array', items: { type: 'string' } }
  },
  required: [
    'rule_id',
    'cwe',
    'owasp',
    'severity_calibrated',
    'confidence',
    'explanation_md',
    'fix',
    'tests_suggested',
    'references'
  ]
} as const;

/* ------------------------------ Utilidades ------------------------------ */
function safeJSON(s: unknown) {
  if (!s || typeof s !== 'string') {return null;}
  try { return JSON.parse(s); } catch { return null; }
}

function langLabel(tag: string | undefined): string {
  const t = (tag || 'es').toLowerCase();
  const map: Record<string, string> = {
    es: 'español', en: 'inglés', fr: 'francés', de: 'alemán',
    it: 'italiano', pt: 'portugués', ja: 'japonés', ko: 'coreano',
    zh: 'chino', 'zh-cn': 'chino simplificado', 'zh-tw': 'chino tradicional'
  };
  return map[t] ?? t;
}

/* -------------------------------- Prompt -------------------------------- */
function buildSystemPrompt(analysisLang: string) {
  return [
    `Actúas como un auditor de seguridad SENIOR especializado en revisión de código y threat modeling.`,
    `Devuelve SOLO JSON válido conforme al esquema proporcionado.`,
    `Responde en ${langLabel(analysisLang)}.`,
    `Si el hallazgo es FALSO POSITIVO: "severity_calibrated":"none" y "confidence" ≤ 0.3 (explica por qué).`,
    `Si hay riesgo real: calibra "severity_calibrated" (none/low/medium/high/critical) y justifica con vector/impacto/evidencia.`,
    `Propón un FIX MÍNIMO y SEGURO (usa diff unificado en "fix.unified_diff", cambios mínimos y aplicables).`,
    `Incluye CWE/OWASP cuando aplique (precisos, no inventados).`,
    `Sugiere hasta 5 pruebas relevantes y hasta 5 referencias de confianza (doc oficial, OWASP, MITRE, RFC...).`,
    `No inventes APIs ni frameworks. Sé conciso y accionable.`
  ].join('\n');
}

function buildUserPrompt(codeLang: string, f: Finding) {
  const where = `${f.file}:${f.range.start.line + 1}`;
  const findingRaw = {
    ruleId: f.ruleId,
    severity: f.severity,
    file: f.file,
    range: f.range,
    message: f.message,
    cwe: f.cwe,
    owasp: f.owasp
  };
  return [
    `LENGUAJE_CODIGO=${codeLang}`,
    `UBICACION=${where}`,
    `HALLAZGO=${JSON.stringify(findingRaw)}`,
    `SNIPPET:\n\n${(f.snippet ?? '').trim()}`
  ].join('\n\n');
}

/* ---------------------------- Llamada principal ---------------------------- */
/**
 * @param codeLang   Lenguaje del archivo (ruby, js, ts, etc.)
 * @param f          Finding normalizado
 * @param analysisLang Idioma de salida del análisis (ej: 'es', 'en', 'fr'...).
 *                     Si no viene, por defecto 'es'.
 */
export async function enrichFinding(
  codeLang: string,
  f: Finding,
  analysisLang: string = 'es'
): Promise<any> {
  const client = getOpenAI();

  const sys = buildSystemPrompt(analysisLang);
  const user = buildUserPrompt(codeLang, f);

  const res = await client.responses.create({
    model: 'gpt-4.1-mini',
    input: [
      { role: 'system', content: sys },
      { role: 'user', content: user }
    ],
    // En Responses API, el formato JSON Schema va en text.format
    text: {
      format: {
        type: 'json_schema',
        name: SCHEMA_NAME,
        schema: SCHEMA_OBJECT
      }
    }
  } as any);

  const anyRes: any = res;
  // Preferir el objeto ya parseado si el SDK lo expone
  const parsed =
    anyRes.output?.[0]?.content?.[0]?.parsed ??
    safeJSON(anyRes.output_text) ??
    safeJSON(anyRes.output?.[0]?.content?.[0]?.text);

  if (!parsed) {
    throw new Error('AI: respuesta no parseable según el schema.');
  }
  return parsed;
}
