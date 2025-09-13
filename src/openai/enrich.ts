import { getOpenAI } from './client.js';
import { Finding } from '../normalize.js';

// JSON Schema puro (sin envolver) + nombre
const SCHEMA_NAME = "EnrichedFinding";
const SCHEMA_OBJECT: any = {
  type: "object",
  additionalProperties: false,
  properties: {
    rule_id: { type: "string" },
    cwe: { type: ["string", "null"] },
    owasp: { type: ["string", "null"] },
    severity_calibrated: { enum: ["none", "low", "medium", "high", "critical"] },
    confidence: { type: "number", minimum: 0, maximum: 1 },
    explanation_md: { type: "string" },
    fix: {
      type: "object",
      additionalProperties: false,
      properties: {
        type: { enum: ["none", "diff"] },
        unified_diff: { type: ["string", "null"] }
      },
      required: ["type", "unified_diff"]
    },
    tests_suggested: { type: "array", items: { type: "string" } },
    references: { type: "array", items: { type: "string" } }
  },
  // 🔧 required debe incluir TODAS las claves de properties según la API
  required: [
    "rule_id",
    "cwe",
    "owasp",
    "severity_calibrated",
    "confidence",
    "explanation_md",
    "fix",
    "tests_suggested",
    "references"
  ]
};

export async function enrichFinding(lang: string, f: Finding) {
  const client = getOpenAI();

  const sys = `Eres un auditor de seguridad de código.
Devuelve SOLO JSON válido que cumpla el JSON Schema.
Si el hallazgo parece falso positivo: severity_calibrated="none", confidence<=0.3.
Si propones fix, usa un diff unificado mínimo que compile.
No inventes APIs; referencia CWE/OWASP si aplica.`;

  const user = [
    `LENGUAJE=${lang}`,
    `FINDING_RAW=${JSON.stringify({
      ruleId: f.ruleId,
      severity: f.severity,
      file: f.file,
      range: f.range,
      message: f.message,
      cwe: f.cwe,
      owasp: f.owasp
    })}`,
    `SNIPPET:\n\n${f.snippet || ''}`
  ].join('\n\n');

  // Responses API: usar text.format con "name" y "schema"
  const res = await client.responses.create({
    model: "gpt-4.1-mini",
    input: [
      { role: "system", content: sys },
      { role: "user", content: user }
    ],
    text: {
      format: {
        type: "json_schema",
        name: SCHEMA_NAME,
        schema: SCHEMA_OBJECT
      }
    }
  } as any); // cast por si los typings aún no recogen el shape nuevo

  // Extracción robusta
  const anyRes: any = res;
  const text =
    anyRes.output_text ??
    anyRes.output?.[0]?.content?.[0]?.text ??
    '{}';

  return JSON.parse(text);
}
