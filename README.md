# Oryon — Documentación

> Extensión de VS Code que escanea tu código con **Semgrep** y enriquece cada hallazgo con **IA** (OpenAI): explicación, severidad calibrada, propuesta de fix (diff), tests sugeridos y referencias.

---

## Tabla de contenidos

- [Guía de Usuario](#guía-de-usuario)
  - [Requisitos](#requisitos)
  - [Instalación](#instalación)
  - [Primeros pasos (Setup Wizard)](#primeros-pasos-setup-wizard)
  - [Ejecutar un escaneo](#ejecutar-un-escaneo)
  - [Informe de seguridad (Security Report)](#informe-de-seguridad-security-report)
    - [Cabecera: contadores, filtro y acciones](#cabecera-contadores-filtro-y-acciones)
    - [Tarjetas por hallazgo](#tarjetas-por-hallazgo)
  - [Comandos disponibles](#comandos-disponibles)
  - [Ajustes de la extensión](#ajustes-de-la-extensión)
  - [Exportación de resultados](#exportación-de-resultados)
  - [Solución de problemas](#solución-de-problemas)
  - [Privacidad](#privacidad)
- [Guía de Desarrollador](#guía-de-desarrollador)
  - [Resumen de arquitectura](#resumen-de-arquitectura)
  - [Estructura del código](#estructura-del-código)
  - [Tipos principales](#tipos-principales)
  - [Flujo end-to-end](#flujo-end-to-end)
  - [Integración con Semgrep](#integración-con-semgrep)
  - [Normalización de resultados](#normalización-de-resultados)
  - [Enriquecimiento con OpenAI](#enriquecimiento-con-openai)
  - [Publicación de diagnósticos](#publicación-de-diagnósticos)
  - [Security Report (Webview)](#security-report-webview)
  - [Setup Wizard (Webview)](#setup-wizard-webview)
  - [Mensajería Webview ⇄ Extensión](#mensajería-webview--extensión)
  - [Configuración y comandos](#configuración-y-comandos)
  - [Build, test y publicación](#build-test-y-publicación)
  - [Extensiones futuras](#extensiones-futuras)
  - [Limitaciones conocidas](#limitaciones-conocidas)
  - [Checklist de QA](#checklist-de-qa)

---

## Guía de Usuario

### Requisitos
- **VS Code** v1.104.0 o superior.
- **Node.js 20+** (si vas a ejecutar en modo dev).
- **Semgrep** instalado (el asistente puede instalarlo por ti).
- **OpenAI API Key** (solo si quieres enriquecimiento por IA).

---

### Instalación

**Desde VSIX**
1. Abre VS Code → “Extensiones” → menú “…” → **Instalar desde VSIX…**.
2. Selecciona el `.vsix` de Oryon.

**Modo desarrollo**
1. `npm install`
2. `npm run compile`
3. F5 para abrir un *Extension Development Host*.

---

### Primeros pasos (Setup Wizard)
Abre **“Oryon: Setup Wizard”** desde la paleta (⇧⌘P / Ctrl+Shift+P).

1) **Semgrep**
   - **Recheck**: detecta si está instalado y muestra versión.
   - **Instalar via pipx**: ejecuta `pipx install semgrep`.

2) **OpenAI API Key**
   - Pega tu `sk-...`, pulsa **Save** (se guarda en Secret Storage).
   - **Test** para verificar conectividad.

3) **Preferencias rápidas**
   - **Minimum severity**: `info | low | medium | high | critical`.
   - **Target directory**: `auto | root | app`.
   - **Analysis language**: `auto | en | es | fr | de | pt | it`.

4) **¡Listo!**
   - **Run first scan**: lanza el primer análisis.
   - Atajos para **Export MD** / **Export JSON** cuando ya hay resultados.

> Puedes reabrir el asistente en cualquier momento para cambiar preferencias.

---

### Ejecutar un escaneo
- Comando: **“Security: Scan Workspace”**.
- Verás un progreso en la barra de VS Code.
- Al finalizar:
  - Se publican **diagnósticos** en la pestaña “Problemas”.
  - Se abre el **Security Report** con los resultados.

---

### Informe de seguridad (Security Report)

#### Cabecera: contadores, filtro y acciones
- **Chips por severidad**: clic para filtrar (puedes activar varios).
- **Búsqueda**: texto libre sobre regla, archivo, explicación, etc.
- **Ordenación**: por severidad, archivo o regla.
- **Acciones**:
  - **Rescan**: vuelve a ejecutar el análisis.
  - **Export MD / JSON**: exporta el informe.

#### Tarjetas por hallazgo
- **Severidad**, **archivo relativo** y **regla** (de Semgrep).
- **Mensaje** y **Explicación** (IA, en tu idioma).
- **Snippet** de código.
- **Propuesta de fix (diff)**:
  - **Copy diff** al portapapeles.
  - **Try patch**: aplica el parche automáticamente (best-effort).
- **Tests sugeridos** y **Referencias** (CWE/OWASP).
- **Open** (abre el archivo), **False Positive**, **Create Issue** (GitHub).

---

### Comandos disponibles
- **Oryon: Setup Wizard** → `sec.setup`
- **Security: Scan Workspace** → `sec.scan`
- **Security: Export Report (MD)** → `sec.exportReport`
- **Security: Export Report (JSON)** → `sec.exportJSON`

---

### Ajustes de la extensión
En **Settings → Oryon**:

- `Oryon.minSeverity`: `info | low | medium | high | critical` (por defecto: `low`)
- `Oryon.targetDirectory`: `auto | root | app` (por defecto: `auto`)
- `Oryon.enrich.language`: `auto | en | es | fr | de | pt | it` (por defecto: `auto`)

---

### Exportación de resultados
- **Markdown**: informe legible para compartir/evidencias.
- **JSON**: integra con pipelines o herramientas internas.

Exporta desde el **Security Report** o con los comandos `sec.exportReport` / `sec.exportJSON`.

---

### Solución de problemas
- **Semgrep no encontrado**
  - Usa “Instalar via pipx” en el Setup.
  - O instala manualmente: `pipx install semgrep`.

- **Error de OpenAI / API Key**
  - Revisa la clave en el Setup (Test).
  - Comprueba conectividad a `api.openai.com`.

- **No aparecen hallazgos**
  - Baja `Minimum severity` a `info`.
  - Cambia `Target directory` a `root`.
  - Asegura que los archivos tengan extensiones soportadas.

- **No se aplica el diff**
  - El parche es “best-effort”. Copia el diff y aplícalo a mano si es necesario.

---

### Privacidad
- **Semgrep** se ejecuta localmente (sin enviar tu código por defecto).
- **Enriquecimiento IA**: se envía únicamente el **snippet relevante** + metadatos del hallazgo.
- Puedes desactivar el enriquecimiento si tu política lo requiere.

---

## Guía de Desarrollador

### Resumen de arquitectura
- `extension.ts` orquesta el escaneo completo: Semgrep → Normalizar → Snippet → **OpenAI** → Diagnostics → **Report**.
- **Webviews**:
  - `setup.ts` (asistente de instalación/ajustes).
  - `report.ts` (UI del informe con acciones).
- **Integraciones**:
  - `scanners/semgrep.ts` (CLI `semgrep --json`).
  - `openai/client.ts` y `openai/enrich.ts` (Responses API con `json_schema`).

---

### Estructura del código
```
src/
  extension.ts            ← entrypoint y comandos
  setup.ts                ← webview Setup Wizard
  report.ts               ← webview Security Report (UI/UX)
  scanners/
    semgrep.ts            ← ejecución semgrep + parsing
  openai/
    client.ts             ← instancia del SDK OpenAI (api key)
    enrich.ts             ← prompt + JSON Schema + Responses API
  normalize.ts            ← de JSON Semgrep → Finding/UIItem
  snippet.ts              ← extrae fragmentos de código
  diagnostics.ts          ← VS Code DiagnosticCollection
esbuild.js                ← bundler
package.json              ← contribuciones (comandos + settings)
tsconfig.json
```

---

### Tipos principales
```ts
// Tras normalizar Semgrep
export type Finding = {
  ruleId: string;
  severity: 'info'|'low'|'medium'|'high'|'critical';
  file: string;
  range: { start: { line: number; col: number }, end: { line: number; col: number } };
  message: string;
  cwe?: string|null;
  owasp?: string|null;
  snippet?: string;
};

// Para UI/Report (Finding + IA)
export type UIItem = Finding & {
  relFile: string;
  fingerprint: string;
  explanation_md: string;
  unified_diff: string|null;
  calibrated: ('none'|'low'|'medium'|'high'|'critical')|null;
  confidence: number|null;
  references: string[];
  tests: string[];
};
```

---

### Flujo end-to-end
```
Comando sec.scan
  → runSemgrep(files, configs)                 // scanners/semgrep.ts
  → fromSemgrep(raw)                           // normalize.ts
  → getSnippet(file, range)                    // snippet.ts
  → enrichFinding(lang, finding)               // openai/enrich.ts
  → publishFindings(uiItems)                   // diagnostics.ts
  → openSecurityReport(ctx, root, uiItems)     // report.ts
```

---

### Integración con Semgrep
- CLI:
  `semgrep --json --quiet --timeout=60 --metrics=off --config p/owasp-top-ten --config p/ruby <files…>`
- `runSemgrep(files, configs, { timeout, onDebug })`:
  - Construye la línea de comando, ejecuta con `child_process`, parsea `stdout` JSON.
  - Opción `onDebug(m)` para trazar progreso/argumentos.

**Selección de ficheros**
- `sec.scan` enumera por extensiones conocidas (Ruby, JS/TS, etc.) bajo `targetRoot`, determinado por `Oryon.targetDirectory` (`auto | root | app`).

---

### Normalización de resultados
- `fromSemgrep(raw): Finding[]`
  - Mapea severidad Semgrep → `info/low/medium/high/critical`.
  - Extrae `ruleId`, `file`, `range`, `message`, `cwe/owasp` (si existen).
- (Opcional) `toUIItem(f, enriched, root)`: fusiona y calcula `relFile`/`fingerprint`.

---

### Enriquecimiento con OpenAI
- `openai/client.ts`: `getOpenAI()` lee `process.env.OPENAI_API_KEY` (el Setup la guarda en Secret Storage y la exporta al env del proceso).
- `openai/enrich.ts`:
  - **JSON Schema** (`EnrichedFinding`) con todos los campos en `required` (evita respuestas parciales).
  - **Prompt**:
    - `system`: rol auditor, estilo conciso, idioma (`auto` → detecta por heurística).
    - `user`: lenguaje, metadatos del hallazgo, **snippet**, reglas de salida estricta (solo JSON).
  - **Responses API** (SDK oficial):
    ```ts
    client.responses.create({
      model: "gpt-4.1-mini",
      input: [{ role: "system", content: sys }, { role: "user", content: user }],
      text: { format: { type: "json_schema", name: "EnrichedFinding", schema: SCHEMA_OBJECT } }
    })
    ```
  - Parseo seguro: `output_text` → `JSON.parse`.

**Concurrencia/cancelación**
- `scanWorkspace()` aplica límite de concurrencia y respeta `CancellationToken`.

---

### Publicación de diagnósticos
- `diagnostics.publishFindings(items)`:
  - Crea/actualiza `DiagnosticCollection('security')`.
  - Mapea severidad a `vscode.DiagnosticSeverity`.
  - Añade `code` (ruleId) y `source` (“Oryon/Semgrep”).
- `clearDiagnostics()` limpia la colección.

---

### Security Report (Webview)
- `report.ts/openSecurityReport(ctx, root, items, meta)`:
  - Renderiza chips por severidad, buscador, sort, y toolbar (Rescan, Export MD/JSON).
  - Tarjetas con explicación Markdown → HTML, snippet, diff (copy/apply), tests, refs.
  - **False Positive**: persiste por `workspaceState` (fingerprint).
  - **Create Issue**: si remoto Git es GitHub, pre-rellena issue con MD.

- `renderMarkdown(items)`: genera el informe consolidado.

- **Aplicación de parches**: “best-effort” por hunk; si no encaja, prueba por coincidencia exacta del bloque/snippet.

---

### Setup Wizard (Webview)
- `setup.ts/openSetupWizard(ctx)`:
  - **Semgrep**: `recheck` y `install` (`pipx install semgrep`).
  - **API Key**: `saveKey`/`testKey` (petición a `/v1/models`).
  - **Preferencias**: `minSeverity`, `targetDirectory`, `enrich.language`.
  - **Run**: dispara `sec.scan`.
  - **Export MD/JSON**: atajos si hay resultados en memoria.

---

### Mensajería Webview ⇄ Extensión

**Setup**
- Webview → Extensión: `recheck`, `install`, `saveKey`, `testKey`, `savePrefs`, `run`, `exportMd`, `exportJson`.
- Extensión → Webview: `semgrep:status`, `semgrep:install`, `key:test`, `key:saved`, `semgrep:auto`.

**Report**
- Webview → Extensión: `openFile`, `copyDiff`, `applyDiff`, `toggleIgnore`, `openExternal`, `createIssue`, `exportMd`, `exportJson`, `rescan`.
- Extensión → Webview: `toggleIgnore:result`, `applyDiff:result`.

---

### Configuración y comandos

**Settings (`package.json → contributes.configuration`)**
- `Oryon.minSeverity`: `info|low|medium|high|critical`
- `Oryon.targetDirectory`: `auto|root|app`
- `Oryon.enrich.language`: `auto|en|es|fr|de|pt|it`

**Comandos**
- `sec.setup` — Oryon: Setup Wizard
- `sec.scan` — Security: Scan Workspace
- `sec.exportReport` — Security: Export Report (MD)
- `sec.exportJSON` — Security: Export Report (JSON)

---

### Build, test y publicación
- Instalar deps: `npm install`
- Compilar: `npm run compile`
- Ejecutar en dev: F5 (Extension Development Host)
- Empaquetar VSIX: `npx @vscode/vsce package` (o script `package`)

**Requisitos de entorno**
- Node 20+
- Semgrep (recomendado vía `pipx`)
- OPENAI_API_KEY (guardada por Setup; exportada al env del proceso actual)

---

### Extensiones futuras
- **Nuevo scanner**:
  1. `src/scanners/<nuevo>.ts` con `run<Nuevo>()`.
  2. Normaliza en `normalize.ts`.
  3. Invoca en `scanWorkspace()` y fusiona `Finding[]`.

- **Más idiomas**: amplía `Oryon.enrich.language` y ajusta prompts.

- **UI extra**: export **SARIF**, vista de **timeline**, métricas por repo/sprint.

---

### Limitaciones conocidas
- Los diffs son **best-effort** (pueden no aplicar si cambió el archivo).
- Algunas reglas Semgrep pueden generar **falsos positivos**.
- La calidad del enriquecimiento depende del **snippet** y el contexto disponible.

---

### Checklist de QA
- [ ] Setup: Recheck/Install Semgrep; Save/Test key; guardar prefs.
- [ ] `sec.scan`: aparecen hallazgos en “Problemas” + Report.
- [ ] Chips/búsqueda/orden funcionan en Report.
- [ ] Open / False Positive / Create Issue correctos.
- [ ] Copy diff / Try patch (al menos un caso real).
- [ ] Export MD/JSON generan ficheros válidos.
- [ ] Rescan actualiza UI y diagnósticos.
- [ ] Idioma de análisis refleja explicaciones (es/en/etc.).
