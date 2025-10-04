// src/openai/client.ts
import OpenAI from 'openai';
import * as vscode from 'vscode';

let client: OpenAI | null = null;

export function getOpenAI(): OpenAI {
  if (client) return client;
  // Recupera clave de VS Code secrets si existe, si no usa process.env
  const key = process.env.OPENAI_API_KEY || process.env.OPENAI_KEY;
  if (!key) throw new Error('OPENAI_API_KEY no configurada. Define la env var o usa VS Code Secrets.');
  client = new OpenAI({ apiKey: key });
  return client;
}
