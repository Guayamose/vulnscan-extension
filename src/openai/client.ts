import OpenAI from 'openai';

let _client: OpenAI | null = null;

export function getOpenAI() {
  if (!_client) {
    const apiKey = process.env.OPENAI_API_KEY;
    if (!apiKey) {throw new Error('OPENAI_API_KEY is not set');}
    _client = new OpenAI({ apiKey });
  }
  return _client;
}
