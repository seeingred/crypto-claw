import { describe, it, expect, vi, beforeEach } from 'vitest';

// Capture all fetch calls.
const fetchCalls = [];
globalThis.fetch = vi.fn(async (url, opts) => {
  fetchCalls.push({ url, method: opts?.method || 'GET' });
  return { ok: true, text: async () => '{}' };
});

const api = await import('./api.js');

beforeEach(() => {
  fetchCalls.length = 0;
});

// These tests verify that frontend API paths match the backend routes in handlers.go.
// Backend routes (from registerAPIRoutes):
//   POST /api/servers/test
//   POST /api/servers/save
//   POST /api/llm/save
//   POST /api/telegram/save
//   POST /api/install/prepare
//   POST /api/deploy
//   GET  /api/deploy/logs    (SSE, not tested here)
//   GET  /api/state
//   POST /api/localhost/setup

describe('API path alignment with backend', () => {
  it('testSSHConnection → POST /api/servers/test', async () => {
    await api.testSSHConnection({ host: 'x' });
    expect(fetchCalls[0].url).toBe('/api/servers/test');
    expect(fetchCalls[0].method).toBe('POST');
  });

  it('saveServers → POST /api/servers/save', async () => {
    await api.saveServers({}, {}, false);
    expect(fetchCalls[0].url).toBe('/api/servers/save');
    expect(fetchCalls[0].method).toBe('POST');
  });

  it('installPrepare → POST /api/install/prepare', async () => {
    await api.installPrepare();
    expect(fetchCalls[0].url).toBe('/api/install/prepare');
    expect(fetchCalls[0].method).toBe('POST');
  });

  it('saveLLMConfig → POST /api/llm/save', async () => {
    await api.saveLLMConfig({ provider: 'anthropic' });
    expect(fetchCalls[0].url).toBe('/api/llm/save');
    expect(fetchCalls[0].method).toBe('POST');
  });

  it('saveTelegramToken → POST /api/telegram/save', async () => {
    await api.saveTelegramToken('tok');
    expect(fetchCalls[0].url).toBe('/api/telegram/save');
    expect(fetchCalls[0].method).toBe('POST');
  });

  it('saveTelegramToken sends botToken field', async () => {
    await api.saveTelegramToken('123:ABC');
    const lastCall = globalThis.fetch.mock.lastCall;
    const parsed = JSON.parse(lastCall[1].body);
    expect(parsed.botToken).toBe('123:ABC');
  });

  it('startDeployment → POST /api/deploy', async () => {
    await api.startDeployment();
    expect(fetchCalls[0].url).toBe('/api/deploy');
    expect(fetchCalls[0].method).toBe('POST');
  });

  it('getState → GET /api/state', async () => {
    await api.getState();
    expect(fetchCalls[0].url).toBe('/api/state');
    expect(fetchCalls[0].method).toBe('GET');
  });
});
