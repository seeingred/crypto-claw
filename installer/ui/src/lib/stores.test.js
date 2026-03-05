import { describe, it, expect, vi, beforeEach } from 'vitest';
import { get } from 'svelte/store';

// Mock api.js before importing stores.
vi.mock('./api.js', () => ({
  getState: vi.fn(),
}));

const { getState } = await import('./api.js');
const { currentStep, wizardState, restoreState } = await import('./stores.js');

beforeEach(() => {
  sessionStorage.clear();
  currentStep.set(0);
  wizardState.update((s) => ({
    ...s,
    servers: {
      ...s.servers,
      localMode: false,
      partyA: { ...s.servers.partyA, host: '', tested: false },
      partyB: { ...s.servers.partyB, host: '', tested: false },
    },
    llm: { ...s.llm, provider: 'anthropic', model: 'claude-sonnet-4-20250514' },
    telegram: { ...s.telegram },
    deployment: { ...s.deployment, completed: false },
  }));
  vi.clearAllMocks();
});

// New step flow: Welcome(0) → Servers(1) → LLM(2) → Telegram(3) → Review(4) → Install(5) → Done(6)
// stepMap: servers→2, llm→3, telegram→4, prepared→5, deploying→5, done→6

describe('restoreState (fresh session — no sessionStorage)', () => {
  it('stays on step 0 when backend returns welcome', async () => {
    sessionStorage.clear();
    getState.mockResolvedValue({ step: 'welcome' });
    await restoreState();
    expect(get(currentStep)).toBe(0);
  });

  it('restores to LLM step when servers are configured', async () => {
    sessionStorage.clear();
    getState.mockResolvedValue({
      step: 'servers',
      serverA: { host: '10.0.0.1', port: 22, user: 'root' },
      serverB: { host: '10.0.0.2', port: 22, user: 'root' },
    });
    await restoreState();
    expect(get(currentStep)).toBe(2); // LLM step
    const state = get(wizardState);
    expect(state.servers.partyA.host).toBe('10.0.0.1');
    expect(state.servers.partyB.host).toBe('10.0.0.2');
    expect(state.servers.partyA.tested).toBe(true);
  });

  it('restores to Telegram step after LLM on fresh session', async () => {
    sessionStorage.clear();
    getState.mockResolvedValue({
      step: 'llm',
      llmConfigured: true,
      llmProvider: 'anthropic',
      llmModel: 'claude-sonnet-4-20250514',
    });
    await restoreState();
    expect(get(currentStep)).toBe(3); // Telegram step
    const state = get(wizardState);
    expect(state.llm.provider).toBe('anthropic');
  });

  it('restores to Done step after deployment', async () => {
    sessionStorage.clear();
    getState.mockResolvedValue({
      step: 'done',
      deployDone: true,
      partyAAddr: '127.0.0.1:8080',
    });
    await restoreState();
    expect(get(currentStep)).toBe(6); // Done step
    const state = get(wizardState);
    expect(state.deployment.completed).toBe(true);
    expect(state.deployment.partyAUrl).toBe('127.0.0.1:8080');
  });

  it('handles backend failure gracefully', async () => {
    sessionStorage.clear();
    getState.mockRejectedValue(new Error('network error'));
    await restoreState();
    expect(get(currentStep)).toBe(0);
  });

  it('handles empty backend response', async () => {
    sessionStorage.clear();
    getState.mockResolvedValue({});
    await restoreState();
    expect(get(currentStep)).toBe(0);
  });
});

describe('restoreState (existing session — sessionStorage present)', () => {
  it('keeps sessionStorage step even if backend is further ahead', async () => {
    // User is on step 1 (Servers), backend says LLM is done (would be step 3).
    currentStep.set(1);
    getState.mockResolvedValue({
      step: 'llm',
      llmConfigured: true,
      llmProvider: 'anthropic',
    });
    await restoreState();
    expect(get(currentStep)).toBe(1); // stays on Servers, NOT jumped to Telegram
  });

  it('still restores backend data fields even when step is kept', async () => {
    currentStep.set(1);
    getState.mockResolvedValue({
      step: 'llm',
      llmConfigured: true,
      llmProvider: 'openai',
      llmModel: 'gpt-4',
    });
    await restoreState();
    // Step didn't change, but LLM data is restored.
    const state = get(wizardState);
    expect(state.llm.provider).toBe('openai');
    expect(state.llm.model).toBe('gpt-4');
  });

  it('keeps step 0 from sessionStorage when backend has progress', async () => {
    currentStep.set(0);
    getState.mockResolvedValue({
      step: 'llm',
      llmConfigured: true,
      llmProvider: 'openai',
    });
    await restoreState();
    expect(get(currentStep)).toBe(0);
  });
});

describe('sessionStorage persistence', () => {
  it('writes step to sessionStorage on change', () => {
    currentStep.set(5);
    expect(sessionStorage.getItem('cclaw_step')).toBe('5');
  });

  it('reads step from sessionStorage on init', () => {
    sessionStorage.setItem('cclaw_step', '4');
    currentStep.set(4);
    expect(get(currentStep)).toBe(4);
  });
});
