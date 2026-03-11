import { writable } from 'svelte/store';
import { getState } from './api.js';

const STEP_KEY = 'cclaw_step';

function loadStep() {
  try {
    const v = sessionStorage.getItem(STEP_KEY);
    if (v !== null) return parseInt(v, 10);
  } catch { /* SSR / test */ }
  return 0;
}

export const currentStep = writable(loadStep());

// Persist every step change to sessionStorage.
currentStep.subscribe((s) => {
  try { sessionStorage.setItem(STEP_KEY, String(s)); } catch { /* noop */ }
});

const defaultState = {
  servers: {
    localMode: false,
    partyA: {
      host: '',
      port: '22',
      username: '',
      password: '',
      sshKeyPath: '',
      useSSHKey: false,
      tested: false,
      connected: false,
    },
    partyB: {
      host: '',
      port: '22',
      username: '',
      password: '',
      sshKeyPath: '',
      useSSHKey: false,
      tested: false,
      connected: false,
    },
    transportPort: '443',
  },
  disableAI: false,
  llm: {
    provider: 'anthropic',
    apiKey: '',
    model: 'claude-sonnet-4-20250514',
    localEndpoint: '',
  },
  telegram: {
    botToken: '',
    botUsername: '',
  },
  deployment: {
    started: false,
    completed: false,
    success: false,
    partyAUrl: '',
  },
};

export const wizardState = writable({ ...defaultState });

export const deployLogs = writable([]);

export const isLoading = writable(false);

// Map backend step names to the frontend step index.
// New flow: Welcome(0) → Servers(1) → LLM(2) → Telegram(3) → Review(4) → Install(5) → Done(6)
const stepMap = {
  welcome: 0,
  servers: 2,    // servers done → go to LLM
  llm: 3,        // LLM done → go to Telegram
  telegram: 4,   // telegram saved → go to Review
  prepared: 5,   // mnemonic generated → Install step
  deploying: 5,  // deployment in progress → Install step
  done: 6,
};

// Restore wizard progress from backend state on page load.
// sessionStorage holds the user's exact position (set on every step change).
// The backend step is only used on a truly fresh session (no sessionStorage)
// to avoid starting from zero when the server already has progress.
export async function restoreState() {
  try {
    const backend = await getState();
    if (!backend || !backend.step || backend.step === 'welcome') return;

    const hasSession = sessionStorage.getItem(STEP_KEY) !== null;
    if (!hasSession) {
      // First visit in this session — use backend as starting point.
      const step = stepMap[backend.step];
      if (step !== undefined && step > 0) {
        currentStep.set(step);
      }
    }
    // If sessionStorage already has a step, we keep it (set during loadStep).

    // Restore frontend store fields from backend.
    wizardState.update((s) => {
      const updated = { ...s };

      if (backend.localMode) {
        updated.servers = { ...s.servers, localMode: true };
      }
      if (backend.serverA?.host) {
        updated.servers = {
          ...updated.servers,
          partyA: {
            ...updated.servers.partyA,
            host: backend.serverA.host,
            port: String(backend.serverA.port || 22),
            username: backend.serverA.user || '',
            tested: true,
            connected: true,
          },
        };
      }
      if (backend.serverB?.host) {
        updated.servers = {
          ...updated.servers,
          partyB: {
            ...updated.servers.partyB,
            host: backend.serverB.host,
            port: String(backend.serverB.port || 22),
            username: backend.serverB.user || '',
            tested: true,
            connected: true,
          },
        };
      }

      if (backend.llmConfigured) {
        updated.disableAI = !!backend.disableAI;
        updated.llm = {
          ...s.llm,
          provider: backend.disableAI ? '' : (backend.llmProvider || s.llm.provider),
          model: backend.disableAI ? '' : (backend.llmModel || s.llm.model),
          localEndpoint: backend.llmEndpoint || '',
        };
      }

      if (backend.telegramConfigured) {
        updated.telegram = {
          ...s.telegram,
          botUsername: backend.telegramBotUsername || '',
        };
      }

      if (backend.deployDone) {
        updated.deployment = {
          ...s.deployment,
          started: true,
          completed: true,
          success: true,
          partyAUrl: backend.partyAAddr || '',
        };
      }

      return updated;
    });
  } catch {
    // Backend not reachable — start fresh.
  }
}
