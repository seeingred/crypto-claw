import { writable } from 'svelte/store';

export const currentStep = writable(0);

export const wizardState = writable({
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
  },
  dkg: {
    completed: false,
    ecdsaPublicKey: '',
    eddsaPublicKey: '',
    seedPhraseA: '',
    seedPhraseB: '',
    seedSaved: false,
  },
  llm: {
    provider: 'anthropic',
    apiKey: '',
    model: 'claude-sonnet-4-20250514',
    localEndpoint: '',
  },
  telegram: {
    botToken: '',
    userId: '',
    authorized: false,
  },
  deployment: {
    started: false,
    completed: false,
    success: false,
    partyAUrl: '',
  },
});

export const deployLogs = writable([]);

export const isLoading = writable(false);
