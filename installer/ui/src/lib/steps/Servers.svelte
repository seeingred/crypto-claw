<script>
  import Button from '../components/Button.svelte';
  import Card from '../components/Card.svelte';
  import Input from '../components/Input.svelte';
  import Alert from '../components/Alert.svelte';
  import { currentStep, wizardState, isLoading } from '../stores.js';
  import { testSSHConnection, saveServers } from '../api.js';

  let testingA = $state(false);
  let testingB = $state(false);
  let errorA = $state('');
  let errorB = $state('');

  let state = $state({});
  wizardState.subscribe((s) => (state = s));

  let localMode = $derived(state.servers?.localMode ?? false);

  function setLocalMode(checked) {
    wizardState.update((s) => ({
      ...s,
      servers: { ...s.servers, localMode: checked },
    }));
  }

  function updateServer(party, field, value) {
    wizardState.update((s) => ({
      ...s,
      servers: {
        ...s.servers,
        [party]: { ...s.servers[party], [field]: value, tested: false, connected: false },
      },
    }));
  }

  function toggleSSHKey(party) {
    wizardState.update((s) => ({
      ...s,
      servers: {
        ...s.servers,
        [party]: {
          ...s.servers[party],
          useSSHKey: !s.servers[party].useSSHKey,
          tested: false,
          connected: false,
        },
      },
    }));
  }

  async function testConnection(party) {
    const isA = party === 'partyA';
    if (isA) {
      testingA = true;
      errorA = '';
    } else {
      testingB = true;
      errorB = '';
    }

    const server = state.servers[party];
    const config = {
      host: server.host,
      port: parseInt(server.port, 10),
      username: server.username,
      ...(server.useSSHKey
        ? { sshKeyPath: server.sshKeyPath }
        : { password: server.password }),
    };

    try {
      await testSSHConnection(config);
      wizardState.update((s) => ({
        ...s,
        servers: {
          ...s.servers,
          [party]: { ...s.servers[party], tested: true, connected: true },
        },
      }));
    } catch (err) {
      if (isA) errorA = err.message;
      else errorB = err.message;
      wizardState.update((s) => ({
        ...s,
        servers: {
          ...s.servers,
          [party]: { ...s.servers[party], tested: true, connected: false },
        },
      }));
    } finally {
      if (isA) testingA = false;
      else testingB = false;
    }
  }

  let canProceed = $derived(
    localMode ||
      (state.servers?.partyA?.connected && state.servers?.partyB?.connected)
  );

  async function handleNext() {
    isLoading.set(true);
    try {
      await saveServers(state.servers.partyA, state.servers.partyB, localMode);
      currentStep.update((n) => n + 1);
    } catch {
      // Proceed anyway if the backend is not available during development
      currentStep.update((n) => n + 1);
    } finally {
      isLoading.set(false);
    }
  }

  function handleBack() {
    currentStep.update((n) => n - 1);
  }
</script>

<div class="max-w-5xl mx-auto animate-fade-in">
  <div class="text-center mb-8">
    <h2 class="text-3xl font-bold text-gray-900 dark:text-white mb-2">
      Server Configuration
    </h2>
    <p class="text-gray-600 dark:text-gray-400">
      Configure the two servers for the threshold signing architecture.
    </p>
  </div>

  <!-- Local mode toggle -->
  <div class="mb-6">
    <label
      class="flex items-center gap-3 p-4 rounded-lg bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-750 transition-colors"
    >
      <input
        type="checkbox"
        checked={localMode}
        onchange={(e) => setLocalMode(e.target.checked)}
        class="w-4 h-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500"
      />
      <div>
        <span class="text-sm font-medium text-gray-900 dark:text-white"
          >Install locally (for testing)</span
        >
        <p class="text-xs text-gray-500 dark:text-gray-400">
          Run both services on this machine instead of remote servers
        </p>
      </div>
    </label>
  </div>

  {#if !localMode}
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
      <!-- Party A -->
      <Card>
        <div class="flex items-center gap-2 mb-4">
          <div
            class="w-8 h-8 rounded-lg bg-indigo-500 text-white flex items-center justify-center text-sm font-bold"
          >
            A
          </div>
          <div>
            <h3 class="font-semibold text-gray-900 dark:text-white">
              Party A - AI Server
            </h3>
            <p class="text-xs text-gray-500 dark:text-gray-400">
              TSS signer + trading bot
            </p>
          </div>
          {#if state.servers?.partyA?.connected}
            <div class="ml-auto">
              <span
                class="inline-flex items-center gap-1 px-2 py-1 text-xs font-medium text-emerald-700 dark:text-emerald-400 bg-emerald-100 dark:bg-emerald-900/30 rounded-full"
              >
                <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="3">
                  <path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7" />
                </svg>
                Connected
              </span>
            </div>
          {/if}
        </div>

        <div class="space-y-3">
          <div class="grid grid-cols-3 gap-3">
            <div class="col-span-2">
              <Input
                label="Host"
                placeholder="192.168.1.100"
                value={state.servers?.partyA?.host ?? ''}
                oninput={(e) => updateServer('partyA', 'host', e.target.value)}
              />
            </div>
            <Input
              label="Port"
              type="number"
              placeholder="22"
              value={state.servers?.partyA?.port ?? '22'}
              oninput={(e) => updateServer('partyA', 'port', e.target.value)}
            />
          </div>

          <Input
            label="Username"
            placeholder="root"
            value={state.servers?.partyA?.username ?? ''}
            oninput={(e) => updateServer('partyA', 'username', e.target.value)}
          />

          <div class="flex items-center gap-2 pt-1">
            <button
              type="button"
              class="text-xs font-medium px-2 py-1 rounded transition-colors
                {state.servers?.partyA?.useSSHKey
                ? 'text-gray-500 dark:text-gray-400 hover:text-gray-700'
                : 'text-indigo-600 dark:text-indigo-400 bg-indigo-50 dark:bg-indigo-900/30'}"
              onclick={() => {
                if (state.servers?.partyA?.useSSHKey) toggleSSHKey('partyA');
              }}
            >
              Password
            </button>
            <button
              type="button"
              class="text-xs font-medium px-2 py-1 rounded transition-colors
                {state.servers?.partyA?.useSSHKey
                ? 'text-indigo-600 dark:text-indigo-400 bg-indigo-50 dark:bg-indigo-900/30'
                : 'text-gray-500 dark:text-gray-400 hover:text-gray-700'}"
              onclick={() => {
                if (!state.servers?.partyA?.useSSHKey) toggleSSHKey('partyA');
              }}
            >
              SSH Key
            </button>
          </div>

          {#if state.servers?.partyA?.useSSHKey}
            <Input
              label="SSH Key Path"
              placeholder="~/.ssh/id_rsa"
              value={state.servers?.partyA?.sshKeyPath ?? ''}
              oninput={(e) =>
                updateServer('partyA', 'sshKeyPath', e.target.value)}
            />
          {:else}
            <Input
              label="Password"
              type="password"
              placeholder="Enter password"
              value={state.servers?.partyA?.password ?? ''}
              oninput={(e) =>
                updateServer('partyA', 'password', e.target.value)}
            />
          {/if}

          {#if errorA}
            <Alert variant="error" title="Connection Failed">
              <p>{errorA}</p>
            </Alert>
          {/if}

          <Button
            variant="secondary"
            size="sm"
            loading={testingA}
            onclick={() => testConnection('partyA')}
          >
            Test Connection
          </Button>
        </div>
      </Card>

      <!-- Party B -->
      <Card>
        <div class="flex items-center gap-2 mb-4">
          <div
            class="w-8 h-8 rounded-lg bg-emerald-500 text-white flex items-center justify-center text-sm font-bold"
          >
            B
          </div>
          <div>
            <h3 class="font-semibold text-gray-900 dark:text-white">
              Party B - Secure Server
            </h3>
            <p class="text-xs text-gray-500 dark:text-gray-400">
              Co-signer + LLM validator
            </p>
          </div>
          {#if state.servers?.partyB?.connected}
            <div class="ml-auto">
              <span
                class="inline-flex items-center gap-1 px-2 py-1 text-xs font-medium text-emerald-700 dark:text-emerald-400 bg-emerald-100 dark:bg-emerald-900/30 rounded-full"
              >
                <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="3">
                  <path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7" />
                </svg>
                Connected
              </span>
            </div>
          {/if}
        </div>

        <div class="space-y-3">
          <div class="grid grid-cols-3 gap-3">
            <div class="col-span-2">
              <Input
                label="Host"
                placeholder="192.168.1.101"
                value={state.servers?.partyB?.host ?? ''}
                oninput={(e) => updateServer('partyB', 'host', e.target.value)}
              />
            </div>
            <Input
              label="Port"
              type="number"
              placeholder="22"
              value={state.servers?.partyB?.port ?? '22'}
              oninput={(e) => updateServer('partyB', 'port', e.target.value)}
            />
          </div>

          <Input
            label="Username"
            placeholder="root"
            value={state.servers?.partyB?.username ?? ''}
            oninput={(e) => updateServer('partyB', 'username', e.target.value)}
          />

          <div class="flex items-center gap-2 pt-1">
            <button
              type="button"
              class="text-xs font-medium px-2 py-1 rounded transition-colors
                {state.servers?.partyB?.useSSHKey
                ? 'text-gray-500 dark:text-gray-400 hover:text-gray-700'
                : 'text-indigo-600 dark:text-indigo-400 bg-indigo-50 dark:bg-indigo-900/30'}"
              onclick={() => {
                if (state.servers?.partyB?.useSSHKey) toggleSSHKey('partyB');
              }}
            >
              Password
            </button>
            <button
              type="button"
              class="text-xs font-medium px-2 py-1 rounded transition-colors
                {state.servers?.partyB?.useSSHKey
                ? 'text-indigo-600 dark:text-indigo-400 bg-indigo-50 dark:bg-indigo-900/30'
                : 'text-gray-500 dark:text-gray-400 hover:text-gray-700'}"
              onclick={() => {
                if (!state.servers?.partyB?.useSSHKey) toggleSSHKey('partyB');
              }}
            >
              SSH Key
            </button>
          </div>

          {#if state.servers?.partyB?.useSSHKey}
            <Input
              label="SSH Key Path"
              placeholder="~/.ssh/id_rsa"
              value={state.servers?.partyB?.sshKeyPath ?? ''}
              oninput={(e) =>
                updateServer('partyB', 'sshKeyPath', e.target.value)}
            />
          {:else}
            <Input
              label="Password"
              type="password"
              placeholder="Enter password"
              value={state.servers?.partyB?.password ?? ''}
              oninput={(e) =>
                updateServer('partyB', 'password', e.target.value)}
            />
          {/if}

          {#if errorB}
            <Alert variant="error" title="Connection Failed">
              <p>{errorB}</p>
            </Alert>
          {/if}

          <Button
            variant="secondary"
            size="sm"
            loading={testingB}
            onclick={() => testConnection('partyB')}
          >
            Test Connection
          </Button>
        </div>
      </Card>
    </div>
  {:else}
    <Alert variant="info" title="Local Mode">
      <p>
        Both Party A and Party B services will be installed on this machine.
        This is suitable for testing and development only.
      </p>
    </Alert>
  {/if}

  <div class="flex justify-between mt-8">
    <Button variant="ghost" onclick={handleBack}>
      <svg class="w-4 h-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
        <path stroke-linecap="round" stroke-linejoin="round" d="M11 17l-5-5m0 0l5-5m-5 5h12" />
      </svg>
      Back
    </Button>
    <Button disabled={!canProceed} onclick={handleNext}>
      Next
      <svg class="w-4 h-4 ml-1" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
        <path stroke-linecap="round" stroke-linejoin="round" d="M13 7l5 5m0 0l-5 5m5-5H6" />
      </svg>
    </Button>
  </div>
</div>
