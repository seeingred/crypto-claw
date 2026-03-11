<script>
  import Button from '../components/Button.svelte';
  import Card from '../components/Card.svelte';
  import Input from '../components/Input.svelte';
  import Alert from '../components/Alert.svelte';
  import { currentStep, wizardState, isLoading } from '../stores.js';
  import { testSSHConnection, saveServers, uploadSSHKey } from '../api.js';

  let testingA = $state(false);
  let testingB = $state(false);
  let errorA = $state('');
  let errorB = $state('');
  let uploadingKeyA = $state(false);
  let uploadingKeyB = $state(false);
  let keyFileNameA = $state('');
  let keyFileNameB = $state('');
  let dragOverA = $state(false);
  let dragOverB = $state(false);
  let globalDrag = $state(false);
  let globalDragCounter = 0;

  function onWindowDragEnter(e) {
    e.preventDefault();
    globalDragCounter++;
    if (globalDragCounter === 1 && !localMode) globalDrag = true;
  }
  function onWindowDragLeave(e) {
    e.preventDefault();
    globalDragCounter--;
    if (globalDragCounter <= 0) { globalDrag = false; globalDragCounter = 0; }
  }
  function onWindowDragOver(e) { e.preventDefault(); }
  function onWindowDrop(e) {
    e.preventDefault();
    globalDrag = false;
    globalDragCounter = 0;
  }

  function handleOverlayDrop(party, e) {
    e.preventDefault();
    e.stopPropagation();
    globalDrag = false;
    globalDragCounter = 0;
    dragOverA = false;
    dragOverB = false;
    const file = e.dataTransfer?.files?.[0];
    if (file) {
      // Auto-switch to SSH key mode
      if (party === 'partyA' && !state.servers?.partyA?.useSSHKey) toggleSSHKey('partyA');
      if (party === 'partyB' && !state.servers?.partyB?.useSSHKey) toggleSSHKey('partyB');
      handleKeyUpload(party, file);
    }
  }

  async function handleKeyUpload(party, file) {
    if (!file) return;
    const isA = party === 'partyA';
    if (isA) { uploadingKeyA = true; errorA = ''; }
    else { uploadingKeyB = true; errorB = ''; }
    try {
      const result = await uploadSSHKey(file);
      updateServer(party, 'sshKeyPath', result.path);
      if (isA) keyFileNameA = file.name;
      else keyFileNameB = file.name;
    } catch (err) {
      if (isA) errorA = err.message;
      else errorB = err.message;
    } finally {
      if (isA) uploadingKeyA = false;
      else uploadingKeyB = false;
    }
  }

  function handleDrop(party, e) {
    e.preventDefault();
    if (party === 'partyA') dragOverA = false;
    else dragOverB = false;
    const file = e.dataTransfer?.files?.[0];
    if (file) handleKeyUpload(party, file);
  }

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
      user: server.username,
      ...(server.useSSHKey
        ? { keyPath: server.sshKeyPath }
        : { password: server.password }),
    };

    try {
      const result = await testSSHConnection(config);
      if (result.success) {
        wizardState.update((s) => ({
          ...s,
          servers: {
            ...s.servers,
            [party]: { ...s.servers[party], tested: true, connected: true },
          },
        }));
      } else {
        if (isA) errorA = result.error || 'Connection failed';
        else errorB = result.error || 'Connection failed';
        wizardState.update((s) => ({
          ...s,
          servers: {
            ...s.servers,
            [party]: { ...s.servers[party], tested: true, connected: false },
          },
        }));
      }
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
      await saveServers(state.servers.partyA, state.servers.partyB, localMode, state.servers.transportPort);
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

<!-- svelte-ignore a11y_no_static_element_interactions -->
<svelte:window
  ondragenter={onWindowDragEnter}
  ondragleave={onWindowDragLeave}
  ondragover={onWindowDragOver}
  ondrop={onWindowDrop}
/>

{#if globalDrag}
  <div class="fixed inset-0 z-50 bg-black/50 backdrop-blur-sm flex items-stretch gap-0">
    <div
      class="flex-1 flex flex-col items-center justify-center gap-3 transition-all border-r border-white/10
        {dragOverA ? 'bg-indigo-500/20' : 'bg-transparent hover:bg-white/5'}"
      ondragover={(e) => { e.preventDefault(); dragOverA = true; }}
      ondragleave={() => { dragOverA = false; }}
      ondrop={(e) => handleOverlayDrop('partyA', e)}
    >
      <div class="w-14 h-14 rounded-xl bg-indigo-500 text-white flex items-center justify-center text-2xl font-bold {dragOverA ? 'scale-110' : ''} transition-transform">A</div>
      <span class="text-white font-semibold text-lg">Party A - AI Server</span>
      <span class="text-white/60 text-sm">Drop SSH key here</span>
    </div>
    <div
      class="flex-1 flex flex-col items-center justify-center gap-3 transition-all
        {dragOverB ? 'bg-emerald-500/20' : 'bg-transparent hover:bg-white/5'}"
      ondragover={(e) => { e.preventDefault(); dragOverB = true; }}
      ondragleave={() => { dragOverB = false; }}
      ondrop={(e) => handleOverlayDrop('partyB', e)}
    >
      <div class="w-14 h-14 rounded-xl bg-emerald-500 text-white flex items-center justify-center text-2xl font-bold {dragOverB ? 'scale-110' : ''} transition-transform">B</div>
      <span class="text-white font-semibold text-lg">Party B - Secure Server</span>
      <span class="text-white/60 text-sm">Drop SSH key here</span>
    </div>
  </div>
{/if}

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
            <div class="space-y-1.5">
              <label class="block text-sm font-medium text-gray-700 dark:text-gray-300">SSH Private Key</label>
              <!-- svelte-ignore a11y_no_static_element_interactions -->
              <div
                class="relative flex items-center justify-center rounded-lg border-2 border-dashed px-4 py-4 text-center transition-colors cursor-pointer
                  {dragOverA ? 'border-indigo-500 bg-indigo-50 dark:bg-indigo-900/20' : 'border-gray-300 dark:border-gray-600 hover:border-gray-400 dark:hover:border-gray-500'}"
                ondragover={(e) => { e.preventDefault(); dragOverA = true; }}
                ondragleave={() => { dragOverA = false; }}
                ondrop={(e) => handleDrop('partyA', e)}
                onclick={() => document.getElementById('key-upload-a')?.click()}
                onkeydown={(e) => { if (e.key === 'Enter' || e.key === ' ') document.getElementById('key-upload-a')?.click(); }}
              >
                <input
                  id="key-upload-a"
                  type="file"
                  class="hidden"
                  onchange={(e) => handleKeyUpload('partyA', e.target.files?.[0])}
                />
                {#if uploadingKeyA}
                  <span class="text-sm text-gray-500">Uploading...</span>
                {:else if state.servers?.partyA?.sshKeyPath}
                  <div class="flex items-center gap-2">
                    <svg class="w-5 h-5 text-emerald-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z"/></svg>
                    <span class="text-sm text-gray-700 dark:text-gray-300">{keyFileNameA || 'Key uploaded'}</span>
                  </div>
                {:else}
                  <div class="text-sm text-gray-500 dark:text-gray-400">
                    <span class="font-medium text-indigo-600 dark:text-indigo-400">Click to browse</span> or drag & drop your private key
                  </div>
                {/if}
              </div>
            </div>
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
            <div class="space-y-1.5">
              <label class="block text-sm font-medium text-gray-700 dark:text-gray-300">SSH Private Key</label>
              <!-- svelte-ignore a11y_no_static_element_interactions -->
              <div
                class="relative flex items-center justify-center rounded-lg border-2 border-dashed px-4 py-4 text-center transition-colors cursor-pointer
                  {dragOverB ? 'border-indigo-500 bg-indigo-50 dark:bg-indigo-900/20' : 'border-gray-300 dark:border-gray-600 hover:border-gray-400 dark:hover:border-gray-500'}"
                ondragover={(e) => { e.preventDefault(); dragOverB = true; }}
                ondragleave={() => { dragOverB = false; }}
                ondrop={(e) => handleDrop('partyB', e)}
                onclick={() => document.getElementById('key-upload-b')?.click()}
                onkeydown={(e) => { if (e.key === 'Enter' || e.key === ' ') document.getElementById('key-upload-b')?.click(); }}
              >
                <input
                  id="key-upload-b"
                  type="file"
                  class="hidden"
                  onchange={(e) => handleKeyUpload('partyB', e.target.files?.[0])}
                />
                {#if uploadingKeyB}
                  <span class="text-sm text-gray-500">Uploading...</span>
                {:else if state.servers?.partyB?.sshKeyPath}
                  <div class="flex items-center gap-2">
                    <svg class="w-5 h-5 text-emerald-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z"/></svg>
                    <span class="text-sm text-gray-700 dark:text-gray-300">{keyFileNameB || 'Key uploaded'}</span>
                  </div>
                {:else}
                  <div class="text-sm text-gray-500 dark:text-gray-400">
                    <span class="font-medium text-indigo-600 dark:text-indigo-400">Click to browse</span> or drag & drop your private key
                  </div>
                {/if}
              </div>
            </div>
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

    <!-- Transport port setting -->
    <div class="mt-6 p-4 rounded-lg bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700">
      <div class="flex items-center gap-4">
        <div class="flex-1">
          <span class="text-sm font-medium text-gray-900 dark:text-white">mTLS Transport Port</span>
          <p class="text-xs text-gray-500 dark:text-gray-400">
            Port for encrypted communication between Party A and Party B. Default 443 works through most firewalls.
          </p>
        </div>
        <div class="w-28">
          <Input
            type="number"
            placeholder="443"
            value={state.servers?.transportPort ?? '443'}
            oninput={(e) => wizardState.update((s) => ({
              ...s,
              servers: { ...s.servers, transportPort: e.target.value },
            }))}
          />
        </div>
      </div>
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
