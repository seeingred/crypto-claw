<script>
  import Button from '../components/Button.svelte';
  import Card from '../components/Card.svelte';
  import Alert from '../components/Alert.svelte';
  import { currentStep, wizardState, deployLogs } from '../stores.js';
  import { installRestore, startUpdate, subscribeDeployLogs } from '../api.js';

  let mode = $state('choose'); // choose | restore | updating | updateDone | updateError
  let restoreMnemonic = $state('');
  let errorMsg = $state('');
  let logs = $state([]);
  let progress = $state(0);
  let logContainer = $state(null);
  let unsubscribeLogs = null;

  function handleNewInstall() {
    wizardState.update((s) => ({ ...s, installMode: 'install' }));
    currentStep.update((n) => n + 1);
  }

  function handleRestoreClick() {
    mode = 'restore';
  }

  async function submitRestore() {
    const words = restoreMnemonic.trim();
    if (!words) {
      errorMsg = 'Please enter your recovery phrase';
      return;
    }
    const wordCount = words.split(/\s+/).length;
    if (wordCount !== 24 && wordCount !== 12) {
      errorMsg = `Recovery phrase should be 12 or 24 words (got ${wordCount})`;
      return;
    }
    errorMsg = '';
    try {
      const result = await installRestore(words);
      wizardState.update((s) => ({
        ...s,
        installMode: 'restore',
        restoredEcdsaPub: result.ecdsaPubKey,
        restoredEddsaPub: result.eddsaPubKey,
      }));
      // Skip to servers step (step 1)
      currentStep.update((n) => n + 1);
    } catch (err) {
      errorMsg = err.message || 'Failed to restore from recovery phrase';
    }
  }

  let logCount = 0;
  const EXPECTED_LOG_COUNT = 8;

  function addLog(message) {
    deployLogs.update((l) => [
      ...l,
      { time: new Date().toISOString(), message },
    ]);
    if (logContainer) {
      requestAnimationFrame(() => {
        if (logContainer) logContainer.scrollTop = logContainer.scrollHeight;
      });
    }
  }

  async function handleUpdate() {
    mode = 'updating';
    deployLogs.set([]);
    progress = 0;
    logCount = 0;

    unsubscribeLogs = subscribeDeployLogs((data) => {
      if (data.type === 'complete') {
        mode = 'updateDone';
        progress = 100;
        addLog(data.message || 'Update complete');
        return;
      }
      if (data.type === 'error') {
        mode = 'updateError';
        errorMsg = data.message || 'Update failed';
        addLog(data.message);
        return;
      }
      logCount++;
      progress = Math.min(95, Math.round((logCount / EXPECTED_LOG_COUNT) * 100));
      addLog(data.message || JSON.stringify(data));
    });

    try {
      await startUpdate();
    } catch (err) {
      if (mode !== 'updateError' && mode !== 'updateDone') {
        errorMsg = err.message || 'Failed to start update';
        mode = 'updateError';
      }
    }
  }

  deployLogs.subscribe((l) => (logs = l));
</script>

<div class="max-w-4xl mx-auto animate-fade-in">
  {#if mode === 'choose'}
    <div class="text-center mb-8">
      <div
        class="inline-flex items-center justify-center w-20 h-20 rounded-2xl bg-indigo-100 dark:bg-indigo-900/50 mb-6 animate-float"
      >
        <svg
          class="w-10 h-10 text-indigo-600 dark:text-indigo-400"
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          stroke-width="1.5"
        >
          <path
            stroke-linecap="round"
            stroke-linejoin="round"
            d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z"
          />
        </svg>
      </div>
      <h1 class="text-4xl font-bold text-gray-900 dark:text-white mb-3">
        Crypto Claw Setup Wizard
      </h1>
      <p class="text-lg text-gray-600 dark:text-gray-400 max-w-2xl mx-auto">
        Set up your secure two-server threshold signing architecture for
        autonomous crypto trading with AI-powered transaction validation.
      </p>
    </div>

    <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
      <!-- New Install -->
      <button
        onclick={handleNewInstall}
        class="text-left p-6 rounded-xl border-2 border-gray-200 dark:border-gray-700 hover:border-indigo-500 dark:hover:border-indigo-500 bg-white dark:bg-gray-800 transition-all hover:shadow-lg cursor-pointer"
      >
        <div class="inline-flex items-center justify-center w-12 h-12 rounded-full bg-indigo-100 dark:bg-indigo-900/50 mb-4">
          <svg class="w-6 h-6 text-indigo-600 dark:text-indigo-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.5">
            <path stroke-linecap="round" stroke-linejoin="round" d="M12 4.5v15m7.5-7.5h-15" />
          </svg>
        </div>
        <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-2">New Install</h3>
        <p class="text-sm text-gray-600 dark:text-gray-400">
          Generate a new recovery phrase and set up fresh wallet keys from scratch.
        </p>
      </button>

      <!-- Restore -->
      <button
        onclick={handleRestoreClick}
        class="text-left p-6 rounded-xl border-2 border-gray-200 dark:border-gray-700 hover:border-emerald-500 dark:hover:border-emerald-500 bg-white dark:bg-gray-800 transition-all hover:shadow-lg cursor-pointer"
      >
        <div class="inline-flex items-center justify-center w-12 h-12 rounded-full bg-emerald-100 dark:bg-emerald-900/50 mb-4">
          <svg class="w-6 h-6 text-emerald-600 dark:text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.5">
            <path stroke-linecap="round" stroke-linejoin="round" d="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0l3.181 3.183a8.25 8.25 0 0013.803-3.7M4.031 9.865a8.25 8.25 0 0113.803-3.7l3.181 3.182" />
          </svg>
        </div>
        <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-2">Restore</h3>
        <p class="text-sm text-gray-600 dark:text-gray-400">
          Restore from an existing 24-word recovery phrase. All derived addresses will be recoverable.
        </p>
      </button>

      <!-- Update -->
      <button
        onclick={handleUpdate}
        class="text-left p-6 rounded-xl border-2 border-gray-200 dark:border-gray-700 hover:border-amber-500 dark:hover:border-amber-500 bg-white dark:bg-gray-800 transition-all hover:shadow-lg cursor-pointer"
      >
        <div class="inline-flex items-center justify-center w-12 h-12 rounded-full bg-amber-100 dark:bg-amber-900/50 mb-4">
          <svg class="w-6 h-6 text-amber-600 dark:text-amber-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.5">
            <path stroke-linecap="round" stroke-linejoin="round" d="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0l3.181 3.183a8.25 8.25 0 0013.803-3.7M4.031 9.865a8.25 8.25 0 0113.803-3.7l3.181 3.182" />
          </svg>
        </div>
        <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-2">Update</h3>
        <p class="text-sm text-gray-600 dark:text-gray-400">
          Redeploy with new code. Keeps existing keys, config, and certificates.
        </p>
      </button>
    </div>

  {:else if mode === 'restore'}
    <!-- Restore: enter mnemonic -->
    <div class="text-center mb-8">
      <h2 class="text-3xl font-bold text-gray-900 dark:text-white mb-2">
        Restore from Recovery Phrase
      </h2>
      <p class="text-gray-600 dark:text-gray-400">
        Enter your 24-word BIP-39 recovery phrase, then continue through the setup wizard.
      </p>
    </div>

    <Card>
      <div class="space-y-4">
        <textarea
          bind:value={restoreMnemonic}
          placeholder="Enter your 24-word recovery phrase, separated by spaces..."
          rows="4"
          class="w-full px-4 py-3 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-900 text-gray-900 dark:text-white font-mono text-sm focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 outline-none resize-none"
        ></textarea>

        {#if errorMsg}
          <Alert variant="error" title="Error">
            <p>{errorMsg}</p>
          </Alert>
        {/if}
      </div>
    </Card>

    <div class="flex justify-between mt-8">
      <Button variant="ghost" onclick={() => { mode = 'choose'; errorMsg = ''; }}>
        <svg class="w-4 h-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M11 17l-5-5m0 0l5-5m-5 5h12" />
        </svg>
        Back
      </Button>
      <Button variant="success" size="lg" onclick={submitRestore}>
        Restore & Continue
        <svg class="w-4 h-4 ml-1" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M13 7l5 5m0 0l-5 5m5-5H6" />
        </svg>
      </Button>
    </div>

  {:else if mode === 'updating' || mode === 'updateDone'}
    <!-- Update progress -->
    <div class="text-center mb-8">
      <h2 class="text-3xl font-bold text-gray-900 dark:text-white mb-2">
        {mode === 'updateDone' ? 'Update Complete' : 'Updating...'}
      </h2>
      <p class="text-gray-600 dark:text-gray-400">
        {#if mode === 'updating'}
          Restarting services with new code.
        {:else}
          All services have been restarted successfully.
        {/if}
      </p>
    </div>

    <div class="mb-6">
      <div class="flex items-center justify-between mb-2">
        <span class="text-sm font-medium text-gray-700 dark:text-gray-300">Progress</span>
        <span class="text-sm font-medium text-gray-700 dark:text-gray-300">{progress}%</span>
      </div>
      <div class="w-full h-3 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
        <div
          class="h-full rounded-full transition-all duration-500 ease-out {mode === 'updateDone' ? 'bg-emerald-500' : 'bg-amber-500'}"
          style="width: {progress}%"
        ></div>
      </div>
    </div>

    {#if mode === 'updateDone'}
      <div class="mb-6">
        <Alert variant="success" title="Update Complete">
          <p>All services are running with the latest code.</p>
        </Alert>
      </div>
    {/if}

    <div class="bg-gray-900 dark:bg-black rounded-xl border border-gray-700 overflow-hidden">
      <div class="flex items-center gap-2 px-4 py-2.5 bg-gray-800 dark:bg-gray-900 border-b border-gray-700">
        <div class="flex gap-1.5">
          <div class="w-3 h-3 rounded-full bg-red-500"></div>
          <div class="w-3 h-3 rounded-full bg-yellow-500"></div>
          <div class="w-3 h-3 rounded-full bg-green-500"></div>
        </div>
        <span class="text-xs text-gray-400 ml-2">Update Logs</span>
      </div>
      <div bind:this={logContainer} class="p-4 h-64 overflow-y-auto">
        {#each logs as log}
          <div class="terminal-log text-gray-300">
            <span class="text-gray-500">[{new Date(log.time).toLocaleTimeString()}]</span>
            {' '}{log.message}
          </div>
        {/each}
        {#if mode === 'updating'}
          <div class="terminal-log text-gray-500 animate-pulse">
            <span class="inline-block w-2 h-4 bg-gray-400 ml-1"></span>
          </div>
        {/if}
      </div>
    </div>

    {#if mode === 'updateDone'}
      <div class="flex justify-center mt-8">
        <Button size="lg" onclick={() => { if (typeof window !== 'undefined') window.close(); }}>
          Close Wizard
        </Button>
      </div>
    {/if}

  {:else if mode === 'updateError'}
    <div class="text-center mb-8">
      <h2 class="text-3xl font-bold text-gray-900 dark:text-white mb-2">
        Update Failed
      </h2>
    </div>

    <Alert variant="error" title="Error">
      <p>{errorMsg || 'An unexpected error occurred.'}</p>
    </Alert>

    {#if logs.length > 0}
      <div class="mt-4 bg-gray-900 dark:bg-black rounded-xl border border-gray-700 overflow-hidden">
        <div class="flex items-center gap-2 px-4 py-2.5 bg-gray-800 dark:bg-gray-900 border-b border-gray-700">
          <div class="flex gap-1.5">
            <div class="w-3 h-3 rounded-full bg-red-500"></div>
            <div class="w-3 h-3 rounded-full bg-yellow-500"></div>
            <div class="w-3 h-3 rounded-full bg-green-500"></div>
          </div>
          <span class="text-xs text-gray-400 ml-2">Update Logs</span>
        </div>
        <div class="p-4 h-48 overflow-y-auto">
          {#each logs as log}
            <div class="terminal-log {log.message?.startsWith?.('ERROR') ? 'text-red-400' : 'text-gray-300'}">
              <span class="text-gray-500">[{new Date(log.time).toLocaleTimeString()}]</span>
              {' '}{log.message}
            </div>
          {/each}
        </div>
      </div>
    {/if}

    <div class="flex justify-between mt-8">
      <Button variant="ghost" onclick={() => { mode = 'choose'; errorMsg = ''; }}>
        <svg class="w-4 h-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M11 17l-5-5m0 0l5-5m-5 5h12" />
        </svg>
        Back
      </Button>
      <Button onclick={handleUpdate}>
        <svg class="w-4 h-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
        </svg>
        Retry Update
      </Button>
    </div>
  {/if}
</div>
