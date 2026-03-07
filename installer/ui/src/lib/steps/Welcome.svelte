<script>
  import Button from '../components/Button.svelte';
  import Card from '../components/Card.svelte';
  import Alert from '../components/Alert.svelte';
  import { currentStep, wizardState, deployLogs } from '../stores.js';
  import { installRestore, installExport, startUpdate, subscribeDeployLogs } from '../api.js';

  let mode = $state('choose');
  let restoreMnemonic = $state('');
  let exportMnemonic = $state('');
  let exportPaths = $state('');
  let exportResult = $state(null);
  let derivingPath = $state('');
  let errorMsg = $state('');
  let logs = $state([]);
  let progress = $state(0);
  let logContainer = $state(null);
  let unsubscribeLogs = null;
  let mnemonicValidated = $state(false);

  function handleNewInstall() {
    wizardState.update((s) => ({ ...s, installMode: 'install' }));
    currentStep.update((n) => n + 1);
  }

  function handleRestoreClick() {
    mode = 'restore';
  }

  function handleExportClick() {
    mode = 'export';
    mnemonicValidated = false;
    exportResult = null;
  }

  async function submitExportMnemonic() {
    const words = exportMnemonic.trim();
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
    mode = 'exporting';
    try {
      // Initial call with no paths — gets SOL key and DB addresses
      const result = await installExport(words, []);
      exportResult = result;
      mnemonicValidated = true;
      mode = 'exported';
    } catch (err) {
      errorMsg = err.message || 'Failed to export keys';
      mode = 'export';
    }
  }

  async function derivePath() {
    const path = derivingPath.trim();
    if (!path) return;
    if (!path.startsWith('m/')) {
      errorMsg = 'Path must start with m/ (e.g. m/44\'/60\'/0\'/0/0)';
      return;
    }
    errorMsg = '';
    try {
      const result = await installExport(exportMnemonic.trim(), [path]);
      if (result.derivedKeys?.length > 0) {
        const newKey = result.derivedKeys[0];
        if (newKey.error) {
          errorMsg = `Failed to derive ${path}: ${newKey.error}`;
          return;
        }
        // Add to existing results, avoid duplicates
        const existing = exportResult.derivedKeys || [];
        const alreadyExists = existing.some(k => k.path === newKey.path);
        if (!alreadyExists) {
          exportResult = {
            ...exportResult,
            derivedKeys: [...existing, newKey],
          };
        }
      }
      derivingPath = '';
    } catch (err) {
      errorMsg = err.message || 'Failed to derive path';
    }
  }

  async function deriveAllDBPaths() {
    if (!exportResult?.dbAddresses?.length) return;
    const ecdsaPaths = exportResult.dbAddresses
      .filter(a => a.curve === 'secp256k1')
      .map(a => a.path);
    if (ecdsaPaths.length === 0) return;
    errorMsg = '';
    try {
      const result = await installExport(exportMnemonic.trim(), ecdsaPaths);
      if (result.derivedKeys?.length > 0) {
        const existing = exportResult.derivedKeys || [];
        const existingPaths = new Set(existing.map(k => k.path));
        const newKeys = result.derivedKeys.filter(k => !existingPaths.has(k.path));
        exportResult = {
          ...exportResult,
          derivedKeys: [...existing, ...newKeys],
        };
      }
    } catch (err) {
      errorMsg = err.message || 'Failed to derive paths';
    }
  }

  function copyToClipboard(text) {
    navigator.clipboard.writeText(text);
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

    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
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
          Restore from an existing recovery phrase and redeploy fresh TSS shares on new servers.
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

      <!-- Disaster Recovery / Export -->
      <button
        onclick={handleExportClick}
        class="text-left p-6 rounded-xl border-2 border-gray-200 dark:border-gray-700 hover:border-rose-500 dark:hover:border-rose-500 bg-white dark:bg-gray-800 transition-all hover:shadow-lg cursor-pointer"
      >
        <div class="inline-flex items-center justify-center w-12 h-12 rounded-full bg-rose-100 dark:bg-rose-900/50 mb-4">
          <svg class="w-6 h-6 text-rose-600 dark:text-rose-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.5">
            <path stroke-linecap="round" stroke-linejoin="round" d="M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z" />
          </svg>
        </div>
        <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-2">Disaster Recovery</h3>
        <p class="text-sm text-gray-600 dark:text-gray-400">
          Lost both servers? Export private keys for any derivation path to move funds to safety.
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
      <div class="flex justify-center gap-4 mt-8">
        <Button variant="ghost" onclick={() => { mode = 'choose'; errorMsg = ''; }}>
          <svg class="w-4 h-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
            <path stroke-linecap="round" stroke-linejoin="round" d="M11 17l-5-5m0 0l5-5m-5 5h12" />
          </svg>
          Back to Menu
        </Button>
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

  {:else if mode === 'export' || mode === 'exporting'}
    <!-- Export: enter mnemonic -->
    <div class="text-center mb-8">
      <h2 class="text-3xl font-bold text-gray-900 dark:text-white mb-2">
        Disaster Recovery
      </h2>
      <p class="text-gray-600 dark:text-gray-400">
        Enter your recovery phrase to derive private keys for any path the bot used.
        Import the keys into MetaMask to transfer funds to safety.
      </p>
    </div>

    <Card>
      <div class="space-y-4">
        <textarea
          bind:value={exportMnemonic}
          placeholder="Enter your 24-word recovery phrase, separated by spaces..."
          rows="4"
          disabled={mode === 'exporting'}
          class="w-full px-4 py-3 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-900 text-gray-900 dark:text-white font-mono text-sm focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 outline-none resize-none disabled:opacity-50"
        ></textarea>

        {#if errorMsg}
          <Alert variant="error" title="Error">
            <p>{errorMsg}</p>
          </Alert>
        {/if}
      </div>
    </Card>

    <div class="flex justify-between mt-8">
      <Button variant="ghost" onclick={() => { mode = 'choose'; errorMsg = ''; }} disabled={mode === 'exporting'}>
        <svg class="w-4 h-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M11 17l-5-5m0 0l5-5m-5 5h12" />
        </svg>
        Back
      </Button>
      <Button variant="success" size="lg" onclick={submitExportMnemonic} disabled={mode === 'exporting'}>
        {mode === 'exporting' ? 'Validating...' : 'Continue'}
        <svg class="w-4 h-4 ml-1" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M13 7l5 5m0 0l-5 5m5-5H6" />
        </svg>
      </Button>
    </div>

  {:else if mode === 'exported'}
    <!-- Export results + derive by path -->
    <div class="text-center mb-8">
      <h2 class="text-3xl font-bold text-gray-900 dark:text-white mb-2">
        Disaster Recovery
      </h2>
      <p class="text-gray-600 dark:text-gray-400">
        Derive private keys for each path the bot used. Import into MetaMask to move funds.
      </p>
    </div>

    <Alert variant="warning" title="Security Warning">
      <p>These private keys give full control over the associated addresses. Never share them.</p>
    </Alert>

    <div class="mt-6 space-y-6">
      <!-- Solana Key (always one address since TSS doesn't derive EdDSA) -->
      {#if exportResult?.solAddress}
        <Card>
          <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-4 flex items-center gap-2">
            <span class="inline-flex items-center justify-center w-8 h-8 rounded-full bg-purple-100 dark:bg-purple-900/50">
              <span class="text-purple-600 dark:text-purple-400 text-sm font-bold">S</span>
            </span>
            Solana (m/44'/501'/0'/0')
          </h3>
          <div class="space-y-3">
            <div>
              <label class="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1">Address</label>
              <div class="flex items-center gap-2">
                <code class="flex-1 px-3 py-2 rounded-lg bg-gray-100 dark:bg-gray-900 text-sm text-gray-900 dark:text-gray-100 font-mono break-all">{exportResult.solAddress}</code>
                <button onclick={() => copyToClipboard(exportResult.solAddress)} class="shrink-0 px-3 py-2 text-xs rounded-lg bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors cursor-pointer">Copy</button>
              </div>
            </div>
            <div>
              <label class="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1">Private Key (for Phantom)</label>
              <div class="flex items-center gap-2">
                <code class="flex-1 px-3 py-2 rounded-lg bg-red-50 dark:bg-red-900/20 text-sm text-red-800 dark:text-red-300 font-mono break-all">{exportResult.solPrivKey}</code>
                <button onclick={() => copyToClipboard(exportResult.solPrivKey)} class="shrink-0 px-3 py-2 text-xs rounded-lg bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors cursor-pointer">Copy</button>
              </div>
            </div>
          </div>
        </Card>
      {/if}

      <!-- Derive EVM keys by path -->
      <Card>
        <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-4 flex items-center gap-2">
          <span class="inline-flex items-center justify-center w-8 h-8 rounded-full bg-blue-100 dark:bg-blue-900/50">
            <span class="text-blue-600 dark:text-blue-400 text-sm font-bold">E</span>
          </span>
          EVM / secp256k1 Keys
        </h3>

        <p class="text-sm text-gray-600 dark:text-gray-400 mb-4">
          Enter a derivation path to get the private key for that address. Use the same paths the bot derived (e.g. <code class="text-xs bg-gray-100 dark:bg-gray-800 px-1 rounded">m/44'/60'/0'/0/0</code>).
        </p>

        <!-- Derive input -->
        <div class="flex gap-2 mb-4">
          <input
            bind:value={derivingPath}
            placeholder="m/44'/60'/0'/0/0"
            class="flex-1 px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-900 text-gray-900 dark:text-white font-mono text-sm focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 outline-none"
            onkeydown={(e) => { if (e.key === 'Enter') derivePath(); }}
          />
          <Button onclick={derivePath}>Derive</Button>
        </div>

        {#if errorMsg}
          <div class="mb-4">
            <Alert variant="error" title="Error">
              <p>{errorMsg}</p>
            </Alert>
          </div>
        {/if}

        <!-- DB paths hint -->
        {#if exportResult?.dbAddresses?.length > 0 && (!exportResult?.derivedKeys || exportResult.derivedKeys.length === 0)}
          <div class="mb-4 p-3 rounded-lg bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800">
            <p class="text-sm text-blue-800 dark:text-blue-300 mb-2">
              Found {exportResult.dbAddresses.filter(a => a.curve === 'secp256k1').length} EVM path(s) in the local database:
            </p>
            <div class="flex flex-wrap gap-1 mb-2">
              {#each exportResult.dbAddresses.filter(a => a.curve === 'secp256k1') as addr}
                <code class="text-xs bg-blue-100 dark:bg-blue-900/40 text-blue-800 dark:text-blue-200 px-2 py-0.5 rounded">{addr.path}</code>
              {/each}
            </div>
            <Button size="sm" onclick={deriveAllDBPaths}>Derive All DB Paths</Button>
          </div>
        {/if}

        <!-- Derived keys table -->
        {#if exportResult?.derivedKeys?.length > 0}
          <div class="space-y-3">
            {#each exportResult.derivedKeys as key}
              <div class="p-3 rounded-lg border border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-900/50">
                <div class="flex items-center justify-between mb-2">
                  <code class="text-xs font-semibold text-gray-700 dark:text-gray-300">{key.path}</code>
                  {#if key.error}
                    <span class="text-xs text-red-500">{key.error}</span>
                  {/if}
                </div>
                {#if !key.error}
                  <div class="space-y-2">
                    <div>
                      <label class="block text-xs text-gray-500 dark:text-gray-400 mb-0.5">Address</label>
                      <div class="flex items-center gap-2">
                        <code class="flex-1 text-xs bg-gray-100 dark:bg-gray-800 px-2 py-1 rounded font-mono break-all">{key.address}</code>
                        <button onclick={() => copyToClipboard(key.address)} class="shrink-0 px-2 py-1 text-xs rounded bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors cursor-pointer">Copy</button>
                      </div>
                    </div>
                    <div>
                      <label class="block text-xs text-gray-500 dark:text-gray-400 mb-0.5">Private Key (import into MetaMask)</label>
                      <div class="flex items-center gap-2">
                        <code class="flex-1 text-xs bg-red-50 dark:bg-red-900/20 text-red-800 dark:text-red-300 px-2 py-1 rounded font-mono break-all">{key.privKeyHex}</code>
                        <button onclick={() => copyToClipboard(key.privKeyHex)} class="shrink-0 px-2 py-1 text-xs rounded bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors cursor-pointer">Copy</button>
                      </div>
                    </div>
                  </div>
                {/if}
              </div>
            {/each}
          </div>
        {:else}
          <p class="text-sm text-gray-500 dark:text-gray-400 italic">
            No keys derived yet. Enter a path above and click Derive.
          </p>
        {/if}
      </Card>
    </div>

    <div class="flex justify-center mt-8">
      <Button variant="ghost" onclick={() => { mode = 'choose'; errorMsg = ''; exportResult = null; mnemonicValidated = false; }}>
        <svg class="w-4 h-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M11 17l-5-5m0 0l5-5m-5 5h12" />
        </svg>
        Back to Menu
      </Button>
    </div>
  {/if}
</div>
