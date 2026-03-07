<script>
  import { onMount, onDestroy } from 'svelte';
  import Button from '../components/Button.svelte';
  import Alert from '../components/Alert.svelte';
  import Card from '../components/Card.svelte';
  import { currentStep, wizardState, deployLogs } from '../stores.js';
  import { installPrepare, startDeployment, subscribeDeployLogs, verifyTelegram } from '../api.js';

  // Phases: generating → mnemonic → telegram → deploying → done → error
  // In restore mode: skip generating/mnemonic, go straight to telegram.
  let phase = $state('generating');
  let mnemonic = $state('');
  let mnemonicWords = $derived(mnemonic ? mnemonic.split(' ') : []);
  let ecdsaPubKey = $state('');
  let eddsaPubKey = $state('');
  let backupConfirmed = $state(false);
  let copied = $state(false);
  let logs = $state([]);
  let progress = $state(0);
  let errorMsg = $state('');
  let logContainer = $state(null);
  let unsubscribeLogs = null;
  let unsubscribeStore = null;
  let isRestore = $state(false);

  // Telegram verification state.
  let state = $state({});
  let botUsername = $derived(state.telegram?.botUsername || '');
  let telegramVerifying = $state(false);
  let telegramVerified = $state(false);
  let telegramUsername = $state('');

  onMount(async () => {
    wizardState.subscribe((s) => (state = s));
    unsubscribeStore = deployLogs.subscribe((l) => (logs = l));

    // Check if we're in restore mode (mnemonic already submitted on Welcome page).
    if (state.installMode === 'restore') {
      isRestore = true;
      phase = 'telegram';
      startTelegramVerify();
    } else {
      await generateKeys();
    }
  });

  onDestroy(() => {
    if (unsubscribeLogs) unsubscribeLogs();
    if (unsubscribeStore) unsubscribeStore();
  });

  async function generateKeys() {
    phase = 'generating';
    try {
      const result = await installPrepare();
      mnemonic = result.mnemonic;
      ecdsaPubKey = result.ecdsaPubKey;
      eddsaPubKey = result.eddsaPubKey;
      phase = 'mnemonic';
    } catch (err) {
      errorMsg = err.message || 'Failed to generate recovery phrase';
      phase = 'error';
    }
  }

  function proceedToTelegram() {
    phase = 'telegram';
    startTelegramVerify();
  }

  async function startTelegramVerify() {
    telegramVerifying = true;
    telegramVerified = false;
    errorMsg = '';
    try {
      const result = await verifyTelegram();
      if (result.status === 'ok') {
        telegramVerified = true;
        telegramUsername = result.username || '';
      } else if (result.status === 'timeout') {
        errorMsg = result.error || 'Timed out waiting for message.';
      } else {
        errorMsg = result.error || 'Verification failed.';
      }
    } catch (err) {
      errorMsg = err.message || 'Verification failed.';
    }
    telegramVerifying = false;
  }

  // Estimate progress from log messages.
  let logCount = 0;
  const EXPECTED_LOG_COUNT = 12;

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

  async function startDeploy() {
    phase = 'deploying';
    deployLogs.set([]);
    progress = 0;
    logCount = 0;

    unsubscribeLogs = subscribeDeployLogs((data) => {
      if (data.type === 'complete') {
        phase = 'done';
        progress = 100;
        addLog(data.message || 'Deployment complete');
        return;
      }

      if (data.type === 'error') {
        phase = 'error';
        errorMsg = data.message || 'Deployment failed';
        addLog(data.message);
        return;
      }

      logCount++;
      progress = Math.min(95, Math.round((logCount / EXPECTED_LOG_COUNT) * 100));
      addLog(data.message || JSON.stringify(data));
    });

    try {
      await startDeployment();
    } catch (err) {
      if (phase !== 'error' && phase !== 'done') {
        errorMsg = err.message || 'Failed to start deployment';
        phase = 'error';
      }
    }
  }

  async function copyMnemonic() {
    try {
      await navigator.clipboard.writeText(mnemonic);
    } catch {
      const textarea = document.createElement('textarea');
      textarea.value = mnemonic;
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      document.body.removeChild(textarea);
    }
    copied = true;
    setTimeout(() => (copied = false), 2000);
  }

  function handleNext() {
    currentStep.update((n) => n + 1);
  }

  function handleBack() {
    currentStep.update((n) => n - 1);
  }
</script>

<div class="max-w-3xl mx-auto animate-fade-in">
  {#if phase === 'generating'}
    <!-- Generating keys -->
    <div class="text-center py-16">
      <div class="inline-flex items-center justify-center w-16 h-16 rounded-full bg-indigo-100 dark:bg-indigo-900/50 mb-6">
        <svg class="w-8 h-8 text-indigo-600 dark:text-indigo-400 animate-spin" fill="none" viewBox="0 0 24 24">
          <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
          <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
        </svg>
      </div>
      <h2 class="text-2xl font-bold text-gray-900 dark:text-white mb-2">
        Generating Recovery Phrase...
      </h2>
      <p class="text-gray-600 dark:text-gray-400">
        Creating your BIP-39 mnemonic and deriving cryptographic keys.
      </p>
    </div>

  {:else if phase === 'mnemonic'}
    <!-- Show mnemonic for backup (new install only) -->
    <div class="text-center mb-8">
      <h2 class="text-3xl font-bold text-gray-900 dark:text-white mb-2">
        Save Your Recovery Phrase
      </h2>
      <p class="text-gray-600 dark:text-gray-400">
        Write down these 24 words in order. This is your emergency backup.
      </p>
    </div>

    <Alert variant="warning" title="Critical: Save This Now">
      <p>
        This recovery phrase will <strong>not</strong> be shown again.
        It allows you to restore your wallet if both servers are lost.
      </p>
    </Alert>

    <Card>
      <div class="grid grid-cols-3 sm:grid-cols-4 gap-2 p-2">
        {#each mnemonicWords as word, i}
          <div class="flex items-center gap-2 p-2 rounded-lg bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-700">
            <span class="text-xs font-medium text-gray-400 dark:text-gray-500 w-5 text-right">{i + 1}.</span>
            <span class="text-sm font-mono font-medium text-gray-900 dark:text-white">{word}</span>
          </div>
        {/each}
      </div>

      <div class="flex justify-center mt-4">
        <Button variant="ghost" onclick={copyMnemonic}>
          {#if copied}
            <svg class="w-4 h-4 mr-1 text-emerald-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7" />
            </svg>
            Copied!
          {:else}
            <svg class="w-4 h-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
            </svg>
            Copy Recovery Phrase
          {/if}
        </Button>
      </div>
    </Card>

    <!-- Confirmation -->
    <label
      class="flex items-center gap-3 p-4 mt-4 rounded-lg bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-750 transition-colors"
    >
      <input
        type="checkbox"
        checked={backupConfirmed}
        onchange={(e) => (backupConfirmed = e.target.checked)}
        class="w-4 h-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500"
      />
      <span class="text-sm font-medium text-gray-900 dark:text-white">
        I have saved my recovery phrase in a secure location
      </span>
    </label>

    <div class="flex justify-between mt-8">
      <Button variant="ghost" onclick={handleBack}>
        <svg class="w-4 h-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M11 17l-5-5m0 0l5-5m-5 5h12" />
        </svg>
        Back
      </Button>
      <Button variant="success" size="lg" disabled={!backupConfirmed} onclick={proceedToTelegram}>
        Continue
        <svg class="w-4 h-4 ml-1" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M13 7l5 5m0 0l-5 5m5-5H6" />
        </svg>
      </Button>
    </div>

  {:else if phase === 'telegram'}
    <!-- Telegram verification -->
    <div class="text-center mb-8">
      <h2 class="text-3xl font-bold text-gray-900 dark:text-white mb-2">
        Connect Your Telegram
      </h2>
      <p class="text-gray-600 dark:text-gray-400">
        Send any message to your bot so we can link your account.
      </p>
    </div>

    <Card>
      <div class="text-center py-6">
        {#if botUsername}
          <p class="text-gray-700 dark:text-gray-300 mb-4">
            Open your Telegram bot and send any message:
          </p>
          <a
            href="https://t.me/{botUsername}"
            target="_blank"
            rel="noopener noreferrer"
            class="inline-flex items-center gap-2 px-6 py-3 rounded-xl bg-blue-500 hover:bg-blue-600 text-white font-medium transition-colors"
          >
            <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
              <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm4.64 6.8c-.15 1.58-.8 5.42-1.13 7.19-.14.75-.42 1-.68 1.03-.58.05-1.02-.38-1.58-.75-.88-.58-1.38-.94-2.23-1.5-.99-.65-.35-1.01.22-1.59.15-.15 2.71-2.48 2.76-2.69.01-.03.01-.14-.07-.2-.08-.06-.19-.04-.27-.02-.12.03-1.99 1.27-5.62 3.72-.53.36-1.01.54-1.44.53-.47-.01-1.38-.27-2.06-.49-.83-.27-1.49-.42-1.43-.88.03-.24.37-.49 1.02-.74 3.98-1.73 6.64-2.87 7.97-3.43 3.79-1.58 4.58-1.86 5.09-1.87.11 0 .37.03.54.17.14.12.18.28.2.45-.01.06.01.24 0 .38z" />
            </svg>
            Open @{botUsername}
          </a>
        {:else}
          <p class="text-gray-700 dark:text-gray-300">
            Open your Telegram bot and send <strong>/start</strong>.
          </p>
        {/if}

        {#if telegramVerifying}
          <div class="mt-6 flex items-center justify-center gap-3">
            <svg class="w-5 h-5 text-blue-500 animate-spin" fill="none" viewBox="0 0 24 24">
              <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
              <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
            </svg>
            <span class="text-sm text-gray-600 dark:text-gray-400">Waiting for your message...</span>
          </div>
        {/if}

        {#if telegramVerified}
          <div class="mt-6">
            <Alert variant="success" title="Connected!">
              <p>Verified as <strong>{telegramUsername}</strong>. Your bot will send notifications to this account.</p>
            </Alert>
          </div>
        {/if}

        {#if errorMsg && !telegramVerifying}
          <div class="mt-6">
            <Alert variant="error" title="Verification Failed">
              <p>{errorMsg}</p>
            </Alert>
          </div>
        {/if}
      </div>
    </Card>

    <div class="flex justify-between mt-8">
      <Button variant="ghost" onclick={handleBack}>
        <svg class="w-4 h-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M11 17l-5-5m0 0l5-5m-5 5h12" />
        </svg>
        Back
      </Button>
      <div class="flex gap-3">
        {#if errorMsg && !telegramVerifying}
          <Button variant="ghost" onclick={startTelegramVerify}>
            Retry
          </Button>
        {/if}
        <Button variant="success" size="lg" disabled={!telegramVerified} onclick={startDeploy}>
          <svg class="w-5 h-5 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
            <path stroke-linecap="round" stroke-linejoin="round" d="M15.59 14.37a6 6 0 01-5.84 7.38v-4.8m5.84-2.58a14.98 14.98 0 006.16-12.12A14.98 14.98 0 009.631 8.41m5.96 5.96a14.926 14.926 0 01-5.841 2.58m-.119-8.54a6 6 0 00-7.381 5.84h4.8m2.581-5.84a14.927 14.927 0 00-2.58 5.84m2.699 2.7c-.103.021-.207.041-.311.06a15.09 15.09 0 01-2.448-2.448 14.9 14.9 0 01.06-.312m-2.24 2.39a4.493 4.493 0 00-1.757 4.306 4.493 4.493 0 004.306-1.758M16.5 9a1.5 1.5 0 11-3 0 1.5 1.5 0 013 0z" />
          </svg>
          Start Installation
        </Button>
      </div>
    </div>

  {:else if phase === 'deploying' || phase === 'done'}
    <!-- Deployment progress -->
    <div class="text-center mb-8">
      <h2 class="text-3xl font-bold text-gray-900 dark:text-white mb-2">
        {phase === 'done' ? 'Installation Complete' : 'Installing...'}
      </h2>
      <p class="text-gray-600 dark:text-gray-400">
        {#if phase === 'deploying'}
          Splitting keys, generating certificates, and deploying services.
        {:else}
          All services have been installed and started successfully.
        {/if}
      </p>
    </div>

    <!-- Progress Bar -->
    <div class="mb-6">
      <div class="flex items-center justify-between mb-2">
        <span class="text-sm font-medium text-gray-700 dark:text-gray-300">Progress</span>
        <span class="text-sm font-medium text-gray-700 dark:text-gray-300">{progress}%</span>
      </div>
      <div class="w-full h-3 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
        <div
          class="h-full rounded-full transition-all duration-500 ease-out
            {phase === 'done' ? 'bg-emerald-500' : 'bg-indigo-500'}"
          style="width: {progress}%"
        ></div>
      </div>
    </div>

    {#if phase === 'done'}
      <div class="mb-6">
        <Alert variant="success" title="Installation Complete">
          <p>All services are running and healthy.</p>
        </Alert>
      </div>
    {/if}

    <!-- Log Output -->
    <div class="bg-gray-900 dark:bg-black rounded-xl border border-gray-700 overflow-hidden">
      <div class="flex items-center gap-2 px-4 py-2.5 bg-gray-800 dark:bg-gray-900 border-b border-gray-700">
        <div class="flex gap-1.5">
          <div class="w-3 h-3 rounded-full bg-red-500"></div>
          <div class="w-3 h-3 rounded-full bg-yellow-500"></div>
          <div class="w-3 h-3 rounded-full bg-green-500"></div>
        </div>
        <span class="text-xs text-gray-400 ml-2">Installation Logs</span>
      </div>
      <div bind:this={logContainer} class="p-4 h-64 overflow-y-auto">
        {#each logs as log}
          <div class="terminal-log text-gray-300">
            <span class="text-gray-500">[{new Date(log.time).toLocaleTimeString()}]</span>
            {' '}{log.message}
          </div>
        {/each}
        {#if phase === 'deploying'}
          <div class="terminal-log text-gray-500 animate-pulse">
            <span class="inline-block w-2 h-4 bg-gray-400 ml-1"></span>
          </div>
        {/if}
      </div>
    </div>

    {#if phase === 'done'}
      <div class="flex justify-end mt-8">
        <Button onclick={handleNext}>
          Next
          <svg class="w-4 h-4 ml-1" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
            <path stroke-linecap="round" stroke-linejoin="round" d="M13 7l5 5m0 0l-5 5m5-5H6" />
          </svg>
        </Button>
      </div>
    {/if}

  {:else if phase === 'error'}
    <!-- Error state -->
    <div class="text-center mb-8">
      <h2 class="text-3xl font-bold text-gray-900 dark:text-white mb-2">
        Installation Failed
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
          <span class="text-xs text-gray-400 ml-2">Installation Logs</span>
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
      <Button variant="ghost" onclick={handleBack}>
        <svg class="w-4 h-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M11 17l-5-5m0 0l5-5m-5 5h12" />
        </svg>
        Back to Review
      </Button>
      <Button onclick={startDeploy}>
        <svg class="w-4 h-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
        </svg>
        Retry Installation
      </Button>
    </div>
  {/if}
</div>
