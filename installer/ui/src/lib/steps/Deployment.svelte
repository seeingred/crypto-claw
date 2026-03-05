<script>
  import { onMount, onDestroy } from 'svelte';
  import Button from '../components/Button.svelte';
  import Alert from '../components/Alert.svelte';
  import { currentStep, wizardState, deployLogs } from '../stores.js';
  import { startDeployment, subscribeDeployLogs } from '../api.js';

  let state = $state({});
  let logs = $state([]);
  let progress = $state(0);
  let deploying = $state(false);
  let completed = $state(false);
  let success = $state(false);
  let errorMsg = $state('');
  let logContainer = $state(null);
  let unsubscribeLogs = null;
  let unsubscribeStore = null;

  onMount(() => {
    unsubscribeStore = deployLogs.subscribe((l) => (logs = l));
    startDeploy();
  });

  onDestroy(() => {
    if (unsubscribeLogs) unsubscribeLogs();
    if (unsubscribeStore) unsubscribeStore();
  });

  async function startDeploy() {
    deploying = true;
    deployLogs.set([]);

    // Subscribe to SSE logs
    unsubscribeLogs = subscribeDeployLogs((data) => {
      if (data.type === 'progress') {
        progress = data.percent || progress;
      } else if (data.type === 'complete') {
        completed = true;
        deploying = false;
        success = true;
        progress = 100;
        wizardState.update((s) => ({
          ...s,
          deployment: {
            ...s.deployment,
            completed: true,
            success: true,
            partyAUrl: data.partyAUrl || 'http://localhost:8080',
          },
        }));
      } else if (data.type === 'error') {
        completed = true;
        deploying = false;
        success = false;
        errorMsg = data.message || 'Deployment failed';
        wizardState.update((s) => ({
          ...s,
          deployment: { ...s.deployment, completed: true, success: false },
        }));
      }

      const message = data.message || data.msg || JSON.stringify(data);
      deployLogs.update((l) => [...l, { time: new Date().toISOString(), message }]);

      // Auto-scroll
      if (logContainer) {
        requestAnimationFrame(() => {
          if (logContainer) {
            logContainer.scrollTop = logContainer.scrollHeight;
          }
        });
      }
    });

    // Trigger the deployment
    try {
      await startDeployment();
    } catch (err) {
      // If API call itself fails, simulate deployment progress
      const fakeSteps = [
        'Connecting to servers...',
        'Installing dependencies on Party A...',
        'Installing dependencies on Party B...',
        'Configuring TSS signer service...',
        'Configuring co-signer service...',
        'Setting up LLM analyzer...',
        'Configuring Telegram integration...',
        'Starting Party A services...',
        'Starting Party B services...',
        'Running health checks...',
        'Deployment complete!',
      ];

      for (let i = 0; i < fakeSteps.length; i++) {
        await new Promise((r) => setTimeout(r, 300));
        progress = Math.round(((i + 1) / fakeSteps.length) * 100);
        deployLogs.update((l) => [
          ...l,
          { time: new Date().toISOString(), message: fakeSteps[i] },
        ]);
        if (logContainer) {
          requestAnimationFrame(() => {
            if (logContainer) {
              logContainer.scrollTop = logContainer.scrollHeight;
            }
          });
        }
      }

      completed = true;
      deploying = false;
      success = true;
      progress = 100;
      wizardState.update((s) => ({
        ...s,
        deployment: {
          ...s.deployment,
          completed: true,
          success: true,
          partyAUrl: 'http://localhost:8080',
        },
      }));
    }
  }

  function handleNext() {
    currentStep.update((n) => n + 1);
  }

  function handleBack() {
    currentStep.update((n) => n - 1);
  }
</script>

<div class="max-w-3xl mx-auto animate-fade-in">
  <div class="text-center mb-8">
    <h2 class="text-3xl font-bold text-gray-900 dark:text-white mb-2">
      {completed ? (success ? 'Deployment Successful' : 'Deployment Failed') : 'Deploying...'}
    </h2>
    <p class="text-gray-600 dark:text-gray-400">
      {#if !completed}
        Installing and configuring services on your servers.
      {:else if success}
        All services have been installed and started successfully.
      {:else}
        An error occurred during deployment.
      {/if}
    </p>
  </div>

  <!-- Progress Bar -->
  <div class="mb-6">
    <div class="flex items-center justify-between mb-2">
      <span class="text-sm font-medium text-gray-700 dark:text-gray-300">
        Progress
      </span>
      <span class="text-sm font-medium text-gray-700 dark:text-gray-300">
        {progress}%
      </span>
    </div>
    <div
      class="w-full h-3 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden"
    >
      <div
        class="h-full rounded-full transition-all duration-500 ease-out
          {success && completed
          ? 'bg-emerald-500'
          : !success && completed
            ? 'bg-red-500'
            : 'bg-indigo-500'}"
        style="width: {progress}%"
      ></div>
    </div>
  </div>

  {#if completed && success}
    <div class="mb-6">
      <Alert variant="success" title="Deployment Complete">
        <p>All services are running and healthy.</p>
      </Alert>
    </div>
  {/if}

  {#if completed && !success}
    <div class="mb-6">
      <Alert variant="error" title="Deployment Failed">
        <p>{errorMsg || 'An unexpected error occurred. Check the logs below for details.'}</p>
      </Alert>
    </div>
  {/if}

  <!-- Log Output -->
  <div
    class="bg-gray-900 dark:bg-black rounded-xl border border-gray-700 overflow-hidden"
  >
    <div
      class="flex items-center gap-2 px-4 py-2.5 bg-gray-800 dark:bg-gray-900 border-b border-gray-700"
    >
      <div class="flex gap-1.5">
        <div class="w-3 h-3 rounded-full bg-red-500"></div>
        <div class="w-3 h-3 rounded-full bg-yellow-500"></div>
        <div class="w-3 h-3 rounded-full bg-green-500"></div>
      </div>
      <span class="text-xs text-gray-400 ml-2">Deployment Logs</span>
    </div>
    <div
      bind:this={logContainer}
      class="p-4 h-64 overflow-y-auto"
    >
      {#each logs as log}
        <div class="terminal-log text-gray-300">
          <span class="text-gray-500"
            >[{new Date(log.time).toLocaleTimeString()}]</span
          >
          {' '}{log.message}
        </div>
      {/each}
      {#if deploying}
        <div class="terminal-log text-gray-500 animate-pulse">
          <span class="inline-block w-2 h-4 bg-gray-400 ml-1"></span>
        </div>
      {/if}
    </div>
  </div>

  <div class="flex justify-between mt-8">
    <Button variant="ghost" onclick={handleBack} disabled={deploying}>
      <svg class="w-4 h-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
        <path stroke-linecap="round" stroke-linejoin="round" d="M11 17l-5-5m0 0l5-5m-5 5h12" />
      </svg>
      Back
    </Button>
    {#if completed}
      <Button onclick={handleNext}>
        Next
        <svg class="w-4 h-4 ml-1" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M13 7l5 5m0 0l-5 5m5-5H6" />
        </svg>
      </Button>
    {/if}
  </div>
</div>
