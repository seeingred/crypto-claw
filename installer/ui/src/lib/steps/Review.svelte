<script>
  import Button from '../components/Button.svelte';
  import Card from '../components/Card.svelte';
  import { currentStep, wizardState } from '../stores.js';

  let state = $state({});
  wizardState.subscribe((s) => (state = s));

  let providerLabel = $derived(
    state.llm?.provider === 'anthropic'
      ? 'Anthropic'
      : state.llm?.provider === 'openai'
        ? 'OpenAI'
        : 'Local Model'
  );

  function handleInstall() {
    currentStep.update((n) => n + 1);
  }

  function handleBack() {
    currentStep.update((n) => n - 1);
  }
</script>

<div class="max-w-3xl mx-auto animate-fade-in">
  <div class="text-center mb-8">
    <h2 class="text-3xl font-bold text-gray-900 dark:text-white mb-2">
      Review Configuration
    </h2>
    <p class="text-gray-600 dark:text-gray-400">
      Review your settings before installing. Nothing has been installed yet.
    </p>
  </div>

  <div class="space-y-4">
    <!-- Servers -->
    <Card title="Servers">
      {#if state.servers?.localMode}
        <div class="flex items-center gap-2">
          <span
            class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-amber-100 dark:bg-amber-900/30 text-amber-800 dark:text-amber-300"
          >
            Local Mode
          </span>
          <span class="text-sm text-gray-600 dark:text-gray-400"
            >Both services on this machine</span
          >
        </div>
      {:else}
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div
            class="p-3 rounded-lg bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-700"
          >
            <div class="flex items-center gap-2 mb-2">
              <div
                class="w-6 h-6 rounded bg-indigo-500 text-white flex items-center justify-center text-xs font-bold"
              >
                A
              </div>
              <span class="text-sm font-medium text-gray-900 dark:text-white"
                >AI Server</span
              >
            </div>
            <p class="text-xs text-gray-600 dark:text-gray-400 font-mono">
              {state.servers?.partyA?.host || 'Not configured'}:{state.servers?.partyA?.port || '22'}
            </p>
            <p class="text-xs text-gray-500 dark:text-gray-500">
              User: {state.servers?.partyA?.username || 'N/A'}
            </p>
          </div>
          <div
            class="p-3 rounded-lg bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-700"
          >
            <div class="flex items-center gap-2 mb-2">
              <div
                class="w-6 h-6 rounded bg-emerald-500 text-white flex items-center justify-center text-xs font-bold"
              >
                B
              </div>
              <span class="text-sm font-medium text-gray-900 dark:text-white"
                >Secure Server</span
              >
            </div>
            <p class="text-xs text-gray-600 dark:text-gray-400 font-mono">
              {state.servers?.partyB?.host || 'Not configured'}:{state.servers?.partyB?.port || '22'}
            </p>
            <p class="text-xs text-gray-500 dark:text-gray-500">
              User: {state.servers?.partyB?.username || 'N/A'}
            </p>
          </div>
        </div>
      {/if}
    </Card>

    <!-- LLM -->
    <Card title="Transaction Analyzer">
      <div class="flex items-center gap-3">
        <div
          class="w-10 h-10 rounded-lg bg-gray-100 dark:bg-gray-700 flex items-center justify-center"
        >
          <svg
            class="w-5 h-5 text-gray-600 dark:text-gray-300"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            stroke-width="1.5"
          >
            <path
              stroke-linecap="round"
              stroke-linejoin="round"
              d="M9.75 3.104v5.714a2.25 2.25 0 01-.659 1.591L5 14.5M9.75 3.104c-.251.023-.501.05-.75.082m.75-.082a24.301 24.301 0 014.5 0m0 0v5.714c0 .597.237 1.17.659 1.591L19.8 15.3M14.25 3.104c.251.023.501.05.75.082M19.8 15.3l-1.57.393A9.065 9.065 0 0112 15a9.065 9.065 0 00-6.23.693L5 14.5m14.8.8l1.402 1.402c1.232 1.232.65 3.318-1.067 3.611A48.309 48.309 0 0112 21c-2.773 0-5.491-.235-8.135-.687-1.718-.293-2.3-2.379-1.067-3.61L5 14.5"
            />
          </svg>
        </div>
        <div>
          <p class="text-sm font-medium text-gray-900 dark:text-white">
            {providerLabel}
          </p>
          <p class="text-xs text-gray-500 dark:text-gray-400">
            {#if state.llm?.provider === 'local'}
              {state.llm?.localEndpoint || 'Not configured'}
            {:else}
              Model: {state.llm?.model || 'Not selected'}
            {/if}
          </p>
        </div>
      </div>
    </Card>

    <!-- Telegram -->
    <Card title="Telegram Bot">
      <div class="flex items-center gap-3">
        <div
          class="w-10 h-10 rounded-lg bg-blue-100 dark:bg-blue-900/30 flex items-center justify-center"
        >
          <svg
            class="w-5 h-5 text-blue-600 dark:text-blue-400"
            fill="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm4.64 6.8c-.15 1.58-.8 5.42-1.13 7.19-.14.75-.42 1-.68 1.03-.58.05-1.02-.38-1.58-.75-.88-.58-1.38-.94-2.23-1.5-.99-.65-.35-1.01.22-1.59.15-.15 2.71-2.48 2.76-2.69.01-.03.01-.14-.07-.2-.08-.06-.19-.04-.27-.02-.12.03-1.99 1.27-5.62 3.72-.53.36-1.01.54-1.44.53-.47-.01-1.38-.27-2.06-.49-.83-.27-1.49-.42-1.43-.88.03-.24.37-.49 1.02-.74 3.98-1.73 6.64-2.87 7.97-3.43 3.79-1.58 4.58-1.86 5.09-1.87.11 0 .37.03.54.17.14.12.18.28.2.45-.01.06.01.24 0 .38z"
            />
          </svg>
        </div>
        <div>
          <p class="text-sm font-medium text-gray-900 dark:text-white">
            Bot token configured
          </p>
          <p class="text-xs text-gray-500 dark:text-gray-400">
            Notifications will be sent via Telegram
          </p>
        </div>
      </div>
    </Card>

    <!-- What happens next -->
    <Card title="What Happens Next">
      <div class="space-y-2 text-sm text-gray-600 dark:text-gray-400">
        <div class="flex items-start gap-2">
          <span class="text-indigo-500 font-bold mt-0.5">1.</span>
          <span>A 24-word recovery phrase will be generated for your wallet</span>
        </div>
        <div class="flex items-start gap-2">
          <span class="text-indigo-500 font-bold mt-0.5">2.</span>
          <span>Private keys are derived and split into threshold shares</span>
        </div>
        <div class="flex items-start gap-2">
          <span class="text-indigo-500 font-bold mt-0.5">3.</span>
          <span>TLS certificates are generated for secure communication</span>
        </div>
        <div class="flex items-start gap-2">
          <span class="text-indigo-500 font-bold mt-0.5">4.</span>
          <span>Services are deployed to your servers</span>
        </div>
      </div>
    </Card>
  </div>

  <div class="flex justify-between mt-8">
    <Button variant="ghost" onclick={handleBack}>
      <svg class="w-4 h-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
        <path stroke-linecap="round" stroke-linejoin="round" d="M11 17l-5-5m0 0l5-5m-5 5h12" />
      </svg>
      Back
    </Button>
    <Button variant="success" size="lg" onclick={handleInstall}>
      <svg class="w-5 h-5 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
        <path stroke-linecap="round" stroke-linejoin="round" d="M15.59 14.37a6 6 0 01-5.84 7.38v-4.8m5.84-2.58a14.98 14.98 0 006.16-12.12A14.98 14.98 0 009.631 8.41m5.96 5.96a14.926 14.926 0 01-5.841 2.58m-.119-8.54a6 6 0 00-7.381 5.84h4.8m2.581-5.84a14.927 14.927 0 00-2.58 5.84m2.699 2.7c-.103.021-.207.041-.311.06a15.09 15.09 0 01-2.448-2.448 14.9 14.9 0 01.06-.312m-2.24 2.39a4.493 4.493 0 00-1.757 4.306 4.493 4.493 0 004.306-1.758M16.5 9a1.5 1.5 0 11-3 0 1.5 1.5 0 013 0z" />
      </svg>
      Install
    </Button>
  </div>
</div>
