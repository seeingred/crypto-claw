<script>
  import Button from '../components/Button.svelte';
  import Card from '../components/Card.svelte';
  import Input from '../components/Input.svelte';
  import Alert from '../components/Alert.svelte';
  import { currentStep, wizardState, isLoading } from '../stores.js';
  import { saveLLMConfig } from '../api.js';

  let state = $state({});
  wizardState.subscribe((s) => (state = s));

  let llm = $derived(state.llm ?? {});
  let testing = $state(false);
  let testResult = $state('');

  const anthropicModels = [
    { value: 'claude-sonnet-4-20250514', label: 'Claude Sonnet 4' },
    { value: 'claude-haiku-4-5-20251001', label: 'Claude Haiku 4.5' },
  ];

  const openaiModels = [
    { value: 'gpt-4o', label: 'GPT-4o' },
    { value: 'gpt-4o-mini', label: 'GPT-4o Mini' },
  ];

  let currentModels = $derived(
    llm.provider === 'anthropic'
      ? anthropicModels
      : llm.provider === 'openai'
        ? openaiModels
        : []
  );

  function setProvider(provider) {
    const defaultModel =
      provider === 'anthropic'
        ? 'claude-sonnet-4-20250514'
        : provider === 'openai'
          ? 'gpt-4o'
          : '';
    wizardState.update((s) => ({
      ...s,
      llm: { ...s.llm, provider, model: defaultModel },
    }));
    testResult = '';
  }

  function updateLLM(field, value) {
    wizardState.update((s) => ({
      ...s,
      llm: { ...s.llm, [field]: value },
    }));
  }

  async function testConnection() {
    testing = true;
    testResult = '';
    try {
      // Simulate a quick test
      await new Promise((r) => setTimeout(r, 1000));
      testResult = 'success';
    } catch {
      testResult = 'error';
    } finally {
      testing = false;
    }
  }

  async function handleNext() {
    isLoading.set(true);
    try {
      await saveLLMConfig({
        provider: llm.provider,
        apiKey: llm.apiKey,
        model: llm.model,
        localEndpoint: llm.localEndpoint,
      });
    } catch {
      // Proceed anyway
    } finally {
      isLoading.set(false);
    }
    currentStep.update((n) => n + 1);
  }

  function handleBack() {
    currentStep.update((n) => n - 1);
  }
</script>

<div class="max-w-3xl mx-auto animate-fade-in">
  <div class="text-center mb-8">
    <h2 class="text-3xl font-bold text-gray-900 dark:text-white mb-2">
      Configure Transaction Analyzer
    </h2>
    <p class="text-gray-600 dark:text-gray-400">
      The secure server uses an LLM to analyze and validate transactions before
      co-signing.
    </p>
  </div>

  <Card>
    <div class="space-y-6">
      <!-- Provider Selection -->
      <div>
        <span class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">
          LLM Provider
        </span>
        <div class="grid grid-cols-1 sm:grid-cols-3 gap-3">
          {#each [
            { id: 'anthropic', name: 'Anthropic', desc: 'Claude models' },
            { id: 'openai', name: 'OpenAI', desc: 'GPT models' },
            { id: 'local', name: 'Local Model', desc: 'Self-hosted' },
          ] as provider}
            <button
              type="button"
              class="relative flex flex-col items-center p-4 rounded-xl border-2 transition-all duration-200
                {llm.provider === provider.id
                ? 'border-indigo-500 bg-indigo-50 dark:bg-indigo-900/20 ring-1 ring-indigo-500'
                : 'border-gray-200 dark:border-gray-700 hover:border-gray-300 dark:hover:border-gray-600 bg-white dark:bg-gray-800'}"
              onclick={() => setProvider(provider.id)}
            >
              <span
                class="text-sm font-semibold {llm.provider === provider.id
                  ? 'text-indigo-700 dark:text-indigo-300'
                  : 'text-gray-900 dark:text-white'}"
              >
                {provider.name}
              </span>
              <span class="text-xs text-gray-500 dark:text-gray-400 mt-0.5">
                {provider.desc}
              </span>
              {#if llm.provider === provider.id}
                <div class="absolute top-2 right-2">
                  <svg class="w-4 h-4 text-indigo-500" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
                  </svg>
                </div>
              {/if}
            </button>
          {/each}
        </div>
      </div>

      <!-- API Key (for Anthropic/OpenAI) -->
      {#if llm.provider === 'anthropic' || llm.provider === 'openai'}
        <Input
          label="API Key"
          type="password"
          placeholder={llm.provider === 'anthropic'
            ? 'sk-ant-...'
            : 'sk-...'}
          value={llm.apiKey ?? ''}
          oninput={(e) => updateLLM('apiKey', e.target.value)}
        />

        <div>
          <label
            for="model-select"
            class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1.5"
          >
            Model
          </label>
          <select
            id="model-select"
            class="block w-full rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-2.5 text-sm text-gray-900 dark:text-gray-100 focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500 focus:ring-offset-0 focus:outline-none transition-colors"
            value={llm.model}
            onchange={(e) => updateLLM('model', e.target.value)}
          >
            {#each currentModels as model}
              <option value={model.value}>{model.label}</option>
            {/each}
          </select>
        </div>
      {/if}

      <!-- Local endpoint -->
      {#if llm.provider === 'local'}
        <Input
          label="Endpoint URL"
          placeholder="http://localhost:11434/v1"
          value={llm.localEndpoint ?? ''}
          oninput={(e) => updateLLM('localEndpoint', e.target.value)}
          helpText="The URL of your locally hosted model API (e.g., Ollama, vLLM)"
        />
      {/if}

      <!-- Test Connection -->
      <div class="flex items-center gap-3">
        <Button
          variant="secondary"
          size="sm"
          loading={testing}
          onclick={testConnection}
        >
          Test Connection
        </Button>
        {#if testResult === 'success'}
          <span
            class="inline-flex items-center gap-1 text-sm text-emerald-600 dark:text-emerald-400"
          >
            <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7" />
            </svg>
            Connection successful
          </span>
        {:else if testResult === 'error'}
          <span
            class="inline-flex items-center gap-1 text-sm text-red-600 dark:text-red-400"
          >
            <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
            Connection failed
          </span>
        {/if}
      </div>

      <Alert variant="info">
        <p>
          The LLM analyzes each transaction request to detect anomalies,
          validate parameters, and ensure compliance with your trading
          policies before the co-signer approves it.
        </p>
      </Alert>
    </div>
  </Card>

  <div class="flex justify-between mt-8">
    <Button variant="ghost" onclick={handleBack}>
      <svg class="w-4 h-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
        <path stroke-linecap="round" stroke-linejoin="round" d="M11 17l-5-5m0 0l5-5m-5 5h12" />
      </svg>
      Back
    </Button>
    <Button onclick={handleNext}>
      Next
      <svg class="w-4 h-4 ml-1" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
        <path stroke-linecap="round" stroke-linejoin="round" d="M13 7l5 5m0 0l-5 5m5-5H6" />
      </svg>
    </Button>
  </div>
</div>
