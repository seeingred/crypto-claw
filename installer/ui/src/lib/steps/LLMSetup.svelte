<script>
  import Button from '../components/Button.svelte';
  import Card from '../components/Card.svelte';
  import Input from '../components/Input.svelte';
  import Alert from '../components/Alert.svelte';
  import { currentStep, wizardState, isLoading } from '../stores.js';
  import { saveLLMConfig, testLLMConnection, skipLLM } from '../api.js';

  let state = $state({});
  wizardState.subscribe((s) => (state = s));

  let llm = $derived(state.llm ?? {});
  let testing = $state(false);
  let testResult = $state('');
  let testError = $state('');
  let useLocal = $state(false);

  const anthropicModels = [
    { value: 'claude-sonnet-4-20250514', label: 'Claude Sonnet 4' },
    { value: 'claude-haiku-4-5-20251001', label: 'Claude Haiku 4.5' },
  ];

  const openaiModels = [
    { value: 'gpt-4o', label: 'GPT-4o' },
    { value: 'gpt-4o-mini', label: 'GPT-4o Mini' },
  ];

  // Auto-detect provider from API key prefix.
  let detectedProvider = $derived(
    llm.apiKey?.startsWith('sk-ant-')
      ? 'anthropic'
      : llm.apiKey?.startsWith('sk-proj-') || llm.apiKey?.startsWith('sk-or-') || (llm.apiKey?.startsWith('sk-') && !llm.apiKey?.startsWith('sk-ant-'))
        ? 'openai'
        : ''
  );

  let currentModels = $derived(
    detectedProvider === 'anthropic'
      ? anthropicModels
      : detectedProvider === 'openai'
        ? openaiModels
        : []
  );

  let effectiveProvider = $derived(useLocal ? 'local' : detectedProvider);

  // Set default model when provider changes.
  function onApiKeyInput(value) {
    wizardState.update((s) => {
      const updated = { ...s, llm: { ...s.llm, apiKey: value } };
      // Auto-set default model when provider is first detected.
      const prov = value?.startsWith('sk-ant-')
        ? 'anthropic'
        : value?.startsWith('sk-proj-') || value?.startsWith('sk-or-') || (value?.startsWith('sk-') && !value?.startsWith('sk-ant-'))
          ? 'openai'
          : '';
      if (prov === 'anthropic' && !anthropicModels.some((m) => m.value === s.llm.model)) {
        updated.llm.model = 'claude-sonnet-4-20250514';
      } else if (prov === 'openai' && !openaiModels.some((m) => m.value === s.llm.model)) {
        updated.llm.model = 'gpt-4o';
      }
      return updated;
    });
    testResult = '';
    testError = '';
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
    testError = '';
    try {
      const res = await testLLMConnection({
        provider: effectiveProvider,
        apiKey: llm.apiKey,
        model: llm.model,
        endpoint: llm.localEndpoint || '',
      });
      if (res.success) {
        testResult = 'success';
      } else {
        testResult = 'error';
        testError = res.error || 'Unknown error';
      }
    } catch (e) {
      testResult = 'error';
      // Parse error message — may contain raw JSON like '{"error":"..."}'
      let msg = e.message || 'Connection failed';
      try {
        const jsonMatch = msg.match(/\{.*\}/);
        if (jsonMatch) {
          const parsed = JSON.parse(jsonMatch[0]);
          msg = parsed.error || msg;
        }
      } catch { /* use raw message */ }
      testError = msg;
    } finally {
      testing = false;
    }
  }

  async function handleNext() {
    isLoading.set(true);
    try {
      await saveLLMConfig({
        provider: effectiveProvider,
        apiKey: llm.apiKey,
        model: llm.model,
        endpoint: llm.localEndpoint,
      });
    } catch {
      // Proceed anyway
    } finally {
      isLoading.set(false);
    }
    wizardState.update((s) => ({
      ...s,
      disableAI: false,
      llm: { ...s.llm, provider: effectiveProvider },
    }));
    currentStep.update((n) => n + 1);
  }

  async function handleSkip() {
    isLoading.set(true);
    try {
      await skipLLM();
    } catch {
      // Proceed anyway
    } finally {
      isLoading.set(false);
    }
    wizardState.update((s) => ({ ...s, disableAI: true, llm: { ...s.llm, provider: '', model: '' } }));
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
      {#if !useLocal}
        <!-- API Key -->
        <Input
          label="API Key"
          type="password"
          placeholder="sk-ant-... or sk-proj-..."
          value={llm.apiKey ?? ''}
          oninput={(e) => onApiKeyInput(e.target.value)}
          helpText="Paste your Anthropic or OpenAI API key — provider is detected automatically"
        />

        {#if detectedProvider}
          <div class="flex items-center gap-2">
            <span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium
              {detectedProvider === 'anthropic'
                ? 'bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-300'
                : 'bg-emerald-100 text-emerald-800 dark:bg-emerald-900/30 dark:text-emerald-300'}">
              <svg class="w-3 h-3" fill="currentColor" viewBox="0 0 20 20">
                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
              </svg>
              {detectedProvider === 'anthropic' ? 'Anthropic' : 'OpenAI'}
            </span>
          </div>

          <!-- Model selector -->
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

        <button
          type="button"
          class="text-xs text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300 underline"
          onclick={() => { useLocal = true; testResult = ''; updateLLM('model', ''); }}
        >
          Using a self-hosted model instead?
        </button>
      {:else}
        <!-- Local model -->
        <Input
          label="Endpoint URL"
          placeholder="http://localhost:11434/v1"
          value={llm.localEndpoint ?? ''}
          oninput={(e) => updateLLM('localEndpoint', e.target.value)}
          helpText="OpenAI-compatible API endpoint (e.g., Ollama, vLLM)"
        />
        <Input
          label="Model Name"
          placeholder="llama3"
          value={llm.model ?? ''}
          oninput={(e) => updateLLM('model', e.target.value)}
        />

        <button
          type="button"
          class="text-xs text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300 underline"
          onclick={() => { useLocal = false; testResult = ''; }}
        >
          Using Anthropic or OpenAI instead?
        </button>
      {/if}

      <!-- Test Connection -->
      <div class="flex items-center gap-3">
        <Button
          variant="secondary"
          size="sm"
          loading={testing}
          onclick={testConnection}
          disabled={useLocal ? !llm.localEndpoint : !llm.apiKey}
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
            {testError || 'Connection failed'}
          </span>
        {/if}
      </div>

      <Alert variant="info">
        <p>
          The LLM analyzes each transaction request to detect anomalies,
          validate parameters, and ensure compliance with your trading
          policies before the co-signer approves it.
          You can also <strong>skip this step</strong> to use deterministic
          checks and address whitelisting only — no LLM dependency required.
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
    <div class="flex gap-3">
      <Button variant="secondary" onclick={handleSkip}>
        Skip — No AI
      </Button>
      <Button onclick={handleNext} disabled={!useLocal && !detectedProvider}>
        Next
        <svg class="w-4 h-4 ml-1" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M13 7l5 5m0 0l-5 5m5-5H6" />
        </svg>
      </Button>
    </div>
  </div>
</div>
