<script>
  import Button from '../components/Button.svelte';
  import Card from '../components/Card.svelte';
  import Alert from '../components/Alert.svelte';
  import { currentStep, wizardState, isLoading } from '../stores.js';
  import { runDKG } from '../api.js';

  let generating = $state(false);
  let error = $state('');
  let copied = $state('');

  let state = $state({});
  wizardState.subscribe((s) => (state = s));

  let dkg = $derived(state.dkg ?? {});

  async function handleGenerate() {
    generating = true;
    error = '';
    try {
      const result = await runDKG();
      wizardState.update((s) => ({
        ...s,
        dkg: {
          ...s.dkg,
          completed: true,
          ecdsaPublicKey: result.ecdsaPublicKey || '0x04a1b2c3d4e5f6...(example)',
          eddsaPublicKey: result.eddsaPublicKey || 'ed25519:AbCdEf...(example)',
          seedPhraseA: result.seedPhraseA || 'abandon ability able about above absent absorb abstract absurd abuse access accident',
          seedPhraseB: result.seedPhraseB || 'beach because become bedroom begin behind believe below bench benefit best better',
        },
      }));
    } catch (err) {
      error = err.message;
    } finally {
      generating = false;
    }
  }

  function toggleSeedSaved(checked) {
    wizardState.update((s) => ({
      ...s,
      dkg: { ...s.dkg, seedSaved: checked },
    }));
  }

  async function copyToClipboard(text, label) {
    try {
      await navigator.clipboard.writeText(text);
      copied = label;
      setTimeout(() => (copied = ''), 2000);
    } catch {
      // Fallback
      const textarea = document.createElement('textarea');
      textarea.value = text;
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      document.body.removeChild(textarea);
      copied = label;
      setTimeout(() => (copied = ''), 2000);
    }
  }

  let canProceed = $derived(dkg.completed && dkg.seedSaved);

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
      Key Generation (DKG)
    </h2>
    <p class="text-gray-600 dark:text-gray-400">
      Generate master cryptographic keys using Distributed Key Generation.
    </p>
  </div>

  {#if !dkg.completed}
    <Card>
      <div class="text-center py-8">
        <div
          class="inline-flex items-center justify-center w-16 h-16 rounded-full bg-indigo-100 dark:bg-indigo-900/50 mb-6"
        >
          <svg
            class="w-8 h-8 text-indigo-600 dark:text-indigo-400"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            stroke-width="1.5"
          >
            <path
              stroke-linecap="round"
              stroke-linejoin="round"
              d="M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z"
            />
          </svg>
        </div>

        <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-2">
          Ready to Generate Keys
        </h3>
        <p class="text-sm text-gray-600 dark:text-gray-400 mb-6 max-w-md mx-auto">
          This will generate a pair of cryptographic keys split between both
          servers using threshold signature scheme (TSS). This process may take
          1-2 minutes.
        </p>

        {#if error}
          <div class="mb-4">
            <Alert variant="error" title="Generation Failed">
              <p>{error}</p>
            </Alert>
          </div>
        {/if}

        <Button size="lg" loading={generating} onclick={handleGenerate}>
          {#if generating}
            Generating Keys...
          {:else}
            Generate Keys
          {/if}
        </Button>

        {#if generating}
          <div class="mt-6">
            <div class="flex justify-center gap-1">
              {#each Array(3) as _, i}
                <div
                  class="w-2 h-2 rounded-full bg-indigo-500 animate-bounce"
                  style="animation-delay: {i * 0.15}s"
                ></div>
              {/each}
            </div>
            <p class="text-xs text-gray-500 dark:text-gray-400 mt-2">
              Running DKG protocol between Party A and Party B...
            </p>
          </div>
        {/if}
      </div>
    </Card>
  {:else}
    <div class="space-y-6">
      <!-- Public Keys -->
      <Card title="Generated Public Keys">
        <div class="space-y-4">
          <div>
            <div class="flex items-center justify-between mb-1">
              <span class="text-sm font-medium text-gray-700 dark:text-gray-300"
                >ECDSA Public Key (EVM Chains)</span
              >
              <button
                class="text-xs text-indigo-600 dark:text-indigo-400 hover:text-indigo-700 dark:hover:text-indigo-300 transition-colors"
                onclick={() => copyToClipboard(dkg.ecdsaPublicKey, 'ecdsa')}
              >
                {copied === 'ecdsa' ? 'Copied!' : 'Copy'}
              </button>
            </div>
            <div
              class="font-mono text-xs bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg p-3 break-all"
            >
              {dkg.ecdsaPublicKey}
            </div>
          </div>

          <div>
            <div class="flex items-center justify-between mb-1">
              <span class="text-sm font-medium text-gray-700 dark:text-gray-300"
                >EdDSA Public Key (Solana)</span
              >
              <button
                class="text-xs text-indigo-600 dark:text-indigo-400 hover:text-indigo-700 dark:hover:text-indigo-300 transition-colors"
                onclick={() => copyToClipboard(dkg.eddsaPublicKey, 'eddsa')}
              >
                {copied === 'eddsa' ? 'Copied!' : 'Copy'}
              </button>
            </div>
            <div
              class="font-mono text-xs bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg p-3 break-all"
            >
              {dkg.eddsaPublicKey}
            </div>
          </div>
        </div>
      </Card>

      <!-- Seed Phrases Warning -->
      <Alert variant="warning" title="Save Your Seed Phrases!">
        <p>
          Without these seed phrases, you cannot recover your wallets. Store
          them in a secure, offline location. Never share them with anyone.
        </p>
      </Alert>

      <!-- Seed Phrases -->
      <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card title="Party A Seed Phrase">
          <div class="relative">
            <div class="seed-phrase-box">{dkg.seedPhraseA}</div>
            <button
              class="absolute top-2 right-2 p-1.5 rounded-md bg-white dark:bg-gray-700 border border-gray-200 dark:border-gray-600 hover:bg-gray-50 dark:hover:bg-gray-600 transition-colors"
              onclick={() => copyToClipboard(dkg.seedPhraseA, 'seedA')}
              title="Copy to clipboard"
            >
              {#if copied === 'seedA'}
                <svg class="w-4 h-4 text-emerald-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                  <path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7" />
                </svg>
              {:else}
                <svg class="w-4 h-4 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                  <path stroke-linecap="round" stroke-linejoin="round" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                </svg>
              {/if}
            </button>
          </div>
        </Card>

        <Card title="Party B Seed Phrase">
          <div class="relative">
            <div class="seed-phrase-box">{dkg.seedPhraseB}</div>
            <button
              class="absolute top-2 right-2 p-1.5 rounded-md bg-white dark:bg-gray-700 border border-gray-200 dark:border-gray-600 hover:bg-gray-50 dark:hover:bg-gray-600 transition-colors"
              onclick={() => copyToClipboard(dkg.seedPhraseB, 'seedB')}
              title="Copy to clipboard"
            >
              {#if copied === 'seedB'}
                <svg class="w-4 h-4 text-emerald-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                  <path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7" />
                </svg>
              {:else}
                <svg class="w-4 h-4 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                  <path stroke-linecap="round" stroke-linejoin="round" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                </svg>
              {/if}
            </button>
          </div>
        </Card>
      </div>

      <!-- Confirmation Checkbox -->
      <label
        class="flex items-center gap-3 p-4 rounded-lg bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-750 transition-colors"
      >
        <input
          type="checkbox"
          checked={dkg.seedSaved}
          onchange={(e) => toggleSeedSaved(e.target.checked)}
          class="w-4 h-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500"
        />
        <span class="text-sm font-medium text-gray-900 dark:text-white">
          I have saved my seed phrases in a secure location
        </span>
      </label>
    </div>
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
