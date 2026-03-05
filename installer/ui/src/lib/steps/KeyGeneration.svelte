<script>
  import Button from '../components/Button.svelte';
  import Card from '../components/Card.svelte';
  import Alert from '../components/Alert.svelte';
  import { currentStep, wizardState, isLoading } from '../stores.js';
  import { runDKG } from '../api.js';

  let generating = $state(false);
  let error = $state('');
  let copied = $state(false);

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
          ecdsaPubKey: result.ecdsaPubKey,
          eddsaPubKey: result.eddsaPubKey,
          backupA: result.backupA,
          backupB: result.backupB,
        },
      }));
    } catch (err) {
      error = err.message;
    } finally {
      generating = false;
    }
  }

  function toggleBackupSaved(checked) {
    wizardState.update((s) => ({
      ...s,
      dkg: { ...s.dkg, backupSaved: checked },
    }));
  }

  function buildBackupJSON() {
    return JSON.stringify(
      {
        ecdsaPubKey: dkg.ecdsaPubKey,
        eddsaPubKey: dkg.eddsaPubKey,
        partyA: JSON.parse(dkg.backupA || '{}'),
        partyB: JSON.parse(dkg.backupB || '{}'),
      },
      null,
      2
    );
  }

  async function copyAll() {
    const text = buildBackupJSON();
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const textarea = document.createElement('textarea');
      textarea.value = text;
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      document.body.removeChild(textarea);
    }
    copied = true;
    setTimeout(() => (copied = false), 2000);
  }

  let canProceed = $derived(dkg.completed && dkg.backupSaved);

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
      <Card title="Master Public Keys">
        <div class="space-y-4">
          <div>
            <span class="text-sm font-medium text-gray-700 dark:text-gray-300"
              >ECDSA (EVM / Cosmos)</span
            >
            <div
              class="font-mono text-xs bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg p-3 mt-1 break-all"
            >
              {dkg.ecdsaPubKey}
            </div>
          </div>

          <div>
            <span class="text-sm font-medium text-gray-700 dark:text-gray-300"
              >EdDSA (Solana)</span
            >
            <div
              class="font-mono text-xs bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg p-3 mt-1 break-all"
            >
              {dkg.eddsaPubKey}
            </div>
          </div>
        </div>
      </Card>

      <!-- Key Share Backup -->
      <Alert variant="warning" title="Back Up Your Key Shares!">
        <p>
          Each party holds a share of two master private keys (ECDSA + EdDSA).
          Neither share alone can sign transactions. Copy the full backup
          below and save it to a secure, offline location. Without it, you
          cannot restore signing capability if a server is lost.
        </p>
      </Alert>

      <div class="text-center">
        <Button size="lg" onclick={copyAll}>
          {#if copied}
            <svg class="w-5 h-5 mr-1 text-emerald-300" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7" />
            </svg>
            Copied!
          {:else}
            <svg class="w-5 h-5 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
            </svg>
            Copy All Key Shares
          {/if}
        </Button>
        <p class="text-xs text-gray-500 dark:text-gray-400 mt-2">
          Copies public keys and both party key shares as JSON
        </p>
      </div>

      <!-- Confirmation Checkbox -->
      <label
        class="flex items-center gap-3 p-4 rounded-lg bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-750 transition-colors"
      >
        <input
          type="checkbox"
          checked={dkg.backupSaved}
          onchange={(e) => toggleBackupSaved(e.target.checked)}
          class="w-4 h-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500"
        />
        <span class="text-sm font-medium text-gray-900 dark:text-white">
          I have saved the key share backup in a secure location
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
