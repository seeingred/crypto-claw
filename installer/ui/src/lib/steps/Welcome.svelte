<script>
  import Button from '../components/Button.svelte';
  import Card from '../components/Card.svelte';
  import { currentStep } from '../stores.js';

  function handleStart() {
    currentStep.update((n) => n + 1);
  }
</script>

<div class="max-w-4xl mx-auto animate-fade-in">
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

  <Card title="Two-Server Architecture">
    <p class="text-sm text-gray-600 dark:text-gray-400 mb-6">
      Crypto Claw uses a distributed key generation (DKG) protocol to split
      signing authority across two independent servers. Both must agree before
      any transaction is signed.
    </p>

    <div
      class="grid grid-cols-1 md:grid-cols-3 gap-4 items-center mb-6"
    >
      <!-- Party A -->
      <div
        class="bg-indigo-50 dark:bg-indigo-900/20 border border-indigo-200 dark:border-indigo-800 rounded-xl p-5"
      >
        <div class="flex items-center gap-2 mb-3">
          <div
            class="w-8 h-8 rounded-lg bg-indigo-500 text-white flex items-center justify-center text-sm font-bold"
          >
            A
          </div>
          <h4 class="font-semibold text-indigo-900 dark:text-indigo-300">
            AI Server
          </h4>
        </div>
        <ul class="text-sm text-gray-600 dark:text-gray-400 space-y-1.5">
          <li class="flex items-start gap-1.5">
            <span class="text-indigo-500 mt-0.5">&#8226;</span>
            TSS signer service
          </li>
          <li class="flex items-start gap-1.5">
            <span class="text-indigo-500 mt-0.5">&#8226;</span>
            Trading bot engine
          </li>
          <li class="flex items-start gap-1.5">
            <span class="text-indigo-500 mt-0.5">&#8226;</span>
            Localhost API
          </li>
        </ul>
      </div>

      <!-- Connection Arrow -->
      <div class="flex flex-col items-center justify-center py-4">
        <div
          class="hidden md:flex items-center gap-1 text-gray-400 dark:text-gray-500"
        >
          <div class="w-12 h-0.5 bg-gray-300 dark:bg-gray-600"></div>
          <svg class="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
            <path stroke-linecap="round" stroke-linejoin="round" d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4" />
          </svg>
          <div class="w-12 h-0.5 bg-gray-300 dark:bg-gray-600"></div>
        </div>
        <div class="md:hidden flex items-center gap-1 text-gray-400 dark:text-gray-500">
          <svg class="w-6 h-6 rotate-90" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
            <path stroke-linecap="round" stroke-linejoin="round" d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4" />
          </svg>
        </div>
        <span
          class="text-xs font-medium text-gray-500 dark:text-gray-400 mt-1 bg-gray-100 dark:bg-gray-700 px-2 py-0.5 rounded"
          >Encrypted</span
        >
      </div>

      <!-- Party B -->
      <div
        class="bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800 rounded-xl p-5"
      >
        <div class="flex items-center gap-2 mb-3">
          <div
            class="w-8 h-8 rounded-lg bg-emerald-500 text-white flex items-center justify-center text-sm font-bold"
          >
            B
          </div>
          <h4 class="font-semibold text-emerald-900 dark:text-emerald-300">
            Secure Server
          </h4>
        </div>
        <ul class="text-sm text-gray-600 dark:text-gray-400 space-y-1.5">
          <li class="flex items-start gap-1.5">
            <span class="text-emerald-500 mt-0.5">&#8226;</span>
            Co-signer service
          </li>
          <li class="flex items-start gap-1.5">
            <span class="text-emerald-500 mt-0.5">&#8226;</span>
            LLM transaction analysis
          </li>
          <li class="flex items-start gap-1.5">
            <span class="text-emerald-500 mt-0.5">&#8226;</span>
            Policy enforcement
          </li>
        </ul>
      </div>
    </div>

    <!-- Architecture Diagram -->
    <div
      class="bg-gray-50 dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-700 p-4 font-mono text-xs text-gray-600 dark:text-gray-400 overflow-x-auto"
    >
      <pre class="text-center leading-relaxed">
  +---------------------------+         +---------------------------+
  |       Party A (AI)        |         |     Party B (Secure)      |
  |                           |   TLS   |                           |
  |  +---------------------+  | &lt;-----&gt; |  +---------------------+  |
  |  |   TSS Signer (1/2)  |  |         |  |  Co-Signer (2/2)    |  |
  |  +---------------------+  |         |  +---------------------+  |
  |  |   Trading Bot        |  |         |  |  LLM Analyzer       |  |
  |  +---------------------+  |         |  +---------------------+  |
  |  |   Web UI / API       |  |         |  |  Policy Engine      |  |
  |  +---------------------+  |         |  +---------------------+  |
  +---------------------------+         +---------------------------+
               |                                     |
        localhost:8080                          AI validates
        Bot commands                         every transaction</pre>
    </div>
  </Card>

  <div class="flex justify-center mt-8">
    <Button size="xl" onclick={handleStart}>
      Get Started
      <svg
        class="w-5 h-5 ml-1"
        fill="none"
        viewBox="0 0 24 24"
        stroke="currentColor"
        stroke-width="2"
      >
        <path
          stroke-linecap="round"
          stroke-linejoin="round"
          d="M13 7l5 5m0 0l-5 5m5-5H6"
        />
      </svg>
    </Button>
  </div>
</div>
