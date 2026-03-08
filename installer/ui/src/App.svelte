<script>
  import StepIndicator from './lib/components/StepIndicator.svelte';
  import Welcome from './lib/steps/Welcome.svelte';
  import Servers from './lib/steps/Servers.svelte';
  import LLMSetup from './lib/steps/LLMSetup.svelte';
  import TelegramBot from './lib/steps/TelegramBot.svelte';
  import Review from './lib/steps/Review.svelte';
  import Install from './lib/steps/Install.svelte';
  import Done from './lib/steps/Done.svelte';
  import { onMount } from 'svelte';
  import { currentStep, restoreState } from './lib/stores.js';

  onMount(() => {
    restoreState();
  });

  const stepNames = [
    'Welcome',
    'Servers',
    'LLM',
    'Telegram',
    'Review',
    'Install',
    'Done',
  ];

  const stepComponents = [
    Welcome,
    Servers,
    LLMSetup,
    TelegramBot,
    Review,
    Install,
    Done,
  ];

  let step = $state(0);
  currentStep.subscribe((s) => (step = s));
</script>

<div class="min-h-screen flex flex-col">
  <!-- Header -->
  <header
    class="sticky top-0 z-10 bg-white/80 dark:bg-gray-900/80 backdrop-blur-lg border-b border-gray-200 dark:border-gray-800"
  >
    <div class="max-w-6xl mx-auto px-4 py-3">
      <div class="flex items-center justify-between mb-2">
        <div class="flex items-center gap-3">
          <div
            class="w-8 h-8 rounded-lg bg-indigo-600 flex items-center justify-center"
          >
            <svg
              class="w-5 h-5 text-white"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              stroke-width="2"
            >
              <path
                stroke-linecap="round"
                stroke-linejoin="round"
                d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z"
              />
            </svg>
          </div>
          <span class="text-lg font-bold text-gray-900 dark:text-white"
            >Crypto Claw</span
          >
        </div>
        <span class="text-sm text-gray-500 dark:text-gray-400">
          Step {step + 1} of {stepNames.length}
        </span>
      </div>
      <StepIndicator currentStep={step} steps={stepNames} />
    </div>
  </header>

  <!-- Main Content -->
  <main class="flex-1 px-4 py-8 sm:py-12">
    {#key step}
      {@const CurrentComponent = stepComponents[step]}
      <CurrentComponent />
    {/key}
  </main>

  <!-- Footer -->
  <footer
    class="border-t border-gray-200 dark:border-gray-800 py-4 px-4 text-center"
  >
    <p class="text-xs text-gray-400 dark:text-gray-500">
      Crypto Claw Installer
    </p>
  </footer>
</div>
