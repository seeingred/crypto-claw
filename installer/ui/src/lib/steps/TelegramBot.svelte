<script>
  import Button from '../components/Button.svelte';
  import Card from '../components/Card.svelte';
  import Input from '../components/Input.svelte';
  import { currentStep, wizardState } from '../stores.js';
  import { saveTelegramToken } from '../api.js';

  let state = $state({});
  wizardState.subscribe((s) => (state = s));

  let botToken = $derived(state.telegram?.botToken ?? '');

  function updateToken(value) {
    wizardState.update((s) => ({
      ...s,
      telegram: { ...s.telegram, botToken: value },
    }));
  }

  async function handleNext() {
    try {
      await saveTelegramToken(botToken);
    } catch {
      // Proceed anyway
    }
    currentStep.update((n) => n + 1);
  }

  function handleBack() {
    currentStep.update((n) => n - 1);
  }

  const steps = [
    {
      num: 1,
      title: 'Open Telegram',
      desc: 'Search for @BotFather in Telegram',
    },
    {
      num: 2,
      title: 'Create a new bot',
      desc: 'Send /newbot and follow the prompts to name your bot',
    },
    {
      num: 3,
      title: 'Copy the token',
      desc: 'BotFather will give you an API token. Paste it below.',
    },
  ];
</script>

<div class="max-w-3xl mx-auto animate-fade-in">
  <div class="text-center mb-8">
    <h2 class="text-3xl font-bold text-gray-900 dark:text-white mb-2">
      Set Up Telegram Notifications
    </h2>
    <p class="text-gray-600 dark:text-gray-400">
      Create a Telegram bot to receive trade notifications and manage your bot.
    </p>
  </div>

  <Card title="How to Create a Telegram Bot">
    <div class="space-y-4 mb-6">
      {#each steps as step}
        <div class="flex items-start gap-4">
          <div
            class="flex-shrink-0 w-8 h-8 rounded-full bg-indigo-100 dark:bg-indigo-900/50 flex items-center justify-center"
          >
            <span class="text-sm font-bold text-indigo-600 dark:text-indigo-400"
              >{step.num}</span
            >
          </div>
          <div class="pt-1">
            <h4 class="text-sm font-semibold text-gray-900 dark:text-white">
              {step.title}
            </h4>
            <p class="text-sm text-gray-600 dark:text-gray-400">{step.desc}</p>
          </div>
        </div>
      {/each}
    </div>

    <div
      class="bg-gray-50 dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-700 p-4 mb-6"
    >
      <div class="flex items-center gap-2 mb-2">
        <svg
          class="w-5 h-5 text-blue-500"
          fill="currentColor"
          viewBox="0 0 24 24"
        >
          <path
            d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm4.64 6.8c-.15 1.58-.8 5.42-1.13 7.19-.14.75-.42 1-.68 1.03-.58.05-1.02-.38-1.58-.75-.88-.58-1.38-.94-2.23-1.5-.99-.65-.35-1.01.22-1.59.15-.15 2.71-2.48 2.76-2.69.01-.03.01-.14-.07-.2-.08-.06-.19-.04-.27-.02-.12.03-1.99 1.27-5.62 3.72-.53.36-1.01.54-1.44.53-.47-.01-1.38-.27-2.06-.49-.83-.27-1.49-.42-1.43-.88.03-.24.37-.49 1.02-.74 3.98-1.73 6.64-2.87 7.97-3.43 3.79-1.58 4.58-1.86 5.09-1.87.11 0 .37.03.54.17.14.12.18.28.2.45-.01.06.01.24 0 .38z"
          />
        </svg>
        <span class="text-sm font-medium text-gray-900 dark:text-white"
          >Quick Link</span
        >
      </div>
      <p class="text-sm text-gray-600 dark:text-gray-400">
        Open
        <a
          href="https://t.me/BotFather"
          target="_blank"
          rel="noopener noreferrer"
          class="text-indigo-600 dark:text-indigo-400 hover:underline font-medium"
          >t.me/BotFather</a
        >
        in your browser or search for
        <span class="font-mono text-xs bg-gray-200 dark:bg-gray-700 px-1.5 py-0.5 rounded"
          >@BotFather</span
        >
        in Telegram.
      </p>
    </div>

    <Input
      label="Bot Token"
      placeholder="123456789:ABCdefGHIjklMNOpqrsTUVwxyz"
      value={botToken}
      oninput={(e) => updateToken(e.target.value)}
      helpText="The token looks like: 123456789:ABCdefGHIjklMNOpqrsTUVwxyz"
    />
  </Card>

  <div class="flex justify-between mt-8">
    <Button variant="ghost" onclick={handleBack}>
      <svg class="w-4 h-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
        <path stroke-linecap="round" stroke-linejoin="round" d="M11 17l-5-5m0 0l5-5m-5 5h12" />
      </svg>
      Back
    </Button>
    <Button disabled={!botToken.trim()} onclick={handleNext}>
      Next
      <svg class="w-4 h-4 ml-1" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
        <path stroke-linecap="round" stroke-linejoin="round" d="M13 7l5 5m0 0l-5 5m5-5H6" />
      </svg>
    </Button>
  </div>
</div>
