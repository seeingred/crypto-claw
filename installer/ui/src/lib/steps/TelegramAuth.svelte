<script>
  import Button from '../components/Button.svelte';
  import Card from '../components/Card.svelte';
  import Alert from '../components/Alert.svelte';
  import { currentStep, wizardState } from '../stores.js';
  import { verifyTelegramUser } from '../api.js';

  let state = $state({});
  wizardState.subscribe((s) => (state = s));

  let telegram = $derived(state.telegram ?? {});
  let listening = $state(false);
  let error = $state('');

  async function startListening() {
    listening = true;
    error = '';
    try {
      const result = await verifyTelegramUser();
      wizardState.update((s) => ({
        ...s,
        telegram: {
          ...s.telegram,
          userId: result.userId || result.user_id || 'unknown',
          authorized: true,
        },
      }));
    } catch (err) {
      error = err.message;
    } finally {
      listening = false;
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
      Authorize Your Telegram Account
    </h2>
    <p class="text-gray-600 dark:text-gray-400">
      Link your Telegram account to receive notifications and control the bot.
    </p>
  </div>

  <Card>
    <div class="text-center py-6">
      {#if !telegram.authorized}
        <div
          class="inline-flex items-center justify-center w-16 h-16 rounded-full bg-blue-100 dark:bg-blue-900/50 mb-6"
        >
          <svg
            class="w-8 h-8 text-blue-600 dark:text-blue-400"
            fill="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm4.64 6.8c-.15 1.58-.8 5.42-1.13 7.19-.14.75-.42 1-.68 1.03-.58.05-1.02-.38-1.58-.75-.88-.58-1.38-.94-2.23-1.5-.99-.65-.35-1.01.22-1.59.15-.15 2.71-2.48 2.76-2.69.01-.03.01-.14-.07-.2-.08-.06-.19-.04-.27-.02-.12.03-1.99 1.27-5.62 3.72-.53.36-1.01.54-1.44.53-.47-.01-1.38-.27-2.06-.49-.83-.27-1.49-.42-1.43-.88.03-.24.37-.49 1.02-.74 3.98-1.73 6.64-2.87 7.97-3.43 3.79-1.58 4.58-1.86 5.09-1.87.11 0 .37.03.54.17.14.12.18.28.2.45-.01.06.01.24 0 .38z"
            />
          </svg>
        </div>

        <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-2">
          Send a Message to Your Bot
        </h3>
        <p class="text-sm text-gray-600 dark:text-gray-400 mb-6 max-w-md mx-auto">
          Open your new Telegram bot and send any message (e.g., "hello"). Then
          click the button below to detect your user ID.
        </p>

        {#if error}
          <div class="mb-4 text-left">
            <Alert variant="error" title="Verification Failed">
              <p>{error}</p>
            </Alert>
          </div>
        {/if}

        <Button size="lg" loading={listening} onclick={startListening}>
          {#if listening}
            Listening for messages...
          {:else}
            Start Listening
          {/if}
        </Button>

        {#if listening}
          <div class="mt-6">
            <div class="flex justify-center gap-1">
              {#each Array(3) as _, i}
                <div
                  class="w-2 h-2 rounded-full bg-blue-500 animate-bounce"
                  style="animation-delay: {i * 0.15}s"
                ></div>
              {/each}
            </div>
            <p class="text-xs text-gray-500 dark:text-gray-400 mt-2">
              Waiting for a message from your Telegram account...
            </p>
          </div>
        {/if}
      {:else}
        <div
          class="inline-flex items-center justify-center w-16 h-16 rounded-full bg-emerald-100 dark:bg-emerald-900/50 mb-6 animate-checkmark"
        >
          <svg
            class="w-8 h-8 text-emerald-600 dark:text-emerald-400"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            stroke-width="2.5"
          >
            <path
              stroke-linecap="round"
              stroke-linejoin="round"
              d="M5 13l4 4L19 7"
            />
          </svg>
        </div>

        <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-2">
          Account Authorized
        </h3>

        <div
          class="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800"
        >
          <svg
            class="w-4 h-4 text-emerald-500"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            stroke-width="2"
          >
            <path
              stroke-linecap="round"
              stroke-linejoin="round"
              d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"
            />
          </svg>
          <span class="text-sm font-medium text-emerald-700 dark:text-emerald-300">
            Authorized user: {telegram.userId}
          </span>
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
    <Button disabled={!telegram.authorized} onclick={handleNext}>
      Next
      <svg class="w-4 h-4 ml-1" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
        <path stroke-linecap="round" stroke-linejoin="round" d="M13 7l5 5m0 0l-5 5m5-5H6" />
      </svg>
    </Button>
  </div>
</div>
