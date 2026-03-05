<script>
  import Button from '../components/Button.svelte';
  import Card from '../components/Card.svelte';
  import { wizardState } from '../stores.js';
  import { onMount } from 'svelte';

  let state = $state({});
  wizardState.subscribe((s) => (state = s));

  let showConfetti = $state(false);
  let showContent = $state(false);

  let partyAUrl = $derived(
    state.deployment?.partyAUrl || 'http://localhost:8080'
  );
  let botUsername = $derived(state.telegram?.botUsername || '');

  onMount(() => {
    showConfetti = true;
    setTimeout(() => {
      showContent = true;
    }, 300);
  });

  let copied = $state('');

  async function copyToClipboard(text, label) {
    try {
      await navigator.clipboard.writeText(text);
      copied = label;
      setTimeout(() => (copied = ''), 2000);
    } catch {
      copied = label;
      setTimeout(() => (copied = ''), 2000);
    }
  }
</script>

<div class="max-w-3xl mx-auto animate-fade-in">
  <!-- Confetti / Success Animation -->
  <div class="relative text-center mb-8">
    {#if showConfetti}
      <div class="absolute inset-0 overflow-hidden pointer-events-none">
        {#each Array(20) as _, i}
          <div
            class="absolute animate-confetti"
            style="
              left: {10 + Math.random() * 80}%;
              top: 50%;
              animation-delay: {Math.random() * 0.5}s;
              animation-duration: {1 + Math.random() * 1.5}s;
            "
          >
            <div
              class="w-2 h-2 rounded-sm"
              style="
                background-color: {[
                '#6366f1',
                '#8b5cf6',
                '#ec4899',
                '#f59e0b',
                '#10b981',
                '#3b82f6',
              ][i % 6]};
                transform: rotate({Math.random() * 360}deg);
              "
            ></div>
          </div>
        {/each}
      </div>
    {/if}

    <!-- Checkmark animation -->
    <div class="relative inline-block mb-6">
      <div
        class="w-24 h-24 rounded-full bg-emerald-100 dark:bg-emerald-900/50 flex items-center justify-center"
        class:animate-checkmark={showContent}
      >
        <svg
          class="w-12 h-12 text-emerald-600 dark:text-emerald-400"
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
    </div>

    <h1 class="text-4xl font-bold text-gray-900 dark:text-white mb-3">
      Setup Complete!
    </h1>
    <p class="text-lg text-gray-600 dark:text-gray-400 max-w-lg mx-auto">
      Crypto Claw has been successfully deployed and is ready to use.
    </p>
  </div>

  {#if showContent}
    <div class="space-y-4">
      <!-- Web UI Link -->
      <Card>
        <div class="flex items-center gap-4">
          <div
            class="flex-shrink-0 w-12 h-12 rounded-xl bg-indigo-100 dark:bg-indigo-900/50 flex items-center justify-center"
          >
            <svg
              class="w-6 h-6 text-indigo-600 dark:text-indigo-400"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              stroke-width="1.5"
            >
              <path
                stroke-linecap="round"
                stroke-linejoin="round"
                d="M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 017.843 4.582M12 3a8.997 8.997 0 00-7.843 4.582m15.686 0A11.953 11.953 0 0112 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0121 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0112 16.5c-3.162 0-6.133-.815-8.716-2.247m0 0A9.015 9.015 0 013 12c0-1.605.42-3.113 1.157-4.418"
              />
            </svg>
          </div>
          <div class="flex-1 min-w-0">
            <h3 class="text-sm font-semibold text-gray-900 dark:text-white">
              Party A Web UI
            </h3>
            <a
              href={partyAUrl}
              target="_blank"
              rel="noopener noreferrer"
              class="text-sm text-indigo-600 dark:text-indigo-400 hover:underline break-all"
            >
              {partyAUrl}
            </a>
          </div>
          <button
            class="p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
            onclick={() => copyToClipboard(partyAUrl, 'url')}
          >
            {#if copied === 'url'}
              <svg class="w-4 h-4 text-emerald-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                <path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7" />
              </svg>
            {:else}
              <svg class="w-4 h-4 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                <path stroke-linecap="round" stroke-linejoin="round" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
              </svg>
            {/if}
          </button>
        </div>
      </Card>

      <!-- Quick Reference -->
      <Card title="Quick Reference">
        <div class="space-y-3">
          <div class="flex items-center justify-between py-2 border-b border-gray-100 dark:border-gray-700">
            <span class="text-sm text-gray-600 dark:text-gray-400">Party A API</span>
            <div class="flex items-center gap-2">
              <code class="text-sm font-mono text-gray-900 dark:text-white">{partyAUrl}/api</code>
              <button
                class="p-1 rounded hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
                onclick={() => copyToClipboard(`${partyAUrl}/api`, 'api')}
              >
                {#if copied === 'api'}
                  <svg class="w-3.5 h-3.5 text-emerald-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7" />
                  </svg>
                {:else}
                  <svg class="w-3.5 h-3.5 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                  </svg>
                {/if}
              </button>
            </div>
          </div>

          {#if botUsername}
            <div class="flex items-center justify-between py-2">
              <span class="text-sm text-gray-600 dark:text-gray-400">Telegram Bot</span>
              <a
                href="https://t.me/{botUsername}"
                target="_blank"
                rel="noopener noreferrer"
                class="text-sm text-indigo-600 dark:text-indigo-400 hover:underline"
              >
                t.me/{botUsername}
              </a>
            </div>
          {/if}
        </div>
      </Card>
    </div>

    <div class="flex justify-center mt-8">
      <Button
        size="lg"
        onclick={() => {
          if (typeof window !== 'undefined') window.close();
        }}
      >
        Close Wizard
      </Button>
    </div>
  {/if}
</div>
