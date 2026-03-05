<script>
  let { currentStep = 0, steps = [] } = $props();
</script>

<nav class="w-full overflow-x-auto py-4 px-2">
  <ol class="flex items-center min-w-max mx-auto justify-center">
    {#each steps as step, i}
      <li class="flex items-center">
        <div class="flex flex-col items-center">
          <div
            class="flex items-center justify-center w-8 h-8 rounded-full text-xs font-bold transition-all duration-300
              {i < currentStep
              ? 'bg-indigo-600 text-white shadow-md'
              : i === currentStep
                ? 'bg-indigo-500 text-white ring-4 ring-indigo-200 dark:ring-indigo-900 shadow-lg'
                : 'bg-gray-200 dark:bg-gray-700 text-gray-500 dark:text-gray-400'}"
          >
            {#if i < currentStep}
              <svg
                class="w-4 h-4"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
                stroke-width="3"
              >
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  d="M5 13l4 4L19 7"
                />
              </svg>
            {:else}
              {i + 1}
            {/if}
          </div>
          <span
            class="mt-1.5 text-xs font-medium whitespace-nowrap max-w-[4.5rem] truncate
              {i <= currentStep
              ? 'text-indigo-600 dark:text-indigo-400'
              : 'text-gray-400 dark:text-gray-500'}"
          >
            {step}
          </span>
        </div>
        {#if i < steps.length - 1}
          <div
            class="step-connector w-8 sm:w-12 lg:w-16 mt-[-1rem]
              {i < currentStep
              ? 'bg-indigo-500'
              : 'bg-gray-200 dark:bg-gray-700'}"
          ></div>
        {/if}
      </li>
    {/each}
  </ol>
</nav>
