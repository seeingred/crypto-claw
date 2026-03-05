<script>
  let { title = '', subtitle = '', padding = true, children } = $props();
</script>

<div
  class="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 shadow-sm {padding
    ? 'p-6'
    : ''}"
>
  {#if title}
    <div class={padding ? 'mb-4' : 'p-6 pb-4'}>
      <h3 class="text-lg font-semibold text-gray-900 dark:text-white">
        {title}
      </h3>
      {#if subtitle}
        <p class="mt-1 text-sm text-gray-500 dark:text-gray-400">{subtitle}</p>
      {/if}
    </div>
  {/if}
  {@render children()}
</div>
