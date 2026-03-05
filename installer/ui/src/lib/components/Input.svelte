<script>
  let {
    label = '',
    type = 'text',
    value = $bindable(''),
    placeholder = '',
    disabled = false,
    error = '',
    helpText = '',
    id = undefined,
    ...rest
  } = $props();

  let inputId = $derived(id || `input-${Math.random().toString(36).slice(2, 9)}`);
</script>

<div class="space-y-1.5">
  {#if label}
    <label
      for={inputId}
      class="block text-sm font-medium text-gray-700 dark:text-gray-300"
    >
      {label}
    </label>
  {/if}
  <input
    id={inputId}
    {type}
    bind:value
    {placeholder}
    {disabled}
    {...rest}
    class="block w-full rounded-lg border px-3 py-2.5 text-sm shadow-sm transition-colors duration-200
      {error
      ? 'border-red-400 dark:border-red-500 focus:border-red-500 focus:ring-red-500'
      : 'border-gray-300 dark:border-gray-600 focus:border-indigo-500 focus:ring-indigo-500'}
      bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100
      placeholder-gray-400 dark:placeholder-gray-500
      focus:outline-none focus:ring-2 focus:ring-offset-0
      disabled:opacity-50 disabled:cursor-not-allowed"
  />
  {#if error}
    <p class="text-sm text-red-500 dark:text-red-400">{error}</p>
  {/if}
  {#if helpText && !error}
    <p class="text-sm text-gray-500 dark:text-gray-400">{helpText}</p>
  {/if}
</div>
