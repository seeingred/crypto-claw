<script>
  let { variant = 'info', title = '', children } = $props();

  const variants = {
    info: {
      bg: 'bg-blue-50 dark:bg-blue-900/30',
      border: 'border-blue-200 dark:border-blue-800',
      icon: 'text-blue-500 dark:text-blue-400',
      title: 'text-blue-800 dark:text-blue-300',
      body: 'text-blue-700 dark:text-blue-300',
    },
    success: {
      bg: 'bg-emerald-50 dark:bg-emerald-900/30',
      border: 'border-emerald-200 dark:border-emerald-800',
      icon: 'text-emerald-500 dark:text-emerald-400',
      title: 'text-emerald-800 dark:text-emerald-300',
      body: 'text-emerald-700 dark:text-emerald-300',
    },
    warning: {
      bg: 'bg-amber-50 dark:bg-amber-900/30',
      border: 'border-amber-200 dark:border-amber-800',
      icon: 'text-amber-500 dark:text-amber-400',
      title: 'text-amber-800 dark:text-amber-300',
      body: 'text-amber-700 dark:text-amber-300',
    },
    error: {
      bg: 'bg-red-50 dark:bg-red-900/30',
      border: 'border-red-200 dark:border-red-800',
      icon: 'text-red-500 dark:text-red-400',
      title: 'text-red-800 dark:text-red-300',
      body: 'text-red-700 dark:text-red-300',
    },
  };

  const v = $derived(variants[variant] || variants.info);

  const icons = {
    info: 'M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z',
    success: 'M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z',
    warning:
      'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z',
    error: 'M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z',
  };
</script>

<div class="rounded-lg border {v.bg} {v.border} p-4">
  <div class="flex">
    <div class="flex-shrink-0">
      <svg
        class="h-5 w-5 {v.icon}"
        xmlns="http://www.w3.org/2000/svg"
        fill="none"
        viewBox="0 0 24 24"
        stroke="currentColor"
        stroke-width="2"
      >
        <path
          stroke-linecap="round"
          stroke-linejoin="round"
          d={icons[variant] || icons.info}
        />
      </svg>
    </div>
    <div class="ml-3 flex-1">
      {#if title}
        <h3 class="text-sm font-medium {v.title}">{title}</h3>
      {/if}
      <div class="text-sm {v.body}" class:mt-1={!!title}>
        {@render children()}
      </div>
    </div>
  </div>
</div>
