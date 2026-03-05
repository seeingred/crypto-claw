import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';

export default defineConfig({
  plugins: [svelte()],
  build: {
    outDir: 'dist',
  },
  server: {
    proxy: {
      '/api': 'http://localhost:8100',
    },
  },
  test: {
    environment: 'jsdom',
  },
  resolve: {
    conditions: ['browser'],
  },
});
