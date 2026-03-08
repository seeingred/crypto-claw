// Progress estimation logic extracted for testability.
// This mirrors the logic in Deployment.svelte exactly.

// Progress distribution:
//   0-5%:   Pre-build (keys, certs, postgres) — happens in <1 second
//   5-48%:  Docker build party-a — the slow part
//   50-89%: Docker build party-b — the slow part
//   90-98%: Container start + verify
export const progressMarkers = [
  { pattern: 'Deriving keys', percent: 1 },
  { pattern: 'Cryptographic parameters ready', percent: 2 },
  { pattern: 'Splitting ECDSA', percent: 2 },
  { pattern: 'Key shares generated', percent: 3 },
  { pattern: 'Generating TLS', percent: 3 },
  { pattern: 'TLS certificates generated', percent: 4 },
  { pattern: 'Stopping any existing', percent: 4 },
  { pattern: 'Setting up PostgreSQL', percent: 4 },
  { pattern: 'PostgreSQL setup complete', percent: 5 },
  { pattern: 'PostgreSQL is ready', percent: 5 },
  { pattern: 'Importing key shares', percent: 5 },
  { pattern: 'master share imported', percent: 5 },
  // Build phase A
  { pattern: 'Building Docker image crypto-claw-party-a', percent: 6 },
  { pattern: 'Rebuilding Docker image crypto-claw-party-a', percent: 6 },
  { pattern: 'built successfully', percent: 48 },
  { pattern: 'Image crypto-claw-party-a', percent: 48 },
  // Build phase B
  { pattern: 'Building Docker image crypto-claw-party-b', percent: 50 },
  { pattern: 'Rebuilding Docker image crypto-claw-party-b', percent: 50 },
  { pattern: 'Image crypto-claw-party-b', percent: 89 },
  // Container start
  { pattern: 'Starting crypto-claw-party-b', percent: 90 },
  { pattern: 'started (container', percent: 92 },
  { pattern: 'Starting crypto-claw-party-a', percent: 94 },
  { pattern: 'deployment complete', percent: 98 },
  { pattern: 'Local deployment complete', percent: 98 },
  { pattern: 'update complete', percent: 98 },
  // Remote deploy markers
  { pattern: 'Deploying Party B', percent: 30 },
  { pattern: 'Deploying Party A', percent: 60 },
  { pattern: 'Pulling Docker image', percent: 45 },
  { pattern: 'Starting Docker container', percent: 80 },
  { pattern: 'Deployment complete', percent: 98 },
];

export const buildCaps = { a: 47, b: 88 };

/**
 * Create a stateful progress estimator.
 * Returns a function that accepts a log message and returns the new progress value.
 */
export function createProgressEstimator() {
  let progress = 0;
  let buildPhase = '';

  return function estimateProgress(message) {
    // Track which image is being built.
    if (message.includes('Building Docker image crypto-claw-party-a') || message.includes('Rebuilding Docker image crypto-claw-party-a')) {
      buildPhase = 'a';
    } else if (message.includes('Building Docker image crypto-claw-party-b') || message.includes('Rebuilding Docker image crypto-claw-party-b')) {
      buildPhase = 'b';
    }

    // Check explicit markers first.
    for (const marker of progressMarkers) {
      if (message.includes(marker.pattern) && marker.percent > progress) {
        progress = marker.percent;
        return progress;
      }
    }

    // Docker build log lines: asymptotically approach the cap.
    // Each line closes 8% of the remaining gap — fast enough to feel responsive
    // but slows down so it never actually reaches the cap.
    if (message.includes('[build]') && buildPhase) {
      const cap = buildCaps[buildPhase];
      const remaining = cap - progress;
      if (remaining > 0.5) {
        progress = Math.round((progress + remaining * 0.08) * 10) / 10;
        return progress;
      }
    }

    return progress;
  };
}
