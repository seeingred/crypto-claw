import { describe, it, expect } from 'vitest';
import { createProgressEstimator } from './progress.js';

// Simulate the exact log messages that DeployLocal() emits in deploy.go + handleDeploy in handlers.go.
const localDeployLogs = [
  // Phase 1-2: Key derivation (from handleDeploy goroutine)
  'Deriving keys from mnemonic...',
  'Cryptographic parameters ready.',
  'Splitting ECDSA key into threshold shares...',
  'Splitting EdDSA key into threshold shares...',
  'Key shares generated.',
  // Phase 3: TLS
  'Generating TLS certificates...',
  'TLS certificates generated.',
  // Phase 4: DeployLocal starts
  'Starting local deployment...',
  '[a] Writing certificates to /Users/test/.crypto-claw/party-a',
  '[a] Writing key shares...',
  '[a] Configuration written to /Users/test/.crypto-claw/party-a',
  '[b] Writing certificates to /Users/test/.crypto-claw/party-b',
  '[b] Writing key shares...',
  '[b] Configuration written to /Users/test/.crypto-claw/party-b',
  '[local] Stopping any existing containers...',
  '[local] Setting up PostgreSQL databases...',
  '[local] PostgreSQL container already running.',
  "[local] Database 'crypto_claw_b' already exists.",
  '[local] PostgreSQL setup complete.',
  '[local] Importing key shares into databases...',
  '[a] ECDSA master share imported.',
  '[a] EdDSA master share imported.',
  '[b] ECDSA master share imported.',
  '[b] EdDSA master share imported.',
  // Phase 5: Docker build party-a (the slow part)
  '[local] Building Docker image crypto-claw-party-a:latest...',
  // Simulate ~50 docker build log lines
  ...Array.from({ length: 50 }, (_, i) => `[build] #${i + 1} [internal] load build definition from Dockerfile.party-a`),
  '[local] Image crypto-claw-party-a built successfully.',
  // Phase 6: Docker build party-b (the slow part)
  '[local] Building Docker image crypto-claw-party-b:latest...',
  ...Array.from({ length: 50 }, (_, i) => `[build] #${i + 1} [internal] load build definition from Dockerfile.party-b`),
  '[local] Image crypto-claw-party-b built successfully.',
  // Phase 7: Start containers
  '[local] Starting crypto-claw-party-b...',
  '[local] crypto-claw-party-b started (container abc123def456)',
  '[local] Starting crypto-claw-party-a...',
  '[local] crypto-claw-party-a started (container 789ghi012jkl)',
  '[local] Local deployment complete.',
  '[local] Config directory: /Users/test/.crypto-claw',
  'Deployment finished successfully.',
];

describe('progress estimator - local deploy', () => {
  it('never exceeds 5% before docker build starts', () => {
    const estimate = createProgressEstimator();
    const buildStartIdx = localDeployLogs.findIndex((m) =>
      m.includes('Building Docker image crypto-claw-party-a'),
    );

    for (let i = 0; i < buildStartIdx; i++) {
      const p = estimate(localDeployLogs[i]);
      expect(p, `log[${i}] "${localDeployLogs[i]}" → ${p}%`).toBeLessThanOrEqual(5);
    }
  });

  it('starts docker build party-a at 6%', () => {
    const estimate = createProgressEstimator();
    let progress = 0;
    for (const msg of localDeployLogs) {
      progress = estimate(msg);
      if (msg.includes('Building Docker image crypto-claw-party-a')) break;
    }
    expect(progress).toBe(6);
  });

  it('docker build party-a lines never exceed 47% cap', () => {
    const estimate = createProgressEstimator();
    let progress = 0;
    for (const msg of localDeployLogs) {
      progress = estimate(msg);
      if (msg.includes('[build]') && !msg.includes('party-b')) {
        expect(progress, `"${msg}" → ${progress}%`).toBeLessThanOrEqual(47);
      }
      if (msg.includes('built successfully')) break;
    }
  });

  it('docker build party-a completes at 48%', () => {
    const estimate = createProgressEstimator();
    let progress = 0;
    for (const msg of localDeployLogs) {
      progress = estimate(msg);
      if (msg.includes('Image crypto-claw-party-a built successfully')) break;
    }
    expect(progress).toBe(48);
  });

  it('docker build party-b starts at 50%', () => {
    const estimate = createProgressEstimator();
    let progress = 0;
    for (const msg of localDeployLogs) {
      progress = estimate(msg);
      if (msg.includes('Building Docker image crypto-claw-party-b')) break;
    }
    expect(progress).toBe(50);
  });

  it('docker build party-b lines never exceed 88% cap', () => {
    const estimate = createProgressEstimator();
    let progress = 0;
    let inBuildB = false;
    for (const msg of localDeployLogs) {
      progress = estimate(msg);
      if (msg.includes('Building Docker image crypto-claw-party-b')) inBuildB = true;
      if (inBuildB && msg.includes('[build]')) {
        expect(progress, `"${msg}" → ${progress}%`).toBeLessThanOrEqual(88);
      }
      if (msg.includes('Image crypto-claw-party-b')) break;
    }
  });

  it('ends at 98% on deployment complete', () => {
    const estimate = createProgressEstimator();
    let progress = 0;
    for (const msg of localDeployLogs) {
      progress = estimate(msg);
    }
    expect(progress).toBe(98);
  });

  it('progress is monotonically non-decreasing', () => {
    const estimate = createProgressEstimator();
    let prev = 0;
    for (let i = 0; i < localDeployLogs.length; i++) {
      const p = estimate(localDeployLogs[i]);
      expect(p, `log[${i}] "${localDeployLogs[i]}": ${p}% < prev ${prev}%`).toBeGreaterThanOrEqual(prev);
      prev = p;
    }
  });

  it('progress during build-a is spread across many values, not clustered', () => {
    const estimate = createProgressEstimator();
    const buildAValues = [];
    let inBuildA = false;
    for (const msg of localDeployLogs) {
      const p = estimate(msg);
      if (msg.includes('Building Docker image crypto-claw-party-a')) inBuildA = true;
      if (inBuildA && msg.includes('[build]')) buildAValues.push(p);
      if (msg.includes('built successfully')) break;
    }
    // With 50 build lines and 4% decay, the first value should be ~7.6
    // and the 50th should be around ~30-35. Verify spread.
    const min = Math.min(...buildAValues);
    const max = Math.max(...buildAValues);
    const range = max - min;
    expect(range, `build-a range: ${min}% to ${max}% (${range}%)`).toBeGreaterThan(10);
    // Should have many distinct integer values (at least 15 different rounded percents)
    const distinctRounded = new Set(buildAValues.map((v) => Math.round(v)));
    expect(
      distinctRounded.size,
      `only ${distinctRounded.size} distinct values in 50 build lines`,
    ).toBeGreaterThanOrEqual(15);
  });

  it('full deploy never shows >5% before build, >50% before build-b, >90% before containers', () => {
    const estimate = createProgressEstimator();
    let phase = 'pre-build';
    for (const msg of localDeployLogs) {
      const p = estimate(msg);
      if (msg.includes('Building Docker image crypto-claw-party-a')) phase = 'build-a';
      if (msg.includes('Building Docker image crypto-claw-party-b')) phase = 'build-b';
      if (msg.includes('Starting crypto-claw-party-b')) phase = 'containers';

      if (phase === 'pre-build') {
        expect(p, `pre-build: ${p}%`).toBeLessThanOrEqual(5);
      }
      // After build-a marker has fired, progress can be up to 48 (built successfully).
      // But before build-b marker fires, should not exceed 49.
      if (phase === 'build-a') {
        expect(p, `build-a: ${p}%`).toBeLessThanOrEqual(49);
      }
    }
  });
});

describe('progress estimator - few build lines (cached docker build)', () => {
  it('handles only 5 build lines per image gracefully', () => {
    const estimate = createProgressEstimator();
    const logs = [
      'Deriving keys from mnemonic...',
      'Key shares generated.',
      'TLS certificates generated.',
      'PostgreSQL setup complete.',
      '[local] Building Docker image crypto-claw-party-a:latest...',
      '[build] #1 CACHED step',
      '[build] #2 CACHED step',
      '[build] #3 CACHED step',
      '[build] #4 CACHED step',
      '[build] #5 CACHED step',
      '[local] Image crypto-claw-party-a built successfully.',
      '[local] Building Docker image crypto-claw-party-b:latest...',
      '[build] #1 CACHED step',
      '[build] #2 CACHED step',
      '[build] #3 CACHED step',
      '[build] #4 CACHED step',
      '[build] #5 CACHED step',
      '[local] Image crypto-claw-party-b built successfully.',
      '[local] Starting crypto-claw-party-b...',
      '[local] crypto-claw-party-b started (container abc)',
      '[local] Starting crypto-claw-party-a...',
      '[local] crypto-claw-party-a started (container def)',
      '[local] Local deployment complete.',
    ];

    let progress = 0;
    let prev = 0;
    for (const msg of logs) {
      progress = estimate(msg);
      expect(progress).toBeGreaterThanOrEqual(prev);
      prev = progress;
    }
    expect(progress).toBe(98);
  });
});

describe('progress estimator - many build lines (full rebuild)', () => {
  it('handles 200 build lines per image without hitting cap too early', () => {
    const estimate = createProgressEstimator();
    const logs = [
      'Deriving keys from mnemonic...',
      'Key shares generated.',
      'TLS certificates generated.',
      'PostgreSQL setup complete.',
      '[local] Building Docker image crypto-claw-party-a:latest...',
      ...Array.from({ length: 200 }, (_, i) => `[build] #${i + 1} RUN go build ./cmd/party-a`),
      '[local] Image crypto-claw-party-a built successfully.',
      '[local] Building Docker image crypto-claw-party-b:latest...',
      ...Array.from({ length: 200 }, (_, i) => `[build] #${i + 1} RUN go build ./cmd/party-b`),
      '[local] Image crypto-claw-party-b built successfully.',
      '[local] Starting crypto-claw-party-b...',
      '[local] crypto-claw-party-b started (container abc)',
      '[local] Starting crypto-claw-party-a...',
      '[local] crypto-claw-party-a started (container def)',
      '[local] Local deployment complete.',
    ];

    let progress = 0;
    const progressAt = {};
    for (const msg of logs) {
      progress = estimate(msg);
      if (msg.includes('Building Docker image crypto-claw-party-a')) progressAt.buildAStart = progress;
      if (msg.includes('built successfully') && !progressAt.buildAEnd) progressAt.buildAEnd = progress;
      if (msg.includes('Building Docker image crypto-claw-party-b')) progressAt.buildBStart = progress;
      if (msg.includes('Image crypto-claw-party-b built')) progressAt.buildBEnd = progress;
    }

    expect(progressAt.buildAStart).toBe(6);
    expect(progressAt.buildAEnd).toBe(48);
    expect(progressAt.buildBStart).toBe(50);
    expect(progressAt.buildBEnd).toBe(89);
    expect(progress).toBe(98);

    // Feed 100 build lines through a fresh estimator and check midpoint
    const est2 = createProgressEstimator();
    est2('PostgreSQL setup complete.');
    est2('[local] Building Docker image crypto-claw-party-a:latest...');
    let midway = 0;
    for (let i = 0; i < 100; i++) {
      midway = est2(`[build] #${i + 1} RUN step`);
    }
    // After 100 lines at 8% decay from 6, should be approaching cap but not there
    expect(midway, `100 lines in: ${midway}%`).toBeLessThan(47);
    expect(midway, `100 lines in: ${midway}%`).toBeGreaterThan(30);
  });
});
