/**
 * Shared configuration for k6 tests.
 *
 * Override via environment variables:
 *   BASE_URL=http://prod:8080 k6 run federation.js
 *   SERVER_NAMES=matrix.org,maunium.net k6 run federation.js
 */

export const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';

// Comma-separated list of Matrix server names to test against
export const SERVER_NAMES = (__ENV.SERVER_NAMES || 'matrix.org,maunium.net,mtrnord.blog').split(',');

/** Pick a random entry from an array */
export function randomItem(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

/**
 * Default thresholds used across load tests.
 *
 * Federation checks are inherently slow (DNS + TLS + HTTP to external servers),
 * so the p95 threshold is intentionally generous at 10s.
 * Adjust per-test as needed.
 */
export const DEFAULT_THRESHOLDS = {
  http_req_failed: ['rate<0.05'],      // fewer than 5% errors
  http_req_duration: ['p(95)<10000'],  // 95th percentile under 10s
};
