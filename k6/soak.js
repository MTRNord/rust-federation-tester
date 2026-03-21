/**
 * Soak test — steady-state load held for an extended period.
 *
 * Runs at a comfortable rate (below the saturation point found by ceiling.js)
 * for 30 minutes. Looking for:
 *   - Memory leaks: latency slowly climbing over time
 *   - Connection pool exhaustion: error rate increasing after N minutes
 *   - Database connection issues: intermittent 500s
 *
 * Default rate is 15 rps (conservative, well below the ~20 rps baseline).
 * Override with SOAK_RPS and SOAK_DURATION env vars.
 *
 * Run:
 *   k6 run k6/soak.js
 *   SOAK_RPS=10 SOAK_DURATION=1h k6 run k6/soak.js
 *   BASE_URL=http://prod:8080 k6 run k6/soak.js
 */

import http from 'k6/http';
import { check } from 'k6';
import { BASE_URL, SERVER_NAMES, randomItem } from './config.js';

const SOAK_RPS      = parseInt(__ENV.SOAK_RPS || '15', 10);
const SOAK_DURATION = __ENV.SOAK_DURATION || '30m';

export const options = {
  scenarios: {
    soak: {
      executor: 'constant-arrival-rate',
      exec: 'federationOk',
      rate: SOAK_RPS,
      timeUnit: '1s',
      duration: SOAK_DURATION,
      // At 15 rps × ~1.5s avg = ~23 VUs needed; allocate headroom
      preAllocatedVUs: 40,
      maxVUs: 80,
    },
  },
  thresholds: {
    http_req_failed:   ['rate<0.05'],
    // If p95 climbs above 5s during a soak that was fine at 1.2s, something is leaking
    http_req_duration: ['p(95)<5000'],
  },
};

export function federationOk() {
  const server = randomItem(SERVER_NAMES);
  const res = http.get(
    `${BASE_URL}/api/federation/federation-ok?server_name=${encodeURIComponent(server)}`,
    { timeout: '15s' },
  );
  check(res, {
    'federation-ok: status 200':  (r) => r.status === 200,
    'federation-ok: GOOD or BAD': (r) =>
      r.body.trim() === 'GOOD' || r.body.trim() === 'BAD',
  });
}
