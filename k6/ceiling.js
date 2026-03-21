/**
 * Ceiling test — finds the sustainable request rate for federation-ok.
 *
 * From the stress test we know:
 *   - 20 rps: p95 ~1.22s (comfortable, from federation.js baseline)
 *   - 50 rps: p95 ~6.83s (saturated, dropped iterations)
 *
 * This test steps through 10 → 20 → 30 → 40 rps in 90s stages to find
 * where latency starts climbing. Watch for:
 *   - p95 crossing 3s  → approaching saturation
 *   - dropped_iterations > 0 → VUs exhausted, ceiling exceeded
 *
 * Run:
 *   k6 run k6/ceiling.js
 *   BASE_URL=http://prod:8080 k6 run k6/ceiling.js
 */

import http from 'k6/http';
import { check } from 'k6';
import { BASE_URL, SERVER_NAMES, randomItem } from './config.js';

// Per-client connection limit: 10 (max_connections_per_key=5, per-client cap=10)
// All k6 VUs share one IP → one budget. Ceiling from a single machine is ~10
// concurrent connections. Stages above that just measure queue drain speed,
// not true server capacity.
export const options = {
  scenarios: {
    ceiling: {
      executor: 'ramping-arrival-rate',
      exec: 'federationOk',
      preAllocatedVUs: 20,
      maxVUs: 30,
      timeUnit: '1s',
      startRate: 2,
      stages: [
        { target: 5,  duration: '60s' }, // well within limit
        { target: 10, duration: '60s' }, // at the connection cap
        { target: 15, duration: '60s' }, // over cap — expect queuing & latency climb
        { target: 20, duration: '60s' }, // confirm saturation behaviour
      ],
    },
  },
  thresholds: {
    http_req_failed:   ['rate<0.05'],
    http_req_duration: ['p(95)<10000'],
  },
};

export function federationOk() {
  const server = randomItem(SERVER_NAMES);
  const res = http.get(
    `${BASE_URL}/api/federation/federation-ok?server_name=${encodeURIComponent(server)}`,
    { timeout: '15s' },
  );
  check(res, {
    'federation-ok: status 200':   (r) => r.status === 200,
    'federation-ok: GOOD or BAD':  (r) =>
      r.body.trim() === 'GOOD' || r.body.trim() === 'BAD',
  });
}
