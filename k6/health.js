/**
 * Health endpoint load test — establishes a baseline for server throughput
 * separate from federation logic (which is network-bound).
 *
 * Run:
 *   k6 run k6/health.js
 *   BASE_URL=http://prod:8080 k6 run k6/health.js
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { BASE_URL, DEFAULT_THRESHOLDS } from './config.js';

export const options = {
  scenarios: {
    health_check: {
      executor: 'constant-vus',
      vus: 20,
      duration: '30s',
    },
  },
  thresholds: {
    ...DEFAULT_THRESHOLDS,
    // Health endpoint should be much faster than federation checks
    http_req_duration: ['p(95)<500'],
  },
};

export default function () {
  const res = http.get(`${BASE_URL}/healthz`);
  check(res, {
    'status 200': (r) => r.status === 200,
    'body is ok': (r) => r.body.trim() === 'ok',
  });
  sleep(0.1);
}
