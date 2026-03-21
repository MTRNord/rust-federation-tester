/**
 * Federation endpoint load test.
 *
 * Tests both /api/federation/report (full check) and /api/federation/federation-ok
 * (lightweight status) under concurrent load. Uses a randomised pool of server names
 * to avoid hitting the connection cache for a single target on every request.
 *
 * Run:
 *   k6 run k6/federation.js
 *   BASE_URL=http://prod:8080 SERVER_NAMES=matrix.org,maunium.net k6 run k6/federation.js
 *
 * Tune VU counts and duration via env vars:
 *   REPORT_VUS=3 OK_VUS=10 DURATION=120s k6 run k6/federation.js
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { BASE_URL, SERVER_NAMES, DEFAULT_THRESHOLDS, randomItem } from './config.js';

const REPORT_VUS = parseInt(__ENV.REPORT_VUS || '3', 10);
const OK_VUS = parseInt(__ENV.OK_VUS || '5', 10);
const DURATION = __ENV.DURATION || '60s';

export const options = {
  scenarios: {
    // Full federation report — expensive (does DNS + TLS + HTTP to external servers)
    federation_report: {
      executor: 'constant-vus',
      vus: REPORT_VUS,
      duration: DURATION,
      exec: 'fullReport',
    },
    // Lightweight status check — much cheaper
    federation_ok: {
      executor: 'constant-vus',
      vus: OK_VUS,
      duration: DURATION,
      exec: 'federationOk',
    },
  },
  thresholds: DEFAULT_THRESHOLDS,
};

export function fullReport() {
  const server = randomItem(SERVER_NAMES);
  const res = http.get(
    `${BASE_URL}/api/federation/report?server_name=${encodeURIComponent(server)}&stats_opt_in=false`,
    { timeout: '30s' },
  );
  check(res, {
    'report: status 200': (r) => r.status === 200,
    'report: has FederationOK': (r) => {
      try {
        return typeof JSON.parse(r.body).FederationOK === 'boolean';
      } catch {
        return false;
      }
    },
  });
  // Small pause — federation checks are slow enough without hammering continuously
  sleep(1);
}

export function federationOk() {
  const server = randomItem(SERVER_NAMES);
  const res = http.get(
    `${BASE_URL}/api/federation/federation-ok?server_name=${encodeURIComponent(server)}`,
    { timeout: '15s' },
  );
  check(res, {
    'federation-ok: status 200': (r) => r.status === 200,
    'federation-ok: GOOD or BAD': (r) =>
      r.body.trim() === 'GOOD' || r.body.trim() === 'BAD',
  });
  sleep(0.5);
}
