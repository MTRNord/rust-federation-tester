/**
 * Stress test — ramps load up to find the server's breaking point.
 *
 * Two scenarios run independently:
 *
 * 1. ramping-arrival-rate (federation-ok)
 *    Controls requests/second directly, independent of response time.
 *    Good for answering: "how many checks/s can the server sustain?"
 *    Starts at 5 rps, ramps to 50 rps, then holds. If the server can't
 *    keep up, VUs queue and latency climbs — you'll see it in the metrics.
 *
 * 2. ramping-vus (federation-report)
 *    Controls concurrent users. Good for answering: "what happens under
 *    N simultaneous long-running federation checks?"
 *    Starts at 2 VUs, ramps to 20, then holds.
 *
 * Run:
 *   k6 run k6/stress.js
 *   BASE_URL=http://prod:8080 SERVER_NAMES=matrix.org,maunium.net k6 run k6/stress.js
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { BASE_URL, SERVER_NAMES, DEFAULT_THRESHOLDS, randomItem } from './config.js';

export const options = {
  scenarios: {
    // Ramp request rate for the lightweight endpoint.
    //
    // NOTE: the server enforces a per-client-IP connection limit of 10.
    // Running k6 from a single machine means all VUs share one IP and
    // therefore one budget. Adding more VUs beyond ~15 just causes queuing
    // behind those 10 slots — it does not increase throughput.
    // Use ceiling.js to find the real single-IP ceiling, or distribute
    // k6 across multiple machines for a meaningful multi-client test.
    federation_ok_rate: {
      executor: 'ramping-arrival-rate',
      exec: 'federationOk',
      preAllocatedVUs: 20,
      maxVUs: 30,
      timeUnit: '1s',
      startRate: 5,
      stages: [
        { target: 5,  duration: '30s' }, // warm up at 5 rps
        { target: 20, duration: '30s' }, // ramp to 20 rps
        { target: 30, duration: '0'   }, // instant jump — stress the connection limit
        { target: 30, duration: '2m'  }, // hold
      ],
    },

    // Ramp concurrent users for the expensive full-report endpoint
    federation_report_vus: {
      executor: 'ramping-vus',
      exec: 'fullReport',
      startVUs: 2,
      stages: [
        { target: 5,  duration: '30s' }, // ramp to 5 concurrent checks
        { target: 20, duration: '30s' }, // ramp to 20
        { target: 20, duration: '2m'  }, // hold
      ],
    },
  },

  thresholds: {
    ...DEFAULT_THRESHOLDS,
    // Tighter threshold for the fast endpoint even under stress
    'http_req_duration{scenario:federation_ok_rate}':    ['p(95)<3000'],
    // Full report can be slower; allow up to 15s at p95 under stress
    'http_req_duration{scenario:federation_report_vus}': ['p(95)<15000'],
  },
};

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
}

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
  sleep(1);
}
