/**
 * Smoke test — single VU, single iteration, verifies all key endpoints respond correctly.
 *
 * Run:
 *   k6 run k6/smoke.js
 *   BASE_URL=http://staging:8080 k6 run k6/smoke.js
 */

import http from 'k6/http';
import { check } from 'k6';
import { BASE_URL } from './config.js';

export const options = {
  vus: 1,
  iterations: 1,
  thresholds: {
    checks: ['rate==1.0'], // every check must pass in smoke mode
  },
};

export default function () {
  // 1. Health check
  {
    const res = http.get(`${BASE_URL}/healthz`);
    check(res, {
      'healthz: status 200': (r) => r.status === 200,
      'healthz: body is ok': (r) => r.body.trim() === 'ok',
    });
  }

  // 2. Federation-ok (simple status endpoint)
  {
    const res = http.get(`${BASE_URL}/api/federation/federation-ok?server_name=matrix.org`);
    check(res, {
      'federation-ok: status 200': (r) => r.status === 200,
      'federation-ok: body is GOOD or BAD': (r) =>
        r.body.trim() === 'GOOD' || r.body.trim() === 'BAD',
    });
  }

  // 3. Full federation report
  {
    const res = http.get(`${BASE_URL}/api/federation/report?server_name=matrix.org`, {
      timeout: '30s',
    });
    check(res, {
      'federation/report: status 200': (r) => r.status === 200,
      'federation/report: has FederationOK field': (r) => {
        try {
          const body = JSON.parse(r.body);
          return typeof body.FederationOK === 'boolean';
        } catch {
          return false;
        }
      },
    });
  }

  // 4. Metrics endpoint (if Prometheus is enabled; gracefully skip if 404)
  {
    const res = http.get(`${BASE_URL}/metrics`);
    check(res, {
      'metrics: status 200 or 404': (r) => r.status === 200 || r.status === 404,
    });
  }
}
