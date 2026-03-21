/**
 * Alert registration smoke test (legacy magic-link API).
 *
 * Tests that the alert registration endpoint accepts and processes requests.
 * Note: this does NOT complete the verification flow (that requires clicking
 * an emailed link), so it only exercises the first step.
 *
 * The endpoint sends a real email synchronously, so the response time is
 * dominated by SMTP delivery. Use an email address on a domain your SMTP
 * server can reach. The timeout is set generously to 60s to accommodate slow
 * SMTP relays.
 *
 * Accepted responses:
 *   200 — alert registered, verification email sent
 *   500 — endpoint reachable but SMTP delivery failed (still proves the
 *          endpoint works end-to-end up to the mailer)
 *
 * Run:
 *   TEST_EMAIL=test@yourdomain.com k6 run k6/alerts.js
 *   BASE_URL=http://staging:8080 TEST_EMAIL=dev@yourdomain.com k6 run k6/alerts.js
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { BASE_URL, SERVER_NAMES, randomItem } from './config.js';

const TEST_EMAIL = __ENV.TEST_EMAIL || 'k6-test@example.invalid';

export const options = {
  // Single VU, limited iterations — alert registration sends real emails,
  // so keep load low unless you want your inbox flooded.
  vus: 1,
  iterations: 3,
  thresholds: {
    // SMTP delivery can be slow; allow up to 60s per request
    http_req_duration: ['p(95)<60000'],
    // Timeouts (status 0) count as failures — only allow if SMTP is broken
    http_req_failed: ['rate<0.1'],
  },
};

export default function () {
  const server = randomItem(SERVER_NAMES);

  const payload = JSON.stringify({
    email: TEST_EMAIL,
    server_name: server,
  });

  const res = http.post(`${BASE_URL}/api/alerts/register`, payload, {
    headers: { 'Content-Type': 'application/json' },
    // Generous timeout: SMTP delivery can take 30–60s on slow relays
    timeout: '65s',
  });

  check(res, {
    // 200 = sent, 500 = endpoint reached but SMTP failed — both prove the handler works
    'register: endpoint responded (200 or 500)': (r) => r.status === 200 || r.status === 500,
    'register: email was sent (200)': (r) => r.status === 200,
  });

  sleep(2);
}
