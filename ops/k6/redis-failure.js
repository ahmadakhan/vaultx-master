import http from 'k6/http';
import { check } from 'k6';

export const options = { vus: 2, duration: __ENV.DURATION || '20s', thresholds: { http_req_failed: ['rate<0.01'], http_req_duration: ['p(95)<1000'] } };
const base = __ENV.BASE_URL || 'http://localhost:8000';

export default function () {
  // Stop vaultx_redis before this run and start it again afterward. The API's
  // rate limiter should remain available through its bounded local fallback.
  const response = http.get(`${base}/health/live`);
  check(response, { 'API remains reachable during Redis outage': (r) => r.status === 200 });
}
