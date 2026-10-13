import http from 'k6/http';
import { check } from 'k6';

export const options = { vus: Number(__ENV.VUS || 5), duration: __ENV.DURATION || '30s', thresholds: { http_req_duration: ['p(95)<1000', 'p(99)<2000'], checks: ['rate>0.99'] } };
const base = __ENV.BASE_URL || 'http://localhost:8000';

export default function () {
  const response = http.get(`${base}/health/live`);
  check(response, { 'liveness is 200': (r) => r.status === 200, 'status is ok': (r) => r.json('status') === 'ok' });
}
