import http from 'k6/http';
import { check, fail } from 'k6';

export const options = { vus: 1, iterations: 5 };
const base = __ENV.BASE_URL || 'http://localhost:8000';

export default function () {
  const response = http.get(`${base}/health/ready`);
  if (!check(response, { 'readiness is 200': (r) => r.status === 200, 'database is ok': (r) => r.json('database') === 'ok' })) {
    fail(`readiness failed: ${response.status}`);
  }
}
