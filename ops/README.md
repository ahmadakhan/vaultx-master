# Self-hosted operations evidence

The Compose stack provisions Prometheus (`:9090`), Grafana (`:3001`), and
Alertmanager (`:9093`) without credentials or external SaaS dependencies.
Prometheus scrapes the backend's `/metrics` endpoint and loads alerts for API
reachability, average latency, and Redis rate-limit fallback. Alertmanager
uses a required webhook receiver. Set `ALERTMANAGER_WEBHOOK_URL` to an
approved internal notification endpoint; Compose refuses to start it without
that value.

Start the evidence stack with the normal required environment variables:

```sh
docker compose up -d --build
```

Enable the scheduled MinIO backup/audit worker explicitly:

```sh
docker compose --profile backup up -d backup-worker
```

Check readiness and metrics directly:

```sh
curl -fsS http://localhost:8000/health/ready
curl -fsS http://localhost:8000/metrics
```

Run k6 evidence against a reachable API (default `http://localhost:8000`):

```sh
k6 run ops/k6/readiness.js
k6 run ops/k6/api-latency.js
k6 run ops/k6/redis-failure.js   # requires permission to stop/start vaultx_redis
```

The Redis scenario verifies the API remains reachable while the limiter uses
its bounded local fallback; it does not claim shared limits remain available.
