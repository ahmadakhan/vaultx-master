# VaultX production-baseline operations

## Required external services

The API requires PostgreSQL and SMTP configuration. A multi-worker deployment
should provide Redis (`RATE_LIMIT_REDIS_URL`) so rate-limit state is shared
across workers. The bundled Compose stack starts PostgreSQL and Redis for local
staging/evidence; replace both images and credentials according to your
deployment policy. No credentials are committed to this repository.

## Rate limiting and failure behavior

`RateLimitMiddleware` uses Redis atomic counters when configured. A short
socket timeout prevents Redis from extending request latency. If Redis is
unavailable, the middleware records `rate_limit_redis_failures_total` and uses
the bounded per-process token bucket (`RATE_LIMIT_MAX_BUCKETS`) instead. This
keeps the API available while providing less protection than shared limiting;
alert on the fallback metric and restore Redis. Configure the URL through a
secret manager rather than source control.

## Correlation, metrics, and health

Every HTTP response includes `X-Request-ID` and `Trace-ID`; an incoming request
ID is preserved (bounded to 128 ASCII characters), and W3C `traceparent` trace
IDs are accepted. Structured logs include both IDs and request duration.

`GET /health/live` checks only process liveness. `GET /health/ready` (also
`/health`) checks PostgreSQL and returns HTTP 503 when unavailable.
`GET /metrics` exposes lightweight Prometheus-compatible counters. Set
`METRICS_ENABLED=false` when metrics are served by a separate sidecar or
ingress. Restrict metrics access at the network boundary in production.

## Failure/load evidence

Run the backend tests with `cd backend && pytest -q`. For a local smoke test,
start Compose with a private `.env`, then repeatedly call `/health/live`,
`/health/ready`, and `/metrics`; stop Redis and verify readiness remains up,
`rate_limit_fallback_total` increases, and restore Redis before load testing.
Use an approved load generator (for example k6 or Locust) outside this repo;
record concurrency, duration, status distribution, p95 latency, and Redis
fallback counters in the deployment evidence artifact. The project does not
ship production credentials or claim a benchmark without that environment's
evidence.
