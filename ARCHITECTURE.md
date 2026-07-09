# Request-Filtering Architecture: Nginx + Unit + Counterparser

## Decision

Nginx enforces, not Unit. Reasons:

- **Position.** Nginx is the outermost layer; blocking there means Unit never spends a cycle on parser traffic. A check inside Unit fires after nginx has already proxied the request — most of the cost is already paid.
- **Hooks.** Nginx has `auth_request`, `mirror`, and a module API. Unit has none of these — it's an app runner, not a filter. Enforcing inside it means embedding the check into application code.
- **Real IPs.** Nginx sees the client directly; Unit sees whatever nginx forwards.

## Integration

Rust daemon (`counterparser`) behind `auth_request`, no nginx recompilation required.

```nginx
upstream counterparser {
    server unix:/run/counterparser.sock;   # the axum daemon
    keepalive 32;
}

server {
    location / {
        auth_request /_check;
        error_page 403 = @respond;   # bare `=`: client gets whatever status @respond returns
        proxy_pass http://unit;
    }

    location = /_check {
        internal;
        proxy_pass http://counterparser/check;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Real-IP $remote_addr;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
    }

    location @respond {
        internal;
        proxy_pass http://counterparser/respond;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
    }
}
```

`/check` decides `204` (pass) or `403` (deny) and never leaks anything to the client — it's a subrequest, nginx only reads the status. On `403`, nginx internally redirects to `@respond`, which proxies to the daemon's `/respond` endpoint; that one always answers `200` with either a randomized joke page (cooldown) or a JS/cookie challenge page (ambiguous IPs) — so the client never sees a 403 or reaches Unit. Over a unix socket with keepalive this adds roughly 50-100 µs — negligible.

## Rollout Path

1. **Passive first — `mirror`.** Use `mirror /_check;` instead of `auth_request`. Nginx fire-and-forgets a copy of each request to the service; responses are ignored, so a bug in the Rust code can't take the site down. Count, log, and build confidence in the counters before enforcing anything.
2. **Enforce — `auth_request`.** Once the counters are trusted, flip the check to `auth_request` for real blocking, as shown above.
3. **Maximum performance (later, only if needed) — native module.** A native module via `ngx-rust` (or logic modeled on `limit_req`) removes IPC entirely, but requires recompiling against nginx, and a panic in the module can kill worker processes. Not worth it until the daemon measurably bottlenecks under `auth_request`.

Unit remains solely the app server; it is never in the filtering path.

## Endpoints

| Endpoint   | Called by                          | Purpose |
|------------|-------------------------------------|---------|
| `/check`   | nginx `auth_request`                | Decides `204`/`403`. |
| `/respond` | nginx `error_page 403 = @respond`   | Renders the actual `200` page the client sees. |
| `/healthz` | liveness probes                     | Plain `200 ok`. |
| `/stats`   | operator / monitoring, direct only  | Aggregate JSON: uptime, tracked IP count, lifetime verdict counts, active cooldowns by service, rDNS cache size. No per-IP data. |

Only `/check` and `/respond` are wired into nginx. `/stats` (and `/healthz`) are reachable by
anyone who can already talk to the daemon's Unix socket directly — e.g. `curl --unix-socket
/run/counterparser.sock http://localhost/stats` from the same host. If you want it scraped by
an external monitoring system, add an explicit nginx location for it with its own auth (basic
auth or an IP allowlist) rather than exposing it unauthenticated.
