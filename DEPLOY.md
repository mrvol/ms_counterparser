# Deploying counterparser to a Linux server (Docker)

nginx stays a native install on the host (per [ARCHITECTURE.md](ARCHITECTURE.md)); only the
daemon runs in Docker. The two talk over a Unix socket, which means the container needs to
write that socket file somewhere nginx can also see it — a bind-mounted host directory, not a
Docker-internal volume.

`docker-compose.yml`'s bind mounts are relative to wherever you put the repo (`./config.toml`,
`./run`) — there's no hardcoded path, so clone it anywhere (`/var/www/counterparser`,
`/srv/counterparser`, wherever). The examples below use `/var/www/counterparser`; substitute
your own path.

## 1. Prepare the host

```bash
sudo mkdir -p /var/www/counterparser
sudo chown "$(id -u)":"$(id -g)" /var/www/counterparser   # or whatever user runs docker compose

cd /var/www/counterparser
git clone <this-repo-url> .   # or scp/rsync the project directory here

cp config.example.toml config.toml
mkdir -p run
```

Edit `config.toml`:
- `server.socket_path` → `/run/counterparser/counterparser.sock` (the *container-internal*
  path — it's the mount target in `docker-compose.yml`, matched to the `./run` directory you
  just created).
- `whitelist.cidrs`, `bot_pools`, `cooldowns` → your real values.
- Leave `challenge.hmac_secret` alone; it's overridden by an env var (next step) so the real
  secret never sits in a file on disk.

Generate a secret and put it in a `.env` file next to `docker-compose.yml` (compose loads `.env`
automatically; keep it out of git):

```bash
echo "COUNTERPARSER_HMAC_SECRET=$(openssl rand -hex 32)" > .env
chmod 600 .env
```

> **`config.toml` and `run/` must exist before the first `docker compose up`.**
> `docker-compose.yml` mounts both with `bind.create_host_path: false`, so if either is
> missing, compose refuses to start with `Error response from daemon: ... bind source path does
> not exist` instead of silently mounting an empty directory in their place — a much clearer
> failure than what used to happen. If you hit that, run the `cp`/`mkdir` steps above and
> `docker compose up -d` again.

## 2. Start

`.github/workflows/docker.yml` builds and pushes `ghcr.io/mrvol/ms_counterparser:latest` on
every push to `main`, so the server just pulls it:

```bash
# If the mrvol/ms_counterparser repo/package is private, authenticate first with a PAT
# that has read:packages scope: docker login ghcr.io -u <github-username>
docker compose pull
docker compose up -d
docker compose logs -f counterparser   # confirm "listening on unix:/run/counterparser/..."
ls -la run                             # counterparser.sock should now exist, mode 0777
```

`docker-compose.yml` only ever runs the prebuilt GHCR image — it has no `build:` key, so
`docker compose up -d` can never silently fall back to a slow from-source build on the server.
To test a local change before pushing it, build and run it directly instead:

```bash
docker build -t counterparser:latest .
docker run -d --name counterparser --restart unless-stopped \
  -e COUNTERPARSER_CONFIG=/etc/counterparser/config.toml \
  -e COUNTERPARSER_HMAC_SECRET="$(openssl rand -hex 32)" \
  -v "$(pwd)/config.toml:/etc/counterparser/config.toml:ro" \
  -v "$(pwd)/run:/run/counterparser" \
  counterparser:latest
```

## 3. Point nginx at the socket

Same `auth_request` / `@respond` setup as in ARCHITECTURE.md — only the socket path changes,
since nginx (on the host) now reaches the daemon (in a container) through the bind-mounted
directory rather than a socket the daemon created directly at `/run/counterparser.sock`. Use the
**absolute** path to wherever you cloned the repo (nginx doesn't understand relative paths):

```nginx
upstream counterparser {
    server unix:/var/www/counterparser/run/counterparser.sock;
    keepalive 32;
}

server {
    location / {
        auth_request /_check;
        error_page 403 = @respond;
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

```bash
sudo nginx -t && sudo systemctl reload nginx
```

If nginx logs `connect() to unix:/var/www/counterparser/run/counterparser.sock failed (13:
Permission denied)`, check that nginx's user can traverse every parent directory in that path
(execute bit) — the socket file itself is created world-read/write (see the `umask 000` note in
the [Dockerfile](Dockerfile)), so the usual failure mode is a directory permission, not the
socket.

## 4. Verify end to end

```bash
curl -s --unix-socket run/counterparser.sock http://localhost/healthz
curl -s -o /dev/null -w "%{http_code}\n" \
  --unix-socket run/counterparser.sock \
  -H "X-Real-IP: 127.0.0.1" http://localhost/check   # expect 204 if 127.0.0.1 is whitelisted

curl -sI https://your-domain.example/   # through nginx end to end
```

For ongoing monitoring, `/stats` (aggregate counts only — see the Endpoints table in
[ARCHITECTURE.md](ARCHITECTURE.md)) is reachable the same way and isn't wired into nginx:

```bash
curl -s --unix-socket run/counterparser.sock http://localhost/stats
```

## Updating

Once CI has finished building the new image for a push (check the Actions tab, or
`gh run watch` from the repo):

```bash
cd /var/www/counterparser
docker compose pull
docker compose up -d   # recreates just the counterparser container; nginx is untouched
```

`config.toml`/`.env` changes need only `docker compose up -d` (no pull/build) — compose picks
up the mounted file on container recreation.
