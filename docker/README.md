# Docker image

A static build of the web app, served by unprivileged nginx, with a same-origin proxy to the X-Road central server named in the configuration anchor. The proxy only passes the global configuration through; all verification happens in the browser.

| File | Purpose |
|---|---|
| `Dockerfile` | Two stages. `node:24.21.0-alpine3.24` runs `pnpm install --frozen-lockfile` and `pnpm --filter web build`. The output goes into `nginxinc/nginx-unprivileged:1.30.5-alpine3.24`, which runs as uid 101. Both images are pinned by tag and digest. Build context is the repo root. |
| `Dockerfile.dockerignore` | BuildKit picks this up for `docker/Dockerfile`. It leaves out `node_modules`, `dist`, `.git` and local env files. |
| `anchor.example.xml` | Placeholder anchor baked into the image (instance `EXAMPLE`, host `cs.example.org`). Replace it with your own. |
| `entrypoint.sh` | Reads `/etc/verifier/anchor.xml`, renders the two templates with `envsubst`, runs `nginx -t`, then `exec nginx`. |
| `nginx/default.conf.template` | The server block: static SPA, `/anchor.xml`, and the `/globalconf/` allow-list. |
| `nginx/proxy-common.conf.template` | Shared proxy settings: SNI, no upstream TLS verification, no cookies or auth, short timeouts, `no-store`. |
| `nginx/security-headers.conf` | CSP and the other security headers. Included in every location that has its own `add_header`. |

## Run

```sh
pnpm docker:build          # docker build -f docker/Dockerfile -t xroad-asic-verifier .
pnpm docker:run            # docker run --rm -p 8080:80 xroad-asic-verifier
docker run --rm -p 8080:80 -v ./anchor.xml:/etc/verifier/anchor.xml:ro xroad-asic-verifier
```

A placeholder anchor (`docker/anchor.example.xml`) is baked in at `/etc/verifier/anchor.xml`, so a plain `docker run` starts, but no global configuration will load. Mount your X-Road instance's internal configuration anchor over that path (on a security server it is `/etc/xroad/configuration-anchor.xml`). Nothing else is configurable: the anchor is the only input.

## Entrypoint: anchor → upstream

1. The anchor must be readable and well-formed (`xmllint --nonet`; no DTD loading or entity expansion). Its root element must be `configurationAnchor`.
2. Only a `<source>` that has both a `downloadURL` and a `verificationCert` counts. The first **https** source wins. If there is none, the first http URL is **upgraded to https**, as X-Road confclient does (`ConfigurationDownloadUtils`). There is no http fallback; see Limitations below.
3. The URL must match `^https://<dns-host>(:port)?(/[A-Za-z0-9._~-]+)+$`, because the values go into the nginx config verbatim. This blocks config injection.
4. The script derives `UPSTREAM_ORIGIN`, `UPSTREAM_HOST` (for SNI), `UPSTREAM_HOSTPORT` (for the Host header) and `DIRECTORY_PATH`. The resolver comes from `/etc/resolv.conf`.
5. Any failure prints `verifier-entrypoint: FATAL: …` and exits 1, so the container stops.

The upstream goes through an nginx variable plus a `resolver`. So an unresolvable host gives a **502 at request time**; nginx doesn't refuse to start. Resolution runs with `ipv6=off`, because Docker Desktop has no IPv6 egress.

## Routes (same semantics as `apps/web/vite.config.ts`)

| Request | Result |
|---|---|
| `/`, any unknown path | static file, otherwise falls back to `index.html` (`Cache-Control: no-cache`) |
| `/assets/*` | hashed bundle, `immutable`; a missing file gives 404 (no SPA fallback) |
| `GET /anchor.xml` | the mounted anchor, `application/xml`, `no-store` |
| `GET /globalconf<DIRECTORY_PATH>` (usually `/globalconf/internalconf`) | proxied to `<origin><DIRECTORY_PATH>`; the **query string is kept** (`?version=6`) |
| `GET /globalconf/V<n>/<digits>/{shared,nextupdate}-params.xml` | proxied to `<origin>/V<n>/<digits>/{shared,nextupdate}-params.xml` (`nextupdate-params.xml` is fetched only when the directory lists it) |
| anything else under `/globalconf/` (private-params, `..`, other files) | **403** |
| non-GET/HEAD on the proxy or anchor routes | 403 |

On proxied responses, upstream `Set-Cookie`, `Cache-Control` and `Expires` are dropped and `Cache-Control: no-store` is set. Timeouts are 5 s connect, 10 s send and 20 s read. The Vite dev server is more permissive: it blocks only `private-params`. nginx is the strict one; for the allowed paths the mapping is the same.

## Headers (every response, including errors)

```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
X-Frame-Options: DENY
Cross-Origin-Opener-Policy: same-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
```

`style-src` has no `'unsafe-inline'`. Svelte 5 with Vite extracts component `<style>` blocks to `/assets/*.css` (the default `css: 'external'` in builds), so this works. When changing the UI, don't switch to `css: 'injected'` and don't use `style="..."` attributes built from strings; Svelte's `style:` directives set CSSOM properties, which CSP allows.

## Troubleshooting

- **The container exits right away** with `verifier-entrypoint: FATAL: …`: the anchor is missing, isn't well-formed XML, isn't a `configurationAnchor`, has no usable `<source>`, or has a `downloadURL` that doesn't match the pattern above. The message says which.
- **`/globalconf/…` returns 502**: nginx couldn't resolve or reach the central server named in the anchor. Check that the host running the container can reach it over HTTPS.
- **`/globalconf/…` returns 504** after about 5 s: the connection to the central server timed out.
- **Requests to `/globalconf/…` return 403**: only the configuration directory and `shared-params.xml` / `nextupdate-params.xml` are proxied (see Routes).
- **Logs**: the access log goes to stdout, so use `docker logs`.

## Limitations

- **No plain-http fallback.** An `http://` anchor URL is upgraded to https, and there is no fallback to plain http (X-Road's confclient does fall back). Central servers serve the configuration over https by default, and a self-signed certificate is fine: the upstream certificate isn't checked, because trust comes from the directory signature. Only a central server with port 443 closed would need an http opt-in in the entrypoint.
