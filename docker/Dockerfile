# syntax=docker/dockerfile:1
# X-Road ASiC Verifier: static Svelte build served by unprivileged nginx, with a
# same-origin proxy to the global configuration upstream named in the anchor.
# Build from the repo root:  docker build -f docker/Dockerfile -t xroad-asic-verifier .

FROM node:26.10.0-alpine3.24@sha256:0b36e8c136b94cd4fcf02188228e76c31ad5872eef3fec8cbd2eee500cfd9e80 AS build
ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0
WORKDIR /src
RUN corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY apps/web/package.json apps/web/
COPY packages/verifier/package.json packages/verifier/
RUN pnpm install --frozen-lockfile
COPY tsconfig.base.json ./
COPY packages/verifier packages/verifier
COPY apps/web apps/web
RUN pnpm --filter web build

FROM nginxinc/nginx-unprivileged:1.31.5-alpine3.24@sha256:19c132c9ab02d3b783f478743dafc7a7f42e27aa7d2bdcbec1bb1128ca8f2a07
USER root
# xmllint parses the anchor (no network, no entity expansion).
RUN apk add --no-cache libxml2-utils \
 && rm -f /etc/nginx/conf.d/default.conf /usr/share/nginx/html/* \
 && mkdir -p /etc/nginx/verifier /etc/verifier /usr/share/verifier/templates \
 && chown nginx /etc/nginx/verifier
COPY docker/nginx/security-headers.conf /etc/nginx/verifier/security-headers.conf
COPY docker/nginx/default.conf.template docker/nginx/proxy-common.conf.template /usr/share/verifier/templates/
# Placeholder anchor so the image starts; mount your instance's anchor over it.
COPY docker/anchor.example.xml /etc/verifier/anchor.xml
COPY --chmod=0755 docker/entrypoint.sh /usr/local/bin/verifier-entrypoint
COPY --from=build /src/apps/web/dist /usr/share/nginx/html
USER 101
# Docker lets non-root processes bind ports below 1024 in the container namespace.
EXPOSE 80
ENTRYPOINT ["/usr/local/bin/verifier-entrypoint"]
CMD ["nginx", "-g", "daemon off;"]
