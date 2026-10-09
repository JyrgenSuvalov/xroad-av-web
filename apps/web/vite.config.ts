import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { defineConfig, type Plugin } from 'vite';

// Dev server mirrors the nginx setup (docker/README.md) so app code is identical:
//   /anchor.xml    → file at ANCHOR_PATH
//   /globalconf/*  → GLOBALCONF_UPSTREAM origin + * (prefix stripped)
//
// The directory's Content-location entries are host-absolute (e.g.
// /V2/<ts>/shared-params.xml), so the proxy maps onto the upstream *origin*:
// the client fetches `/globalconf` + <anchor downloadURL path> for the
// directory (e.g. /globalconf/internalconf) and `/globalconf` + Content-location
// for parts. GLOBALCONF_UPSTREAM may be the full downloadURL; only its origin is used.
const repoRoot = resolve(import.meta.dirname, '../..');
const upstream = new URL(
  process.env.GLOBALCONF_UPSTREAM ?? 'https://cs.example.org/internalconf',
).origin;
const anchorPath = resolve(
  process.env.ANCHOR_PATH ?? resolve(repoRoot, 'docker/anchor.example.xml'),
);

function devAnchorAndProxyGuard(): Plugin {
  return {
    name: 'xrav-dev-anchor',
    configureServer(server) {
      server.middlewares.use(async (req, res, next) => {
        const path = (req.url ?? '').split('?')[0] ?? '';
        if (path === '/anchor.xml') {
          try {
            const xml = await readFile(anchorPath);
            res.setHeader('Content-Type', 'application/xml');
            res.setHeader('Cache-Control', 'no-store');
            res.end(xml);
          } catch {
            res.statusCode = 404;
            res.end(`anchor not found at ${anchorPath} (set ANCHOR_PATH)`);
          }
          return;
        }
        // Like nginx: only the directory and shared-params pass through.
        if (path.startsWith('/globalconf/') && /private-params/i.test(path)) {
          res.statusCode = 403;
          res.end('forbidden');
          return;
        }
        next();
      });
    },
  };
}

export default defineConfig({
  plugins: [svelte(), devAnchorAndProxyGuard()],
  server: {
    proxy: {
      '/globalconf/': {
        target: upstream,
        changeOrigin: true,
        // Central server certs are often self-signed; trust comes from the directory signature vs. the anchor.
        secure: false,
        rewrite: (p) => p.replace(/^\/globalconf/, ''),
      },
    },
  },
});
