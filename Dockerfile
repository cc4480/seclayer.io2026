# --- Build stage: install all deps, build client + server, drop dev deps ---
FROM node:22-bookworm-slim AS build
WORKDIR /app

# Browsers are fetched explicitly below, never by playwright's postinstall: the
# install path must be a known, copyable location (the default is a HOME-relative
# cache that differs between stages), and package.json's allowScripts list
# governs which packages may run lifecycle scripts at all.
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build && npm prune --omit=dev

# Chromium for the DOM-XSS probe and the crawl renderer (both gated behind
# ENABLE_BROWSER_RENDERING). Installed AFTER the prune so it isn't discarded,
# and only the browser — `--with-deps` would apt-install libraries into this
# stage, which the runtime stage never receives; those are installed there
# directly instead.
#
# Invoked through node against playwright's own cli.js rather than `npx
# playwright`: npx resolves the binary through node_modules/.bin, which is not
# reliably populated here (it exited 127, "command not found", even with
# playwright present in the lockfile). Calling the CLI entrypoint directly has
# no such dependency. The `ls` afterwards turns a silently-missing browser into
# a failed build — without it, the image would ship fine and the DOM-XSS probe
# would just never run at runtime.
RUN node node_modules/playwright/cli.js install chromium && \
    ls -d /ms-playwright/chromium-* > /dev/null

# --- Runtime stage: minimal image with prod deps + built artifacts ---
FROM node:22-bookworm-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production \
    PORT=3000 \
    DB_PATH=/data/seclayer.sqlite

# Network Reconnaissance: install nmap. Deliberately NO file capabilities on the
# binary and NO USER directive, so nmap runs as root.
#
# Why no setcap: a binary's file capabilities can never exceed the container's
# capability bounding set, and a cap in the file's EFFECTIVE set that isn't in
# the bounding set makes the kernel refuse to even exec the binary ("spawn
# EPERM"). Managed platforms like Railway strip CAP_NET_RAW (and CAP_NET_ADMIN)
# from the bounding set entirely and don't let you add them back — so ANY
# effective file cap made nmap fail to exec there, disabling the whole feature
# (this was the original bug). With no file caps nmap execs cleanly everywhere.
#
# Where the platform's bounding set DOES include CAP_NET_RAW (a normal
# `docker run`, compose, a VPS), root nmap gets raw sockets natively — no setcap
# needed — and the app runs full SYN + OS-detection scans. Where it doesn't
# (Railway), the boot probe in server/nmap/detect.ts detects that and the scan
# runs in unprivileged TCP-connect mode (-sT, no -O). Either way the feature is
# PRESENT and functional; it stays absent only when the binary is missing (e.g.
# the Vercel-hosted deployment), which the app feature-detects and hides cleanly.
# Shared libraries headless Chromium links against, for the DOM-XSS probe and
# crawl renderer. Listed explicitly rather than via `playwright install-deps`
# because that needs the playwright CLI and npx, and npx is deliberately removed
# from this image below. Installed in the same layer as nmap to avoid a second
# apt cache round-trip.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      nmap \
      libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libatspi2.0-0 libcups2 \
      libdrm2 libgbm1 libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 \
      libxrandr2 libpango-1.0-0 libcairo2 libasound2 libxshmfence1 fonts-liberation && \
    rm -rf /var/lib/apt/lists/*

# The base image ships a global `npm` CLI (with its own vendored
# node_modules — tar, brace-expansion, sigstore, etc.) that this image never
# invokes: the runtime CMD is a plain `node`, never `npm`/`npx`. Removing it
# isn't just cleanup — a vulnerability scan (docker scout / trivy) otherwise
# flags CVEs in npm's bundled deps (e.g. a CRITICAL in its vendored `tar`)
# that have zero real exposure here, but show up indistinguishable from ones
# that do. Trim it so the report only reflects code actually in the request path.
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx

# Carry over pruned node_modules (incl. the prebuilt better-sqlite3 binary).
# vite (and its transitive esbuild/plugin deps) is intentionally NOT here:
# server.ts only reaches it via a dynamic import() inside the dev-only branch,
# so `npm prune --omit=dev` drops it — it's devDependencies-only in
# package.json for exactly this reason. Same motivation as removing npm
# above: vite/esbuild carry their own CVEs (esbuild embeds a Go binary with
# unrelated Go-stdlib CVEs) that a vulnerability scan can't tell apart from
# something actually reachable in production.
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./

# The Chromium build fetched in the build stage. PLAYWRIGHT_BROWSERS_PATH must
# match the path it was installed to there, or playwright looks in a
# HOME-relative cache that doesn't exist here and reports the browser as missing
# — which the app would surface as the DOM-XSS probe silently not running.
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
COPY --from=build /ms-playwright /ms-playwright

# SQLite database lives on a persistent volume, attached at deploy time (e.g.
# docker-compose.yml's `seclayer-data:/data`, or a Railway Volume mounted at
# /data). No `VOLUME` instruction here on purpose — Railway's builder rejects
# it outright ("dockerfile invalid: docker VOLUME ... is not supported, use
# Railway Volumes"), and it was never load-bearing for the documented
# docker/compose flows above, which already bind an explicit named volume.
RUN mkdir -p /data

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://localhost:'+(process.env.PORT||3000)+'/api/system/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "dist/server.cjs"]
