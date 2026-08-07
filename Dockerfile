# --- Build stage: install all deps, build client + server, drop dev deps ---
FROM node:22-bookworm-slim AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build && npm prune --omit=dev

# --- Runtime stage: minimal image with prod deps + built artifacts ---
FROM node:22-bookworm-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production \
    PORT=3000 \
    DB_PATH=/data/seclayer.sqlite

# Network Reconnaissance: install nmap and grant its binary the raw-socket
# capability SYN scan (-sS) and OS detection (-O) need, via a file capability
# on the binary itself rather than running the whole container as root —
# least privilege at the process level. This alone is NOT sufficient at
# `docker run` time, though: Docker's default capability set includes
# NET_RAW but not NET_ADMIN, and a binary's file capabilities can never
# exceed the container's own bounding set — without --cap-add=NET_ADMIN
# (NET_RAW is already default, but pass both for clarity) nmap fails to even
# exec ("spawn EPERM"), on every docker run, not just hardened
# --cap-drop=ALL setups. See docker-compose.yml / DEPLOY.md §7 for the
# required flags. If the binary is ever missing/unrunnable, the app
# feature-detects that at boot (server/nmap/detect.ts) and cleanly hides the
# whole feature instead of erroring — this is what makes it PRESENT on this
# self-hosted image while staying absent on the Vercel-hosted deployment.
RUN apt-get update && \
    apt-get install -y --no-install-recommends nmap libcap2-bin && \
    setcap cap_net_raw,cap_net_admin+eip "$(command -v nmap)" && \
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
