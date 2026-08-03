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
# on the binary itself rather than running the whole container as root or
# requiring --cap-add at `docker run` time — least privilege, works out of
# the box. (Some hardened `docker run --cap-drop=ALL` setups still need
# --cap-add=NET_RAW --cap-add=NET_ADMIN added back — see DEPLOY.md.) If the
# binary is ever missing/unrunnable, the app feature-detects that at boot
# (server/nmap/detect.ts) and cleanly hides the whole feature instead of
# erroring — this is what makes it PRESENT on this self-hosted image while
# staying absent on the Vercel-hosted deployment.
RUN apt-get update && \
    apt-get install -y --no-install-recommends nmap libcap2-bin && \
    setcap cap_net_raw,cap_net_admin+eip "$(command -v nmap)" && \
    rm -rf /var/lib/apt/lists/*

# Carry over pruned node_modules (incl. the prebuilt better-sqlite3 binary).
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./

# SQLite database lives on a persistent volume.
RUN mkdir -p /data
VOLUME ["/data"]

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://localhost:'+(process.env.PORT||3000)+'/api/system/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "dist/server.cjs"]
