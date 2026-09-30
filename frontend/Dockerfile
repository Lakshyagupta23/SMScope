# ============================================================================
# SecureMailScope Frontend - Multi-Stage Docker Build
# ============================================================================
# CRITICAL VITE BEHAVIOR: VITE_* environment variables are embedded at BUILD
# TIME (not runtime). They must be passed as Docker ARGs (build args), not
# as environment variables at container startup.
#
# HOW TO USE:
#   docker build \
#     --build-arg VITE_BACKEND_URL=http://YOUR_HOST:8000 \
#     --build-arg VITE_WS_URL=ws://YOUR_HOST:8000 \
#     -t securemailscope-frontend .
#
# In docker-compose, these come from the `build.args:` section.
# ============================================================================

# --- Stage 1: Build ---
FROM node:20-alpine AS builder

WORKDIR /app

# Accept build-time config as ARGs
# These are the BROWSER-accessible URLs, not Docker-internal service names.
ARG VITE_BACKEND_URL=http://localhost:8000
ARG VITE_WS_URL=ws://localhost:8000

# Export ARGs as ENV vars so Vite sees them during `npm run build`
ENV VITE_BACKEND_URL=${VITE_BACKEND_URL}
ENV VITE_WS_URL=${VITE_WS_URL}

# Install dependencies first (cached unless package.json changes)
COPY package*.json ./
RUN npm ci --prefer-offline

# Copy source and build
COPY . .
RUN npm run build

# --- Stage 2: Serve ---
FROM node:20-alpine AS runner

RUN npm install -g serve

WORKDIR /app
COPY --from=builder /app/dist ./dist

EXPOSE 5173
CMD ["serve", "-s", "dist", "-l", "5173"]
