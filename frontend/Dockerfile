# =============================
# FRONTEND (Next.js Production)
# =============================

# ---- Stage 1: Dependencies ----
FROM node:20-alpine AS deps
WORKDIR /app

# Copy dependency manifests
COPY package*.json ./

# Install all deps including dev (required for build)
RUN npm install

# ---- Stage 2: Build ----
FROM node:20-alpine AS builder
WORKDIR /app
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1
ARG NEXT_PUBLIC_API_URL=http://backend:8000
ENV NEXT_PUBLIC_API_URL=${NEXT_PUBLIC_API_URL}

# Copy deps and source
COPY --from=deps /app/node_modules ./node_modules
COPY . .

# Run build
RUN npm run build

# ---- Stage 3: Runtime ----
FROM node:20-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1

# Copy only what’s needed to run
COPY --from=builder /app/public ./public
COPY --from=builder /app/.next ./.next
COPY --from=builder /app/package*.json ./
COPY --from=builder /app/node_modules ./node_modules

# Health check to make sure .next exists
RUN test -d .next || (echo ".next directory missing!" && exit 1)

# Create a non-root user
RUN adduser -D nextjs
USER nextjs

EXPOSE ${PORT:-3000}

CMD ["npm", "start"]
