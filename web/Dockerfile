# ---- base ----
    FROM node:20.18.0-alpine AS base
    WORKDIR /app
    RUN apk add --no-cache libc6-compat
    
    # ---- deps (install once) ----
    FROM base AS deps
    COPY package.json package-lock.json ./
    RUN --mount=type=cache,target=/root/.npm npm ci --no-audit --no-fund
    
    # ---- dev (hot reload) ----
    FROM deps AS dev
    COPY . .
    EXPOSE 3000
    CMD ["npm", "run", "dev"]
    
    # ---- builder (for prod) ----
    FROM deps AS builder
    COPY . .
    RUN npm run build
    
    # ---- prod (runtime) ----
    FROM base AS prod
    ENV NODE_ENV=production
    ENV NEXT_TELEMETRY_DISABLED=1
    COPY --from=builder /app ./
    EXPOSE 3000
    CMD ["npm", "run", "start"]
    