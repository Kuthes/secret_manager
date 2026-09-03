FROM node:22-alpine AS builder

RUN apk add --no-cache bash coreutils

WORKDIR /app

COPY package*.json ./
COPY vendor ./vendor
RUN npm ci

COPY . .
RUN npm run build

FROM node:22-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production

COPY --from=builder /app/package*.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/public ./public
COPY --from=builder /app/app ./app

USER node

EXPOSE 3000

CMD ["npm", "run", "start"]
