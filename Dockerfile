FROM node:20-alpine

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY src ./src
COPY public ./public

ENV DATA_DIR=/data
VOLUME ["/data"]

EXPOSE 3939
HEALTHCHECK --interval=30s --timeout=5s CMD node -e "fetch('http://localhost:3939/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "src/server.js"]
