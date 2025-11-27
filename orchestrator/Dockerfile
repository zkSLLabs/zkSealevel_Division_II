FROM node:22-bullseye-slim AS deps
WORKDIR /app
COPY package.json tsconfig.json .
COPY types ./types
RUN npm install --no-audit --no-fund

FROM deps AS build
WORKDIR /app
COPY src ./src
RUN npm run build

FROM node:22-bullseye-slim AS runner
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY --from=build /app/package.json ./package.json
RUN npm prune --omit=dev
RUN chown -R node:node /app
USER node
EXPOSE 8080
CMD ["node", "dist/src/server.js"]


