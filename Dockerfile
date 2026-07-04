FROM node:26-alpine

RUN addgroup -g 4242 docknode && adduser -D -u 4242 -G docknode docknode

ENV NODE_ENV=production
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm install --omit=dev --no-audit --no-fund

COPY basicutils.js acl.js audit.js clientip.js dbinit.js dbmigrate.js dbopts.js \
     errors.js index.js ipmatch.js keygen.js kek.js keystore.js kvadmin.js \
     server.js serverauth.js serverdb.js serverhandlers.js serveropts.js ./
COPY tr-key-vault kv-admin kek-gen ./
COPY migrations ./migrations

USER docknode
EXPOSE 8888

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s \
  CMD wget -q -O /dev/null http://127.0.0.1:8888/healthz || exit 1

CMD ["node", "./tr-key-vault"]
