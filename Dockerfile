FROM node:24-alpine
WORKDIR /app
# the app needs only node: drop npm, npx, yarn and corepack (and the CVEs that come with them)
RUN rm -rf /usr/local/lib/node_modules /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack /opt/yarn-* /usr/local/bin/yarn /usr/local/bin/yarnpkg
ENV NODE_ENV=production PORT=8200 LOCKBOX_DATA=/data/lockbox.json
COPY package.json ./
COPY src ./src
COPY public ./public
RUN mkdir /data && chown 1000:1000 /data
# numeric uid, so Kubernetes can verify runAsNonRoot
USER 1000:1000
VOLUME /data
EXPOSE 8200
HEALTHCHECK CMD wget -qO- http://127.0.0.1:8200/v1/health || exit 1
CMD ["node", "src/server.js"]
