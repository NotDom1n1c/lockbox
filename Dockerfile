FROM node:24-alpine
WORKDIR /app
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
