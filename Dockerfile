# Universal Resolver driver for did:cimd.
# The driver has no dependencies beyond the Node.js runtime, so there is no build stage.
FROM node:26.12.0-alpine3.24

ENV NODE_ENV=production
WORKDIR /opt/driver-did-cimd

COPY LICENSE package.json ./
COPY src ./src

USER node
EXPOSE 8080
CMD ["node", "src/main.js"]
