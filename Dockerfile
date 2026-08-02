FROM node:20-bookworm-slim
WORKDIR /srv
COPY package.json ./
RUN npm install --omit=dev
COPY server.mjs login.html ./
COPY dist ./dist
ENV PORT=8000
EXPOSE 8000
CMD ["node","server.mjs"]
