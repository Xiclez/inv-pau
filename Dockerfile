FROM node:20-alpine

WORKDIR /app

# Capa de dependencias separada: solo se reinstala si cambia package*.json
COPY package*.json ./
RUN npm install --omit=dev

COPY . .

RUN mkdir -p /app/data

ENV NODE_ENV=production
ENV PORT=3010
EXPOSE 3010

CMD ["node", "server.js"]
