FROM node:18-alpine
WORKDIR /app
COPY proxy.js .
COPY config.example.json config.json
EXPOSE 18801
CMD ["node", "proxy.js"]
