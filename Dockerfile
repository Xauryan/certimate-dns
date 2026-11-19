FROM node:24-alpine AS webui-builder
WORKDIR /app
COPY . /app/
RUN \
  cd /app/ui && \
  npm ci && \
  npm run build



FROM golang:1.25-alpine AS server-builder
WORKDIR /app
COPY . /app/
COPY --from=webui-builder /app/ui/dist /app/ui/dist
ENV CGO_ENABLED=0
RUN go build -mod=readonly -trimpath -ldflags="-s -w" -o certimate



FROM alpine:latest
WORKDIR /app
COPY --from=server-builder /app/certimate .
ENTRYPOINT ["./certimate", "serve", "--dir", "/app/pb_data", "--http", "0.0.0.0:8090"]
