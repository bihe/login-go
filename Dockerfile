## fronted build-phase
## --------------------------------------------------------------------------
FROM node:lts-alpine AS FRONTEND-BUILD
WORKDIR /frontend-build
COPY ./frontend.angular .
RUN yarn global add @angular/cli@latest && yarn install && yarn run build --prod --base-href /ui/
## --------------------------------------------------------------------------

## backend build-phase
## --------------------------------------------------------------------------
FROM golang:alpine AS BACKEND-BUILD

ARG buildtime_variable_version=2.0.0
ARG buildtime_variable_timestamp=YYYYMMDD
ARG buildtime_varialbe_commit=b75038e5e9924b67db7bbf3b1147a8e3512b2acb
ARG buildtime_variable_runtime=golang

ENV VERSION=${buildtime_variable_version}
ENV BUILD=${buildtime_variable_timestamp}
ENV RUNTIME=${buildtime_variable_runtime}
ENV COMMIT=${buildtime_varialbe_commit}

WORKDIR /backend-build
COPY . .
RUN GOOS=linux GOARCH=amd64 go build -ldflags="-w -s -X main.Version=${VERSION}-${COMMIT} -X main.Build=${BUILD} -X main.Runtime=${RUNTIME}" -tags prod -o login.api cmd/server/main.go
## --------------------------------------------------------------------------

## runtime
## --------------------------------------------------------------------------
FROM alpine:latest
LABEL author="henrik@binggl.net"
WORKDIR /opt/login
RUN mkdir -p /opt/login/ui && mkdir -p /opt/login/etc && mkdir -p /opt/login/logs && mkdir -p /opt/login/templates && mkdir -p /opt/login/logs
## required folders assets && templates
COPY --from=BACKEND-BUILD /backend-build/assets /opt/login/assets
COPY --from=BACKEND-BUILD /backend-build/templates /opt/login/templates
## the executable
COPY --from=BACKEND-BUILD /backend-build/login.api /opt/login
## the SPA frontend
COPY --from=FRONTEND-BUILD /frontend-build/dist  /opt/login/ui

EXPOSE 3000

CMD ["/opt/login/login.api","--c=/opt/login/etc/application.json","--port=3000", "--hostname=0.0.0.0"]
