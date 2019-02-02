FROM golang:alpine AS build

RUN apk add --virtual git

RUN mkdir /build
ADD . /build/
WORKDIR /build

RUN go get -u github.com/labstack/echo/... \
 && go get -u github.com/rs/zerolog/log \
 && CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-extldflags "-static"' -o gos3b2 .

FROM alpine

RUN mkdir /app
COPY --from=build /build/gos3b2 /app/

RUN apk add --virtual ca-certificates \
 && update-ca-certificates

CMD ["/app/gos3b2"]
