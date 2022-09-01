FROM golang:1.19 as builder
ENV GOOS linux
ENV CGO_ENABLED 0
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o /app/main

FROM alpine:3.16
ARG PORT
WORKDIR /
RUN apk add --no-cache ca-certificates bash
COPY --from=builder /app/main /app
COPY wait-for-it.sh /wait-for-it.sh
RUN chmod +x app
EXPOSE ${PORT}
CMD ./app
