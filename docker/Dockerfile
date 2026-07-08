# Build stage
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /bin/securedb ./cmd/server

# Runtime stage
FROM alpine:3.21
RUN adduser -D -H securedb && apk add --no-cache ca-certificates tzdata
USER securedb
COPY --from=build /bin/securedb /usr/local/bin/securedb
EXPOSE 8080
ENTRYPOINT ["securedb"]
