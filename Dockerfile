# syntax=docker/dockerfile:1.6
FROM golang:1.25-alpine AS build
WORKDIR /src
RUN apk add --no-cache git
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/fauxbrowser .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/fauxbrowser /fauxbrowser
EXPOSE 18443
# Default listens on all interfaces inside the container.
ENTRYPOINT ["/fauxbrowser", "-listen", "0.0.0.0:18443"]
