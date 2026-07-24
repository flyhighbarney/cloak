FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/policyd ./cmd/policyd

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/policyd /policyd
COPY configs /configs
EXPOSE 4000 4001
USER nonroot:nonroot
ENTRYPOINT ["/policyd", "--config", "/configs"]
