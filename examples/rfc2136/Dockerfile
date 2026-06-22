FROM golang:1.25-alpine AS build
WORKDIR /src
# Copy provider module (needed by the replace directive in the example's go.mod)
COPY go.mod go.sum *.go ./
# Copy example module
COPY examples/rfc2136/ ./examples/rfc2136/
WORKDIR /src/examples/rfc2136
RUN CGO_ENABLED=0 go build -trimpath -o /rfc2136 .

FROM alpine:3.21
COPY --from=build /rfc2136 /rfc2136
EXPOSE 5353/udp
EXPOSE 5353/tcp
ENTRYPOINT ["/rfc2136"]
