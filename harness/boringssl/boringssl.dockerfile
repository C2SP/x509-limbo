FROM ghcr.io/woodruffw/openssl-dockerfiles/boringssl:latest

WORKDIR /tmp/harness

COPY ./ .

RUN apk add --no-cache make date-dev nlohmann-json
RUN make

ENTRYPOINT ["./main"]
