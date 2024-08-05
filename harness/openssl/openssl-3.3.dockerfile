FROM ghcr.io/woodruffw/openssl-dockerfiles/openssl-3.3:latest

WORKDIR /tmp/harness

COPY ./ .

RUN apk add --no-cache date-dev nlohmann-json
RUN make

ENTRYPOINT ["./main"]
