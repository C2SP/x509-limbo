FROM ghcr.io/woodruffw/openssl-dockerfiles/openssl-1.1.1:latest

WORKDIR /tmp/harness

COPY ./ .

RUN apk add --no-cache date-dev nlohmann-json
RUN make

ENTRYPOINT ["./main"]
