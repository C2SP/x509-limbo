FROM ghcr.io/woodruffw/openssl-dockerfiles/boringssl:latest

WORKDIR /tmp/harness

COPY ./ .

RUN apk add --no-cache make
RUN make BORINGSSL=1

ENTRYPOINT ["./main"]
