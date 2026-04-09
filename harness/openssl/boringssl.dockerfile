FROM ghcr.io/woodruffw/openssl-dockerfiles/boringssl:latest

# Our base boringssl image uses cmake not make, so we need to add it here.
RUN apk add --no-cache make

WORKDIR /tmp/harness

COPY ./ .

RUN make

ENTRYPOINT ["./main"]
