FROM ghcr.io/woodruffw/openssl-dockerfiles/libressl-3.9:latest

WORKDIR /tmp/harness

COPY ./ .

RUN make

ENTRYPOINT ["./main"]
