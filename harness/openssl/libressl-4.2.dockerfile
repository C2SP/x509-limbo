FROM ghcr.io/woodruffw/openssl-dockerfiles/libressl-4.2:latest

WORKDIR /tmp/harness

COPY ./ .

RUN make

ENTRYPOINT ["./main"]
