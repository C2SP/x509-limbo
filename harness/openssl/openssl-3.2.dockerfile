FROM ghcr.io/woodruffw/openssl-dockerfiles/openssl-3.2:latest

WORKDIR /tmp/harness

COPY ./ .

RUN make

ENTRYPOINT ["./main"]
