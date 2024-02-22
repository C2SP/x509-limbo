FROM ghcr.io/woodruffw/openssl-dockerfiles/openssl-1.1.1:latest

WORKDIR /tmp/harness

COPY ./ .

RUN make

ENTRYPOINT ["./main"]
