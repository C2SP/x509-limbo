FROM ghcr.io/woodruffw/openssl-dockerfiles/openssl-3.5:latest

WORKDIR /tmp/harness

COPY ./ .

RUN make

ENTRYPOINT ["./main"]
