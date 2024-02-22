FROM alpine

WORKDIR /tmp/openssl

RUN apk add --no-cache \
        bash \
        g++ \
        gcc \
        libc-dev \
        linux-headers \
        make \
        perl \
        pkgconf

ADD https://github.com/openssl/openssl/archive/OpenSSL_1_1_1-stable.tar.gz openssl-src.tar.gz

RUN tar \
        --extract \
        --file openssl-src.tar.gz \
        --strip 1 \
    && ./config \
        --openssldir=/srv/openssl \
        --prefix=/build/openssl \
        -static \
    && make -j \
    && make install

ENV PKG_CONFIG_PATH=/build/openssl/lib/pkgconfig/

WORKDIR /tmp/harness

COPY ./ .

RUN make

ENTRYPOINT ["./main"]
