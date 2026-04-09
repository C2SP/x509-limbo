# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

# Inspired by:
# https://github.com/woodruffw/openssl-dockerfiles/blob/1587dafa01254dd377c69a75a2d17d320acc2be1/boringssl.dockerfile
# https://github.com/aws/aws-lc/blob/9ce727c8b66d39c4df44149eda71c54d033cb299/.github/docker_images/alpine-linux/Dockerfile

FROM alpine

WORKDIR /tmp

RUN apk add --no-cache \
    cmake \
    g++ \
    gcc \
    libc-dev \
    ninja \
    perl \
    pkgconf \
    git \
    go \
    make \
    linux-headers

RUN git clone --depth 1 https://github.com/aws/aws-lc.git

WORKDIR /tmp/aws-lc

RUN cmake -G Ninja -B build \
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
        -DCMAKE_INSTALL_PREFIX=/build/aws-lc \
        -DBUILD_TESTING=OFF && \
    ninja -C build install

WORKDIR /build/aws-lc

RUN rm -rf /tmp/aws-lc

ENV PKG_CONFIG_PATH=/build/aws-lc/lib/pkgconfig/

WORKDIR /tmp/harness

COPY ./ .

RUN make

ENTRYPOINT ["./main"]
