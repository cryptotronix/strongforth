FROM golang:1.16-buster

ARG CRYPTOAUTHLIB_RELEASE=3.2.5

RUN apt update && apt install -y \
    cmake

WORKDIR /root

RUN wget -c https://github.com/MicrochipTech/cryptoauthlib/archive/refs/tags/v${CRYPTOAUTHLIB_RELEASE}.tar.gz -O - | tar xz \
    && cd cryptoauthlib-${CRYPTOAUTHLIB_RELEASE} \
    && cmake -B ./build . \
    && cmake --build ./build \
    && cmake --build ./build --target install \
    && touch /usr/include/cryptoauthlib/hal/atca_start_config.h \
    && touch /usr/include/cryptoauthlib/hal/atca_start_iface.h

COPY . /go/src/strongforth

RUN cd /go/src/strongforth/server \
    && cmake -B ./build . \
    && cmake --build ./build \
    && cmake --build ./build --target install

