FROM erlang:alpine

LABEL maintaner="Alexander Komlev <aleksandr.komlev@gmail.com>"

ENV SSH_PROXY_ROOT=/opt/ssh-proxy
ENV SSH_PROXY_DATA=/opt/data
ENV SSH_PROXY_HOST_KEY=$SSH_PROXY_DATA/server/ssh_host_rsa_key

RUN mkdir -p \
        $SSH_PROXY_ROOT \
        $SSH_PROXY_DATA/auth \
        $SSH_PROXY_DATA/users \
        $SSH_PROXY_DATA/server

ADD ssh-proxy.erl $SSH_PROXY_ROOT/

RUN apk add --no-cache --virtual deps \
    openssl && \
    openssl genrsa -out $SSH_PROXY_HOST_KEY && \
    apk del deps

ENTRYPOINT [ \
    "/bin/sh", "-c", \
    "$SSH_PROXY_ROOT/ssh-proxy.erl -i $SSH_PROXY_DATA/auth -u $SSH_PROXY_DATA/users -t $SSH_PROXY_DATA/server" \
]
