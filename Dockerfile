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

ADD sshd.erl $SSH_PROXY_ROOT/

RUN apk add --no-cache --virtual deps \
    openssh && \
    ssh-keygen -t rsa -f $SSH_PROXY_HOST_KEY && \
    apk del deps

ENTRYPOINT [ \
    "/bin/sh", "-c", \
    "$SSH_PROXY_ROOT/sshd.erl -i $SSH_PROXY_DATA/auth -u $SSH_PROXY_DATA/users -t $SSH_PROXY_DATA/server" \
]
