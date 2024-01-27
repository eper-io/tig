#!/bin/bash

# This document is Licensed under Creative Commons CC0.
# To the extent possible under law, the author(s) have dedicated all copyright and related and neighboring rights
# to this document to the public domain worldwide.
# This document is distributed without any warranty.
# You should have received a copy of the CC0 Public Domain Dedication along with this document.
# If not, see https://creativecommons.org/publicdomain/zero/1.0/legalcode.

# Potential resolution of errors
#sudo systemctl stop firewalld
#sudo systemctl disable firewalld

export DOMAIN=example.com

cat <<EOF >Dockerfile
FROM golang@sha256:10e3c0f39f8e237baa5b66c5295c578cac42a99536cc9333d8505324a82407d9
RUN apt update -y && apt install -y certbot
CMD echo certbot certonly -m 'example@$DOMAIN' --standalone -d '$DOMAIN'; certbot renew;
EOF

docker build --pull --no-cache -t local/certbot .
docker run -t -i -p 80:80 -v /etc/letsencrypt:/etc/letsencrypt:rw local/certbot

cat <<EOF >Dockerfile
FROM golang@sha256:10e3c0f39f8e237baa5b66c5295c578cac42a99536cc9333d8505324a82407d9

RUN git clone https://gitlab.com/eper.io/tig.git src

WORKDIR /go/src

RUN go build -o /go/bin/replace ./main.go

RUN /go/bin/replace ./main.go "var cleanup = 10 * time.Minute" "var cleanup = 14 * 24 * time.Hour"

RUN /go/bin/replace ./main.go "var root = \"/tmp\"" "var root = \"/data\""

CMD go run ./main.go

EOF

docker build --pull --no-cache -t local/private .
rm -f Dockerfile

mkdir -p /data

docker stop tig
docker rm tig
docker run --name tig -d --restart=always -p 443:443 -v /data:/data -v /etc/letsencrypt/live/$DOMAIN/privkey.pem:/etc/ssl/tig.key:ro -v /etc/letsencrypt/live/$DOMAIN/fullchain.pem:/etc/ssl/tig.crt:ro local/private
