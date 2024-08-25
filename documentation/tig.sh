#!/bin/bash

# This document is Licensed under Creative Commons CC0.
# To the extent possible under law, the author(s) have dedicated all copyright and related and neighboring rights
# to this document to the public domain worldwide.
# This document is distributed without any warranty.
# You should have received a copy of the CC0 Public Domain Dedication along with this document.
# If not, see https://creativecommons.org/publicdomain/zero/1.0/legalcode.

# export DATASET=https://example.com?apikey=abcd
# export DATAGET=https://example.com

printf "" | curl -X PUT --data-binary @- $DATASET'&format=%25s' || echo Environment not set.
curl $DATAGET/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.tig || echo Environment not set.

# Collect the TLS file into our tarball and tar this code directory with it. That is it.
echo >/tmp/tig.sh
test -f $IMPLEMENTATION/private.key && cat $IMPLEMENTATION/private.key|curl -X PUT --data-binary @- $DATASET'&format=curl%20'$DATAGET'*%20>/etc/ssl/tig.key' >>/tmp/tig.sh
echo >>/tmp/tig.sh
test -f $IMPLEMENTATION/certificate.crt && test -f $IMPLEMENTATION/ca_bundle.crt && cat $IMPLEMENTATION/certificate.crt $IMPLEMENTATION/ca_bundle.crt | curl -X PUT --data-binary @- $DATASET'&format=curl%20'$DATAGET'*%20>/etc/ssl/tig.crt' >>/tmp/tig.sh
echo >>/tmp/tig.sh
echo cd /go/src >>/tmp/tig.sh
echo >>/tmp/tig.sh
tar --exclude .git -c . | curl --data-binary @- -X POST $DATASET'&format=*' >/tmp/code.txt
echo curl $DATAGET$(cat /tmp/code.txt)" | tar -x" >>/tmp/tig.sh
echo go run main.go >>/tmp/tig.sh
cat /tmp/tig.sh | curl -X PUT --data-binary @- $DATASET'&format=*' >/tmp/launcher.txt

# Make sure everything is installed.
echo 'apt update && apt install -y docker.io' >/tmp/tig.sh
echo 'yum install -y docker  && docker ps && touch /etc/containers/nodocker' >>/tmp/tig.sh
echo 'service docker start; docker ps' >>/tmp/tig.sh
# Invasive restart of the service. /data may be retained in alternatives.
echo docker stop tig >>/tmp/tig.sh
echo docker rm tig >>/tmp/tig.sh
echo docker run --name tig -d --rm -p 443:443 --tmpfs /data:rw,size=4g docker.io/library/golang@sha256:10e3c0f39f8e237baa5b66c5295c578cac42a99536cc9333d8505324a82407d9 bash -c \''curl '$DATAGET$(cat /tmp/launcher.txt)'|bash'\' >>/tmp/tig.sh
echo 'service docker start; sleep 6; docker ps' >>/tmp/tig.sh
# Print out the files
cat /tmp/tig.sh | curl -X PUT --data-binary @- $DATASET'&format=curl%20'$DATAGET'*'%20%7C%20sudo%20bash
cat /tmp/tig.sh | curl -X PUT --data-binary @- $DATASET'&format=curl%20'$DATAGET'*'%20%7C%20sudo%20bash >>$IMPLEMENTATION/tig.log
echo >>$IMPLEMENTATION/tig.log

