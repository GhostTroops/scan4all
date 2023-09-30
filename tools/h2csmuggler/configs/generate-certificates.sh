#!/bin/bash

if [ $(basename $PWD) == "configs" ]; then
    PREFIX="."
else
    PREFIX="configs"
fi

# Delete previous
rm $PREFIX/key.pem $PREFIX/cert.pem $PREFIX/haproxy.pem 2> /dev/null
# Delete empty dirs created by docker-compose
rmdir $PREFIX/key.pem $PREFIX/cert.pem $PREFIX/haproxy.pem 2>/dev/null

openssl genrsa > $PREFIX/key.pem
openssl req -new -x509 -key $PREFIX/key.pem -out $PREFIX/cert.pem -days 365 -nodes \
    -subj "/C=US/ST=Test/L=Test/O=Test/OU=Test/CN=localhost"
cat $PREFIX/key.pem $PREFIX/cert.pem > $PREFIX/haproxy.pem
