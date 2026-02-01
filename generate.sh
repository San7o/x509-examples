#!/bin/sh

#
# Generate a self-signed certificate with openssl
#
# Note that for ssh key generation, you should use the utility `ssh-keygen`
#

PUBLIC_KEY_NAME=public.pem
PRIVATE_KEY_NAME=private.key

C=US
STATE_NAME=Oregon
CITY_NAME=Portland
COMPANY_NAME=Company Name
COMPANY_SECTION_NAME=Org
COMPANY_HOSTNAME=www.example.com

openssl req -x509 \
    -newkey rsa:4096 \
    -keyout $PUBLIC_KEY_NAME \
    -out $PRIVATE_KEY_NAME \
    -sha256 \
    -days 3650 \
    -nodes \
    -subj "/C=$C/ST=$STATE_NAME/L=$CITY_NAME/O=$COMPANY_NAME/OU=$COMPANY_SECTION_NAME/CN=$COMPANY_HOSTNAME"
