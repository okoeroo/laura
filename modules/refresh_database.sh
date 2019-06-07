#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

echo $DIR
cd $DIR

curl https://iptoasn.com/data/ip2country-v4.tsv.gz | gunzip -d > ip2country-v4.tsv
curl https://iptoasn.com/data/ip2country-v6.tsv.gz | gunzip -d > ip2country-v6.tsv
curl https://iptoasn.com/data/ip2asn-combined.tsv.gz | gunzip -d > ip2asn-combined.tsv

./produce_db.py
./download-cabundle.sh

