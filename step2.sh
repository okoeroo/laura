#!/bin/bash

BATCH=$1
if [ -z "$BATCH" ]; then
    BATCH=200
fi

./laura-create-work.py --fb-apikey $(cat facebook-app.apikey)  --error-file error.list --couch-user okoeroo --couch-pw qwerty123 --batch-size $BATCH
