# Bootstrap

1. start-backend.sh
2. modules/refresh\_database.sh
3. modules/produce\_db.py

# Ready to run
./laura.py --fb-apikey $(cat facebook-app.apikey) --input list.txt.oscar --output-json output.json

# Requires
pip install dnspython ipwhois pyOpenSSL requests requests-cache netaddr

pip install gunicorn falcon

pip install python-dateutil 

pip install asn1crypto cert_human

