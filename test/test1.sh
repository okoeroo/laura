curl \
    -X POST \
    -H "Content-Type: application/json" \
    --data '{ "host": "oscar.koeroo.net", "port": "443", "sni": "oscar.koeroo.net" }' \
    http://localhost:5000/certificate \
