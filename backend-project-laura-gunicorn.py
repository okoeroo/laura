#!/usr/bin/env python3

from datetime import tzinfo, timedelta, datetime
import subprocess, os, sys
import time
import json
import uuid
import falcon
import requests
import requests_cache
import dns.resolver
import OpenSSL
import ssl
import socket
from wsgiref import simple_server


def jsonify_certificate(cert):
    results = {}

    # Fetch Subject DN
    subject = ''
    for comp in cert.get_subject().get_components():
        if comp[0].decode('UTF-8') == 'CN':
            results['common_name'] = comp[1].decode('UTF-8')

        rdn = comp[0].decode('UTF-8') + "=" + comp[1].decode('UTF-8')
        if subject == '':
            subject = rdn
        else:
            subject = ",".join([subject, rdn])
    results['subject'] = subject

    # Fetch Issuer DN
    issuer = ''
    for comp in cert.get_issuer().get_components():
        rdn = comp[0].decode('UTF-8') + "=" + comp[1].decode('UTF-8')
        if issuer == '':
            issuer = rdn
        else:
            issuer = ",".join([issuer, rdn])
    results['issuer'] = issuer

    results['public_key'] = OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, \
                                cert.get_pubkey()).decode('UTF-8')

    results['serial'] = '{0:x}'.format(cert.get_serial_number())
    results['signature_algo'] = cert.get_signature_algorithm().decode('UTF-8')

    results['not_before_raw'] = cert.get_notBefore().decode('UTF-8')
    not_before_dt = datetime.strptime(cert.get_notBefore().decode('UTF-8')[:-1] + 'UTC', "%Y%m%d%H%M%S%Z")
    results['not_before_iso'] = not_before_dt.isoformat()

    results['not_after_raw']  = cert.get_notAfter().decode('UTF-8')
    not_after_dt = datetime.strptime(cert.get_notAfter().decode('UTF-8')[:-1] + 'UTC', "%Y%m%d%H%M%S%Z")
    results['not_after_iso'] = not_after_dt.isoformat()


    # Is the certificate valid?
    if datetime.now() < not_before_dt:
        results['cert_valid'] = 'not_yet_valid'
    elif datetime.now() > not_after_dt:
        results['cert_valid'] = 'expired'
    elif datetime.now() > not_before_dt and datetime.now() < not_after_dt:
        results['cert_valid'] = 'valid'
    else:
        results['cert_valid'] = 'something_seriously_wrong'

    for i in range(cert.get_extension_count()):
        ext = cert.get_extension(i)
        if ext.get_short_name().decode('UTF-8') == 'subjectAltName':
            #results['subject_alt_names_raw'] = str(ext)
            l = []
            for alt_name in str(ext).split(", "):
                alt_name_k_v = {}
                alt_name_k_v[alt_name.split(":")[0]] = alt_name.split(":")[1]
                l.append(alt_name_k_v)
            results['subject_alt_names'] = l

    return results

def test_ssl_connect(host_addr, port, server_name):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(4)

    # PROTOCOL_TLS_CLIENT requires valid cert chain and hostname
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.load_verify_locations('modules/cabundle.pem')

    conn = context.wrap_socket(sock, server_hostname=server_name)
    try:
        conn.connect((host_addr, port))
    except Exception as e:
        print(e)
        pass

    tls = {}
    tls['tls_version'] = conn.version()
    tls['encryption'] = { 'cipher_suite': conn.cipher()[0], 'security_bits': conn.cipher()[2] }

    # When the verification fails, no parsed certificate is returned. But a raw
    # DER output is possible, which can be converted to PEM and parsed further
    cert_bin = conn.getpeercert(True)
    pem_cert = ssl.DER_cert_to_PEM_cert(conn.getpeercert(True))
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem_cert)

    j_cert = jsonify_certificate(x509)

    tls['certificate']  = j_cert
    return tls


def tls_get_peer_certificate(host, port, sni):
    return test_ssl_connect(host, port, sni)


class CertificateAPI:
    def on_get(self, req, res):
        res.status = falcon.HTTP_200
        res.body = "Certificate hunter is Ready"

    def on_post(self, req, res):
        j = req.media
        print(j)

        if j.get("host") is None:
            res.body = 'Error: no host provided'
            res.status = falcon.HTTP_400
            return

        if j.get("port") is None:
            res.body = 'Error: no host provided'
            res.status = falcon.HTTP_400
            return

        if j.get("sni") is None:
            res.body = 'Error: no host provided'
            res.status = falcon.HTTP_400
            return

        if j.get("test") is not None:
            # Benchmark only
            res.body = 'done'
            res.status = falcon.HTTP_201
            return

        if isinstance(j.get("port"), str):
            port = int(j.get("port"))
        elif isinstance(j.get("port"), int):
            port = j.get("port")
        else:
            res.body = 'error: port number not parseable'
            res.status = falcon.HTTP_400
            return

        j_result = tls_get_peer_certificate(j.get("host"), port, j.get("sni"))
        if j_result is None:
            res.status = falcon.HTTP_500
        else:
            res.body = json.dumps(j_result)
            res.status = falcon.HTTP_200

# Init
PATH = os.path.dirname(os.path.realpath(__file__)) + '/'

#### Start
api = falcon.API()
api.add_route('/certificate', CertificateAPI())
print("Loaded route: '/certificate'")
####

print("Ready.")

### Main
if __name__ == "__main__":
    httpd = simple_server.make_server("127.0.0.1", 5000, api)
    bind_complete = True

    httpd.daemon_threads = True
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("Service stopped by user.")
        pass

