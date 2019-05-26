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
from wsgiref import simple_server


HTTPResponse = requests.packages.urllib3.response.HTTPResponse
orig_HTTPResponse__init__ = HTTPResponse.__init__
def new_HTTPResponse__init__(self, *args, **kwargs):
    orig_HTTPResponse__init__(self, *args, **kwargs)
    try:
        self.peer_certificate = self._connection.peer_certificate
    except AttributeError:
        pass
HTTPResponse.__init__ = new_HTTPResponse__init__

HTTPAdapter = requests.adapters.HTTPAdapter
orig_HTTPAdapter_build_response = HTTPAdapter.build_response
def new_HTTPAdapter_build_response(self, request, resp):
    response = orig_HTTPAdapter_build_response(self, request, resp)
    try:
        response.peer_certificate = resp.peer_certificate
    except AttributeError:
        pass
    return response
HTTPAdapter.build_response = new_HTTPAdapter_build_response

HTTPSConnection = requests.packages.urllib3.connection.HTTPSConnection
orig_HTTPSConnection_connect = HTTPSConnection.connect
def new_HTTPSConnection_connect(self):
    orig_HTTPSConnection_connect(self)
    try:
        self.peer_certificate = self.sock.connection.get_peer_certificate()
    except AttributeError:
        pass
HTTPSConnection.connect = new_HTTPSConnection_connect


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


def req_get_inner(schema, fqdn):
#    expire_after = timedelta(minutes=15)
#    requests_cache.install_cache('demo_cache1', expire_after=expire_after)

    results = {}
    results['schema'] = schema
    results['fqdn'] = fqdn
    results['base_url'] = results['schema'] + results['fqdn']

    try:
        requests.packages.urllib3.disable_warnings()
        r = requests.get(results['base_url'], allow_redirects=False, timeout=5, verify=False)
        results['status_code'] = r.status_code

        if schema == 'https://':
            try:
                # Extract the certificate
                j_cert = jsonify_certificate(r.peer_certificate)
                results['certificate'] = j_cert

            except Exception as e:
                print(e)

        if r.status_code >= 300 and r.status_code < 400:
            # Redirect found, let's see if it has a Location
            if 'Location' in r.headers.keys():
                results['location'] = r.headers['Location']

                # Recurse
                if results['location'].lower().startswith('http://'):
                    location_schema = 'http://'
                    location_url = results['location'].lower().split('http://', 1)[1]

                elif results['location'].lower().startswith('https://'):
                    location_schema = 'https://'
                    location_url = results['location'].lower().split('https://', 1)[1]

                results['recurse'] = req_get_inner(location_schema, location_url)
            else:
                print("No Location header found")
    except:
        pass

    return results

def tls_get_peer_certificate(host, port, sni):
    return req_get_inner('https://', host)


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

        j_result = tls_get_peer_certificate(j.get("host"), j.get("port"), j.get("sni"))
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
