#!/usr/bin/env python3

### System imports

import dns.resolver
from datetime import tzinfo, timedelta, datetime
import time
import uuid
import sys
import os
import threading
import ipaddress
from multiprocessing import Process, Queue, JoinableQueue
import warnings
from ipwhois.net import Net
from ipwhois.asn import IPASN
from pprint import pprint
import re
import sqlite3
from urllib.request import urlopen
import requests
import requests_cache
import json

import pprint


### Private imports
modpath = "".join([os.path.dirname(os.path.realpath(__file__)), "/", "modules"])
sys.path.append(modpath)

import oscarlib

####################
def req_get_inner(schema, fqdn_rec):
#    expire_after = timedelta(minutes=15)
#    requests_cache.install_cache('demo_cache1', expire_after=expire_after)

    base_url = schema + fqdn_rec['fqdn']
    try:
        r = requests.get(base_url, allow_redirects=False, timeout=2)
        if r.status_code >= 300 and r.status_code < 400:
            if 'Location' in r.headers.keys():
                u = w.add_redirect(schema, fqdn_rec['fqdn'], r.headers['Location'])
                w.add_fqdn2redirect(fqdn_rec['uuid'], u)
                print("Location found:",
                      schema + fqdn_rec['fqdn'],
                      r.headers['Location'],
                      file=sys.stderr)
                return True
    except:
        pass

    return False


def req_get(fqdn_rec):
    print(fqdn_rec)
    req_get_inner('http://', fqdn_rec)
    req_get_inner('https://', fqdn_rec)
####################





##### MAIN #####
import argparse


# Init
PATH = os.path.dirname(os.path.realpath(__file__)) + '/'

# Parser
parser = argparse.ArgumentParser("laura.py")
parser.add_argument("--cs-apikey",   dest='cs_apikey', help="CertSpotter API Key", type=str)
parser.add_argument("--fb-apikey",   dest='fb_apikey', help="Facebook App API Key", type=str)
parser.add_argument("--input",       dest='input', help="Input list", type=str)
parser.add_argument('--output-json', dest='output_json', help="Output JSON", type=str)
args = parser.parse_args()

if not args.input:
    print("No input")
    sys.exit(1)



## Initialize ASN database
#asn_lookup = oscarlib.ASNLookUp()
#print(asn_lookup.asn_origin('AS1104'))
#print("----------")
#print(asn_lookup.asn_origin('1104'))
#print("----------")
#print(asn_lookup.asn_origin(1104))
#print("----------")
#print(asn_lookup.asn_get('164.132.194.210'))
#print(oscarlib.ASNLookUp().asn_get('164.132.194.210'))
#
#print(oscarlib.ASNLookUp().asn_origin(1136))
#
#sys.exit(1)

#r = oscarlib.get_asn_origin('AS286')
#pprint.pprint(r, indent=4)
#sys.exit(1)

#print(oscarlib.tcp_test_range('164.132.194.210'))
#sys.exit(1)

domains_to_search = oscarlib.load_file_into_array(args.input)

print("Scan started for:")
print("=========")

total_results_list = []

for d in domains_to_search:
    list_per_domain = []
    list_per_domain.append(d)
    list_per_domain.append(oscarlib.get_wildcard_canary(d))
    list_per_domain = list_per_domain + \
                      oscarlib.load_static_domain_prefixes(d)
    list_per_domain = list_per_domain + \
                      oscarlib.ct_facebook_search_domain_for_more_hostnames(d, False, args.fb_apikey)

    list_per_domain = oscarlib.list_dedup(list_per_domain)
    print(list_per_domain)
    print()
    print("Start DNS checks")

    m = oscarlib.my_threading(oscarlib.dns_resolve_all_r_type, list_per_domain)
    results = m.get_results()
    pprint.pprint(results, indent=4)

    total_results_list.extend(results)


print()
print("=============================================")
print("=============================================")
print()


# Write output
if args.output_json is not None:
    with open(args.output_json, 'w') as outfile:
        json.dump(total_results_list, outfile, indent=4)



# Total results, integrated
pprint.pprint(total_results_list, indent=4)

#    pl = oscarlib.Parallelism()
#    pl.add(oscarlib.dns_resolve_all_r_type, list_per_domain)
#    pl.run()
#    data = pl.get_results()
#    results_per_domain = list(data)
#
#    pprint.pprint(results_per_domain, indent=4)
#    print("=========")

#    results_per_domain = []
#    for i in list_per_domain:
#        print(i)
#        r = oscarlib.dns_resolve_all_r_type(i)
#        results_per_domain = results_per_domain + r
#        print(r)
#        print("------")


#    print(results_per_domain)
#    pprint.pprint(results_per_domain, indent=4)
#    print("=========")

print()




