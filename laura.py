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

#################
# Private imports
modpath = "".join([os.path.dirname(os.path.realpath(__file__)), "/", "modules"])
sys.path.append(modpath)

import oscarlib
#################


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
parser.add_argument('--cert-api',    dest='cert_api', help="URL to the Certificate Hunter API. Example: http://localhost:5000/certificate", type=str)
args = parser.parse_args()

if not args.input:
    print("No input")
    sys.exit(1)



#pprint.pprint(oscarlib.req_get_inner('https://', "oscar.koeroo.net"))
#pprint.pprint(oscarlib.req_get_inner('https://', "www.kpn.com"))
#pprint.pprint(oscarlib.req_get_inner('https://', "expired.badssl.com"))
#sys.exit(0)

if not args.cert_api:
    print("Using default certificate API backend")
    oscarlib.set_cert_api("http://localhost:5000/certificate")
else:
    print("Using \"{}\" as certificate API backend".format(args.cert_api))
    oscarlib.set_cert_api(args.cert_api)


# Lock and load the input for processing
domains_to_search = oscarlib.load_file_into_array(args.input, emptylines=False)

print("Scan started for:")
print("=========")

pprint.pprint(domains_to_search)

total_results_list = []

for d in domains_to_search:
    # Is this a proper domain?
    if not oscarlib.is_valid_hostname(d):
        continue

    list_per_domain = []
    list_per_domain.append(d)
    list_per_domain.append(oscarlib.get_wildcard_canary(d))
    list_per_domain = list_per_domain + \
                      oscarlib.load_static_domain_prefixes(d)
    fb_search_d_f_m_h_results = oscarlib.ct_facebook_search_domain_for_more_hostnames(d, False, args.fb_apikey)
    if fb_search_d_f_m_h_results is None:
        print("Error: can't process {}".format(d))
        continue

    list_per_domain = list_per_domain + fb_search_d_f_m_h_results

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




