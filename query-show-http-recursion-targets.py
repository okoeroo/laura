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
import argparse
from pprint import pprint


PATH = os.path.dirname(os.path.realpath(__file__)) + '/'


def http_recurse(htp):
    if not 'fqdn' in htp:
        if htp == "Maximum recursion reached":
            print("\"Maximum recursion reached\"", end='')
        return

    print(htp['fqdn'], end='')
    if 'recurse' in htp:
        print(" -> ", end='')
        h = htp['recurse']
        http_recurse(h)


### Main
if __name__ == "__main__":
    parser = argparse.ArgumentParser("query.py")
    parser.add_argument("--input",       dest='input', help="Input list", type=str)
    args = parser.parse_args()


    if not args.input:
        print("No input")
        sys.exit(1)

    raw = open(args.input, 'r').read()
    j_data = json.loads(raw)

    #pprint(j_data)

    for j_finding in j_data:
        if j_finding['rdtype'] != 'A':
            continue

        for rrset_item in j_finding['rrset']:
            if 'http' in rrset_item['connection']:
                h = rrset_item['connection']['http']

            elif 'https' in rrset_item['connection']:
                h = rrset_item['connection']['https']

            else:
                # HTTP stuff? GTFO
                continue

            # Recurse
            http_recurse(h)
            print("")

