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
import csv


PATH = os.path.dirname(os.path.realpath(__file__)) + '/'


def http_recurse(htp, context):
    if not 'fqdn' in htp:
        return

    if 'tls' in htp:
        if 'certificate' in htp['tls']:
            if htp['tls']['certificate']['cert_valid'] != 'valid':
                if 'csv_writer' not in context:
                    print("-> Not valid at FQDN: ", htp['fqdn'])
                    print(" -> ", htp['tls']['certificate']['subject'])
                    print(" -> ", htp['tls']['certificate']['issuer'])
                    print(" -> ", htp['tls']['certificate']['not_before_iso'])
                    print(" -> ", htp['tls']['certificate']['not_after_iso'])
                    print(" -> ", htp['tls']['certificate']['serial'])
                    print(" -> ", htp['tls']['certificate']['signature_algo'])
                    print(" -> ", htp['tls']['certificate']['common_name'])
                    if 'subject_alt_names' in htp['tls']['certificate']:
                        print(" -> ", htp['tls']['certificate']['subject_alt_names'])
                    else:
                        print("====== No SANs ======")
                else:
                    # Write as CSV file row
                    if 'subject_alt_names' in htp['tls']['certificate']:
                        context['csv_writer'].writerow([htp['tls']['certificate']['subject'],
                                                        htp['tls']['certificate']['issuer'],
                                                        htp['tls']['certificate']['not_before_iso'],
                                                        htp['tls']['certificate']['not_after_iso'],
                                                        htp['tls']['certificate']['serial'],
                                                        htp['tls']['certificate']['signature_algo'],
                                                        htp['tls']['certificate']['common_name'],
                                                        htp['tls']['certificate']['subject_alt_names']])
                    else:
                        context['csv_writer'].writerow([htp['tls']['certificate']['subject'],
                                                        htp['tls']['certificate']['issuer'],
                                                        htp['tls']['certificate']['not_before_iso'],
                                                        htp['tls']['certificate']['not_after_iso'],
                                                        htp['tls']['certificate']['serial'],
                                                        htp['tls']['certificate']['signature_algo'],
                                                        htp['tls']['certificate']['common_name'],
                                                        "-no SANs-"])


    if 'recurse' in htp:
        h = htp['recurse']
        http_recurse(h, context)


### Main
if __name__ == "__main__":
    parser = argparse.ArgumentParser("query.py")
    parser.add_argument("--input",
                        dest='input',
                        help="Input list",
                        type=str)
    parser.add_argument("--csv",
                        dest='csv_output',
                        help="CSV format output file",
                        type=str)
    parser.add_argument("--include-expired",
                        dest='include_expired',
                        help="Should CSV format output file",
                        choices=['yes', 'no'],
                        default='no',
                        type=str)
    parser.add_argument("--months-prior-to-expiration",
                        dest='months_prior',
                        help="How many months prio to expiration of the " \
                             "certificate should it be included in the list. ",
                        default='1',
                        type=str)
    args = parser.parse_args()

    # Config and other stuff is consolidated in the context
    context = {}
    context['include_expired']  = args.include_expired
    context['months_prior']     = args.months_prior


    if not args.input:
        print("No input")
        sys.exit(1)

    raw = open(args.input, 'r').read()
    j_data = json.loads(raw)


    if args.csv_output:
        csv_file = open(args.csv_output, mode='w')
        csv_writer = csv.writer(csv_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)

        # Store CSV writer
        context['csv_writer'] = csv_writer

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
            http_recurse(h, context)

    # Close it
    if args.csv_output:
        csv_file.close()

    csv_file = open(args.csv_output, mode='r')
    csv_reader = csv.reader(csv_file)
    cnt = 0
    for row in csv_reader:
        cnt += 1

    print("{} certificate(s) found to be expired.".format(cnt))
