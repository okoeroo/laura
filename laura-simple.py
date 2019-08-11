#!/usr/bin/env python3

### System imports

import sys
import os
import argparse
import csv


#################
# Private imports
modpath = "".join([os.path.dirname(os.path.realpath(__file__)), "/", "modules"])
sys.path.append(modpath)

import oscarlib
#################


#u = "12move.nl"
#r = oscarlib.http_probe(u)
#s = oscarlib.http_probe_extract_recursions(r)
#print(s)
#sys.exit(1)


##### MAIN #####
def write_line_to_file(filename, msg):
    with open(filename, 'a+') as f:
        f.write(msg)
        f.write('\n')
        f.flush()

oscarlib.set_cert_api("http://localhost:5000/certificate")

# Parser
parser = argparse.ArgumentParser("laura-load.py")
parser.add_argument("--input",          dest='input_file', 
                                        help="Input, expecting a CSV file", 
                                        type=str)
parser.add_argument("--input-column",   dest='input_col',
                                        help="Input column, default is 0", 
                                        default=0,
                                        type=int)
parser.add_argument("--input-delimeter",dest='input_del',
                                        help="Input delimeter, default is ;", 
                                        default=';',
                                        type=str)
parser.add_argument("--input-quotechar",dest='input_quote',
                                        help="Input quote character, default is \"", 
                                        default='"',
                                        type=str)

parser.add_argument("--output",         dest='output', 
                                        help="Output list", 
                                        type=str)
parser.add_argument("--error-file",     dest='error_file', help="List filled with domain names resulting in errors.", type=str)
args = parser.parse_args()

if not args.input_file:
    print("No input")
    sys.exit(1)

if not args.output:
    print("No output")
    sys.exit(1)

ctx = {}
ctx['input_file']  = args.input_file
ctx['input_col']   = args.input_col
ctx['input_del']   = args.input_del
ctx['input_quote'] = args.input_quote
ctx['output_file'] = args.output



# Load CSV file and list the column into ctx['input_csv_selection']
oscarlib.load_csv_file(ctx)

# Setup administration - make array of dict
ctx['work'] = []
for line in ctx['input_csv_selection']:
    item = {}
    item['domain'] = line.strip()
    ctx['work'].append(item)

# Purify input - valid names only
for work_item in ctx['work']:
    if not oscarlib.is_valid_hostname(work_item['domain']):
        print("Error: \"{}\" is not a valid hostname to hunt".format(work_item['domain']))
        ctx['work'].remove(work_item)
        continue

# Check if SOA records exists, and if so the NS records
for work_item in ctx['work']:
    # Record DNS stuff
    work_item['DNS'] = {}

    work_item['DNS']['SOA'] = oscarlib.dns_resolve_r_type(work_item['domain'], 'SOA')
    print(work_item['domain'], 'SOA', work_item['DNS']['SOA']['error'])

    # Got an error?
    if work_item['DNS']['SOA']['error'] == 'NOERROR':
        work_item['DNS']['NS'] = oscarlib.dns_resolve_r_type(work_item['domain'], 'NS')
        print(work_item['domain'], 'NS', work_item['DNS']['NS']['error'])

        # Got an error?
        if work_item['DNS']['NS']['error'] == 'NOERROR':
            # Fetch A
            work_item['DNS']['A']    = oscarlib.dns_resolve_r_type(work_item['domain'], 'A')
            print(work_item['domain'], 'A', work_item['DNS']['A']['error'])

            # Fetch AAAA
            work_item['DNS']['AAAA'] = oscarlib.dns_resolve_r_type(work_item['domain'], 'AAAA')
            print(work_item['domain'], 'AAAA', work_item['DNS']['AAAA']['error'])

            # Fetch MX
            work_item['DNS']['MX'] = oscarlib.dns_resolve_r_type(work_item['domain'], 'MX')
            print(work_item['domain'], 'MX', work_item['DNS']['MX']['error'])

            # Fetch TXT
            work_item['DNS']['TXT']    = oscarlib.dns_resolve_r_type(work_item['domain'], 'TXT')
            print(work_item['domain'], 'TXT', work_item['DNS']['TXT']['error'])

            # Check if there is an MX record
            if work_item['DNS']['MX']['error'] == 'NOERROR':
                # Walk rrset and resolve an A and AAAA for the MX host
                for rr_set_item in work_item['DNS']['MX']['rrset']:
                    rr_set_item['mx_host_resolve_A']    = oscarlib.dns_resolve_r_type(rr_set_item['mx_host'], 'A')
                    print(work_item['domain'], 'MX', "=>", rr_set_item['mx_host'], "=>", rr_set_item['mx_host_resolve_A']['error'])
                    ### Can't work with IPv6
                    # rr_set_item['mx_host_resolve_AAAA'] = oscarlib.dns_resolve_r_type(rr_set_item['mx_host'], 'AAAA')


            # Check TCP connectivity on A
            if work_item['DNS']['A']['error'] == 'NOERROR':
                for rr_set_item in work_item['DNS']['A']['rrset']:
                    print(work_item['domain'], rr_set_item['value'])

                    # TCP probe, after check on cache
                    rr_set_item['tcp_probe'] = oscarlib.tcp_probe_range(rr_set_item['value'], [80, 443, 25])

                    # Results from A check on tcp_probe, next is port 80 and 443 walks...
                    print(work_item['domain'], "=>", 'A', "=>", rr_set_item['value'], "=>", rr_set_item['tcp_probe'])

                    # Probe for HTTP
                    if rr_set_item['tcp_probe']['80'] == True:
                        rr_set_item['http_probe'] = {}

                        base_A_endpoint = 'http://' + work_item['domain']
                        r = oscarlib.http_probe(base_A_endpoint)
                        s = oscarlib.http_probe_extract_recursions(r)

                        rr_set_item['http_probe']['base_A_endpoint'] = base_A_endpoint
                        rr_set_item['http_probe']['base_A_result'] = r
                        rr_set_item['http_probe']['base_A_recursion'] = s

                        print(base_A_endpoint, "->", s)

                    # Probe for HTTPS
                    if rr_set_item['tcp_probe']['443'] == True:
                        rr_set_item['https_probe'] = {}

                        base_A_endpoint = 'https://' + work_item['domain']
                        r = oscarlib.http_probe(base_A_endpoint)
                        s = oscarlib.http_probe_extract_recursions(r)

                        rr_set_item['https_probe']['base_A_endpoint'] = base_A_endpoint
                        rr_set_item['https_probe']['base_A_result'] = r
                        rr_set_item['https_probe']['base_A_recursion'] = s

                        print(base_A_endpoint, "->", s)


            # Check TCP connectivity on MX
            if work_item['DNS']['MX']['error'] == 'NOERROR':
                for rr_set_item in work_item['DNS']['MX']['rrset']:
                    if rr_set_item['mx_host_resolve_A']['error'] == 'NOERROR':
                        for rr_set_item_inner_mx_host in rr_set_item['mx_host_resolve_A']['rrset']:
                            print(work_item['domain'], "MX", rr_set_item['value'], "MX => A", rr_set_item_inner_mx_host['value'])

                            # TCP probe, after check on cache
                            rr_set_item_inner_mx_host['tcp_probe'] = oscarlib.tcp_probe_range(rr_set_item_inner_mx_host['value'], [80, 443, 25])

                            # Results from MX's A's check on tcp_probe, next is port 80 and 443 walks...
                            print(work_item['domain'], "MX", rr_set_item['value'], "MX => A", rr_set_item_inner_mx_host['value'], "=>", rr_set_item_inner_mx_host['tcp_probe'])


import json
with open('data.json', 'w', encoding='utf-8') as f:
    json.dump(ctx, f, ensure_ascii=False, indent=4)

#WHOIS


sys.exit(0)




### Write output
csv_file = open(ctx['output_file'], mode='w')

fieldnames = ['fqdn', 'error', 'first_NS', 'first_A_base', 'first_A_base_tcp_probe', 'first_A_www_base', 'first_A_www_base_tcp_probe', 'first_MX_base', 'first_MX_base_tcp_probe']
csv_writer = csv.writer(csv_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
#csv_writer = csv.DictWriter(csv_file, fieldnames=fieldnames)

# Write header
csv_writer.writerow(fieldnames)

for i in domains_to_search_as_a_of_dict:
    if 'error' not in i:
        continue

    l = []
    l.append(i['fqdn'])
    l.append(i['error'])

    if 'first_NS' in i:
        l.append(i['first_NS'])
    else:
        l.append("")

    if 'first_A_base' in i:
        l.append(i['first_A_base'])
    else:
        l.append("")

    if 'first_A_base_tcp_probe' in i:
        l.append(i['first_A_base_tcp_probe'])
    else:
        l.append("")

    if 'first_A_www_base' in i:
        l.append(i['first_A_www_base'])
    else:
        l.append("")

    if 'first_A_www_base_tcp_probe' in i:
        l.append(i['first_A_www_base_tcp_probe'])
    else:
        l.append("")

    if 'first_MX_base' in i:
        l.append(i['first_MX_base'])
    else:
        l.append("")

    if 'first_MX_base_tcp_probe' in i:
        l.append(i['first_MX_base_tcp_probe'])
    else:
        l.append("")


    csv_writer.writerow(l)


print("Done.")

