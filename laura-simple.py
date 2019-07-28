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

# Parser
parser = argparse.ArgumentParser("laura-load.py")
parser.add_argument("--input",          dest='input', 
                                        help="Input list", 
                                        type=str)
parser.add_argument("--output",         dest='output', 
                                        help="Output list", 
                                        type=str)
parser.add_argument("--error-file",     dest='error_file', help="List filled with domain names resulting in errors.", type=str)
args = parser.parse_args()

if not args.input:
    print("No input")
    sys.exit(1)

if not args.output:
    print("No output")
    sys.exit(1)

ctx = {}
ctx['input_file']  = args.input
ctx['output_file'] = args.output


# Lock and load the input for processing
domains_to_search_as_a_of_dict = oscarlib.load_file_into_array_of_dict(args.input)

# Hot fix
for i in domains_to_search_as_a_of_dict:
    i['_id'] = i['fqdn']

    # Purify input - valid names only
    if not oscarlib.is_valid_hostname(i['fqdn']):
        print("Error: \"{}\" is not a valid hostname to hunt".format(i['fqdn']))
        continue

cnt = 0

# Load all data into CouchDB
print("Loading work in memory...")
for i in domains_to_search_as_a_of_dict:
#    cnt += 1
#    if cnt > 500:
#        break


    print(i['fqdn'])
    r = oscarlib.dns_resolve_r_type(i['fqdn'], 'NS')
    i['error'] = r['error']

    # Have NS
    if r['error'] == 'NOERROR':
        i['first_NS'] = r['rrset'][0]['value']

        # Check for A for base
        r_A_base = oscarlib.dns_resolve_r_type(i['fqdn'], 'A')
        if r_A_base['error'] == 'NOERROR':
            i['first_A_base'] = r_A_base['rrset'][0]['value']

            # Check TCP
            tcp_probe = oscarlib.tcp_probe_range(i['first_A_base'])
            i['first_A_base_tcp_probe'] = tcp_probe
            print(tcp_probe)

            if tcp_probe['80'] == True:
                r = oscarlib.http_probe('http://' + i['fqdn'])
                s = oscarlib.http_probe_extract_recursions(r)

                i['first_A_base_http_probe']           = r
                i['first_A_base_http_probe_endpoint']  = 'http://' + i['fqdn']
                i['first_A_base_http_probe_recursion'] = s

            if tcp_probe['443'] == True:
                r = oscarlib.https_probe('https://' + i['fqdn'])
                s = oscarlib.https_probe_extract_recursions(r)

                i['first_A_base_https_probe']           = r
                i['first_A_base_https_probe_endpoint']  = 'https://' + i['fqdn']
                i['first_A_base_https_probe_recursion'] = s

        # Check for A for www.base
        r_A_www_base = oscarlib.dns_resolve_r_type('www.' + i['fqdn'], 'A')
        if r_A_www_base['error'] == 'NOERROR':
            i['first_A_www_base'] = r_A_www_base['rrset'][0]['value']

            # Check TCP
            tcp_probe = oscarlib.tcp_probe_range(i['first_A_www_base'])
            i['first_A_www_base_tcp_probe'] = tcp_probe

            if tcp_probe['80'] == True:
                r = oscarlib.http_probe('http://www.' + i['fqdn'])
                s = oscarlib.http_probe_extract_recursions(r)

                i['first_A_www_base_http_probe']           = r
                i['first_A_www_base_http_probe_endpoint']  = 'http://www.' + i['fqdn']
                i['first_A_www_base_http_probe_recursion'] = s

            if tcp_probe['443'] == True:
                r = oscarlib.https_probe('https://www.' + i['fqdn'])
                s = oscarlib.https_probe_extract_recursions(r)

                i['first_A_www_base_https_probe']           = r
                i['first_A_www_base_https_probe_endpoint']  = 'https://www.' + i['fqdn']
                i['first_A_www_base_https_probe_recursion'] = s

        # Check for MX
        r_MX_base = oscarlib.dns_resolve_r_type(i['fqdn'], 'MX')
        if r_MX_base['error'] == 'NOERROR':
            i['first_MX_host'] = r_MX_base['rrset'][0]['mx_host']

            # Check TCP
            rr_mx_host = oscarlib.dns_resolve_r_type(i['first_MX_host'], 'A')
            if rr_mx_host['error'] == 'NOERROR':
                tcp_probe = oscarlib.tcp_probe_range(rr_mx_host['rrset'][0]['value'])
                i['first_MX_host_tcp_probe'] = tcp_probe



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

