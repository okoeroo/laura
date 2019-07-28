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
#    if cnt > 100:
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

        # Check for A for www.base
        r_A_www_base = oscarlib.dns_resolve_r_type('www.' + i['fqdn'], 'A')
        if r_A_www_base['error'] == 'NOERROR':
            i['first_A_www_base'] = r_A_www_base['rrset'][0]['value']

        # Check for MX
        r_MX_base = oscarlib.dns_resolve_r_type(i['fqdn'], 'MX')
        if r_MX_base['error'] == 'NOERROR':
            i['first_MX_host'] = r_MX_base['rrset'][0]['mx_host']


### Write output
csv_file = open(ctx['output_file'], mode='w')

fieldnames = ['fqdn', 'error', 'first_NS', 'first_A_base', 'first_A_www_base', 'first_MX_base']
csv_writer = csv.writer(csv_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
#csv_writer = csv.DictWriter(csv_file, fieldnames=fieldnames)

# Write header
csv_writer.writerow('fqdn', 'error', 'first_NS', 'first_A_base', 'first_A_www_base', 'first_MX_base')

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

    if 'first_A_www_base' in i:
        l.append(i['first_A_www_base'])
    else:
        l.append("")

    if 'first_MX_base' in i:
        l.append(i['first_MX_base'])
    else:
        l.append("")

    csv_writer.writerow(l)


print("Done.")

