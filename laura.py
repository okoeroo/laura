#!/usr/bin/env python3

### System imports

import sys
import os
import argparse


#################
# Private imports
modpath = "".join([os.path.dirname(os.path.realpath(__file__)), "/", "modules"])
sys.path.append(modpath)

import oscarlib
#################


import pprint

#################
# Private imports
modpath = "".join([os.path.dirname(os.path.realpath(__file__)), "/", "modules"])
sys.path.append(modpath)

import oscarlib
#################


##### MAIN #####
import argparse



def write_line_to_file(filename, msg):
    with open(filename, 'a+') as f:
        f.write(msg)
        f.write('\n')
        f.flush()


# Parser
parser = argparse.ArgumentParser("laura.py")
parser.add_argument("--cs-apikey",      dest='cs_apikey',
                                        help="CertSpotter API Key",
                                        default=None,
                                        type=str)
parser.add_argument("--fb-apikey",      dest='fb_apikey',
                                        help="Facebook App API Key",
                                        default=None,
                                        type=str)
parser.add_argument("--input",          dest='input', 
                                        help="Input list", 
                                        type=str)
parser.add_argument("--error-file",     dest='error_file', help="List filled with domain names resulting in errors.", type=str)
parser.add_argument('--output-dir',     dest='output_dir', help="Output directory with JSON files", type=str)
parser.add_argument('--output-json',    dest='output_json', help="Output JSON", type=str)
parser.add_argument('--cert-api',       dest='cert_api', help="URL to the Certificate Hunter API. Example: http://localhost:5000/certificate", type=str)
parser.add_argument('--couch-url',      dest='couch_url', 
                                        help='CouchDB URL', 
                                        default='http://127.0.0.1:5984',
                                        type=str)
parser.add_argument('--couch-db',       dest='couch_db', help='CouchDB database', type=str)
parser.add_argument('--couch-user',     dest='couch_user', help='CouchDB user', type=str)
parser.add_argument('--couch-pw',       dest='couch_pw', help='CouchDB password', type=str)
args = parser.parse_args()

if not args.input:
    print("No input")
    sys.exit(1)

ctx = {}
ctx['couch_url']  = args.couch_url
ctx['couch_user'] = args.couch_user
ctx['couch_pw']   = args.couch_pw
ctx['fb_apikey']  = args.fb_apikey
ctx['cs_apikey']  = args.cs_apikey
ctx['cert_api']   = args.cert_api


if not args.cert_api:
    print("Using default certificate API backend")
    oscarlib.set_cert_api("http://localhost:5000/certificate")
else:
    print("Using \"{}\" as certificate API backend".format(args.cert_api))
    oscarlib.set_cert_api(args.cert_api)


def create_dns_work():
    # 1. Fetch 'work' from the couch.
    # 2. Enrich the lists.
    # 3. Store it in 'dns_work'
    # 4. Update 'work' from 'todo' to 'done'

    oscarlib.couchdb_get_docs(ctx,
                              'work',
                              'status',
                              '$eq',
                              'todo')


total_results_list = []

for d in domains_to_search:
    try:
        list_per_domain = []
        list_per_domain.append(d)
        list_per_domain.append(oscarlib.get_wildcard_canary(d))
        list_per_domain = list_per_domain + \
                          oscarlib.load_static_domain_prefixes(d)
        fb_search_d_f_m_h_results = oscarlib.ct_facebook_search_domain_for_more_hostnames(d, False, args.fb_apikey)
        if fb_search_d_f_m_h_results is None:
            print("Error: can't process {}".format(d))
            # Write to error file, when such destination is set
            if args.error_file is not None:
                write_line_to_file(args.error_file, d)
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
    except:
        # Write to error file, when such destination is set
        if args.error_file is not None:
            write_line_to_file(args.error_file, d)
        pass
    finally:
        # Write this result down
        if args.output_dir is not None:
            with open(args.output_dir + '/' + d + '.json', 'w') as outfile:
                json.dump(results, outfile, indent=4)

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




