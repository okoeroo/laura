#!/usr/bin/env python3

### System imports

import sys
import os
import argparse
import uuid
import pprint
from datetime import tzinfo, timedelta, datetime


#################
# Private imports
modpath = "".join([os.path.dirname(os.path.realpath(__file__)), "/", "modules"])
sys.path.append(modpath)

import oscarlib
#################


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
parser.add_argument("--error-file",     dest='error_file', help="List filled with domain names resulting in errors.", type=str)
parser.add_argument('--output-dir',     dest='output_dir', help="Output directory with JSON files", type=str)
parser.add_argument('--output-json',    dest='output_json', help="Output JSON", type=str)
parser.add_argument('--cert-api',       dest='cert_api', help="URL to the Certificate Hunter API. Example: http://localhost:5000/certificate", type=str)
parser.add_argument('--couch-url',      dest='couch_url', 
                                        help='CouchDB URL', 
                                        default='http://127.0.0.1:5984',
                                        type=str)
parser.add_argument('--couch-user',     dest='couch_user', help='CouchDB user', type=str)
parser.add_argument('--couch-pw',       dest='couch_pw', help='CouchDB password', type=str)
parser.add_argument('--batch-size',     dest='batch_size',
                                        help="Process the given amount at a time. (default: 10)",
                                        default=10,
                                        type=int)
args = parser.parse_args()


ctx = {}
ctx['couch_url']    = args.couch_url
ctx['couch_user']   = args.couch_user
ctx['couch_pw']     = args.couch_pw
ctx['error_file']   = args.error_file
ctx['batch_size']   = args.batch_size


def process_dns_work(ctx, batch_size):
    # 1. Fetch 'dns_work' from the couch
    # 2. Enrich the lists.
    # 3. Store it in 'dns_work'
    # 4. Update 'work' from 'todo' to 'done'

    # This UUID is the relation to this sub-hunt
    process_uuid = str(uuid.uuid4())

    # Fetching a work list
    docs = oscarlib.couchdb_get_docs(ctx,
                                     'laura_discovered_fqdn',
                                     'status',
                                     '$eq',
                                     'todo',
                                     limit=batch_size,
                                     skip=0)
    # Change status to processing
    for domain_doc in docs:
        print("=====")
        for fqdn in domain_doc['domainlist']:
            m = oscarlib.dns_resolve_all_r_type(fqdn)

            o = {}
            o['domain'] = domain_doc['_id']
            o['fqdn'] = fqdn
            o['rr'] = m
            oscarlib.couchdb_put_obj(ctx, 'laura_discovered_dns_rr', o)

    return
#
#
#        m = oscarlib.my_threading(oscarlib.dns_resolve_all_r_type, domain_doc['domainlist'])
#        results = m.get_results()
#        pprint.pprint(results, indent=4)
#
#        continue
#
#        pprint.pprint(domain_doc)
#
#    return
#        oscarlib.couchdb_update_docs(ctx,
#                                     'work',
#                                     'fqdn',
#                                     '$eq',
#                                     i['fqdn'],
#                                     'status',
#                                     process_uuid)
#
#    # Fetching a work list
#    docs = oscarlib.couchdb_get_docs(ctx,
#                                     'laura_loaded_research_domain',
#                                     'status',
#                                     '$eq',
#                                     process_uuid,
#                                     limit=100,
#                                     skip=0)
#    # Create list of FQDNs from the domain to hunt and store it on the Couch
#    for i in docs:
#        create_work_list_per_domain(ctx,
#                                    process_uuid,
#                                    i['fqdn'])
#    return

# Create all the stuff
process_dns_work(ctx, args.batch_size)

###### 
sys.exit(1)


total_results_list = []

for d in domains_to_search:
    try:
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

#    for i in list_per_domain:
#        print("--", i)

#    print()
#    print("Start DNS checks")
#
#    m = oscarlib.my_threading(oscarlib.dns_resolve_all_r_type, list_per_domain)
#    results = m.get_results()
#    pprint.pprint(results, indent=4)
#
#    total_results_list.extend(results)

