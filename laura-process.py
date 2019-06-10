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
args = parser.parse_args()


ctx = {}
ctx['couch_url']    = args.couch_url
ctx['couch_user']   = args.couch_user
ctx['couch_pw']     = args.couch_pw
ctx['error_file']   = args.error_file


def create_work_list_per_domain(ctx, process_uuid, domain):
    # List of domains
    list_per_domain = []

    # Initial load the search list with static information
    list_per_domain.append(domain)
    list_per_domain.append(oscarlib.get_wildcard_canary(domain))
    list_per_domain = list_per_domain + \
            oscarlib.load_static_domain_prefixes(domain)

    try:
        # Use the Facebook Developer API to search the Certificate Transparency lists
        fb_search_d_f_m_h_results = \
                oscarlib.ct_facebook_search_domain_for_more_hostnames(domain,
                                                                      False,
                                                                      ctx['fb_apikey'])
    except:
        on_fb_error(ctx, domain)
        return

    # Report on Error, probably overloading the API again
    if fb_search_d_f_m_h_results is None:
        on_fb_error(ctx, domain)
        return

    # Extend list with Facebook API results
    list_per_domain = list_per_domain + fb_search_d_f_m_h_results

    # Dedub the result
    list_per_domain = oscarlib.list_dedup(list_per_domain)

    # Create object for on the Couch
    work_list = {}
    work_list['_id'] = domain
    work_list['process_id'] = process_uuid
    work_list['process_datetime'] = datetime.now().isoformat()
    work_list['domainlist'] = list_per_domain

    # Store DNS work
    oscarlib.couchdb_put_obj(ctx, 'dns_work', work_list)

    print("Added info for {} as process UUID {}".format(domain, process_uuid))

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


def process_dns_work(ctx):
    # 1. Fetch 'work' from the couch, change status to processing
    # 2. Enrich the lists.
    # 3. Store it in 'dns_work'
    # 4. Update 'work' from 'todo' to 'done'

    # This UUID is the relation to this sub-hunt
    process_uuid = str(uuid.uuid4())

    # Fetching a work list
    docs = oscarlib.couchdb_get_docs(ctx,
                                     'dns_work',
                                     'status',
                                     '$eq',
                                     'todo',
                                     limit=10,
                                     skip=0)
    # Change status to processing
    for i in docs:
        pprint.pprint(i)

    return
#        oscarlib.couchdb_update_docs(ctx,
#                                     'work',
#                                     'fqdn',
#                                     '$eq',
#                                     i['fqdn'],
#                                     'status',
#                                     process_uuid)

    # Fetching a work list
    docs = oscarlib.couchdb_get_docs(ctx,
                                     'work',
                                     'status',
                                     '$eq',
                                     process_uuid,
                                     limit=100,
                                     skip=0)
    # Create list of FQDNs from the domain to hunt and store it on the Couch
    for i in docs:
        create_work_list_per_domain(ctx,
                                    process_uuid,
                                    i['fqdn'])
    return

# Create all the stuff
process_dns_work(ctx)
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

