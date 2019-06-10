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
ctx['fb_apikey']    = args.fb_apikey
ctx['cs_apikey']    = args.cs_apikey
ctx['error_file']   = args.error_file
ctx['batch_size']   = args.batch_size


#if not args.cert_api:
#    print("Using default certificate API backend")
#    oscarlib.set_cert_api("http://localhost:5000/certificate")
#else:
#    print("Using \"{}\" as certificate API backend".format(args.cert_api))
#    oscarlib.set_cert_api(args.cert_api)

def on_fb_error(ctx, domain):
    print("Error: can't process {}".format(domain))
    # Write to error file, when such destination is set
    if 'error_file' in ctx:
        write_line_to_file(ctx['error_file'], domain)

def create_work_list_per_domain(ctx, process_uuid, domain):
    # List of domains
    list_per_domain = []

    # Initial load the search list with static information
    list_per_domain.append(domain)
    list_per_domain.append(oscarlib.get_wildcard_canary(domain))
    list_per_domain = list_per_domain + \
            oscarlib.load_static_domain_prefixes(domain)

    # Use the Facebook Developer API to search the Certificate Transparency lists
    try:
        fb_search_d_f_m_h_results = \
                oscarlib.ct_facebook_search_domain_for_more_hostnames(domain,
                                                                      False,
                                                                      ctx['fb_apikey'])
    except:
        pass
        on_fb_error(ctx, domain)

    # Report on Error, probably overloading the API again
    if fb_search_d_f_m_h_results is None:
        on_fb_error(ctx, domain)
        return False

    # Extend list with Facebook API results
    list_per_domain = list_per_domain + fb_search_d_f_m_h_results

    # Dedub the result
    list_per_domain = oscarlib.list_dedup(list_per_domain)

    # Create object for on the Couch
    work_list = {}
    work_list['_id']                = domain
    work_list['process_id']         = process_uuid
    work_list['process_datetime']   = datetime.now().isoformat()
    work_list['status']             = 'todo'
    work_list['domainlist']         = list_per_domain

    # Store DNS work
    oscarlib.couchdb_put_obj(ctx, 'dns_work', work_list)

    print("Added info for {} as process UUID {}".format(domain, process_uuid))
    return True


def create_dns_work(ctx, limit):
    # 1. Fetch 'work' from the couch, change status to processing
    # 2. Enrich the lists.
    # 3. Store it in 'dns_work'
    # 4. Update 'work' from 'todo' to 'done'

    # This UUID is the relation to this sub-hunt
    process_uuid = str(uuid.uuid4())

    # Fetching a work list
    docs = oscarlib.couchdb_get_docs(ctx,
                                     'work',
                                     'status',
                                     '$eq',
                                     'todo',
                                     limit=limit,
                                     skip=0)
    # Change status to processing
    for i in docs:
        print(i['fqdn'])
        oscarlib.couchdb_update_docs(ctx,
                                     'work',
                                     'fqdn',
                                     '$eq',
                                     i['fqdn'],
                                     'status',
                                     process_uuid)

    # Fetching a work list
    docs = oscarlib.couchdb_get_docs(ctx,
                                     'work',
                                     'status',
                                     '$eq',
                                     process_uuid,
                                     limit=limit,
                                     skip=0)
    # Create list of FQDNs from the domain to hunt and store it on the Couch
    for i in docs:
        create_work_list_per_domain(ctx,
                                    process_uuid,
                                    i['fqdn'])
    return

# Create all the stuff
create_dns_work(ctx, args.batch_size)
