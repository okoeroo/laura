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
parser.add_argument("--error-file",     dest='error_file', help="List filled with domain names resulting in errors.", type=str)
parser.add_argument('--couch-url',      dest='couch_url', 
                                        help='CouchDB URL', 
                                        default='http://127.0.0.1:5984',
                                        type=str)
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


# Lock and load the input for processing
domains_to_search_as_a_of_dict = oscarlib.load_file_into_array_of_dict(args.input)

# Hot fix
for i in domains_to_search_as_a_of_dict:
    i['_id'] = i['fqdn']

    # Purify input - valid names only
    if not oscarlib.is_valid_hostname(i['fqdn']):
        print("Error: \"{}\" is not a valid hostname to hunt".format(i['fqdn']))
        continue

# Load all data into CouchDB
print("Loading work on the couch...")
oscarlib.load_work_on_to_couch(ctx, domains_to_search_as_a_of_dict)
print("Done.")

