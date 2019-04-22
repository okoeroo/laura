#!/usr/bin/env python3

### System imports

import dns.resolver
from datetime import tzinfo, timedelta, datetime
import time
import uuid
import sys
import os
import threading
import ipaddress
from multiprocessing import Process, Queue, JoinableQueue
import warnings
from ipwhois.net import Net
from ipwhois.asn import IPASN
from pprint import pprint
import re
import sqlite3
from urllib.request import urlopen
import requests
import requests_cache
import json

import pprint


### Private imports
modpath = "".join([os.path.dirname(os.path.realpath(__file__)), "/", "modules"])
sys.path.append(modpath)

import oscarlib

###


### Classes

class Workload:
    store_db = {}
    mem_db = {}

    def __init__(self, base_fqdn, uuid_hunt=None):
        self.base_fqdn = base_fqdn
        self.wildcard_canary = 'wildcardcanary' + '.' + self.base_fqdn

        self.initialize_db()
        self.s_dt = datetime.utcnow()
        if uuid_hunt is None:
            self.uuid_hunt = str(uuid.uuid4())
        else:
            self.uuid_hunt = uuid_hunt

    def initialize_db(self):
        self.mem_db['connection'] = sqlite3.connect(':memory:')
        self.mem_db['connection'].isolation_level = None
        # self.mem_db['connection'] = sqlite3.connect(PATH + 'db/domainhunter2.db')
        self.mem_db['cursor'] = self.mem_db['connection'].cursor()
        self.mem_db['connection'].execute('''CREATE TABLE fqdns (uuid_fqdn TEXT, fqdn TEXT, status TEXT, uuid_parent TEXT)''')
        self.mem_db['connection'].execute('''CREATE TABLE dns_rr (uuid_rr TEXT, fqdn TEXT, r_type TEXT, value TEXT)''')
        self.mem_db['connection'].execute('''CREATE TABLE asn (uuid_asn TEXT, asn TEXT, asn_description TEXT,
                                                               asn_date TEXT, asn_registry TEXT,
                                                               asn_country_code TEXT, asn_cidr TEXT
                                                              )''')
        self.mem_db['connection'].execute('''CREATE TABLE ip (uuid_ip TEXT, ip TEXT, version TEXT)''')
        self.mem_db['connection'].execute('''CREATE TABLE ip2asn (uuid_ip TEXT, uuid_asn TEXT)''')
        self.mem_db['connection'].execute('''CREATE TABLE dns_rr_parent_child (uuid_parent TEXT, uuid_child TEXT)''')
        self.mem_db['connection'].execute('''CREATE TABLE dns_rr_to_ip (uuid_rr TEXT, uuid_ip TEXT)''')
        self.mem_db['connection'].execute('''CREATE TABLE redirect (uuid_redir TEXT, schema TEXT, fqdn TEXT, location TEXT)''')
        self.mem_db['connection'].execute('''CREATE TABLE fqdn2redirect (uuid_fqdn TEXT, uuid_redir TEXT)''')

        self.store_db['connection'] = sqlite3.connect(PATH + 'db/domainhunter2.db')
        self.store_db['connection'].isolation_level = None
        self.store_db['cursor'] = self.store_db['connection'].cursor()
        try:
            self.store_db['connection'].execute('''CREATE TABLE dns_rr_cache (fqdn TEXT, r_type TEXT, value TEXT, error TEXT)''')
        except:
            pass

    ### Disk cache of dns_rr records for speed up
    ### TODO: should get a (longer) TTL
    def add_cache_entry(self, fqdn, r_type, value, error):
        sql = ' '.join(["INSERT INTO dns_rr_cache",
                                    "(fqdn, r_type, value, error)"
                             "VALUES (:fqdn, :r_type, :value, :error)"])
        self.store_db['cursor'].execute(sql,
                                        {"fqdn":fqdn,
                                         "r_type":r_type,
                                         "value":value,
                                         "error":error})
        return True

    def has_cache_hit(self, fqdn, r_type, error):
        sql = ' '.join(["SELECT count(*)"
                          "FROM dns_rr_cache",
                         "WHERE fqdn = :fqdn",
                           "AND r_type = :r_type",
                           "AND error = :error"])
        self.store_db['cursor'].execute(sql,
                                        {"fqdn":fqdn,
                                         "r_type":r_type,
                                         "error":error})
        cnt = self.store_db['cursor'].fetchone()[0]
        return cnt > 0

    def get_cache_hit(self, fqdn, r_type):
        sql = ' '.join(["SELECT fqdn, r_type, value, error"
                          "FROM dns_rr_cache",
                         "WHERE fqdn = :fqdn",
                           "AND r_type = :r_type"])
        self.store_db['cursor'].execute(sql,
                                        {"fqdn":fqdn,
                                         "r_type":r_type})
        res = self.store_db['cursor'].fetchone()

        rec = {}
        rec['fqdn'] = res[0]
        rec['r_type'] = res[1]
        rec['value'] = res[2]
        rec['error'] = res[3]
        return rec

    ### Clean up stuff, milage may vary...
    def detect_none_base_fqdn_rr_wilds_for_cleanup(self):
        all_recs = self.get_dns_rr()
        base_fqdn_rr = self.get_dns_rr_by_fqdn(self.base_fqdn)

        for ar in all_recs:
            if ar['r_type'] in ['NS', 'MX', 'SOA', 'TXT']:
                for bfr in base_fqdn_rr:
                    if bfr['r_type'] == ar['r_type'] and bfr['value'] == ar['value']:
                        print(bfr['r_type'], "==", ar['r_type'], "and", bfr['value'], "==", ar['value'])

                        # Remove from all_recs (in the db)
                        self.delete_dns_rr_by_fqdn_and_r_type(ar['fqdn'], ar['r_type'])

    def detect_and_remove_dns_wildcard(self):
        canary_recs = self.get_dns_rr_by_fqdn(self.wildcard_canary)
        print("Canary rec count:", len(canary_recs), file=sys.stderr)
        all_recs = self.get_dns_rr()
        print("All rec count:", len(all_recs), file=sys.stderr)

        # Is the data of the canary_recs is found in the all_recs, than
        # remove that record from the all_recs, unless it's the base_fqdn and the wildcard_canary itself
        for ar in all_recs:
            for cr in canary_recs:
                if ar['value'] == cr['value'] and ar['r_type'] == cr['r_type']:
                    # Eligable for removal
                    if ar['fqdn'] == self.base_fqdn or ar['fqdn'] == self.wildcard_canary:
                        continue
                    else:
                        # Remove from all_recs (in the db)
                        self.delete_dns_rr_by_fqdn_and_r_type(ar['fqdn'], ar['r_type'])

    ### Table: dns_rr
    def delete_dns_rr_by_fqdn_and_r_type(self, g_fqdn, g_r_type):
        # Remove linkages
        all_recs = self.get_dns_rr()
        for r in all_recs:
            if r['fqdn'] == g_fqdn and r['r_type'] == g_r_type:
                self.delete_dns_rr_to_ip_by_uuid_rr(r['uuid_rr'])

        # Remove DNS RR
        sql = ' '.join(["DELETE FROM dns_rr",
                              "WHERE fqdn = :fqdn",
                                "AND r_type = :r_type"])
        self.mem_db['cursor'].execute(sql,
                                     {"fqdn":g_fqdn,
                                      "r_type":g_r_type})
        return True

    def count_dns_rr_by_r_type_and_value(self, c_r_type, c_value):
        sql = ' '.join(["SELECT count(*)"
                          "FROM dns_rr",
                         "WHERE r_type = :r_type",
                           "AND value = :value"])
        self.mem_db['cursor'].execute(sql,
                                      {"r_type":c_r_type,
                                       "value":c_value})
        cnt = self.mem_db['cursor'].fetchone()[0]
        return cnt

    def add_dns_rr(self, fqdn, r_type, value):
        u = str(uuid.uuid4())
        sql = ' '.join(["INSERT INTO dns_rr",
                                    "(uuid_rr, fqdn, r_type, value)",
                             "VALUES (:uuid_rr, :fqdn, :r_type, :value)"])
        self.mem_db['cursor'].execute(sql,
                                      {"uuid_rr":u,
                                       "fqdn":fqdn,
                                       "r_type": r_type,
                                       "value": value})
        return u

    def get_dns_rr_by_fqdn(self, g_fqdn):
        all_dns_rr = []
        sql = ' '.join(["SELECT uuid_rr, fqdn, r_type, value",
                          "FROM dns_rr",
                         "WHERE fqdn = :fqdn"])
        self.mem_db['cursor'].execute(sql,
                                      {"fqdn":g_fqdn})
        for (uuid_rr, fqdn, r_type, value) in self.mem_db['cursor']:
            rec = {}
            rec['uuid_rr'] = uuid_rr
            rec['fqdn'] = fqdn
            rec['r_type'] = r_type
            rec['value'] = value
            all_dns_rr.append(rec)
        return all_dns_rr

    def get_dns_rr(self):
        all_dns_rr = []
        sql = ' '.join(["SELECT uuid_rr, fqdn, r_type, value",
                          "FROM dns_rr"])
        self.mem_db['cursor'].execute(sql)
        for (uuid_rr, fqdn, r_type, value) in self.mem_db['cursor']:
            rec = {}
            rec['uuid_rr'] = uuid_rr
            rec['fqdn'] = fqdn
            rec['r_type'] = r_type
            rec['value'] = value
            all_dns_rr.append(rec)
        return all_dns_rr

    def count_dns_rr_by_fqdn_and_r_type(self, g_fqdn, g_r_type):
        sql = ' '.join(["SELECT count(*)",
                          "FROM dns_rr",
                         "WHERE fqdn = :fqdn",
                           "AND r_type = :r_type"])
        self.mem_db['cursor'].execute(sql,
                                      {"fqdn":g_fqdn, "r_type":g_r_type})
        cnt = self.mem_db['cursor'].fetchone()[0]
        return cnt

    ### Table: dns_rr_to_ip
    def delete_dns_rr_to_ip_by_uuid_rr(self, g_uuid_rr):
        sql = ' '.join(["DELETE FROM dns_rr_to_ip",
                              "WHERE uuid_rr = :uuid_rr"])
        self.mem_db['cursor'].execute(sql,
                                     {"uuid_rr":g_uuid_rr})
        return True


    def add_dns_rr_to_ip(self, uuid_rr, uuid_ip):
        sql = ' '.join(["INSERT INTO dns_rr_to_ip",
                                    "(uuid_rr, uuid_ip)"
                             "VALUES (:uuid_rr, :uuid_ip)"])
        self.mem_db['cursor'].execute(sql,
                                     {"uuid_rr":uuid_rr,
                                      "uuid_ip":uuid_ip})
        return True

    ### Table: dns_rr_parent_child
    def add_dns_rr_parent_child(self, uuid_parent, uuid_child):
        sql = ' '.join(["INSERT INTO dns_rr_parent_child",
                                    "(uuid_parent, uuid_child)",
                             "VALUES (:uuid_parent, :uuid_child)"])
        self.mem_db['cursor'].execute(sql,
                                     {"uuid_parent":uuid_parent,
                                      "uuid_child":uuid_child})
        return True

    def get_dns_rr_parent_child(self):
        dns_rr_parent_child = []
        sql = ' '.join(["SELECT uuid_parent, uuid_child",
                          "FROM dns_rr_parent_child"])
        self.mem_db['cursor'].execute(sql)
        for (uuid_parent, uuid_child) in self.mem_db['cursor']:
            rec = {}
            rec['uuid_parent'] = uuid_parent
            rec['uuid_child'] = uuid_child
            dns_rr_parent_child.append(rec)
        return dns_rr_parent_child

    ### Table: fqdns
    def add_fqdn(self, fqdn, uuid_parent):
        # Status: "todo", "processing", "done"
        u = str(uuid.uuid4())
        sql = ' '.join(["INSERT INTO fqdns",
                                    "(uuid_fqdn, fqdn, status, uuid_parent)",
                             "VALUES (:uuid_fqdn, :fqdn, :status, :uuid_parent)"])
        self.mem_db['cursor'].execute(sql,
                                      {"uuid_fqdn":u,
                                       "fqdn": fqdn,
                                       "status": "todo",
                                       "uuid_parent": uuid_parent})
        return u

    def get_fqdns_not_done(self):
        records = []
        sql = ' '.join(["SELECT uuid_fqdn, fqdn, status, uuid_parent",
                          "FROM fqdns",
                         "WHERE status <> :status"])
        self.mem_db['cursor'].execute(sql,
                                      {"status":"done"})
        for (uuid_fqdn, fqdn, status, uuid_parent) in self.mem_db['cursor']:
            rec = {}
            rec['uuid'] = uuid_fqdn
            rec['fqdn'] = fqdn
            rec['status'] = status
            rec['uuid_parent'] = uuid_parent
            records.append(rec)
        return records

    def get_fqdns_by_fqdn(self, g_fqdn):
        records = []
        sql = ' '.join(["SELECT uuid_fqdn, fqdn, status, uuid_parent",
                          "FROM fqdns",
                         "WHERE fqdn = :fqdn"])
        self.mem_db['cursor'].execute(sql,
                                      {"fqdn":g_fqdn})
        for (uuid_fqdn, fqdn, status, uuid_parent) in self.mem_db['cursor']:
            rec = {}
            rec['uuid'] = uuid_fqdn
            rec['fqdn'] = fqdn
            rec['status'] = status
            rec['uuid_parent'] = uuid_parent
            records.append(rec)
        return records

    def update_fqdns_status_by_fqdn(self, u_fqdn, u_status):
        records = []
        sql = ' '.join(["UPDATE fqdns",
                           "SET status = :status",
                         "WHERE fqdn = :fqdn"])
        self.mem_db['cursor'].execute(sql,
                                      {"fqdn": u_fqdn,
                                       "status": u_status})
        return True

    def count_fqdns_by_fqdn(self, c_fqdn):
        sql = ' '.join(["SELECT count(*)",
                          "FROM fqdns",
                         "WHERE fqdn = :fqdn"])
        self.mem_db['cursor'].execute(sql,
                                      {"fqdn":c_fqdn})
        cnt = self.mem_db['cursor'].fetchone()[0]
        return cnt

    def count_fqdns_by_status(self, c_status):
        sql = ' '.join(["SELECT count(status)",
                          "FROM fqdns",
                         "WHERE status = :status"])
        self.mem_db['cursor'].execute(sql,
                                      {"status":c_status})
        cnt = self.mem_db['cursor'].fetchone()[0]
        return cnt

    ### Table: asn
    def add_asn(self, asn, asn_description, asn_date, asn_registry, asn_country_code, asn_cidr):
        u = str(uuid.uuid4())
        sql = ' '.join(["INSERT INTO asn",
                                   "(uuid_asn, asn, asn_description,",
                                    "asn_date, asn_registry, asn_country_code,",
                                    "asn_cidr)",
                            "VALUES (:uuid_asn, :asn, :asn_description,",
                                    ":asn_date, :asn_registry, :asn_country_code,",
                                    ":asn_cidr)"])
        self.mem_db['cursor'].execute(sql,
                                     {"uuid_asn":u,
                                      "asn":asn,
                                      "asn_description":asn_description,
                                      "asn_date":asn_date,
                                      "asn_registry":asn_registry,
                                      "asn_country_code":asn_country_code,
                                      "asn_cidr":asn_cidr})
        return u

    def count_asn_by_asn_and_asn_cidr(self, c_asn, c_asn_cidr):
        sql = ' '.join(["SELECT count(*)"
                          "FROM asn",
                         "WHERE asn = :asn",
                           "AND asn_cidr = :asn_cidr"])
        self.mem_db['cursor'].execute(sql,
                                      {"asn":c_asn, "asn_cidr":c_asn_cidr})
        cnt = self.mem_db['cursor'].fetchone()[0]
        return cnt

    def get_asns(self):
        asns = []
        sql = ' '.join(["SELECT uuid_asn, asn, asn_description,",
                               "asn_date, asn_registry, asn_country_code,",
                               "asn_cidr",
                          "FROM asn"])
        self.mem_db['cursor'].execute(sql)
        for (uuid_asn, asn, asn_description, asn_date,
             asn_registry, asn_country_code, asn_cidr) in self.mem_db['cursor']:
            rec = {}
            rec['uuid_asn'] = uuid_asn
            rec['asn'] = asn
            rec['asn_description'] = asn_description
            rec['asn_date'] = asn_date
            rec['asn_registry'] = asn_registry
            rec['asn_country_code'] = asn_country_code
            rec['asn_cidr'] = asn_cidr
            asns.append(rec)
        return asns

    def get_asn_by_asn_and_asn_cidr(self, c_asn, c_asn_cidr):
        sql = ' '.join(["SELECT uuid_asn, asn, asn_description,",
                               "asn_date, asn_registry, asn_country_code,",
                               "asn_cidr",
                          "FROM asn",
                         "WHERE asn = :asn",
                           "AND asn_cidr = :asn_cidr"])
        self.mem_db['cursor'].execute(sql,
                                      {"asn":c_asn, "asn_cidr":c_asn_cidr})
        for (uuid_asn, asn, asn_description, asn_date,
             asn_registry, asn_country_code, asn_cidr) in self.mem_db['cursor']:
            rec = {}
            rec['uuid_asn'] = uuid_asn
            rec['asn'] = asn
            rec['asn_description'] = asn_description
            rec['asn_date'] = asn_date
            rec['asn_registry'] = asn_registry
            rec['asn_country_code'] = asn_country_code
            rec['asn_cidr'] = asn_cidr
            # Only get the first, yes, indenting matters
            return rec

    ### Table: ip
    def add_ip(self, ip, version):
        u = str(uuid.uuid4())
        sql = ' '.join(["INSERT INTO ip (uuid_ip, ip, version)",
                                "VALUES (:uuid_ip, :ip, :version)"])
        self.mem_db['cursor'].execute(sql,
                                      {"uuid_ip":u, "ip":ip, "version":version})
        return u

    def count_ip_by_ip(self, c_ip):
        sql = ' '.join(["SELECT count(ip)",
                          "FROM ip",
                         "WHERE ip = :ip"])
        self.mem_db['cursor'].execute(sql,
                                      {"ip":c_ip})
        cnt = self.mem_db['cursor'].fetchone()[0]
        return cnt

    def get_ip_by_ip(self, g_ip):
        sql = ' '.join(["SELECT uuid_ip, ip, version",
                          "FROM ip",
                         "WHERE ip = :ip"])
        self.mem_db['cursor'].execute(sql,
                                      {"ip":g_ip})
        for (uuid_ip, ip, version) in self.mem_db['cursor']:
            rec = {}
            rec['uuid_ip'] = uuid_ip
            rec['ip'] = ip
            rec['version'] = version
            # Only get the first, yes, indenting matters
            return rec

    def get_ips(self):
        all_ips = []
        sql = ' '.join(["SELECT uuid_ip, ip, version",
                          "FROM ip"])
        self.mem_db['cursor'].execute(sql)
        for (uuid_ip, ip, version) in self.mem_db['cursor']:
            rec = {}
            rec['uuid_ip'] = uuid_ip
            rec['ip'] = ip
            rec['version'] = version
            all_ips.append(rec)
        return all_ips

    ### Table: ip2asn
    def add_ip2asn(self, uuid_ip, uuid_asn):
        sql = ' '.join(["INSERT INTO ip2asn (uuid_ip, uuid_asn)",
                                    "VALUES (:uuid_ip, :uuid_asn)"])
        self.mem_db['cursor'].execute(sql,
                                      {"uuid_ip":uuid_ip, "uuid_asn":uuid_asn})
        return True

    def get_ip2asns(self):
        all_ip2asns = []
        sql = ' '.join(["SELECT uuid_ip, uuid_asn",
                          "FROM ip2asn"])
        self.mem_db['cursor'].execute(sql)
        for (uuid_ip, uuid_asn) in self.mem_db['cursor']:
            rec = {}
            rec['uuid_ip'] = uuid_ip
            rec['uuid_asn'] = uuid_asn
            all_ip2asns.append(rec)
        return all_ip2asns

    ### Table: redirect
    def add_redirect(self, schema, fqdn, location):
        u = str(uuid.uuid4())
        sql = ' '.join(["INSERT INTO redirect (uuid_redir, schema, fqdn, location)",
                                    "VALUES (:uuid_redir, :schema, :fqdn, :location)"])
        self.mem_db['cursor'].execute(sql,
                                      {"uuid_redir":u,
                                       "schema":schema,
                                       "fqdn":fqdn,
                                       "location":location})
        return u

    def get_redirects(self):
        all_redirects = []
        sql = ' '.join(["SELECT uuid_redir, schema, fqdn, location",
                          "FROM redirect"])
        self.mem_db['cursor'].execute(sql)
        for (uuid_redir, schema, fqdn, location) in self.mem_db['cursor']:
            rec = {}
            rec['uuid_redir'] = uuid_redir
            rec['schema'] = schema
            rec['fqdn'] = fqdn
            rec['location'] = location
            all_redirects.append(rec)
        return all_redirects

    ### Table: fqdn2redirect
    def add_fqdn2redirect(self, uuid_fqdn, uuid_redir):
        sql = ' '.join(["INSERT INTO fqdn2redirect (uuid_fqdn, uuid_redir)",
                                    "VALUES (:uuid_fqdn, :uuid_redir)"])
        self.mem_db['cursor'].execute(sql,
                                      {"uuid_fqdn":uuid_fqdn,
                                       "uuid_redir":uuid_redir})
        return True

    def get_fqdn2redirects(self):
        all_fqdn2redirects = []
        sql = ' '.join(["SELECT uuid_fqdn, uuid_redir",
                          "FROM fqdn2redirect"])
        self.mem_db['cursor'].execute(sql)
        for (uuid_fqdn, uuid_redir) in self.mem_db['cursor']:
            rec = {}
            rec['uuid_fqdn'] = uuid_fqdn
            rec['uuid_redir'] = uuid_redir
            all_fqdn2redirects.append(rec)
        return all_fqdn2redirects

    ### Drawing stuff
    def draw_txt(self, destination):
        f = open(destination, "w")
        all_dns_rr = self.get_dns_rr()
        all_dns_rr_parent_child = self.get_dns_rr_parent_child()
        for rec in all_dns_rr:
            for rec_pc in all_dns_rr_parent_child:
                if rec_pc['uuid_parent'] == self.uuid_hunt and rec['uuid_rr'] == rec_pc['uuid_child']:
                    f.write(''.join([self.base_fqdn, " (base2fqdn) ", rec['fqdn'], " {", rec['r_type'], "/", rec['value'], "}", "\n"]))

        for rec in all_dns_rr:
            f.write(''.join([rec['fqdn'], " (", rec['r_type'], ") ", rec['value'], "\n"]))

        # IP to ASN
        all_ips = self.get_ips()
        all_ip2asns = self.get_ip2asns()
        all_asns = self.get_asns()
        for rec in all_asns:
            llma = []
            llma.append("ASN:")
            if rec['asn'] is not None:
                llma.append(rec['asn'])
            if rec['asn_description'] is not None:
                llma.append(rec['asn_description'])
            if rec['asn_registry'] is not None:
                llma.append(rec['asn_registry'])
            if rec['asn_country_code'] is not None:
                llma.append(rec['asn_country_code'])
            label = ' '.join(llma)

            for rec_ip in all_ips:
                for ip2asn in all_ip2asns:
                    if ip2asn['uuid_ip'] == rec_ip['uuid_ip']:
                        if ip2asn['uuid_asn'] == rec['uuid_asn']:
                            f.write(''.join([rec_ip['ip'], " (ip2asn) ", label, "\n"]))

        f.close()


        # HACK: re-plot the CNAME linkage to all RR types not yet linked
#        for rr in self.get_dns_rr():
#            if rr['r_type'] == 'CNAME':
#                for rr_inner in self.get_dns_rr():
#                    # Combine the CNAME value to whatever RR
#                    if rr['value'] == rr_inner['fqdn']:
#                        self.add_dns_rr_parent_child(rr['uuid_rr'], rr_inner['uuid_rr'])


### Functions

def analyse_record2(uuid_child, uuid_parent, k, key_type, val, val_type, status, reason, dt, last_key_is_fqdn):
    try:
        # Remember where we came from. Required for SPF1 and DMARC
        if key_type == 'FQDN':
            last_key_is_fqdn = k

        if val_type == 'FQDN':
            # Need to resolve this FQDN again, but with the current uuid_child as its parent
            if w.count_fqdns_by_fqdn(val) == 0:
                w.add_fqdn(val, uuid_child)

        # A, AAAA or results from SPF1 and other records with an IP address in it
        ### Error handling CIDR notation -
        elif val_type == 'A' or val_type == 'AAAA':
            print ("analyse_record2", "debug", 'key_type', key_type, 'key', k,
                   'val_type', val_type, 'value', val, file=sys.stderr)

            # Currenct RR is uuid_child, which has an A result.
            # This is stored already. Need to add the IP
            # and bind the IP uuid to the RR uuid, which is the child_uuid
            if w.count_ip_by_ip(val) == 0:
                if val_type == 'A':
                    uuid_ip = w.add_ip(val, 4)
                elif val_type == 'AAAA':
                    uuid_ip = w.add_ip(val, 6)

                # The new IP needs an ASN resolve and IP to ASN attachment
                # Take A or AAAA value to resolve as part of an AS plus AS info
                asn_result = analyse_asn(val)

                # The IP is now resolved to an ASN. Did we have this one from another ASN?
                # If yes, get that one, if not, create a new one.
                # Result is an uuid_asn
                if w.count_asn_by_asn_and_asn_cidr(asn_result['asn'],
                                                   asn_result['asn_cidr']) == 0:
                    uuid_asn = w.add_asn(asn_result['asn'], asn_result['asn_description'],
                                         asn_result['asn_date'], asn_result['asn_registry'],
                                         asn_result['asn_country_code'], asn_result['asn_cidr'])
                else:
                    rec_asn = w.get_asn_by_asn_and_asn_cidr(asn_result['asn'],
                                                            asn_result['asn_cidr'])
                    uuid_asn = rec_asn['uuid_asn']

                # Combine this IP address with an the ASN per CIDR
                w.add_ip2asn(uuid_ip, uuid_asn)
            else:
                rec_ip = w.get_ip_by_ip(val)
                uuid_ip = rec_ip['ip']

            # in all cases, uuid_ip is the new one or the existing one
            w.add_dns_rr_to_ip(uuid_child, uuid_ip)


    except Exception as inst:
        print("analyse_record2", "Error:", type(inst), inst,
              'key_type', key_type, 'val_type', val_type, file=sys.stderr)


def analyse_asn(ip):
    net = Net(ip)
    obj = IPASN(net)
    results = obj.lookup()

    print (results, file=sys.stderr)
    return results

    # {'asn': '15169', 'asn_date': '2008-09-30', 'asn_description': 'GOOGLE -
    # Google LLC, US', 'asn_cidr': '2404:6800:4003::/48', 'asn_registry':
    # 'apnic', 'asn_country_code': 'AU'}

    # {'asn': '15169', 'asn_date': '2007-03-13', 'asn_description': 'GOOGLE -
    # Google LLC, US', 'asn_cidr': '74.125.200.0/24', 'asn_registry': 'arin',
    # 'asn_country_code': 'US'}


#    elif r_type == 'A':
#        # Assume A record is already stored, only analyse deeper.
#        print("analyse A", str(r_data), file=sys.stderr)
#
#        try:
#            # Search Shodan
#            results = api.search(str(r_data))
#
#            # Show the results
#            print('Results found: %s' % results['total'], file=sys.stderr)
#            for result in results['matches']:
#                print('IP: %s' % result['ip_str'], file=sys.stderr)
#                print(result['data'], file=sys.stderr)
#                print('', file=sys.stderr)
#        except shodan.APIError as e:
#            print('Error: %s' % e, file=sys.stderr)
#
#        #store_record(uuid_child, uuid_parent, fqdn, r_type, str(r_data), s_dt, q_dt, r_dt)


def req_get_inner(schema, fqdn_rec):
#    expire_after = timedelta(minutes=15)
#    requests_cache.install_cache('demo_cache1', expire_after=expire_after)

    base_url = schema + fqdn_rec['fqdn']
    try:
        r = requests.get(base_url, allow_redirects=False, timeout=2)
        if r.status_code >= 300 and r.status_code < 400:
            if 'Location' in r.headers.keys():
                u = w.add_redirect(schema, fqdn_rec['fqdn'], r.headers['Location'])
                w.add_fqdn2redirect(fqdn_rec['uuid'], u)
                print("Location found:",
                      schema + fqdn_rec['fqdn'],
                      r.headers['Location'],
                      file=sys.stderr)
                return True
    except:
        pass

    return False


def req_get(fqdn_rec):
    print(fqdn_rec)
    req_get_inner('http://', fqdn_rec)
    req_get_inner('https://', fqdn_rec)



def resolve_multi_sub_domains():
    print("Count todo", w.count_fqdns_by_status("todo"), file=sys.stderr)
    print("Count done", w.count_fqdns_by_status("done"), file=sys.stderr)

    # Total workload
    while True:
        l = w.get_fqdns_not_done()
        if len(l) == 0:
            print("Count todo", w.count_fqdns_by_status("todo"), file=sys.stderr)
            print("Count done", w.count_fqdns_by_status("done"), file=sys.stderr)
            break

        for fqdn_rec in l:
            print("FQDN to examine (workload)", fqdn_rec['fqdn'], file=sys.stderr)
            # Start resolving.
            resolve_multi_type(fqdn_rec['uuid_parent'], fqdn_rec['fqdn'])

            # HTTP Get and record Location
            req_get(fqdn_rec)

            # Flag this FQDN as done.
            w.update_fqdns_status_by_fqdn(fqdn_rec['fqdn'], "done")

        print("Count todo", w.count_fqdns_by_status("todo"), file=sys.stderr)
        print("Count done", w.count_fqdns_by_status("done"), file=sys.stderr)

    # Post processing
    # Debug
    print(w.get_redirects())

#    w.detect_and_remove_dns_wildcard()
#    w.detect_none_base_fqdn_rr_wilds_for_cleanup()



##### MAIN #####
import argparse


# Init
PATH = os.path.dirname(os.path.realpath(__file__)) + '/'

# Parser
parser = argparse.ArgumentParser("laura.py")
parser.add_argument("--cs-apikey",   dest='cs_apikey', help="CertSpotter API Key", type=str)
parser.add_argument("--fb-apikey",   dest='fb_apikey', help="Facebook App API Key", type=str)
parser.add_argument("--input",       dest='input', help="Input list", type=str)
parser.add_argument('--output-json', dest='output_json', help="Output JSON", type=str)
args = parser.parse_args()

if not args.input:
    print("No input")
    sys.exit(1)



## Initialize ASN database
#asn_lookup = oscarlib.ASNLookUp()
#print(asn_lookup.asn_origin('AS1104'))
#print("----------")
#print(asn_lookup.asn_origin('1104'))
#print("----------")
#print(asn_lookup.asn_origin(1104))
#print("----------")
#print(asn_lookup.asn_get('164.132.194.210'))
#print(oscarlib.ASNLookUp().asn_get('164.132.194.210'))
#
#print(oscarlib.ASNLookUp().asn_origin(1136))
#
#sys.exit(1)

#r = oscarlib.get_asn_origin('AS286')
#pprint.pprint(r, indent=4)
#sys.exit(1)

domains_to_search = oscarlib.load_file_into_array(args.input)

print("Scan started for:")
print("=========")

total_results_list = []

for d in domains_to_search:
    list_per_domain = []
    list_per_domain.append(d)
    list_per_domain.append(oscarlib.get_wildcard_canary(d))
    list_per_domain = list_per_domain + \
                      oscarlib.load_static_domain_prefixes(d)
    list_per_domain = list_per_domain + \
                      oscarlib.ct_facebook_search_domain_for_more_hostnames(d, False, args.fb_apikey)

    list_per_domain = oscarlib.list_dedup(list_per_domain)
    print(list_per_domain)
    print()
    print("Start DNS checks")

    m = oscarlib.my_threading(oscarlib.dns_resolve_all_r_type, list_per_domain)
    results = m.get_results()
    pprint.pprint(results, indent=4)

    total_results_list.extend(results)


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


sys.exit(0)




# Generate or Get UUID for this hunt
if not args.inject_uuid:
    w = Workload(args.domain)
else:
    w = Workload(args.domain, args.inject_uuid)

# Announce
if args.output:
    print(str(w.uuid_hunt), "for a search on base FQDN", w.base_fqdn, "started at", str(w.s_dt), "output will be written to", args.output, file=sys.stdout)
else:
    print(str(w.uuid_hunt), "for a search on base FQDN", w.base_fqdn, "started at", str(w.s_dt), file=sys.stdout)

# Start the hunt
resolve_multi_sub_domains(args.scopecreep, sideloaded)

# Draw
if args.output:
    print("Draw mode: plotting to", args.output, file=sys.stderr)
    if args.output.endswith(".svg"):
        w.draw_svg(args.output)
    elif args.output.endswith(".txt"):
        w.draw_txt(args.output)


#pr.disable()
#pr.print_stats(sort='time')
# End
