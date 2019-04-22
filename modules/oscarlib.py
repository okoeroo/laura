#!/usr/bin/env python3

import dns.resolver
from datetime import tzinfo, timedelta, datetime
import time
import sys
import os
import json
import pprint

from ipwhois.net import Net
from ipwhois.asn import IPASN
from ipwhois.asn import ASNOrigin

from urllib.request import urlopen
import requests
import requests_cache
import threading

from netaddr import *

import multiprocessing
import queue

import csv


class ASNLookUp(object):
    def __init__(self, ip2asndb='ip2asn-combined.tsv'):
        PATH = os.path.dirname(os.path.realpath(__file__)) + '/'

        self.ip2asn_db = PATH + ip2asndb
        self.asn2ip = []

        self.initialize_asn_databases()

    def initialize_asn_databases(self):
        print("Read: ip2asn-combined.tsv")
        with open(self.ip2asn_db) as csv_file:
            csv_reader = csv.reader(csv_file, delimiter='\t')
            for row in csv_reader:
                r = {}
                r['range_start']     = row[0]
                r['range_start_obj'] = IPAddress(row[0])
                r['range_end']       = row[1]
                r['range_end_obj']   = IPAddress(row[1])
                r['as_number']       = int(row[2])
                r['as_country']      = row[3]
                r['as_description']  = row[4]

                self.asn2ip.append(r)

    def asn_serialize(self, rec):
        r = {}
        r['range_start']     = rec['range_start']
        r['range_end']       = rec['range_end']
        r['cidrs']           = []

        ipr = IPRange(rec['range_start'], rec['range_end'])
        for c in ipr.cidrs():
            r['cidrs'].append(str(c))

        r['as_number']       = rec['as_number']
        r['as_country']      = rec['as_country']
        r['as_description']  = rec['as_description']
        return r

    def asn_get(self, ipaddress):
        ip = IPAddress(ipaddress)

        for r in self.asn2ip:
            if r['range_start_obj'] <= ip and \
                    r['range_end_obj'] >= ip and \
                    r['as_description'] != "Not routed":
                print(ip, r)
                return self.asn_serialize(r)

    def asn_origin(self, asnumber):
        if isinstance(asnumber, str):
            if asnumber[:2].upper() == 'AS':
                i_asnum = int(asnumber[2:])
            else:
                i_asnum = int(asnumber)
        elif isinstance(asnumber, int):
            i_asnum = asnumber
        else:
            return None

        # Search in list
        l_per_as = []
        for r in self.asn2ip:
            if int(r['as_number']) == int(i_asnum):
                l_per_as.append(r)

        return l_per_as


def get_asn_origin(asnumber):
# net = Net('2001:43f8:7b0::')
# obj = ASNOrigin(net)
# results = obj.lookup(asn='AS37578')
# pprint(results)

    net = Net('0.0.0.0')
    obj = ASNOrigin(net)
#    obj = ASNOrigin()
    results = obj.lookup(asn=asnumber)
    return results

class my_threading(object):
    def __init__(self, func, list_of_work):
        self.q = queue.Queue()
        self.r = []
        self.func = func
        self.list_of_work = list_of_work
        self.threads = []

        # Setup work
        for i in self.list_of_work:
            work = {}
            work['func'] = self.func
            work['data'] = i
            self.q.put(work)

        self.para()

    def worker(self):
        while True:
            item = self.q.get()
            if item is None:
                break

            res = item['func'](item['data'])
            self.r.extend(res)
            self.q.task_done()

    def para(self):
        for i in range(32):
            t = threading.Thread(target=self.worker)
            t.start()
            self.threads.append(t)


        # block until all tasks are done
        self.q.join()

        # stop workers
        for i in range(32):
            self.q.put(None)
        for t in self.threads:
            t.join()

    def get_results(self):
        return self.r


def wrapper(func, in_queue, out_queue):
    out_queue.put(func(in_queue.get()))

class Parallelism(object):
    def __init__(self, progress=False, processes=multiprocessing.cpu_count()):
        self.total_processes = 0
        self.completed_processes = 0
        self.results = []
        self.data = None
        self.cores = processes
        self.progress = progress

        self.pool = Pool(processes=processes)

        self.q = Queue()
        self.r = Queue()

    def add(self, func, it):
        self.func = func
        for i in it:
            print("- added to queue", i)
            self.q.put(i)

    def complete(self, result):
        self.results.extend(self.r.get())
        self.completed_processes += 1

#        self.results.append(r.get())
        if self.progress:
            print('Progress: {:.2f}%'.format((self.completed_processes / self.total_processes) * 100))
#            print(self.results)


    def run(self):
        while not self.q.empty():
            self.data = self.pool.apply_async(func=wrapper,
                                              args=(self.func, self.q, self.r),
                                              callback=self.complete)
            self.total_processes += 1

        print("All submitted")
        self.pool.close()
#        self.pool.join()

    def get_results(self):
        return self.results

def daemonize(func_child, j_args):
    newpid = os.fork()
    if newpid == 0:
        # Child 1
        # New session id
        os.setsid()
        # Double fork
        newpid = os.fork()
        if newpid == 0:
            # Child 2
            func_child(j_args)
        else:
            # Parent 2
            pids = (os.getpid(), newpid)
        # Exit child 1
        os._exit(0)
    else:
        # Parent 1
        os.waitpid(newpid, 0)
        pids = (os.getpid(), newpid)

def check_fqdn_is_legit(fqdn):
    expire_after = timedelta(minutes=30)
    requests_cache.install_cache('requests_tld_cache', expire_after=expire_after)

    base_url = URL_TLDS
    try:
        r = requests.get(base_url, allow_redirects=True, timeout=10)
        if (r.status_code >= 400 and r.status_code <600):
            return False

        for line in r.iter_lines():
            lo = fqdn.lower()
            if lo.endswith("." + line.decode('utf8').lower()):
                return True

    except:
        pass

    return False

def load_file_into_array(filename):
    return open(filename, "r").read().splitlines()

def load_static_domain_prefixes(base_fqdn):
    results = []

    # Add static list
    PATH = os.path.dirname(os.path.realpath(__file__)) + '/'

    temp = open(PATH + 'research.list','r').read().splitlines()
    for prefix in temp:
        results.append(prefix + '.' + base_fqdn)

    return results

def list_dedup(seq, idfun=None):
   # order preserving
   if idfun is None:
       def idfun(x): return x
   seen = {}
   result = []
   for item in seq:
       marker = idfun(item)
       # in old Python versions:
       # if seen.has_key(marker)
       # but in new ones:
       if marker in seen: continue
       seen[marker] = 1
       result.append(item)
   return result

def ct_facebook_paged_query(url, base_fqdn, scopecreep, apikey):
    results = []

    headers = {}
    headers['Authorization'] = " ".join(["Bearer", apikey])
    r = requests.get(url=url, headers=headers)

    page = r.json()

    for ct_cert in page['data']:
        for fqdn in ct_cert['domains']:
            if not scopecreep and not fqdn.endswith("." + base_fqdn):
                # Skip, because we are avoiding scope creep
                continue

            results.append(fqdn)

    if 'paging' in page:
        if 'next' in page['paging']:
            # page_next is the Next URL as part of the paging results
            page_next = page['paging']['next']
            next_results = ct_facebook_paged_query(page_next,
                                                   base_fqdn,
                                                   scopecreep,
                                                   apikey)
            results = results + next_results

    return results

def ct_facebook_search_domain_for_more_hostnames(base_fqdn, scopecreep, apikey):
    # This interface requires an API Key
    if apikey is None:
        return None

    expire_after = timedelta(minutes=60)
    requests_cache.install_cache('/tmp/laura.cache', expire_after=expire_after)

    results = []

    base_url = "https://graph.facebook.com/certificates"
    querystring = "&".join(["query=" + base_fqdn,
                            "limit=1000",
                            "fields=cert_hash_sha256,domains,issuer_name"
                           ])
    url = base_url + "?" + querystring

    # Paged query interface
    results = ct_facebook_paged_query(url,
                                      base_fqdn,
                                      scopecreep,
                                      apikey)
    return results

def get_wildcard_canary(base_fqdn=None):
    if base_fqdn is None:
        return 'wildcardcanary'
    else:
        return 'wildcardcanary.' + base_fqdn

def ct_certspotter_search_domain_for_more_hostnames(base_fqdn, scopecreep, apikey):
    expire_after = timedelta(minutes=60)
    requests_cache.install_cache('/tmp/laura.cache', expire_after=expire_after)

    results = []

    base_url = "https://api.certspotter.com/v1/issuances"
    querystring = "&".join(["match_wildcards=true",
                            "include_subdomains=true",
                            "expired=false",
                            "expand=dns_names",
                            "expand=issuer",
                            "domain=" + base_fqdn
                           ])
    url = base_url + "?" + querystring

    if apikey is None:
        r = requests.get(url)
    else:
        headers = {}
        headers['Authorization'] = " ".join(["Bearer", apikey])
        r = requests.get(url=url, headers=headers)

    res = r.json()

#    html = urlopen("https://certspotter.com/api/v0/certs?expired=false&duplicate=false&domain=" + base_fqdn)
#    s = html.read()
#    res = json.loads(s.decode('utf8'))

    for ct_cert in res:
        for fqdn in ct_cert['dns_names']:
            if not scopecreep and not fqdn.endswith("." + base_fqdn):
                # Skip, because we are avoiding scope creep
                continue

            results.append(fqdn)
    return results

def dns_resolve_r_type(fqdn, r_type):
    ### DNS Resolve FQDN with resource type
    answers = None
    try:
        resolver = dns.resolver.Resolver()
        # resolver.nameservers=['8.8.8.8', '8.8.4.4', '9.9.9.9']
        # resolver.nameservers=['127.0.0.1']
        resolver.timeout = 5
        resolver.lifetime = 8
        answer = resolver.query(fqdn, r_type)

        results = {}
        results['qname'] = str(answer.qname)

        results['rdtype'] = dns.rdatatype.to_text(answer.rdtype)
        results['rdclass'] = answer.rdclass

        ### Full packet is too much
        ### results['response'] = answer.response

        results['rrset'] = []
        results['expiration'] = answer.expiration
        results['canonical_name'] = str(answer.canonical_name)

        # Extract rrset
        for r_data in answer.rrset:
            tup = {}

            # The resulted value from the query.
            tup['value'] = str(r_data)

            # Depending upon the type, let's dive deeper
            if r_type == 'CNAME':
                # HACK: Recursing CNAME could become dangerous when this goes
                #       to infinity
                tup['cname_follow'] = dns_resolve_r_type(tup['value'], r_type)

            elif r_type == 'AAAA':
                asn = asn_get(tup['value'])
                if asn is not None:
                    tup['asn'] = asn

                # Reverse lookup
                tup['ptr_follow'] = dns_resolve_r_type(IPAddress(tup['value']).reverse_dns, 'PTR')

            elif r_type == 'A':
                asn = asn_get(tup['value'])
                if asn is not None:
                    tup['asn'] = asn

                # Reverse lookup
                tup['ptr_follow'] = dns_resolve_r_type(IPAddress(tup['value']).reverse_dns, 'PTR')

            elif r_type == 'MX':
                if not len(str(r_data).split()) == 2:
                    tup['error'] = "malformed MX rr data"
                else:
                    tup['priority'] = str(r_data).split()[0]
                    tup['mx_host']  = str(r_data).split()[1]

            elif r_type == 'SOA':
                if not len(str(r_data).split()) == 7:
                    tup['error'] = "malformed SOA rr data"
                else:
                    tup['mname']   = str(r_data).split()[0]
                    tup['rname']   = str(r_data).split()[1]
                    tup['serial']  = str(r_data).split()[2]
                    tup['refresh'] = str(r_data).split()[3]
                    tup['retry']   = str(r_data).split()[4]
                    tup['expire']  = str(r_data).split()[5]
                    tup['ttl']     = str(r_data).split()[6]

            elif r_type == 'SRV':
                if not len(str(r_data).split()) == 8:
                    tup['error'] = "malformed SOA rr data"
                else:
                    tup['srv_proto_name'] = str(r_data).split()[0]
                    tup['ttl']            = str(r_data).split()[1]
                    tup['class']          = str(r_data).split()[2]
                    tup['srv']            = str(r_data).split()[3]
                    tup['priority']       = str(r_data).split()[4]
                    tup['weight']         = str(r_data).split()[5]
                    tup['port']           = str(r_data).split()[6]
                    tup['target']         = str(r_data).split()[7]

            elif r_type == 'TXT':
                # Clean up TXT record by stripping generic stuff
                eval_txt = str(r_data).strip(" \t\n\r\"\'")

                # Detect SPF record
                if eval_txt.lower().startswith('v=spf1'):
                    for spf_elem in eval_txt.split():
                        if spf_elem.startswith('v='):
                            tup['spf_version'] = spf_elem
                        elif spf_elem.lower() == 'mx':
                            tup['spf_mx'] = True
                        elif spf_elem.lower() == 'a':
                            tup['spf_a'] = True
                        elif spf_elem.lower() == 'aaaa':
                            tup['spf_aaaa'] = True
                        elif spf_elem.lower() == 'ptr':
                            tup['spf_ptr'] = True
                        elif spf_elem.lower().startswith('ip4:'):
                            tup['spf_ip4'] = spf_elem
                        elif spf_elem.lower().startswith('ip6:'):
                            tup['spf_ip6'] = spf_elem
                        elif spf_elem.lower().startswith('include:'):
                            tup['spf_include'] = spf_elem
                        elif spf_elem.lower().startswith('exists:'):
                            tup['spf_exists'] = spf_elem
                        elif spf_elem.lower().endswith('all'):
                            tup['spf_all'] = spf_elem
                        else:
                            tup['spf_unknown'] = spf_elem

                # Detect DMARC record
                if eval_txt.lower().startswith('v=dmarc'):
                    for dmarc_elem in eval_txt.split():
                        if dmarc_elem.startswith('v='):
                            tup['dmarc_version'] = dmarc_elem.strip(';').split("=")[1].lower()
                        elif dmarc_elem.startswith('p='):
                            tup['dmarc_policy'] = dmarc_elem.strip(';').split("=")[1]
                        elif dmarc_elem.startswith('rua='):
                            tup['dmarc_rua'] = dmarc_elem.strip(';').split("=")[1]
                        elif dmarc_elem.startswith('ruf='):
                            tup['dmarc_ruf'] = dmarc_elem.strip(';').split("=")[1]
                        elif dmarc_elem.startswith('adkim='):
                            tup['dmarc_adkim'] = dmarc_elem.strip(';').split("=")[1]
                        elif dmarc_elem.startswith('aspf='):
                            tup['dmarc_aspf'] = dmarc_elem.strip(';').split("=")[1]
                        elif dmarc_elem.startswith('pct='):
                            tup['dmarc_pct'] = dmarc_elem.strip(';').split("=")[1]
                        elif dmarc_elem.startswith('sp='):
                            tup['dmarc_sp'] = dmarc_elem.strip(';').split("=")[1]
                        else:
                            tup['dmarc_unknown'] = dmarc_elem

                # Detect DKIM record
                if eval_txt.lower().startswith('v=dkim'):
                    for dkim_elem in eval_txt.split(';'):
                        if dkim_elem.lstrip().startswith('v='):
                            tup['dkim_version'] = dkim_elem.strip().split("=")[1].lower()
                        elif dkim_elem.lstrip().startswith('p='):
                            tup['dkim_pubkey'] = dkim_elem.strip().split("=")[1].replace('\" \"','')
                        elif dkim_elem.lstrip().startswith('k='):
                            tup['dkim_keytype'] = dkim_elem.strip().split("=")[1].lower()
                        else:
                            tup['dkim_unknown'] = dkim_elem

                # Detect Google Verification
                if eval_txt.lower().startswith('google-site-verification='):
                    tup['google-site-verification'] = eval_txt.split("=")[1]

                # Detect Microsoft Verification
                if eval_txt.lower().startswith('ms=ms'):
                    tup['ms'] = eval_txt.split("=")[1]

            elif r_type == 'CAA':
                # Clean up TXT record by stripping generic stuff
                eval_caa = str(r_data).strip(" \t\n\r\"\'")

                # Clean up for parsing - hack
                clean_caa = eval_caa.replace('  ', ' ')
                tup['caa_flag']  = clean_caa.split()[0]
                tup['caa_tag']   = clean_caa.split()[1]
                tup['caa_value'] = clean_caa.split()[2].strip(' \t\'\"')

            elif r_type == 'SSHFP':
                # Clean up TXT record by stripping generic stuff
                eval_sshfp = str(r_data).strip(" \t\n\r\"\'")

                # Clean up for parsing - hack
                clean_sshfp = eval_sshfp.replace('  ', ' ')
                tup['sshfp_algo'] = clean_sshfp.split()[0]
                tup['sshfp_type'] = clean_sshfp.split()[1]
                tup['sshfp_fp']   = clean_sshfp.split()[2].strip(' \t\'\"')

                # SSH authentication algorithm
                if tup['sshfp_algo'] == '1':
                    tup['sshfp_algo_text'] = 'rsa'
                elif tup['sshfp_algo'] == '2':
                    tup['sshfp_algo_text'] = 'dsa'
                elif tup['sshfp_algo'] == '3':
                    tup['sshfp_algo_text'] = 'ecdsa'
                elif tup['sshfp_algo'] == '4':
                    tup['sshfp_algo_text'] = 'ed25519'

                # SSH hash algorithm
                if tup['sshfp_type'] == '1':
                    tup['sshfp_type_text'] = 'sha1'
                elif tup['sshfp_type'] == '2':
                    tup['sshfp_type_text'] = 'sha256'

            elif r_type == 'TLSA':
                # Clean up TXT record by stripping generic stuff
                eval_tlsa = str(r_data).strip(" \t\n\r\"\'")

                # Clean up for parsing - hack
                clean_tlsa = eval_tlsa.replace('  ', ' ')

                tup['tlsa_port'] = int(str(answer.qname).split('.')[0][1:])
                tup['tlsa_protocol'] = str(answer.qname).split('.')[1][1:].lower()

                tup['tlsa_usage']        = int(clean_tlsa.split()[0])
                if tup['tlsa_usage'] == 0:
                    tup['tlsa_usage_text'] = 'CA constraint (and PKIX-TA)'
                elif tup['tlsa_usage'] == 1:
                    tup['tlsa_usage_text'] = 'Service certificate constraint (and PKIX-EE)'
                elif tup['tlsa_usage'] == 2:
                    tup['tlsa_usage_text'] = 'Trust Anchor Assertion (and DANE-TA)'
                elif tup['tlsa_usage'] == 3:
                    tup['tlsa_usage_text'] = 'Domain issued certificate (and DANE-EE)'

                tup['tlsa_selector']     = int(clean_tlsa.split()[1])
                if tup['tlsa_selector'] == 0:
                    tup['tlsa_selector_text'] = 'select entire certificate'
                elif tup['tlsa_selector'] == 1:
                    tup['tlsa_selector_text'] = 'select public key'

                tup['tlsa_matchingtype'] = int(clean_tlsa.split()[2])
                if tup['tlsa_matchingtype'] == 0:
                    tup['tlsa_matchingtype_text'] = 'full data'
                if tup['tlsa_matchingtype'] == 1:
                    tup['tlsa_matchingtype_text'] = 'sha256 hash'
                if tup['tlsa_matchingtype'] == 2:
                    tup['tlsa_matchingtype_text'] = 'sha512 hash'

                tup['tlsa_cert_hash']    = clean_tlsa.split()[3]

            ## Add this tupple to the rrset representing array
            results['rrset'].append(tup)

            results['error'] = 'NOERROR'
        return results

    except (dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoMetaqueries,
            dns.resolver.NoNameservers,
            dns.resolver.NoRootSOA,
            dns.resolver.NotAbsolute,
            dns.resolver.YXDOMAIN,
            dns.exception.Timeout) as e:

        error = {}
        error['rdtype'] = r_type
        if fqdn.endswith('.'):
            error['qname'] = fqdn
        else:
            error['qname'] = fqdn + '.'

        if isinstance(e, dns.resolver.NXDOMAIN):
            error['error'] = 'NXDOMAIN'
        elif isinstance(e, dns.resolver.NoAnswer):
            error['error'] = 'NoAnswer'
        elif isinstance(e, dns.resolver.NoMetaqueries):
            error['error'] = 'NoMetaqueries'
        elif isinstance(e, dns.resolver.NoNameservers):
            error['error'] = 'NoNameservers'
        elif isinstance(e, dns.resolver.NoRootSOA):
            error['error'] = 'NoRootSOA'
        elif isinstance(e, dns.resolver.NotAbsolute):
            error['error'] = 'NotAbsolute'
        elif isinstance(e, dns.resolver.YXDOMAIN):
            error['error'] = 'YXDOMAIN'
        elif isinstance(e, dns.exception.Timeout):
            error['error'] = 'Timeout'
        else:
            error['error'] = 'unknown error'


    except EOFError:
        print("Resolver error: EOF Error.", 'FQDN', fqdn, 'r_type', r_type, file=sys.stderr)
        error = None

    except Exception as e:
        print("Resolver error:", e, 'FQDN', fqdn, 'r_type', r_type, file=sys.stderr)
        error = None

    return error



def dns_resolve_all_r_type(fqdn):
    # The rest, without CNAME
    #types = [ 'CNAME', 'SOA', 'A', 'NS', 'MD', 'MF', 'CNAME5', 'MB', 'MG', 'MR', 'NULL', 'WKS', 'PTR', 'HINFO', 'MINFO', 'MX', 'TXT', 'RP', 'AFSDB', 'X25', 'ISDN', 'RT', 'NSAP', 'NSAP_PTR', 'SIG', 'KEY', 'PX', 'GPOS', 'AAAA', 'LOC', 'NXT', 'SRV', 'NAPTR', 'KX', 'CERT', 'A6', 'DNAME', 'OPT', 'APL', 'DS', 'SSHFP', 'IPSECKEY', 'RRSIG', 'NSEC', 'DNSKEY', 'DHCID', 'NSEC3', 'NSEC3PARAM', 'TLSA', 'HIP', 'CDS', 'CDNSKEY', 'CSYNC', 'SPF', 'UNSPEC', 'EUI48', 'EUI64', 'TKEY', 'TSIG', 'IXFR', 'AXFR', 'MAILB', 'MAILA', 'ANY', 'URI', 'CAA', 'AVC', 'TA', 'DLV' ]
    types = [ 'CNAME', 'SOA', 'A', 'NS', 'MD', 'MF', 'MB', 'MG', 'MR', 'NULL', 'WKS', 'PTR', 'HINFO', 'MINFO', 'MX', 'TXT', 'RP', 'AFSDB', 'X25', 'ISDN', 'RT', 'NSAP', 'SIG', 'KEY', 'PX', 'GPOS', 'AAAA', 'LOC', 'NXT', 'SRV', 'NAPTR', 'KX', 'CERT', 'A6', 'DNAME', 'OPT', 'APL', 'DS', 'SSHFP', 'IPSECKEY', 'RRSIG', 'NSEC', 'DNSKEY', 'DHCID', 'NSEC3', 'NSEC3PARAM', 'TLSA', 'HIP', 'CDS', 'CDNSKEY', 'CSYNC', 'SPF', 'UNSPEC', 'EUI48', 'EUI64', 'TKEY', 'TSIG', 'IXFR', 'AXFR', 'MAILB', 'MAILA', 'ANY', 'URI', 'CAA', 'AVC', 'TA', 'DLV' ]
    types = [   'CNAME', 'SOA', 'A', 'AAAA', 'NS', \
                'MX', 'TXT', 'CAA', 'SRV', \
                'DS', 'NSEC3', 'NSEC', 'RRSIG' ]

    results = []

    for t in types:
        o = dns_resolve_r_type(fqdn, t)
        if o['error'] != 'NOERROR':
            continue

        results.append(o)

    return results
