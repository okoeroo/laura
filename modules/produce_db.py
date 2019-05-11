#!/usr/bin/env python3

from netaddr import *

import multiprocessing
import queue

import csv
import os
import sys

import sqlite3


if __name__ == "__main__":
    PATH = os.path.dirname(os.path.realpath(__file__)) + '/'
    DB_PATH = PATH + 'bgp_lookup.db'

    sqlite_conn = sqlite3.connect(DB_PATH)
    # Activate autocommit
    #sqlite_conn.isolation_level = None
    sqlite_cur = sqlite_conn.cursor()

    print("Dropping tables")
    sqlite_conn.execute('''DROP TABLE IF EXISTS ip2asn''')
    sqlite_conn.execute('''DROP TABLE IF EXISTS ipv4country''')
    sqlite_conn.execute('''DROP TABLE IF EXISTS ipv6country''')

    print("Creating tables")
    sqlite_conn.execute('''CREATE TABLE ip2asn (range_start TEXT, range_start_bits BLOB, range_end TEXT, range_end_bits BLOB, AS_number INT, country_code TEXT, AS_description TEXT)''')
    sqlite_conn.execute('''CREATE TABLE ipv4country (range_start TEXT, range_start_bits BLOB, range_end TEXT, range_end_bits BLOB, country_code TEXT)''')
    sqlite_conn.execute('''CREATE TABLE ipv6country (range_start TEXT, range_start_bits BLOB, range_end TEXT, range_end_bits BLOB, country_code TEXT)''')


    print("Read: ip2asn-combined.tsv")
    with open('ip2asn-combined.tsv') as csv_file:
        csv_reader = csv.reader(csv_file, delimiter='\t')
        for row in csv_reader:
            sql = ' '.join(["INSERT INTO ip2asn",
                                        "( range_start,  range_start_bits,  range_end,  range_end_bits,  AS_number,  country_code,  AS_description)",
                                 "VALUES (:range_start, :range_start_bits, :range_end, :range_end_bits, :AS_number, :country_code, :AS_description)"])

#            print(IPAddress(row[0]).packed)
#            print(bytes([int(IPAddress(row[0]).bin[2:], 2)]))
#            print(row)

            sqlite_cur.execute(sql,
                               {"range_start":row[0],
                                "range_start_bits":IPAddress(row[0]).packed,
                                "range_end":row[1],
                                "range_end_bits":IPAddress(row[1]).packed,
                                "AS_number":int(row[2]),
                                "country_code":row[3],
                                "AS_description":row[4]})

    print("Process: ip2asn-combined.tsv")
    sqlite_cur.execute("commit")

    print("Creating indexes")
    sqlite_conn.execute('''CREATE INDEX i_as_number ON ip2asn (AS_number)''')
    sqlite_conn.execute('''CREATE INDEX i_range_end_bits ON ip2asn (range_end_bits)''')
    sqlite_conn.execute('''CREATE INDEX i_range_start_bits ON ip2asn (range_start_bits)''')

#    sqlite_cur.execute("select range_start_bits from ip2asn")
#    print("select range_start_bits from ip2asn")
#    for row in sqlite_cur:
#        print(row)
#    sys.exit(1)

    print("Read: ip2country-v4.tsv")
    with open('ip2country-v4.tsv') as csv_file:
        csv_reader = csv.reader(csv_file, delimiter='\t')
        for row in csv_reader:
            sql = ' '.join(["INSERT INTO ipv4country",
                                        "( range_start,  range_start_bits,  range_end,  range_end_bits,  country_code)",
                                 "VALUES (:range_start, :range_start_bits, :range_end, :range_end_bits, :country_code)"])
            sqlite_cur.execute(sql,
                               {"range_start":row[0],
                                "range_start_bits":IPAddress(row[0]).packed,
                                "range_end":row[1],
                                "range_end_bits":IPAddress(row[1]).packed,
                                "country_code":row[2]})
    print("Process: ip2country-v4.tsv")
    sqlite_cur.execute("commit")


    print("Read: ip2country-v6.tsv")
    with open('ip2country-v6.tsv') as csv_file:
        csv_reader = csv.reader(csv_file, delimiter='\t')
        for row in csv_reader:
            sql = ' '.join(["INSERT INTO ipv6country",
                                        "(range_start, range_start_bits, range_end, range_end_bits, country_code)",
                                 "VALUES (:range_start, :range_start_bits, :range_end, :range_end_bits, :country_code)"])
            sqlite_cur.execute(sql,
                               {"range_start":row[0],
                                "range_start_bits":IPAddress(row[0]).packed,
                                "range_end":row[1],
                                "range_end_bits":IPAddress(row[1]).packed,
                                "country_code":row[2]})
    print("Process: ip2country-v6.tsv")
    sqlite_cur.execute("commit")




#            ipr = IPRange(row[0], row[1])

#            a = []
#            for c in ipr.cidrs():
#                a.append(str(c))

#            c = ",".join(a)
#            print(row[0], row[1], "--->", c)

