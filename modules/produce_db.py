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
    sqlite_conn.execute('''DROP TABLE ip2asn''')
    sqlite_conn.execute('''DROP TABLE ipv4country''')
    sqlite_conn.execute('''DROP TABLE ipv6country''')
    print("Creating tables")
    sqlite_conn.execute('''CREATE TABLE ip2asn (range_start TEXT, range_end TEXT, AS_number INT, country_code TEXT, AS_description TEXT)''')
    sqlite_conn.execute('''CREATE TABLE ip2asn (range_start TEXT, range_end TEXT, country_code TEXT)''')

    print("Read: ip2asn-combined.tsv")
    with open('ip2asn-combined.tsv') as csv_file:
        csv_reader = csv.reader(csv_file, delimiter='\t')
        for row in csv_reader:
            sql = ' '.join(["INSERT INTO ip2asn",
                                        "(range_start, range_end, AS_number, country_code, AS_description)",
                                 "VALUES (:range_start, :range_end, :AS_number, :country_code, :AS_description)"])
            sqlite_cur.execute(sql,
                               {"range_start":row[0],
                                "range_end":row[1],
                                "AS_number":int(row[2]),
                                "country_code":row[3],
                                "AS_description":row[4]})
    print("Process: ip2asn-combined.tsv")
    sqlite_cur.execute("commit")




#            ipr = IPRange(row[0], row[1])

#            a = []
#            for c in ipr.cidrs():
#                a.append(str(c))

#            c = ",".join(a)
#            print(row[0], row[1], "--->", c)

