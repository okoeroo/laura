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

    sqlite_cur.execute("SELECT range_start,  range_start_bits,  range_end,  range_end_bits,  AS_number,  country_code,  AS_description " +
                       "  FROM ip2asn " +
                       " WHERE range_start_bits <= :myip AND range_end_bits >= :myip AND AS_number <> 0",
                       {"myip":IPAddress('2001:610:120:1000::199:160').packed})
    for row in sqlite_cur:
        print(row)

    sqlite_cur.execute("SELECT range_start,  range_start_bits,  range_end,  range_end_bits,  AS_number,  country_code,  AS_description " +
                       "  FROM ip2asn " +
                       " WHERE AS_number = :asn",
                       {"asn":286})
    for row in sqlite_cur:
        print(row)


