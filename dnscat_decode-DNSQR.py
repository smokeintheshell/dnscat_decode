#!/usr/bin/env python2
import sys
from scapy.all import rdpcap, DNSQR, DNSRR
import struct 
def dothis(filename):
    f = ''
    last = ''
    for p in rdpcap(filename):
              if p.haslayer(DNSQR) and not p.haslayer(DNSRR):
                      qry = p[DNSQR].qname.replace(".point3.dev","").strip().split(".")
                      qry = ''.join(_.decode('hex') for _ in qry)[9:]
                      if last != qry:
                              print qry
                              f += qry
                      last = qry
    print f

dothis(sys.argv[1])
