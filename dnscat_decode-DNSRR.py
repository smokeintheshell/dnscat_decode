#!/usr/bin/env python2
import sys
from scapy.all import rdpcap, DNSQR, DNSRR
import struct 

def dothis(filename):
    f = ''
    last = ''
    for p in rdpcap(filename):
        if p.haslayer(DNSRR) and len(p[DNSRR].rdata) > 22:
            prdata = str(p[DNSRR].rdata).replace(".point3.dev","").strip(".")
            prdata = str(prdata.replace(".",""))
            prdata = prdata.replace('[','')
            prdata = prdata.replace("'","")
            prdata = prdata.replace(']','')
#            prdata = prdata.replace("0a","")

            prdata = prdata[8:]
            print prdata.decode('hex')
            if last != prdata:
                print prdata
dothis(sys.argv[1])

