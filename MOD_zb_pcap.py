#! /usr/bin/env python

###############################
# Imports taken from zbscapy
###############################

# Import logging to suppress Warning messages
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
	from scapy.all import *
except ImportError:
	print 'This Requires Scapy To Be Installed.'
	from sys import exit
	exit(-1)

from killerbee import *
from killerbee.scapy_extensions import *	# this is explicit because I didn't want to modify __init__.py

del hexdump
from scapy.utils import hexdump				# Force using Scapy's hexdump()
import os, sys, struct
from glob import glob
###############################

###############################
# Processing Functions
###############################
# Defaults
indent      = "    "
DEBUG       = False
SHOW_RAW    = False
zb_file     = None
zb_output   = None
find_key    = False
cert_key    = None
SE_Smart_Energy_Profile = 0x0109 # 265

# Dictionaries may not be processed in order. Therefore, these must be separate lists
ZB_Layers = [ \
    Dot15d4, \
    Dot15d4FCS, \
    Dot15d4Beacon, \
    Dot15d4Data, \
    Dot15d4Ack, \
    Dot15d4Cmd, \
    ZigbeeNWK, \
    ZigBeeBeacon, \
    ZigbeeSecurityHeader, \
    ZigbeeAppDataPayload, \
    ZigbeeAppCommandPayload, \
]
ZB_Layers_Names = [ \
    "Dot15d4", \
    "Dot15d4FCS", \
    "Dot15d4Beacon", \
    "Dot15d4Data", \
    "Dot15d4Ack", \
    "Dot15d4Cmd", \
    "ZigbeeNWK", \
    "ZigBeeBeacon", \
    "ZigbeeSecurityHeader", \
    "ZigbeeAppDataPayload", \
    "ZigbeeAppCommandPayload" \
]

# Addresses
zb_addrs = { \
    'src_addr':'00:00:00:00:00:00', \
    'dest_addr':'00:00:00:00:00:00', \
    'extended_pan_id':'00:00:00:00:00:00', \
    'src_addr':0xffff, \
    'source':'00:00:00:00:00:00', \
    #'source':0xffff, \
    'src_panid':0xffff, \
    'ext_src':'00:00:00:00:00:00', \
    'dest_panid':0xffff, \
    'dest_addr':0x0, \
    'destination':0xffff \
}
addr_names = zb_addrs.keys()

def usage():
    print "%s Usage"%sys.argv[0]
    print "    -h: help"
    print "    -f <filename>: capture file with zigbee packets."
    print "    -o <filename>: file to write new zigbee packets."
    print "    -D: Turn on debugging. This supresses writing to a file."
    sys.exit()

def detect_encryption(pkt):
    '''detect_entryption: Does this packet have encrypted information? Return: True or False'''
    if not pkt.haslayer(ZigbeeSecurityHeader) or not pkt.haslayer(ZigbeeNWK):
        return False
    return True

def detect_app_layer(pkt):
    '''detect_entryption: Does this packet have encrypted information? Return: True or False'''
    if not pkt.haslayer(ZigbeeAppDataPayload):
        return False
    return True

def detect_layer(pkt,layer):
    '''detect_entryption: Does this packet have encrypted information? Return: True or False'''
    #if not pkt.haslayer(ZigbeeAppDataPayload):
    if not pkt.haslayer(layer):
        return False
    return True
###############################

if __name__ == '__main__':

    # Process options
    ops = ['-f','-o','-D','-h']

    while len(sys.argv) > 1:
        op = sys.argv.pop(1)
        if op == '-f':
            # Users can only update one pcap file per run
            zb_file = sys.argv.pop(1)
        if op == '-o':
            zb_output = sys.argv.pop(1)
        if op == '-D':
            DEBUG = True
        if op == '-h':
            usage()
        if op not in ops:
            print "Unknown option:",op
            usage()

    # Test for user input
    if not zb_file: usage()
    if not zb_output: usage()
    new_addr = {}

    if DEBUG: print "\nProcessing file:",zb_file,"\n"
    if DEBUG: print "\nOutput file:",zb_output,"\n"
    data = kbrdpcap(zb_file)
    num_pkts = len(data)

    for e in range(num_pkts):
        print data[e].summary()

    # Process Pcap File
    if DEBUG: print indent + "Processing Pcap File"
    for e in range(num_pkts):
        if DEBUG: print indent  + str(e),repr(data[e]),"\n"

        # Process each layer individually
        for l in ZB_Layers:
            if detect_layer(data[e],l): 
                fields = data[e].getlayer(l).fields
                # Look for all of the possible address fields
                for a in addr_names:
                    if fields.has_key(a) and fields[a]: 
                        val = fields[a]
                        # If this is an extended address then we have to split
                        if val > 0xffff:
                            if not new_addr.has_key(val): new_addr[val] = randbytes(8)
                            val = int(new_addr[val].encode('hex'),16)
                        else:
                            # Avoid broadcast short addresses
                            if val < 0xfff0 and not (val == 0):
                                if not new_addr.has_key(val): new_addr[val] = randbytes(2)
                                val = int(new_addr[val].encode('hex'),16)
                        data[e].getlayer(l).fields[a] = val

    # Write results
    if DEBUG: 
        print ""
        print "Results not written to output file in debug mode:",zb_output
        print "New Addresses:",new_addr
        print ""
        print "New Packets"
        for e in range(num_pkts):
            print indent + "new_" + str(e),repr(data[e]),"\n"

    # Write new file
    if not DEBUG: 
        print "Sending output to new pcap file:",zb_output
        kbwrpcap(zb_output,data)

