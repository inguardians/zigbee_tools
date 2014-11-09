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
import os, sys
from glob import glob
###############################

###############################
# Processing Functions
###############################
# Defaults
DEBUG       = False
SHOW_RAW    = False
#zb_file     = None
zb_files    = []
find_key    = False
network_key = "\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf" # Network Key from zbgoodfind
cert_key    = None
SE_Smart_Energy_Profile = 0x0109 # 265

def usage():
    print "%s Usage"%sys.argv[0]
    print "    -h: help"
    print "    -f <filename>: capture file with zigbee packets."
    print "    -d <directory name>: directory containing capture files with zigbee packets."
    print "    -k <network_key>: Network Key in ASCII format. Will be converted for use."
    print "    -c <cert_key>: Certificate Key in ASCII format to decrypt Application Layer Data. Will be converted for use."
    print "    -K: find Network Key from capture file."
    print "    -D: Turn on debugging."
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
###############################

if __name__ == '__main__':

    # Process options
    ops = ['-f','-d','-k','-K','-c','-r','-D','-h']

    while len(sys.argv) > 1:
        op = sys.argv.pop(1)
        if op == '-f':
            #zb_file = sys.argv.pop(1)
            zb_files = [sys.argv.pop(1)]
        if op == '-d':
            dir_name = sys.argv.pop(1)
            zb_files = glob(os.path.abspath(os.path.expanduser(os.path.expandvars(dir_name))) + '/*.pcap')
        if op == '-k':
            network_key = sys.argv.pop(1).decode('hex')
        if op == '-K':
            find_key = True
        if op == '-c':
            cert_key = sys.argv.pop(1).decode('hex')
        if op == '-r':
            SHOW_RAW = True
        if op == '-D':
            DEBUG = True
        if op == '-h':
            usage()
        if op not in ops:
            print "Unknown option:",op
            usage()

    # Test for user input
    if not zb_files: usage()
    if not network_key: usage()

    if DEBUG: print "\nProcessing files:",zb_files,"\n"
    for zb_file in zb_files:
        if DEBUG: print "\nProcessing file:",zb_file,"\n"
        #print "\nProcessing file:",zb_file,"\n"
        data = kbrdpcap(zb_file)
        num_pkts = len(data)

        # Pull Network Key from the file and use it
        if find_key:
            if DEBUG: print "    Finding Network Key from capture file."
            net_info    = kbgetnetworkkey(data)
            if DEBUG: print "        Network Info:",net_info
            # If we found Network Key then save it. Else, roll with the default
            if net_info.has_key('key'): 
                network_key = ''.join(net_info['key'].split(':')).decode('hex')
                if DEBUG: "        Network Key Found:",network_key.encode('hex')
            else:
                if DEBUG: "        Network Key Not Found, using default value:",network_key.encode('hex')

        # Detect Encrypted Packets
        enc_pkts = []
        if DEBUG: print "    Find encrypted packets using network key:",network_key.encode('hex')
        for e in range(num_pkts):
            if detect_encryption(data[e]): 
                enc_pkts.append(e)
        if DEBUG: 
            if enc_pkts: 
                print "        Security Layer Found in packet numbers:",enc_pkts
            else:
                print "        No packets contain Security Layer. Exiting"
                #sys.exit()
                continue
        if DEBUG: print

        # Decrypt Packets
        if DEBUG: print "    Find packets with Application Layer."
        for e in enc_pkts:
            enc_data = kbdecrypt(data[e],network_key)
            if detect_app_layer(enc_data):
                if DEBUG: print "        Packet has Application Layer:",e
                #if DEBUG: print enc_data.summary,'\n'
                try:
                    if DEBUG: print "            Profile: %s"%scapy.layers.dot15d4._zcl_profile_identifier[enc_data.getlayer(ZigbeeAppDataPayload).fields['profile']]
                except:
                    if DEBUG: print "            Profile with unknown value:",hex(enc_data.getlayer(ZigbeeAppDataPayload).fields['profile'])
                if DEBUG: print
            else:
                if DEBUG: print "        Packet has no Application Layer:",e



