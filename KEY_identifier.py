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
SE_Smart_Energy_Profile = 0x0109 # 265

def usage():
    print "%s Usage"%sys.argv[0]
    print "    -h: help"
    print "    -f <filename>: capture file with zigbee packets."
    print "    -d <directory name>: directory containing capture files with zigbee packets."
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
    ops = ['-f','-d','-D','-h']

    while len(sys.argv) > 1:
        op = sys.argv.pop(1)
        if op == '-f':
            #zb_file = sys.argv.pop(1)
            zb_files = [sys.argv.pop(1)]
        if op == '-d':
            dir_name = sys.argv.pop(1)
            zb_files = glob(os.path.abspath(os.path.expanduser(os.path.expandvars(dir_name))) + '/*.pcap')
        if op == '-D':
            DEBUG = True
        if op == '-h':
            usage()
        if op not in ops:
            print "Unknown option:",op
            usage()

    # Test for user input
    if not zb_files: usage()

    if DEBUG: print "\nProcessing files:",zb_files
    for zb_file in zb_files:
        print "\nProcessing file:",zb_file,""
        data = kbrdpcap(zb_file)
        num_pkts = len(data)

        # Pull Network Key from the file and use it
        net_info    = kbgetnetworkkey(data)
        if DEBUG and net_info: print "    Network Info:",net_info
        # If we found Network Key then save it. Else, roll with the default
        if net_info.has_key('key'): 
            network_key = ''.join(net_info['key'].split(':')).decode('hex')
            print "    Network Key Found:",network_key.encode('hex')
        else:
            print "    Network Key Not Found"
