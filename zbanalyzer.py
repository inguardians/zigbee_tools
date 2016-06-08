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

# Set up color
conf.color_theme = ColorOnBlackTheme()

from killerbee import *
from killerbee.scapy_extensions import *    # this is explicit because I didn't want to modify __init__.py

del hexdump
from scapy.utils import hexdump             # Force using Scapy's hexdump()
import os, sys
from glob import glob
###############################

###############################
# Processing Functions
###############################
# TODO: Determine which variables should be set here and which should be set in main.
# Defaults
indent      = "    "
DEBUG       = False
zb_files    = []
find_key    = False
in_panid       = None
#network_key = "\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf" # Network Key from zbgoodfind
in_network_key = None
cert_key    = None
SE_Smart_Energy_Profile = 0x0109 # 265
cntlrs = {}
REPROS      = False
SHOW        = False
SINGLE        = False

def usage():
    print "%s Usage"%sys.argv[0]
    print "    -h: help"
    print "    -f <filename>: capture file with zigbee packets."
    print "    -d <directory>: directory with ZigBee capture files."
    print "    -p <panid>: Pan ID in ASCII format. Will be converted for use."
    print "    -k <network_key>: Network Key in ASCII format. Will be converted for use. Requires -p."
    print "    -R: Turn on reprocessing. This will parse for keys and addresses first then reprocess and print zbscapy parsed packets."
    print "    -s <packet number>: Print a single packet. Numbered from 0."
    print "    -S: Show all information that has been processed and stored."
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

def new_controller(cntlrs,cntlr,panid):
    if not cntlrs:
        if DEBUG: print "First Controller:",hex(cntlr),"which controls PAN ID:",hex(panid)
        cntlrs[cntlr] = Controller(cntlr)
        cntlrs[cntlr].pans.append(panid)
    else:
        if cntlrs.has_key(cntlr): 
            if panid not in cntlrs[cntlr].pans:
                cntlrs[cntlr].pans.append(panid)
        else:
            if DEBUG: print "New Controller:",hex(cntlr),"which controls PAN ID:",hex(panid)
            cntlrs[cntlr] = Controller(cntlr)
            cntlrs[cntlr].pans.append(panid)
    return

class Controller():

    def __init__(self, extended_addr, panid = None,network_key = None):
        self.extended_addr  = 0x0           # Controller extended address
        self.short_addr     = 0x0000        # Controller short_addr is always 0
        self.broadcast_addr = 0xffff        # Broadcast address is 0xffff. It might be others? 0xfffd
        self.pans           = []            # Personal Area Networks (PAN)
        self.end_nodes      = {}            # End-nodes are "extended_addr:short_addr"
        self.keys           = {}            # "panid:network_key","panid:transport_key","end_nodes.ext_addr:link_key"

        self.extended_addr = extended_addr

        # Test for panid if network key is provided
        if network_key and not panid:
            print "ERROR: Providing a network key also requires the network with which it is associated."
            print "ERROR: Please provide a panid.\n"
            usage()

        # Store user supplied panid and network_key
        if panid:
            self.pans.append(panid)
            if network_key:
                self.keys[panid] = network_key

    # print Controller information
    def __repr__(self):
        info = "\n###############################\n"
        info += "Controller: " + self.fmt_ext_addr(self.extended_addr) + '\n'
        # Print Pan IDs
        info += "    Pan IDs: \n"
        for e in self.pans:
            # Pan IDs can be formatted like short addresses
            info += "        " + self.fmt_sht_addr(e) + '\n'
        # Print End Nodes
        info += "    End Nodes: \n"
        for e in self.end_nodes.keys():
            info += "        " + self.fmt_ext_addr(e) + ":\n"
            for a in self.end_nodes[e]:
                if a: info += "            " + self.fmt_sht_addr(a) + '\n'
        # Print Encryption Keys
        info += "    Keys: \n"
        for e in self.keys.keys():
            if e: info += "        Pan ID " + hex(e) + ": " + self.keys[e].encode('hex') + '\n'

        info += "###############################\n"
        return info

    # Return Formatted Extended Address
    def fmt_ext_addr(self,addr):
        x = "%016x"%addr
        addr = ":".join(["%s%s" % (x[i], x[i+1]) for i in range(0,len(x),2)])
        return addr

    def fmt_sht_addr(self,addr):
        addr = "0x%04x"%addr
        #addr = ":".join(["%s%s" % (x[i], x[i+1]) for i in range(0,len(x),2)])
        return addr

    # Add end node
    def add_node(self,ext_addr,sht_addr):
        # Pcap could contain multiple short addresses
        if self.end_nodes.has_key(ext_addr):
            self.end_nodes[ext_addr].append(sht_addr)
        else:
            self.end_nodes[ext_addr] = [sht_addr]

    # Has end node
    def has_node(self,ext_addr=None,sht_addr=None):
        # If given extended address we can just test for that
        if ext_addr and self.end_nodes.has_key(ext_addr): return True
        # If given short address we have to loop through all extended addresses
        if sht_addr:
            for e in self.end_nodes.keys():
                if sht_addr in self.end_nodes[e]: return True
        # No end_node address found
        return False

    # Has Pan ID
    def has_panid(self,panid):
        if panid in self.pans:
            return True
        return False

    # Return Network Key
    def get_netKey(self,panid):
        #if panid in self.pans:
        if panid in self.pans and self.keys.has_key(panid):
            return self.keys[panid]
        return None

###############################

if __name__ == '__main__':

    # Process options
    ops = ['-f','-d','-k','-p','-R','-S','-s','-D','-h']

    while len(sys.argv) > 1:
        op = sys.argv.pop(1)
        if op == '-f':
            zb_files = [sys.argv.pop(1)]
        if op == '-d':
            dir_name = sys.argv.pop(1)
            zb_files = glob(os.path.abspath(os.path.expanduser(os.path.expandvars(dir_name))) + '/*.pcap')
        if op == '-k':
            in_network_key = sys.argv.pop(1).decode('hex')
        if op == '-p':
            in_panid = int(sys.argv.pop(1),16)
        if op == '-R':
            REPROS = True
        if op == '-S':
            SHOW = True
        if op == '-s':
            SINGLE = True
            #in_pkt_num = int(sys.argv.pop(1),16)
            in_pkt_num = int(sys.argv.pop(1),10)
        if op == '-D':
            DEBUG = True
        if op == '-h':
            usage()
        if op not in ops:
            print "Unknown option:",op
            usage()

    # Test for user input
    if not zb_files: usage()
    if in_network_key and not in_panid: usage()

    # Process file
    for zb_file in zb_files:
        if DEBUG: print "\nProcessing file:",zb_file,"\n"
        #print "\nProcessing file:",zb_file,"\n"
        data = kbrdpcap(zb_file)
        num_pkts = len(data)


        # There are various ways to identify controllers, pans, and end_nodes
        for e in data:
            # Reset for when analyzing multiple files
            panid       = None
            network_key = None
            cert_key    = None

            # Find controllers using Beacon Frames.
            if e.haslayer(Dot15d4Beacon):
                cntlr = e.getlayer(ZigBeeBeacon).fields['extended_pan_id']
                panid = e.getlayer(Dot15d4Beacon).fields['src_panid']
                # Test for and store controller
                new_controller(cntlrs,cntlr,panid)
                continue

            # Find controllers from Security Headers (helps if there are no beacon frames)
            if e.haslayer(ZigbeeNWK):
                if 'ext_src' in e.getlayer(ZigbeeNWK).fields: 
                    panid = e.getlayer(Dot15d4Data).fields['dest_panid']
                    cntlr = e.getlayer(ZigbeeNWK).fields['ext_src']
                    # Test for Controller identified as 0x0 and skip
                    if not cntlr: continue
                    # Test for and store controller
                    new_controller(cntlrs,cntlr,panid)

        # Process Again for nodes and keys
        for e in data:
            # Find Association packets and get new end nodes
            if e.haslayer(Dot15d4CmdAssocResp):
                # Grab packet data
                cntlr    = e.getlayer(Dot15d4Cmd).fields['src_addr']
                panid    = e.getlayer(Dot15d4Cmd).fields['dest_panid']
                end_node_ext = e.getlayer(Dot15d4Cmd).fields['dest_addr']
                end_node_sht = e.getlayer(Dot15d4CmdAssocResp).fields['short_address']
                # Test for and store controller
                new_controller(cntlrs,cntlr,panid)
                # Update controller with new end_node
                if not cntlrs[cntlr].has_node(sht_addr=end_node_sht):
                    cntlrs[cntlr].add_node(end_node_ext,end_node_sht)

            # We can find end nodes extended addresses from encrypted packets to controller
            if e.haslayer(ZigbeeSecurityHeader):
                if not e.getlayer(Dot15d4Data).fields['dest_addr']:
                    end_node_ext = e.getlayer(ZigbeeSecurityHeader).fields['source']
                    end_node_sht = e.getlayer(Dot15d4Data).fields['src_addr']
                    panid = e.getlayer(Dot15d4Data).fields['dest_panid']
                    # Find cntlr with this end_node
                    for c in cntlrs.keys():
                        if cntlrs[c].has_panid(panid):
                            if not cntlrs[c].has_node(ext_addr=end_node_ext,sht_addr=None):
                            #if not cntlrs[c].has_node(sht_addr=end_node_sht):
                                cntlrs[c].add_node(end_node_ext,end_node_sht)

            # Grab network key if available
            APS_CMD_TRANSPORT_KEY = 5       # TODO: determine if this is set in Scapy-com dot15d4 zigbee layer
            if e.haslayer(ZigbeeAppCommandPayload):
                # Check to see if the Command Idenfier indicates this is a network/transport key
                if e.getlayer(ZigbeeAppCommandPayload).fields['cmd_identifier'] == APS_CMD_TRANSPORT_KEY:
                    #cntlr = struct.unpack('<Q',e.getlayer(ZigbeeAppCommandPayload).fields['data'][26:34])[0]
                    #cntlr = struct.unpack('<Q',e.getlayer(ZigbeeAppCommandPayload).fields['key_src_address'])
                    cntlr = e.getlayer(ZigbeeAppCommandPayload).fields['key_src_address']
                    panid = e.getlayer(Dot15d4Data).fields['dest_panid']
                    # Test for and store controller
                    new_controller(cntlrs,cntlr,panid)
                    # Set Network Key associated with the Pan ID
                    if DEBUG: print "FOUND KEY IN PACKET:",str(data.index(e))
                    #cntlrs[cntlr].keys[panid] = e.getlayer(ZigbeeAppCommandPayload).fields['data'][1:17]
                    cntlrs[cntlr].keys[panid] = e.getlayer(ZigbeeAppCommandPayload).fields['key']

        for e in cntlrs:
            if in_panid not in cntlrs[e].keys.keys():
                if DEBUG and in_network_key and in_panid: print "Adding user input network key:",in_network_key.encode('hex'),"for PAN ID:",in_panid
                #cntlrs[e].keys[in_panid] = in_network_key.decode('hex')
                cntlrs[e].keys[in_panid] = in_network_key
            

    # Show addresses if requested. Might not want to show if reprocessing packets
    if SHOW:
        for e in cntlrs.keys():
            print repr(cntlrs[e])

    # Should we reprocess the files and print the packets?
    if not REPROS:
        sys.exit()

    # Reprocessing in order may be desired because of network keys and other data.
    # If so, rename files so that they are processed in the appropriate order.
    print "##############################################"
    print "# Reprocessing pcaps "
    print "# NOTE: Directory read may not be in order"
    print "##############################################"

    # Reprocess files to decrypt data
    for zb_file in zb_files:
        #if DEBUG: print "\nProcessing file:",zb_file,"\n"
        print "##############################################"
        print "Processing file:",zb_file
        print "##############################################"
        data = kbrdpcap(zb_file)
        num_pkts = len(data)

        for p in range(len(data)):
            # Reset for when analyzing multiple files
            panid       = None
            network_key = None
            cert_key    = None
            source      = ''
            # TODO: This method for printing a single packet is inefficient. Fix
            # TODO: Also, this should be a range.
            if SINGLE and not p == in_pkt_num:
                continue
            print str(p) + ":",repr(data[p]),'\n'
            # ZigBee Security Header indicates an encrypted packet
            if data[p].haslayer(ZigbeeSecurityHeader):
                # Check for source, if 0x0 then we need to determine cntlr origin
                panid = data[p].getlayer(Dot15d4Data).fields['dest_panid']
                source = data[p].getlayer(ZigbeeSecurityHeader).fields['source']
                for k in cntlrs.keys():
                    if panid in cntlrs[k].pans:
                        if source == '' or source == 0x0: source = k
                        network_key = cntlrs[k].get_netKey(panid)
                if not network_key:
                    if DEBUG: print "    No Network Key for PANID:",hex(panid),'\n'
                    continue
                    
                # kbdecrypt2 provides the ability to input a source address in case it is necessary for decrypting packets
                #ed = kbdecrypt2(data[p],network_key.decode('hex'),source=source,verbose=3)
                ##ed = kbdecrypt2(data[p],network_key,source=source,verbose=3)
                #ed = kbdecrypt2(data[p],network_key,source=source)
                ed = kbdecrypt(data[p],network_key,verbose=3)
                print str(p),"Enc Data:",repr(ed) + '\n'
                if ed == '': continue
                if DEBUG and ed.haslayer(Raw): print "    Raw:",ed.getlayer(Raw).fields['load'].encode('hex') + '\n'
                # TODO: Remove if unnecessary
                # This is old code. I doubt anything will have a second security layer. But, just in case
                # Additional ZigBee Security Header indicates additional data
                if ed.haslayer(ZigbeeSecurityHeader):
                    ##ed2 = kbdecrypt2(ed,network_key.decode('hex'),source=source,verbose=3)
                    #ed2 = kbdecrypt2(ed,network_key,source=source,verbose=3)
                    #ed2 = kbdecrypt2(ed,network_key,source=source)
                    #ed2 = kbdecrypt2(ed.get_layer(ZigbeeAppSec).fields['data'],network_key,source=source,verbose=3)
                    ed2 = kbdecrypt(ed,network_key.decode('hex'),verbose=3)
                    print str(p),"Enc2 Data:",repr(ed2) + '\n'
                    if DEBUG and ed2.haslayer(Raw): print "    Raw2:",ed2.getlayer(Raw).fields['load'].encode('hex') + '\n'

    print "##############################################"
    print "# Done: Reprocessing pcaps "
    print "##############################################"

