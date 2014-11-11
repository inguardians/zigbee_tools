zigbee_tools
============

A few ZigBee Tools to compliment KillerBee. These tools leverage the KillerBee and Scapy-Com ZigBee Layer tools and functions.

## LAYER_identifier.py 
The Layer Identifier tool is designed to determine the different layers in a ZigBee packet. It will print a summary of each ZigBee packet and then print the different layers found in that packet. If the packet has encrypted layers and a key is provided the encrypted layers will be decrypted and the internal layers parsed.

```
user> python LAYER_identifier.py -h
LAYER_identifier.py Usage
    -h: help
    -f <filename>: capture file with zigbee packets.
    -d <directory name>: directory containing capture files with zigbee packets.
    -k <network_key>: Network Key in ASCII format. Will be converted for use.
    -D: Turn on debugging.
```

## APP_identifier.py 
The Application Identifier tool is designed to review each ZigBee packet and determine if it has an Application Layer. If so, the layer is reviewed to determine the type of Application Layer present.

```
user> python APP_identifier.py -h
APP_identifier.py Usage
    -h: help
    -f <filename>: capture file with zigbee packets.
    -d <directory name>: directory containing capture files with zigbee packets.
    -k <network_key>: Network Key in ASCII format. Will be converted for use.
    -K: find Network Key from capture file.
    -D: Turn on debugging.
```

## MOD_zb_pcap.py
The Modify ZigBee Pcap tool takes in a single ZigBee pcap file, identifies all extended and short addresses, and updates these with random values. This tool is used to obfuscate ZigBee capture files for sharing and analysis. Note: the addresses are NOT compliant with any manufacturer codes. 

```
user> python MOD_zb_pcap.py -h
MOD_zb_pcap.py Usage
    -h: help
    -f <filename>: capture file with zigbee packets.
    -o <filename>: file to write new zigbee packets.
    -D: Turn on debugging. This supresses writing to a file.
```

## ADDRESS_identifier.py
The Address Identification tool is designed to locate all of the extended and short addresses of ZigBee devices from a Pcap file. Currently this tool just spits out the addresses (which was needed for the MOD_zb_pcap.py tool). Future versions of this tool should identify ZigBee devices with specific roles.

```
user> python ADDRESS_identifier.py -h
ADDRESS_identifier.py Usage
    -h: help
    -f <filename>: capture file with zigbee packets.
    -d <directory name>: directory containing capture files with zigbee packets.
    -D: Turn on debugging.
```

## KEY_identifier.py
The Key Identifier tool searches a ZigBee Pcap file for a Network Key and prints it for the user. Future versions should include the identification of other keys and certs and whether or not additional encryption is being used by the devices on the ZigBee network.

```
user> python KEY_identifier.py -h
KEY_identifier.py Usage
    -h: help
    -f <filename>: capture file with zigbee packets.
    -d <directory name>: directory containing capture files with zigbee packets.
    -D: Turn on debugging.
```

## SEP_confirm.py
The Smart Energy Profile Confirmation tools is designed to review a ZigBee packet capture and determine if it contains SEP data. Detection of SEP data will very likely require decrypting the Network Layer. This tool will decrypt the Network Layer by using a Network Key provided by the user or by searching the packet capture for the key.

```
user> python SEP_confirm.py -h
SEP_confirm.py Usage
    -h: help
    -f <filename>: capture file with zigbee packets.
    -d <directory name>: directory containing capture files with zigbee packets.
    -k <network_key>: Network Key in ASCII format. Will be converted for use.
    -c <cert_key>: Certificate Key in ASCII format to decrypt Application Layer Data. Will be converted for use.
    -K: find Network Key from capture file.
    -D: Turn on debugging.
```

# InGuardians, Inc.
- http://www.inguardians.com
- http://labs.inguardians.com
