zigbee_tools
============

A few ZigBee Tools to compliment KillerBee. These tools leverage the KillerBee and Scapy-Com ZigBee Layer tools and functions.

# LAYER_identifier.py 
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

# APP_identifier.py 
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

# SEP_confirm.py
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
