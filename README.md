Fast PCAP de-encapsulation tool

Supports:
- VLAN
- MPLS 
- VNTAG 
- ERSPAN v3

Roadmap:
- Metamako
- Arista DANZ
- Ixia Packet Broker

Usage:

Input is stdin
Output is stdout

Example:

cat erspan.pcap | pcap_decap > output.pcap

