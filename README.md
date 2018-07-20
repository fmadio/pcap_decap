![Alt text](http://fmad.io/analytics/logo_decap.png "fmadio pcap de-encapsulation utility")
[fmadio 10G 40G 100G Packet Capture](https://fmad.io)

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

