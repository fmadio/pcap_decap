![Alt text](http://fmad.io/analytics/logo_decap.png "fmadio pcap de-encapsulation utility")

[fmadio 10G 40G 100G Packet Capture](https://fmad.io)

Fast PCAP de-encapsulation tool. Utility removes ecnapsuation from packets, and also updates any timestamp in the PCAP with any specialized header/footer. This provides more accurate timestamps at the ingress port instead of at the capture port.

Supports:
- VLAN
- MPLS 
- VNTAG 
- ERSPAN v3 Timestamp
- Metamako TimeStamp

Experimental
- Ixia X40 Stream Packet Broker Timestamp
- Arista DANZ TimeStamp

Roadmap:
- Ask! -> support@fmad.io

Usage:

Input is stdin

Output is stdout

Example:

cat erspan.pcap | pcap_decap > output.pcap

```
PCAP De-encapsuation : FMADIO 10G 40G 100G Packet Capture : http://www.fmad.io
pcap_decap

Command works entirely based linux input / ouput pipes.
For example:
$ cat erspan.pcap | pcap_decap > output.pcap

Options:
-v                 : verbose output
-vv                : dump every packet

Protocols:
--metamako         : assume every packet has metamako footer
--ixia             : Ixia X40 Stream. replace FCS with a TS
--arista           : Arista DANZ replace FCS with a TS

```
