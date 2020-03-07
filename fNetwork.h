//---------------------------------------------------------
//
// fmadio pcap de-encapsuation utility
//
// Copyright (C) 2018 fmad engineering llc aaron foo 
// 
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//
//
// Common network packet types 
//
//---------------------------------------------------------

#ifndef  FMADIO_NETWORK_H
#define  FMADIO_NETWORK_H

// ethernet header
typedef struct fEther_t
{
	u8		Dst[6];
	u8		Src[6];
	u16		Proto;

} fEther_t;

#define ETHER_PROTO_IPV4		0x0800 
#define ETHER_PROTO_IPV6		0x86dd 
#define ETHER_PROTO_IP  		0x0888		// special made up type indicating ipv4 or ipv6 
#define ETHER_PROTO_VLAN		0x8100	
#define ETHER_PROTO_VNTAG		0x8926		// vntag / etag
#define ETHER_PROTO_MPLS		0x8847

typedef struct
{
	union
	{
		u32		IP4;	
		u8		IP[4];
	};

} IPv4_t;

typedef struct
{
	union
	{
#ifndef __LCPP_INDENT__
// luajit cant process u128
		u128	IP6;	
#endif
		u8		IP[16];
	};

} IPv6_t;

typedef struct
{
	u16			VIDhi	: 4;
	u16			DEI		: 1;
	u16			PCP		: 3;
	u16			VIDlo	: 8;

} __attribute__((packed)) VLANTag_t;
#define VLANTag_ID(a) (( a->VIDhi << 8 ) | a->VIDlo )

typedef struct
{
	u16			VIDhi	: 4;
	u16			DEI		: 1;
	u16			PCP		: 3;
	u16			VIDlo	: 8;

	u16		 	Proto;		

} __attribute__((packed)) VLANHeader_t;

// just skip the tag its 4 bytes + 2 bytes for the proto (2 more than a vlan tag)
typedef struct
{
	u8			pad[4];

} __attribute__((packed)) VNTag_t; 

// NOTE: the bit pattern is all fucked up due to it being bigedian structure with gcc bitfieds 
typedef struct
{
	u32			L0		: 8; 	// label[19:12]	
	u32			L1		: 8; 	// label[11:4]	


	u32			BOS		: 1;	
	u32			TC		: 3;	

	u32			L2		: 4;	// label[3:0]	

	u32			TTL		: 8;	

} __attribute__((packed)) MPLSHeader_t;

#define MPLS_LABEL(a)  ( (a->L0 << 12) | (a->L1<<4) | a->L2 )


#define IPv4_FLAG_RES			((1<<2) << 13)
#define IPv4_FLAG_NOFRAGMENT	((1<<1) << 13)
#define IPv4_FLAG_FRAGMENT		((1<<0) << 13)

#define IPv4_FRAGMENT_MASK		(0x1fff)

#define IPv4_PROTO_IGMP			2
#define IPv4_PROTO_TCP			6
#define IPv4_PROTO_UDP			17	
#define IPv4_PROTO_GRE			47	

#define TCP_FLAG_SYN(a) ((a >>(8+1))&1)
#define TCP_FLAG_ACK(a) ((a >>(8+4))&1)
#define TCP_FLAG_FIN(a) ((a >>(8+0))&1)

typedef struct
{
	u32		HLen  	 : 4;
	u32		Version	 : 4;
	u32		Service	 : 8;
	u32		Len		 : 16;
	u16		Ident;
	u16		Frag;
	u8		TTL;
	u8		Proto;
	u16		CSum;

	IPv4_t	Src;
	IPv4_t	Dst;

} __attribute__((packed)) IPv4Header_t;


#define IPv6_PROTO_IGMP			2
#define IPv6_PROTO_TCP			6
#define IPv6_PROTO_UDP			17	

typedef struct
{
	u32			Version			: 4;
	u32			TrafficClass	: 8;
	u32			Flow			: 20;

	u16			Length;
	u8			Proto;
	u8			Hop;

	IPv6_t		Src;
	IPv6_t		Dst;

} __attribute__((packed)) IPv6Header_t; 



typedef struct
{
	u16			PortSrc;
	u16			PortDst;
	u32			SeqNo;
	u32			AckNo;
	u16			Flags;
	u16			Window;
	u16			CSum;
	u16			Urgent;

} __attribute__((packed)) TCPHeader_t;


#define UDP_PORT_VXLAN			4789

#define UDP_PORT_CAPWAP_CMD		5256	
#define UDP_PORT_CAPWAP_DAT		5247	

typedef struct
{
	u16			PortSrc;
	u16			PortDst;
	u16			Length;
	u16			CSum;

} __attribute__((packed)) UDPHeader_t;

typedef struct
{
	u8			Type;
	u8			MaxRespTime;
	u16			CSum;

	u32			GroupAddress;

} __attribute__((packed)) IGMPv2_t;

typedef struct
{
	u8			Type;
	u8			MaxRespTime;
	u16			CSum;

	u32			GroupAddress;

	u16			Flags;
	u16			SrcCnt;

	u32			SrcAddress;

} __attribute__((packed)) IGMPv3Query_t;

typedef struct
{ 

	u8					RecordType;
	u8					AuxDat;
	u16					SrcCnt;
	IPv4_t				MulticastAddress;

} __attribute__((packed)) IGMPv3GroupRecord_t;


#define IGMP_RECTYPE_INCLUDE		3		// (leave)
#define IGMP_RECTYPE_EXCLUDE		4		// (join) yeah... its backwards

#define IGMP_TYPE_V2_REPORT			0x16	// igmp v2 report
#define IGMP_TYPE_V2_LEAVE			0x17	// igmp v2 leave 
#define IGMP_TYPE_v3_REPORT			0x22	// igmp v3 report messages

typedef struct
{
	u8					Type;
	u8					res0;
	u16					CSum;
	u16					res1;
	u16					GroupCnt;

	IGMPv3GroupRecord_t	Group[1];

} __attribute__((packed)) IGMPv3_Report_t;

// ARP header

#define ARPHRD_ETHER		1 

#define ARPOP_REQUEST		1               /* ARP request                  */
#define ARPOP_REPLY			2               /* ARP reply                    */
#define ARPOP_RREQUEST		3               /* RARP request                 */
#define ARPOP_RREPLY		4               /* RARP reply                   */
#define ARPOP_InREQUEST		8               /* InARP request                */
#define ARPOP_InREPLY		9               /* InARP reply                  */
#define ARPOP_NAK			10              /* (ATM)ARP NAK                 */

typedef struct
{
	u8			h_dest[6];			// destination ether addr */
	u8			h_source[6];		// source ether addr */
	u16			h_proto;			// packet type ID field */

	u16 		htype;				// hardware type (must be ARPHRD_ETHER)
	u16 		ptype;				// protocol type (must be ETH_P_IP)
	u8  		hlen;				// hardware address length (must be 6)
	u8  		plen;				// protocol address length (must be 4)
	u16 		operation;			// ARP opcode */

	u8  		SenderMAC[6];		// sender's hardware address
	u8  		SenderIP[4];		// sender's IP address

	u8  		TargetMAC[6];		// target's hardware address
	u8  		TargetIP[4];		// target's IP address

	u8  		pad[18];			// pad for min. Ethernet payload (60 bytes)

} ARPHeader_t;

typedef struct
{
	u8			h_dest[6];			// destination ether addr */
	u8			h_source[6];		// source ether addr */
	u16			h_proto;			// packet type ID field */

	VLANTag_t	vlan;				// vlan header
	u16			vlan_proto;			// packet type ID field */

	u16 		htype;				// hardware type (must be ARPHRD_ETHER)
	u16 		ptype;				// protocol type (must be ETH_P_IP)
	u8  		hlen;				// hardware address length (must be 6)
	u8  		plen;				// protocol address length (must be 4)
	u16 		operation;			// ARP opcode */

	u8  		SenderMAC[6];		// sender's hardware address
	u8  		SenderIP[4];		// sender's IP address
	
	u8  		TargetMAC[6];		// target's hardware address
	u8  		TargetIP[4];		// target's IP address

	u8  		pad[18];			// pad for min. Ethernet payload (60 bytes)

} ARPHeaderVLAN_t;



#define GRE_PROTO_ERSPAN2         0x88be
#define GRE_PROTO_ERSPAN3         0x22eb

typedef struct
{

    u32         Version : 4;
    u32         S       : 1;
    u32         K       : 1;
    u32         pad0    : 1;
    u32         C       : 1;

    u32         pad1    : 8;

    u32         Proto   : 16;

} __attribute__((packed)) GREHeader_t;

typedef union
{
    struct
    {
		u32         Session     : 10;
        u32         T           : 1;
        u32         BSO         : 2;
        u32         COS         : 3;
        u32         VLAN        : 12;
        u32         Version     : 4;

        u32         TS          : 32;

        u32         O           : 1;
        u32         Gra         : 2;
        u32         D           : 1;
        u32         HWID        : 6;
        u32         FT          : 5;
        u32         P           : 1;
        u32         SGT         : 16;

    } __attribute__((packed)) Header;
    u32 d32[5];

} __attribute__((packed)) ERSPANv3_t;

typedef union
{
    struct
    {
        u32         Session     : 10;
        u32         T           : 1;
        u32         En          : 2;
        u32         COS         : 3;
        u32         VLAN        : 12;
        u32         Version     : 4;

        u32         Index       : 20;
        u32         pad         : 12;

    } __attribute__((packed)) Header;
    u32 d32[2];

} __attribute__((packed)) ERSPANv2_t;

//------------------------------------------------------------------------------------------------------
//
// MetaMako timestamp format
//

// meta mako packet format
typedef struct MetaMakoFooter_t
{
	u32             OrigFCS;            // orignial FCS
	u32             Sec;                // timestamp secconds     (big endian)
	u32             NSec;               // timestamp nanoseconds  (big endian)
	u8              Flag;               // flags
	                                    // bit 0 : orig FCS is correct

	u16             DeviceID;           // metamako device id
	u8              PortID;             // metamako port number
	u32             MMakoFCS;           // packets new FCS generated by mmako

} __attribute__((packed)) MetaMakoFooter_t;


typedef struct ExablazeFooter_t
{
	u32		OrigFCS;		// originial FCS 
	u8		DeviceID;		// device id
	u8		PortID;			// port on the device
	u32		Sec;			// seccond timestamp 
	u32		NSec;			// subnano timestamp 
	u8		PSec;			// pico second 
	u8		pad0;
	u32		FCS;			// updated FCS

} __attribute__((packed)) ExablazeFooter_t; 

//------------------------------------------------------------------------------------------------------
//
// Ixia 4B footer 
//

typedef struct Ixia4BFooter_t 
{
	u32             Counter;      	// 200mhz clock counter 
	u32             FCS;            // FSC with the timestamp footer 

} __attribute__((packed)) Ixia4BFooter_t;


//------------------------------------------------------------------------------------------------------
//
// arista timestamp 
//
typedef struct
{
	u64			ASICTick;				// 1 tick is 20/7 nsec coresponds to UTCTime
	u64			UTCTime;				// in nano seconds

	u64			LastASIC;				// last sync?
	u64			SkewNum;				// ASIC Skew numerator
	u64			SkewDen;				// ASIC Skew denomitor 
	u64			ASICTS;					// ASIC TS of this key 
	u64			EgressIFDrop;			// egress interface fraqme drops... not sure what this means
	u16			DeviceID;				// DeviceID 
	u16			EgressIF;				// egress port 
	u8			FCSType;				// 0 - timestamp disabled 
										// 1 - timestamp appended + new FCS
										// 2 - timestamp overwrites FCS 
	u8			res0;

} __attribute__((packed)) AristaKeyFrame_t;

//------------------------------------------------------------------------------------------------------
// VXLan

typedef struct
{
	u32		Flag	: 16;
	u32		Group	: 16;
	u32		VNI		: 24;
	u32		Res1	: 8;

} __attribute__((packed)) VXLANHeader_t; 

//------------------------------------------------------------------------------------------------------
// CAPWAP

typedef struct
{
	u8		Preamble;	

	u16 	_RID_Hi: 	3,
			HLen: 		5,
			FLag: 		1,
			WBID: 		5,
			_RID_Lo: 	2;

	u8 		Flag_res: 	3,
			Flag_k: 	1,
			Flag_m: 	1,
			Flag_w: 	1,
			Flag_l: 	1,
			Flag_f: 	1;

	u16		FragID;
	u16 	FragOff;

} __attribute__((packed)) CAPWAP_t;

#define IEEE80211_FRAMECTRL_CMD			0x0004
#define IEEE80211_FRAMECTRL_DATA		0x0008
typedef struct
{
	u16		FrameCtrl;
	u16		DurationID;

	u8		MACReceiver		[6];
	u8		MACTransmitter	[6];
	u8		MACSrc			[6];

	u16	 	SeqCtrl;	

} __attribute__((packed)) IEEE802_11Header_t;

typedef struct 
{
	u8		DSAP;
	u8		SSAP;
	u8		Ctrl;
	u8		Org[3];
	u16		Proto;	

} __attribute__((packed)) IEEE802_LinkCtrl_t;
//------------------------------------------------------------------------------------------------------

static inline u32 IP4Address(u32 a, u32 b, u32 c, u32 d)
{
	return (a <<0) | (b << 8) | (c << 16) | (d << 24);
}

// Computing the internet checksum (RFC 1071).
// Note that the internet checksum does not preclude collisions.
static inline uint16_t IP4Checksum(u16 *addr, int len)
{
  s32 count = len;
  u32 sum = 0;
  u16 answer = 0;

  // Sum up 2-byte values until none or only one byte left.
  do
  {
    sum += addr[0];

   	addr += 1; 
    count -= 2;
  } while (count > 1);

  // Add left-over byte, if any.
  u8* addr8 = (u8*)addr;
  if (count > 0) {
    sum += addr8[0];
	addr8++;
  }

  // Fold 32-bit sum into 16 bits; we lose information by doing this,
  // increasing the chances of a collision.
  // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  // Checksum is one's compliment of sum.
  answer = ~sum;

  return (answer);
}

static u16 TCPSum16(IPv4Header_t* IPHeader, void* _D, u32 Len)
{
    u8* D   = (u8 *)_D;
    u32 Sum = 0;
    u8* E   = D + (Len&(~1));

    while (D < E)
    {
        u16 v = (D[1]<<8) | (D[0]);
        Sum += v;
        D += 2;
    }

    if (Len&1)
    {
        Sum += *D;
    }

    u16* Src = (u16*)&IPHeader->Src;
    u16* Dst = (u16*)&IPHeader->Dst;

    Sum += Src[0];
    Sum += Src[1];

    Sum += Dst[0];
    Sum += Dst[1];

    Sum += swap16(IPHeader->Proto);
    Sum += swap16(Len);

    while (Sum>>16)
	{
        Sum = (Sum & 0xFFFF) + (Sum >> 16);
	}

    return ~Sum;
}

static u16 UDPSum16(IPv4Header_t* IPHeader, void* _D, u32 Len)
{
    u8* D   = (u8 *)_D;
    u32 Sum = 0;
    u8* E   = D + (Len&(~1));

    while (D < E)
    {
        u16 v = (D[1]<<8) | (D[0]);
        Sum += v;
		if (Sum & 0x80000000)
		{
			Sum = (Sum & 0xffff) + (Sum >> 16);	
		}
        D += 2;
    }

    if (Len&1)
    {
        Sum += *D;
    }

    u16* Src = (u16*)&IPHeader->Src;
    u16* Dst = (u16*)&IPHeader->Dst;

    Sum += Src[0];
    Sum += Src[1];

    Sum += Dst[0];
    Sum += Dst[1];

    Sum += swap16(IPHeader->Proto);
    Sum += swap16(Len);

    while (Sum>>16)
	{
        Sum = (Sum & 0xFFFF) + (Sum >> 16);
	}

	// final sum
	u16 Ret = ~Sum;

	// special case some weird part of the UDP spec 
	//
	// Bugfix: A calculated UDP checksum of 0 should be set as 0xFFFF in the
    // frame as per RFC 768. A checksum value of 0 in the frame is "special" and 
	// indicates that no checksum was calculated and hence receiver should not verify 
	// the same. This special case seems to be only for UDP, not TCP though.
	//
	// https://github.com/cdm-work/ostinato/commit/144b369bac637e2a6b0f7dc223facbfd43b6e783
	if (Ret == 0)
	{
		Ret = 0xffff;
	}
    return Ret; 
}

static u16 IGMPSum16(u16* _D, u32 Len)
{
	u8* D   = (u8 *)_D;
    u32 Sum = 0;
    u8* E   = D + (Len&(~1));
    while (D < E)
    {
        u16 v = (D[1]<<8) | (D[0]);
        Sum += v;
        D += 2;
    }

    if (Len&1)
    {
        Sum += *D;
    }

    while (Sum>>16)
    {
        Sum = (Sum & 0xFFFF) + (Sum >> 16);
    }

    return ~Sum;

}

// always min payload size
static u32 IGMPPacketReport(	void* Buffer, 
						u32 RecType,
						u8 LocalIP0, u8 LocalIP1, u8 LocalIP2, u8 LocalIP3, 
						u8 MCGroup0, u8 MCGroup1, u8 MCGroup2, u8 MCGroup3)
{
	// ipv4 header
	IPv4Header_t* IPv4	= (IPv4Header_t*)Buffer;
	IPv4->Version		= 0x4; 
	IPv4->HLen			= 0x5; 
	IPv4->Service		= 0xc0; 
	IPv4->Len			= swap16(sizeof(IPv4Header_t) + sizeof(IGMPv3_Report_t) ); 
	IPv4->Ident			= 0; 
	IPv4->Frag			= 0; 
	IPv4->TTL			= 1; 				// must be TTL 1 for single hop igmp messages
	IPv4->Proto			= IPv4_PROTO_IGMP;

	IPv4->Src.IP[0]		= LocalIP0; 
	IPv4->Src.IP[1]		= LocalIP1; 
	IPv4->Src.IP[2]		= LocalIP2; 
	IPv4->Src.IP[3]		= LocalIP3; 

	IPv4->Dst.IP[0]		= 224; 				// this is join request group
	IPv4->Dst.IP[1]		= 0; 
	IPv4->Dst.IP[2]		= 0; 
	IPv4->Dst.IP[3]		= 22; 

	IPv4->CSum			= 0; 
	IPv4->CSum			= IP4Checksum( (u16*)IPv4, sizeof(IPv4Header_t) ); 

	// igmp report message
	IGMPv3_Report_t* IGMP					= (IGMPv3_Report_t*)(IPv4 + 1);
	IGMP->Type								= IGMP_TYPE_v3_REPORT;
	IGMP->res0								= 0;
	IGMP->res1								= 0;
	IGMP->GroupCnt							= swap16(1); 
	IGMP->Group[0].RecordType				= RecType; 
	IGMP->Group[0].AuxDat					= 0; 
	IGMP->Group[0].SrcCnt					= swap16(0); 
	IGMP->Group[0].MulticastAddress.IP[0]	= MCGroup0; 
	IGMP->Group[0].MulticastAddress.IP[1]	= MCGroup1; 
	IGMP->Group[0].MulticastAddress.IP[2]	= MCGroup2; 
	IGMP->Group[0].MulticastAddress.IP[3]	= MCGroup3; 

	IGMP->CSum								= 0;
	IGMP->CSum								= IGMPSum16( (u16*)IGMP, sizeof(IGMPv3_Report_t));

	return 64;
}

// always min payload size
static u32 IGMPv2PacketReport(	void* Buffer, 
								u32 RecType,
								u8 LocalIP0, u8 LocalIP1, u8 LocalIP2, u8 LocalIP3, 
								u8 MCGroup0, u8 MCGroup1, u8 MCGroup2, u8 MCGroup3)
{
	// ipv4 header
	IPv4Header_t* IPv4		= (IPv4Header_t*)Buffer;
	IPv4->Version			= 0x4; 
	IPv4->HLen				= 0x6; 
	IPv4->Service			= 0xc0; 
	IPv4->Len				= swap16(sizeof(IPv4Header_t) + 4 + sizeof(IGMPv2_t) ); 
	IPv4->Ident				= 0; 
	IPv4->Frag				= 0x2 << 5;
	IPv4->TTL				= 1; 				// must be TTL 1 for single hop igmp messages
	IPv4->Proto				= IPv4_PROTO_IGMP;

	IPv4->Src.IP[0]			= LocalIP0; 
	IPv4->Src.IP[1]			= LocalIP1; 
	IPv4->Src.IP[2]			= LocalIP2; 
	IPv4->Src.IP[3]			= LocalIP3; 

	IPv4->Dst.IP[0]			= MCGroup0; 				// this is join request group
	IPv4->Dst.IP[1]			= MCGroup1; 
	IPv4->Dst.IP[2]			= MCGroup2; 
	IPv4->Dst.IP[3]			= MCGroup3; 

	IPv4->CSum				= 0; 
	IPv4->CSum				= IP4Checksum( (u16*)IPv4, sizeof(IPv4Header_t) ); 

	/// Router Alert option
	u32* Option				= (u32*)(IPv4 + 1); 
	Option[0]				= 0x00000494;

	// igmp report message
	IGMPv2_t* IGMP			= (IGMPv2_t*)(Option+1);
	IGMP->Type				= RecType;
	IGMP->MaxRespTime		= 0;
	IGMP->GroupAddress		= (MCGroup3 << 24) | (MCGroup2 << 16) | (MCGroup1 << 8) | (MCGroup0 << 0); 
	IGMP->CSum				= 0;
	IGMP->CSum				= IGMPSum16( (u16*)IGMP, sizeof(IGMPv2_t) );

	return 64;
}

static u32 IGMPPacketJoin( 		void* Buffer, 
								u8 LocalIP0, u8 LocalIP1, u8 LocalIP2, u8 LocalIP3, 
								u8 MCGroup0, u8 MCGroup1, u8 MCGroup2, u8 MCGroup3)
{
	//return IGMPPacketReport(Buffer, IGMP_RECTYPE_EXCLUDE, LocalIP0, LocalIP1, LocalIP2, LocalIP3, MCGroup0, MCGroup1, MCGroup2, MCGroup3);
	return IGMPv2PacketReport(Buffer, IGMP_TYPE_V2_REPORT, LocalIP0, LocalIP1, LocalIP2, LocalIP3, MCGroup0, MCGroup1, MCGroup2, MCGroup3);
}

static u32  IGMPPacketLeave(	void* Buffer, 
								u8 LocalIP0, u8 LocalIP1, u8 LocalIP2, u8 LocalIP3, 
								u8 MCGroup0, u8 MCGroup1, u8 MCGroup2, u8 MCGroup3)
{
	//return IGMPPacketReport(Buffer, IGMP_RECTYPE_INCLUDE, LocalIP0, LocalIP1, LocalIP2, LocalIP3, MCGroup0, MCGroup1, MCGroup2, MCGroup3);
	return IGMPv2PacketReport(Buffer, IGMP_TYPE_V2_LEAVE, LocalIP0, LocalIP1, LocalIP2, LocalIP3, MCGroup0, MCGroup1, MCGroup2, MCGroup3);
}



#ifndef __LCPP_INDENT__		// luajit cant process this

//-------------------------------------------------------------------------------------------------
// FCS generator
/*
#define CRCPOLY2 0xEDB88320UL  // left-right reversal 
static unsigned long FCSCalculate(int n, unsigned char c[])
{
	int i, j;
	unsigned long r;

	r = 0xFFFFFFFFUL;
	for (i = 0; i < n; i++) {
		r ^= c[i];
		for (j = 0; j < CHAR_BIT; j++)
			if (r & 1) r = (r >> 1) ^ CRCPOLY2;
			else       r >>= 1;
	}
	return r ^ 0xFFFFFFFFUL;
}
*/
/* generated using the AUTODIN II polynomial
 *	x^32 + x^26 + x^23 + x^22 + x^16 +
 *	x^12 + x^11 + x^10 + x^8 + x^7 + x^5 + x^4 + x^2 + x^1 + 1
 */
static const u32 crctab[256] = 
{
	0x00000000, 0x77073096, 0xee0e612c, 0x990951ba,
	0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
	0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
	0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
	0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de,
	0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
	0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec,
	0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
	0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
	0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
	0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940,
	0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
	0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116,
	0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
	0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
	0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
	0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a,
	0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
	0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818,
	0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
	0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
	0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
	0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c,
	0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
	0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2,
	0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
	0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
	0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
	0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086,
	0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
	0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4,
	0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
	0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
	0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
	0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8,
	0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
	0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe,
	0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
	0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
	0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
	0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252,
	0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
	0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60,
	0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
	0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
	0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
	0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04,
	0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
	0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a,
	0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
	0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
	0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
	0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e,
	0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
	0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c,
	0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
	0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
	0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
	0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0,
	0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
	0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6,
	0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
	0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
	0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d,
};

#define CRC(crc, ch)	 (crc = (crc >> 8) ^ crctab[(crc ^ (ch)) & 0xff])
static unsigned long FCSCalculate(int Len, unsigned char* c)
{
	u32 crc 		= 0xffffffff;
	u32 crc32_total	= 0;
    crc32_total 	= ~crc32_total ;
	for (int i=0; i < Len; i++)
	{
		u32 b = c[i]; 
		crc = (crc >> 8) ^ crctab[(crc ^ (b)) & 0xff];
/*
u32 crc_swap = 0;
for (int j=0; j < 32; j++)
{
	crc_swap |= (((crc^0xffffffff) >> j) & 1) << (31 - j);
}
printf("%4i : %08x\n", i, crc ^ 0xffffffff, crc_swap);
*/

	}
	return crc ^ 0xffffffff;
}

//---------------------------------------------------------
// pcap headers

#define PCAPHEADER_MAGIC_NANO		0xa1b23c4d
#define PCAPHEADER_MAGIC_USEC		0xa1b2c3d4
#define PCAPHEADER_MAJOR			2
#define PCAPHEADER_MINOR			4
#define PCAPHEADER_LINK_ETHERNET	1
#define PCAPHEADER_LINK_ERF			197	

typedef struct
{

	u32				Magic;
	u16				Major;
	u16				Minor;
	u32				TimeZone;
	u32				SigFlag;
	u32				SnapLen;
	u32				Link;

} __attribute__((packed)) PCAPHeader_t;

typedef struct PCAPPacket_t
{
	u32				Sec;					// time stamp sec since epoch 
	u32				NSec;					// nsec fraction since epoch

	u32				LengthCapture;			// captured length, inc trailing / aligned data
	u32				LengthWire; 			// length on the wire 

} __attribute__((packed)) PCAPPacket_t;



#endif

#endif
