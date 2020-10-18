//---------------------------------------------------------
//
// fmadio pcap de-encapsuation utility
//
// Copyright (C) 2018-2019 fmad engineering llc aaron foo 
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
// automatic packet de-encapsulation 
//
//---------------------------------------------------------

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/ioctl.h>

#include "fTypes.h"
#include "fNetwork.h"

#include "decap.h"

bool g_DecapDump			= false;
bool g_DecapVerbose			= false;
bool g_DecapMetaMako		= false;
bool g_DecapIxia			= false;
bool g_DecapAristaInsert	= false;
bool g_DecapAristaOver		= false;
bool g_DecapExablaze		= false;


//---------------------------------------------------------------------------------------------
// error codes

static u64 	s_DecapErrorCnt[DECAP_ERROR_MAX];	// number of errors

static u64	s_GREProtoHistogram[0x10000];		// gre protocol histogram

//---------------------------------------------------------------------------------------------


void fDecap_Arista_Open		(int argc, char* argv[]);
void fDecap_ERSPAN3_Open	(int argc, char* argv[]);
void fDecap_MetaMako_Open	(int argc, char* argv[]);
void fDecap_Ixia_Open		(int argc, char* argv[]);
void fDecap_Exablaze_Open	(int argc, char* argv[]);

void fDecap_Arista_Close	(void);
void fDecap_ERSPAN3_Close	(void);
void fDecap_MetaMako_Close	(void);
void fDecap_Ixia_Close		(void);
void fDecap_Exablaze_Close	(void);

u16 fDecap_ERSPAN3_Unpack	(u64 TS, fEther_t** pEther, u8** pPayload, u32* pPayloadLength, u32* MetaPort, u64* MetaTS, u32* MetaFCS);
u16 fDecap_MetaMako_Unpack	(u64 PCAPTS, fEther_t** pEther, u8** pPayload, u32* pPayloadLength, u32* pMetaPort, u64* pMetaTS, u32* pMetaFCS);
u16 fDecap_Ixia_Unpack		(u64 PCAPTS, fEther_t** pEther, u8** pPayload, u32* pPayloadLength, u32* pMetaPort, u64* pMetaTS, u32* pMetaFCS);
u16 fDecap_Arista_Unpack	(u64 PCAPTS, fEther_t** pEther, u8** pPayload, u32* pPayloadLength, u32* pMetaPort, u64* pMetaTS, u32* pMetaFCS);
u16 fDecap_Exablaze_Unpack	(u64 PCAPTS, fEther_t** pEther, u8** pPayload, u32* pPayloadLength, u32* pMetaPort, u64* pMetaTS, u32* pMetaFCS);

//---------------------------------------------------------------------------------------------
/*
void fDecap_Mode(u32 Mode)
{
	// reset all
	g_DecapMetaMako 	= false;
	g_DecapIxia 		= false;
	g_DecapAristaInsert	= false;
	g_DecapAristaOver 	= false;

	trace("set decap mode: %i\n", Mode);

	switch (Mode)
	{
	case FNIC_PACKET_TSMODE_NIC:
		break;

	case FNIC_PACKET_TSMODE_MMAKO:
		g_DecapMetaMako = true;
		break;

	case FNIC_PACKET_TSMODE_IXIA:
		g_DecapIxia 	= true;
		break;

	case FNIC_PACKET_TSMODE_DANZ_INSERT:
		g_DecapAristaInsert = true;
		break;

	case FNIC_PACKET_TSMODE_DANZ_OVERWRITE:
		g_DecapAristaOver = true;
		break;

	default:
		trace("unknown decap mode\n");
		break;
	}
}
*/

//---------------------------------------------------------------------------------------------

void fDecap_Open(int argc, char* argv[])
{
	for (int i=1; i < argc; i++)
	{
		if (strcmp(argv[i], "-v") == 0)
		{
			fprintf(stderr, "Verbose Output\n");
			g_DecapVerbose = true;
		}
		else if (strcmp(argv[i], "-vv") == 0)
		{
			fprintf(stderr, "Dump Output\n");
			g_DecapDump = true;
		}
	}

	// packet meta data is explicit 
	fDecap_MetaMako_Open(argc, argv);
	fDecap_Exablaze_Open(argc, argv);
	fDecap_Arista_Open	(argc, argv);
	fDecap_Ixia_Open	(argc, argv);

	// protocol implicit in the payload 
	fDecap_ERSPAN3_Open(argc, argv);

	// reset error counts
	memset(s_DecapErrorCnt, 0, sizeof(s_DecapErrorCnt));

	// reset GRE histogram
	memset(s_GREProtoHistogram, 0, sizeof(s_GREProtoHistogram));
}

//---------------------------------------------------------------------------------------------

void fDecap_Close(void)
{
	// packet meta data is explicit 
	if (g_DecapAristaInsert = g_DecapAristaOver)	fDecap_Arista_Close		();

	if (g_DecapMetaMako) 	fDecap_MetaMako_Close	();
	if (g_DecapIxia) 		fDecap_Ixia_Close		();
	if (g_DecapExablaze) 	fDecap_Exablaze_Close	();

	// protocol implicit in the payload 
	fDecap_ERSPAN3_Close();

	// print any errors
	for (int i=0; i < DECAP_ERROR_MAX; i++)
	{
		if (s_DecapErrorCnt[i] == 0) continue;

		u8* Desc = "undef";
		switch (i)
		{
		case DECAP_ERROR_GRE_UNSUPPORTED	: Desc = "GRE_UNSUPPORTED"; 	break;
		case DECAP_ERROR_ERSPAN_UNSUPPORTED	: Desc = "ERSPAN_UNSUPPORTED"; 	break;
		case DECAP_ERROR_ERSPAN_TYPEII		: Desc = "ERSPAN_TYPE_II"; 		break;
		}
		fprintf(stderr, "Error: %10lli %s\n", s_DecapErrorCnt[i], Desc);
	}

	// print GRE histogram 
	fprintf(stderr, "GRE Histogram:\n");
	for (int i=0; i < 0x10000; i++)
	{
		if (s_GREProtoHistogram[i] == 0) continue;
		fprintf(stderr, "    %04x : %16lli\n", i, s_GREProtoHistogram[i]);
	}
}

//---------------------------------------------------------------------------------------------
// found an error, dont print per packet as it spewes alot of crap
void fDecap_Error(u32 Index)
{
	if (Index > DECAP_ERROR_MAX) return;

	s_DecapErrorCnt[Index]++;
}

//---------------------------------------------------------------------------------------------
// de-encapsulate a packet
u16 fDecap_Packet(	u64 PCAPTS,
					struct fEther_t** pEther, 

					u8** pPayload, 
					u32* pPayloadLength,

					u32* pMetaPort, 
					u64* pMetaTS, 
					u32* pMetaFCS)
{
	fEther_t* Ether = pEther[0];

	// get first level ether protocol 
	u16 EtherProto = swap16(Ether->Proto);
	//fprintf(stderr, "decap: %04x\n", EtherProto); 

	u8* Payload 			= pPayload[0];
	u32 PayloadLength 		= pPayloadLength[0];

	// because footers dont care about encasulation data
	// keep the original payload info 
	u8* OrigPayload 		= Payload; 
	u32 OrigPayloadLength 	= PayloadLength;

	// vlan decode
	if (EtherProto == ETHER_PROTO_VLAN)
	{
		VLANTag_t* Header 	= (VLANTag_t*)(Ether+1);
		u16* Proto 			= (u16*)(Header + 1);

		// update to the acutal proto / ipv4 header
		EtherProto 			= swap16(Proto[0]);
		Payload 			= (u8*)(Proto + 1);

		// VNTag unpack (BME) 
		if (EtherProto == ETHER_PROTO_VNTAG)
		{
			VNTag_t* Header = (VNTag_t*)(Proto+1);
			Proto 			= (u16*)(Header + 1);

			// update to the acutal proto / ipv4 header
			EtherProto 		= swap16(Proto[0]);
			Payload 		= (u8*)(Proto + 1);
		}

		// is it double tagged ? 
		if (EtherProto == ETHER_PROTO_VLAN)
		{
			Header 			= (VLANTag_t*)(Proto+1);
			Proto 			= (u16*)(Header + 1);

			// update to the acutal proto / ipv4 header
			EtherProto 		= swap16(Proto[0]);
			Payload 		= (u8*)(Proto + 1);
		}
	}

	// QinQ vlan double tag 
	if (EtherProto == ETHER_PROTO_802_1ad)
	{
		Q802_1ad_t* Header 	= (Q802_1ad_t*)(Ether+1);

		// update to the acutal proto / ipv4 header
		EtherProto 			= swap16(Header->Proto);
		Payload 			= (u8*)(Header + 1);

		// is it double tagged ? 
		if (EtherProto == ETHER_PROTO_VLAN)
		{
			VLANTag_t* Header	= (VLANTag_t*)(Payload);
			u16* Proto 			= (u16*)(Header + 1);

			// update to the acutal proto / ipv4 header
			EtherProto 			= swap16(Proto[0]);
			Payload 			= (u8*)(Proto + 1);
		}
	}

	// mpls decode 
	if (EtherProto == ETHER_PROTO_MPLS)
	{
		// find bottom of stack
		MPLSHeader_t* Header0 	= (MPLSHeader_t*)(Ether+1);
		MPLSHeader_t* Header1 	= Header0 + 1; 
		MPLSHeader_t* Header2 	= Header0 + 2; 
		MPLSHeader_t* Header3 	= Header0 + 3; 

		// assume its always IPv4 (tho could be IPv6)
		EtherProto 			= ETHER_PROTO_IPV4;

		// single tag
		if (Header0->BOS)
		{
			Payload 			= (u8*)(Header0 + 1);
		}
		// dobuble tag
		else if (Header1->BOS)
		{
			Payload 			= (u8*)(Header1 + 1);
		}
		// tripple tag
		else if (Header2->BOS)
		{
			Payload 			= (u8*)(Header2 + 1);
		}
		// quad tag
		else if (Header3->BOS)
		{
			Payload 			= (u8*)(Header3 + 1);
		}
	}

	// VNTag unpack (BME) 
	if (EtherProto == ETHER_PROTO_VNTAG)
	{
		VNTag_t* Header 	= (VNTag_t*)(Ether+1);
		u16* Proto 			= (u16*)(Header + 1);

		// update to the acutal proto / ipv4 header
		EtherProto 			= swap16(Proto[0]);
		Payload 			= (u8*)(Proto + 1);
	}

	// GRE/ERSPAN
	if (EtherProto == ETHER_PROTO_IPV4)
	{
		IPv4Header_t* IPv4Header = (IPv4Header_t*)Payload;

		if (IPv4Header->Proto == IPv4_PROTO_GRE)
		{
			GREHeader_t* GRE = (GREHeader_t*)((u8*)IPv4Header + IPv4Header->HLen*4);

			u32 GREProto = swap16(GRE->Proto);
			switch(GREProto)
			{
			case GRE_PROTO_ERSPAN2: 
			case GRE_PROTO_ERSPAN3: 
				return fDecap_ERSPAN3_Unpack(PCAPTS, pEther, pPayload, pPayloadLength, pMetaPort, pMetaTS, pMetaFCS);

			default:
				//trace("GRE Proto unsuported format: %x\n", GREProto);
				fDecap_Error(DECAP_ERROR_GRE_UNSUPPORTED);
				break;
			}

			// update histogram
			s_GREProtoHistogram[GREProto]++;
		}

		// VXLAN
		if (IPv4Header->Proto == IPv4_PROTO_UDP)
		{
			UDPHeader_t* UDP = (UDPHeader_t*)((u8*)IPv4Header + IPv4Header->HLen*4);

			// VXLAN decode
			switch ( swap16(UDP->PortDst))
			{
			case UDP_PORT_VXLAN:
			{
				VXLANHeader_t* VXLAN = (VXLANHeader_t*)(UDP + 1);
				//hfprintf(stderr, "VXLan %04x Group:%04x VNI:%06x\n", VXLAN->Flag, VXLAN->Group, VXLAN->VNI);


				fEther_t* EtherNew = (fEther_t*)(VXLAN + 1);
				u8* PayloadNew		= (u8*)(EtherNew + 1);

				pEther[0] 			= EtherNew; 
				pPayloadLength[0] 	-=  PayloadNew - pPayload[0];
				pPayload[0] 		= PayloadNew; 
			}
			break;
		
			// CAPWAP decode
			case UDP_PORT_CAPWAP_CMD:
			case UDP_PORT_CAPWAP_DAT:
			{
				CAPWAP_t* CAPWAP = (CAPWAP_t*)(UDP + 1);

				u32 RadioID		= (CAPWAP->_RID_Hi << 2) | CAPWAP->_RID_Lo;
				u32 WirelessID	= CAPWAP->WBID;
				u32 Offset		= CAPWAP->HLen * 4;

				IEEE802_11Header_t* IEEE802_11 = (IEEE802_11Header_t*)( (u8*)CAPWAP + Offset);

				// data payload is attached
				if ((swap16(IEEE802_11->FrameCtrl) & 0x00ff) == IEEE80211_FRAMECTRL_DATA)
				{
					IEEE802_LinkCtrl_t* LLC = (IEEE802_LinkCtrl_t*)(IEEE802_11 + 1);

					// update to the acutal proto / ipv4 header
					EtherProto 			= swap16(LLC->Proto);

					PayloadLength		-=(u8*)(LLC + 1) - Payload;
					Payload 			= (u8*)(LLC + 1);

					// update the ethernet address only. just the 2x6B on src/dst header 
					// ethernet protocl is specified with EtherProto 
					Ether 				= (fEther_t*)IEEE802_11->MACTransmitter;  

					//fprintf(stderr, "CAPWAN Proto:%04x\n", EtherProto);
				}	
			}
			break;
			}
		}
	}

	// set new Ether header (if any)
	pEther[0] 			= Ether;

	// set new IP header
	pPayload[0] 		= Payload;
	pPayloadLength[0]	= PayloadLength;

	// extract data from footers 
	if (g_DecapMetaMako)
	{
		fDecap_MetaMako_Unpack	(PCAPTS, pEther, &OrigPayload, &OrigPayloadLength, pMetaPort, pMetaTS, pMetaFCS);
	}
	if (g_DecapIxia)
	{
		fDecap_Ixia_Unpack		(PCAPTS,     pEther, &OrigPayload, &OrigPayloadLength, pMetaPort, pMetaTS, pMetaFCS);
	}
	if (g_DecapAristaInsert | g_DecapAristaOver)
	{
		fDecap_Arista_Unpack	(PCAPTS, pEther, pPayload, pPayloadLength, pMetaPort, pMetaTS, pMetaFCS);
	}
	if (g_DecapExablaze)
	{
		fDecap_Exablaze_Unpack	(PCAPTS, pEther, pPayload, pPayloadLength, pMetaPort, pMetaTS, pMetaFCS);
	}

	if (g_DecapDump) trace("\n");

	// update
	return EtherProto;
}
