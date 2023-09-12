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

/*
bool g_DecapDump				= false;
bool g_DecapVerbose				= false;
bool g_DecapMetaMako			= false;
bool g_DecapIxia				= false;
bool g_DecapArista7150Insert	= false;
bool g_DecapArista7150Over		= false;
bool g_DecapArista7280MAC48		= false;
bool g_DecapArista7280ETH64		= false;
bool g_DecapExablaze			= false;

//---------------------------------------------------------------------------------------------
// error codes

static u64 	s_DecapErrorCnt[DECAP_ERROR_MAX];	// number of errors

static u64	s_GREProtoHistogram[0x10000];		// gre protocol histogram
*/

//---------------------------------------------------------------------------------------------


void fDecap_Arista7150_Open		(fDecap_t* D, int argc, char* argv[]);
void fDecap_Arista7280_Open		(fDecap_t* D, int argc, char* argv[]);
void fDecap_Arista7130_Open		(fDecap_t* D, int argc, char* argv[]);
void fDecap_ERSPAN3_Open		(fDecap_t* D, int argc, char* argv[]);
void fDecap_Ixia_Open			(fDecap_t* D, int argc, char* argv[]);
void fDecap_Cisco3550_Open		(fDecap_t* D, int argc, char* argv[]);

void fDecap_Arista7150_Close	(fDecap_t* D);
void fDecap_Arista7280_Close	(fDecap_t* D);
void fDecap_Arista7130_Close	(fDecap_t* D);
void fDecap_ERSPAN3_Close		(fDecap_t* D);
void fDecap_Ixia_Close			(fDecap_t* D);
void fDecap_Cisco3550_Close		(fDecap_t* D);

u16 fDecap_ERSPAN3_Unpack		(fDecap_t* D, u64 TS, fEther_t** pEther, u8** pPayload, u32* pPayloadLength, u32* MetaPort, u64* MetaTS, u32* MetaFCS);
u16 fDecap_Ixia_Unpack			(fDecap_t* D, u64 PCAPTS, fEther_t** pEther, u8** pPayload, u32* pPayloadLength, u32* pMetaPort, u64* pMetaTS, u32* pMetaFCS);
u16 fDecap_Arista7130_Unpack	(fDecap_t* D, u64 PCAPTS, fEther_t** pEther, u8** pPayload, u32* pPayloadLength, u32* pMetaPort, u64* pMetaTS, u32* pMetaFCS);
u16 fDecap_Arista7150_Unpack	(fDecap_t* D, u64 PCAPTS, fEther_t** pEther, u8** pPayload, u32* pPayloadLength, u32* pMetaPort, u64* pMetaTS, u32* pMetaFCS);
u16 fDecap_Arista7280_Unpack	(fDecap_t* D, u64 PCAPTS, fEther_t** pEther, u8** pPayload, u32* pPayloadLength, u32* pMetaPort, u64* pMetaTS, u32* pMetaFCS);
u16 fDecap_Cisco3550_Unpack		(fDecap_t* D, u64 PCAPTS, fEther_t** pEther, u8** pPayload, u32* pPayloadLength, u32* pMetaPort, u64* pMetaTS, u32* pMetaFCS);

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

fDecap_t* fDecap_Open(int argc, char* argv[])
{
	fDecap_t* D = malloc(sizeof(fDecap_t));
	memset(D, 0, sizeof(fDecap_t));

	for (int i=1; i < argc; i++)
	{
		if (strcmp(argv[i], "-v") == 0)
		{
			fprintf(stderr, "Verbose Output\n");
			D->DecapVerbose = true;
		}
		else if (strcmp(argv[i], "-vv") == 0)
		{
			fprintf(stderr, "Dump Output\n");
			D->DecapDump = true;
		}

	}

	// packet meta data is explicit 
	fDecap_Arista7130_Open	(D, argc, argv);
	fDecap_Arista7150_Open	(D, argc, argv);
	fDecap_Arista7280_Open	(D, argc, argv);
	fDecap_Cisco3550_Open	(D, argc, argv);
	fDecap_Ixia_Open		(D, argc, argv);

	// protocol implicit in the payload 
	fDecap_ERSPAN3_Open		(D, argc, argv);

	// reset error counts
	memset(D->DecapErrorCnt, 0, sizeof(D->DecapErrorCnt));

	// reset GRE histogram
	memset(D->GREProtoHistogram, 0, sizeof(D->GREProtoHistogram));

	return D;
}

//---------------------------------------------------------------------------------------------

void fDecap_Close(fDecap_t* D)
{
	// packet meta data is explicit 
	if (D->DecapArista7150Insert || D->DecapArista7150Over)		fDecap_Arista7150_Close		(D);
	if (D->DecapArista7280MAC48  || D->DecapArista7280ETH64)	fDecap_Arista7280_Close		(D);

	if (D->DecapArista7130) fDecap_Arista7130_Close	(D);
	if (D->DecapIxia) 		fDecap_Ixia_Close		(D);
	if (D->DecapCisco3550) 	fDecap_Cisco3550_Close	(D);

	// protocol implicit in the payload 
	fDecap_ERSPAN3_Close(D);

	// print any errors
	for (int i=0; i < DECAP_ERROR_MAX; i++)
	{
		if (D->DecapErrorCnt[i] == 0) continue;

		u8* Desc = "undef";
		switch (i)
		{
		case DECAP_ERROR_GRE_UNSUPPORTED	: Desc = "GRE_UNSUPPORTED"; 	break;
		case DECAP_ERROR_ERSPAN_UNSUPPORTED	: Desc = "ERSPAN_UNSUPPORTED"; 	break;
		case DECAP_ERROR_ERSPAN_TYPEII		: Desc = "ERSPAN_TYPE_II"; 		break;
		}
		fprintf(stderr, "Error: %10lli %s\n", D->DecapErrorCnt[i], Desc);
	}

	// print GRE histogram 
	fprintf(stderr, "GRE Histogram:\n");
	for (int i=0; i < 0x10000; i++)
	{
		if (D->GREProtoHistogram[i] == 0) continue;
		fprintf(stderr, "    %04x : %16lli\n", i, D->GREProtoHistogram[i]);
	}
}

//---------------------------------------------------------------------------------------------
// found an error, dont print per packet as it spewes alot of crap
void fDecap_Error(fDecap_t* D, u32 Index)
{
	if (Index > DECAP_ERROR_MAX) return;

	D->DecapErrorCnt[Index]++;
}

//---------------------------------------------------------------------------------------------
// de-encapsulate a packet
u16 fDecap_Packet(	fDecap_t* D,	
					u64 PCAPTS,
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
	if ((EtherProto == ETHER_PROTO_VLAN) 	 ||  		//origial tastey vlan
		(EtherProto == ETHER_PROTO_VLAN9100) ||  		// an old kind of QnQ style tag
		(EtherProto == ETHER_PROTO_VLAN9200) 	 		// another variation of QnQ
	){
		VLANTag_t* Header 	= (VLANTag_t*)(Ether+1);
		u16* Proto 			= (u16*)(Header + 1);

		// update to the acutal proto / ipv4 header
		EtherProto 			= swap16(Proto[0]);
		Payload 			= (u8*)(Proto + 1);
		PayloadLength		-= 4;

		// VNTag unpack (BME) 
		if (EtherProto == ETHER_PROTO_VNTAG)
		{
			VNTag_t* Header = (VNTag_t*)(Proto+1);
			Proto 			= (u16*)(Header + 1);

			// update to the acutal proto / ipv4 header
			EtherProto 		= swap16(Proto[0]);
			Payload 		= (u8*)(Proto + 1);
			PayloadLength	-= 4;
		}

		// is it double tagged ? 
		if (EtherProto == ETHER_PROTO_VLAN)
		{
			Header 			= (VLANTag_t*)(Proto+1);
			Proto 			= (u16*)(Header + 1);

			// update to the acutal proto / ipv4 header
			EtherProto 		= swap16(Proto[0]);
			Payload 		= (u8*)(Proto + 1);
			PayloadLength	-= 4;
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

				// include any encapsulation updates 
				pPayload[0] 		= Payload;
				pPayloadLength[0]	= PayloadLength;

				return fDecap_ERSPAN3_Unpack(D, PCAPTS, pEther, pPayload, pPayloadLength, pMetaPort, pMetaTS, pMetaFCS);

			default:
				//trace("GRE Proto unsuported format: %x\n", GREProto);
				fDecap_Error(D, DECAP_ERROR_GRE_UNSUPPORTED);
				break;
			}

			// update histogram
			D->GREProtoHistogram[GREProto]++;
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
	if (D->DecapArista7130)
	{
		fDecap_Arista7130_Unpack		(D, PCAPTS, pEther, &OrigPayload, &OrigPayloadLength, pMetaPort, pMetaTS, pMetaFCS);
	}
	if (D->DecapIxia)
	{
		fDecap_Ixia_Unpack			(D, PCAPTS,     pEther, &OrigPayload, &OrigPayloadLength, pMetaPort, pMetaTS, pMetaFCS);
	}
	if (D->DecapArista7150Insert | D->DecapArista7150Over)
	{
		fDecap_Arista7150_Unpack	(D, PCAPTS, pEther, pPayload, pPayloadLength, pMetaPort, pMetaTS, pMetaFCS);
	}
	if (D->DecapArista7280MAC48  | D->DecapArista7280ETH64)
	{
		fDecap_Arista7280_Unpack	(D, PCAPTS, pEther, pPayload, pPayloadLength, pMetaPort, pMetaTS, pMetaFCS);
	}
	if (D->DecapCisco3550)
	{
		fDecap_Cisco3550_Unpack		(D, PCAPTS, pEther, pPayload, pPayloadLength, pMetaPort, pMetaTS, pMetaFCS);
	}

	if (D->DecapDump) trace("\n");

	// update
	return EtherProto;
}
