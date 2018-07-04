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
#include <linux/tcp.h>

#include "fTypes.h"
#include "fNetwork.h"

extern bool g_Verbose;

//---------------------------------------------------------------------------------------------
// ERSPan v3 statsitics 
typedef struct
{
	u32		SeqNo;
	u64		DropCnt;
	u64		TotalDrop;
	u64		TotalPkt;
	u64		TotalByte;

} ERSPAN3Session_t;

static ERSPAN3Session_t* s_ERSPAN3;

void ERSPAN3Open(void)
{
	// reset session info
	s_ERSPAN3 = (ERSPAN3Session_t*)malloc(sizeof(ERSPAN3Session_t) * (1<<10) );
	memset(s_ERSPAN3, 0, sizeof(ERSPAN3Session_t) * (1<<10) );
}
void ERSPAN3Close(void)
{
	// list session info 
	for (int i=0; i < 1 << 10; i++)
	{
		ERSPAN3Session_t* S = &s_ERSPAN3[i];

		if (S->TotalPkt == 0) continue;

		fprintf(stderr, "ERSPAN Session:%08x PktCnt:%8lli Bytes:%8lli Drop:%8lli GapCnt:%6lli\n",
				i, 
				S->TotalPkt, 
				S->TotalByte,
				S->TotalDrop,
				S->DropCnt);
	}
}

static inline void ERSPAN3Sample(ERSPANv3_t* ERSpan, u32 PayloadLength, u32 SeqNo)
{
	u32 Session = ERSpan->Header.Session;

	ERSPAN3Session_t* S = &s_ERSPAN3[Session];

	S->TotalPkt++;
	S->TotalByte += PayloadLength;

	// first seq no ? 
	if (S->SeqNo != 0)
	{
		// check for drops
		s32 dSeq = SeqNo - S->SeqNo;
		if (dSeq != 1)
		{
			// print gaps
			if (g_Verbose)
			{
				fprintf(stderr, "ERSPAN Session:%08x Drop SeqNo:%i  LastSeqNo:%i  Delta:%i\n", Session, SeqNo, S->SeqNo, dSeq);
			}

			S->DropCnt++;	
			S->TotalDrop += abs(dSeq);
		}
	}
	S->SeqNo = SeqNo;
}

//---------------------------------------------------------------------------------------------
// de-encapsulate a packet
u16 DeEncapsulate(	fEther_t** pEther, 

					u8** pPayload, 
					u32* pPayloadLength,

					u32* MetaPort, 
					u32* MetaSec, 
					u32* MetaNSec, 
					u32* MetaFCS)
{
	fEther_t* Ether = pEther[0];

	// get first level ether protocol 
	u16 EtherProto = swap16(Ether->Proto);
	//fprintf(stderr, "decap: %04x\n", EtherProto); 

	u8* Payload 		= pPayload[0];
	u32 PayloadLength 	= pPayloadLength[0];

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

			u32 GRELength	 = 4;
			if (GRE->C) GRELength += 4; 
			if (GRE->K) GRELength += 2; 

			// seq no
			u32 SeqNo = 0;
			if (GRE->S)
			{
				u32* pSeqNo = (u32*)((u8*)GRE + GRELength);
				SeqNo 		= swap32(pSeqNo[0]);
				GRELength 	+= 4; 
			}

			// decode the GRE format
			u32 GREProto = swap16(GRE->Proto);
			switch(GREProto)
			{
			case GRE_PROTO_ERSPAN3:
			{
				ERSPANv3_t* ERSpan = (ERSPANv3_t*)((u8*)GRE + GRELength);
				u32 ERSpanLen = 3*4;

				// Update new Ethernet header
				Ether = (fEther_t*)((u8*)ERSpan + ERSpanLen);

				// new encapsulated protocol 
				u16* pProto = (u16*)( (u8*)ERSpan + ERSpanLen + 12);

				// update encapsulation
				EtherProto = swap16(pProto[0]);

				// point to (potentially) IPv4 header
				Payload = (u8*)(pProto + 1);

				// adjust the payload size
				PayloadLength -= Payload - pPayload[0]; 

				// update stats
				ERSPAN3Sample(ERSpan, PayloadLength, SeqNo);	

				//fprintf(stderr, "ERSPAN %08x %10i : %04x\n", ERSpan->Header.Session, SeqNo, EtherProto); 
			}
			break;

			default:
				fprintf(stderr, "ERSPAN unsuported format: %x\n", GREProto);
				break;
			}
		}
	}

	// set new Ether header (if any)
	pEther[0] 			= Ether;

	// set new IP header
	pPayload[0] 		= Payload;
	pPayloadLength[0]	= PayloadLength;

	return EtherProto;
}
