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
