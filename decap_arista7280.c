//------------------------------------------------------------------------------------------------
//
// fmadio pcap de-encapsuation utility
//
// Copyright (C) 2018-2023 fmad engineering llc aaron foo 
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
// Arista 7280 timestamps 
//   - 48bit Mac Src overwrite
//   - 64bit Ethernet header 
//
// Timestamp format is: https://www.arista.com/assets/data/pdf/Whitepapers/Overview_Arista_Timestamps.pdf 
//
//------------------------------------------------------------------------------------------------

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

//---------------------------------------------------------------------------------------------

extern bool 	g_DecapVerbose;
extern bool 	g_DecapDump;
extern bool 	g_DecapArista7280MAC48;
extern bool 	g_DecapArista7280ETH64;

static u64		s_TotalPkts = 0;			// total number of packets processed
static u64 		s_TotalTS 	= 0;			// total number of packets whose TS was updated
static u64 		s_TotalKeys	= 0;			// total number of keyframes recevied 

static s32		s_FooterOffset = -4;		// assume overwrite fcs

u8* PrettyNumber(u64 num);

//---------------------------------------------------------------------------------------------

void fDecap_Arista7280_Open(int argc, char* argv[])
{
	for (int i=0; i < argc; i++)
	{
		if (strcmp(argv[i], "--arista7280-mac48") == 0)
		{
			trace("Arista 7280 Timestamping Format (48bit Source MAC overwrite)\n");
			g_DecapArista7280MAC48 = true;
			s_FooterOffset = -8;
		}
		if (strcmp(argv[i], "--arista7280-eth64") == 0)
		{
			trace("Arista 7280 Timestamping Format (64bit Ether Header)\n");
			g_DecapArista7280ETH64 = true;
			s_FooterOffset = -4;
		}
	}

	s_TotalPkts = 0;
	s_TotalTS 	= 0;
	s_TotalKeys	= 0;
}

void fDecap_Arista7280_Close(void)
{
	trace("Arista7280 Timestamp\n");
	trace("    Total Pkt      : %s\n",			PrettyNumber(s_TotalPkts));
	trace("    Total TS Update: %s (%.4f)\n",	PrettyNumber(s_TotalTS), s_TotalTS / (float)s_TotalPkts );
}

//---------------------------------------------------------------------------------------------
// decode footer 
u16 fDecap_Arista7280_Unpack(	u64 PCAPTS,
								fEther_t** pEther, 

								u8** pPayload, 
								u32* pPayloadLength,
	
								u32* pMetaPort, 
								u64* pMetaTS, 
								u32* pMetaFCS)
{
	fEther_t* Ether 	= pEther[0];
	u16 EtherProto 		= swap16(Ether->Proto);

	u8* Payload 		= pPayload[0];
	u32 PayloadLength 	= pPayloadLength[0];

	u64 AristaTS = 0;		

	// source mac 48bit overwrite
	if (g_DecapArista7280MAC48)
	{
		// the 48bits are derivied as follows
		//
		// byte 5 : epoch sec  mac_src[47:48] 
		// byte 4 : epoch sec  mac_src[39:32] 
		// byte 3 : epoch nsec mac_src[31:24] 
		// byte 2 : epoch nsec mac_src[23:16] 
		// byte 1 : epoch nsec mac_src[15: 8] 
		// byte 0 : epoch nsec mac_src[ 7: 0] 
		//
		// this means need to convert the PCAPTS (epoch 64bit) into a "seconds" part
		// and append the upper 2 bytes of the PCAPTS "seconds" to the src_mac "seconds" value 
		//
		// NOTE: there is still the problem of ingress/egress delta. 7280 lower 32bits (nsec)
		//       is timestamps at the ingress pipline. where as the uppler 32bits (sec)
		//       is appeneded at the egress pipeline 
		u64 Sec = 0;

		u64 SecPCAP = PCAPTS / 1000000000ULL;

		// upper 16bits by the fmadio
		Sec  |= ((SecPCAP >> (3*8)) << 3*8);
		Sec  |= ((SecPCAP >> (2*8)) << 2*8);

		//lower 48bits in the source mac
		Sec  |= ( ((u64)Ether->Src[0])  << 1*8);
		Sec  |= ( ((u64)Ether->Src[1])  << 0*8);

		//lower 32bits is the nsec part of the timestamp
		u64 NSec = 0;
		NSec |= ( ((u64)Ether->Src[2]) << 3*8);
		NSec |= ( ((u64)Ether->Src[3]) << 2*8);
		NSec |= ( ((u64)Ether->Src[4]) << 1*8);
		NSec |= ( ((u64)Ether->Src[5]) << 0*8);

		AristaTS = Sec * 1000000000ULL + NSec;
	}

	// 64bit ethernet header
	if (g_DecapArista7280ETH64)
	{
		// 64bit ethernet header version appends a header after the MAC (0xd28b)
		// this has format of Arista7280_t which includes a full 64bit timestamp
		// split into sec(32bit) and nsec(32bit) 
		if (EtherProto == ETHER_PROTO_ARISTA)
		{
			Arista7280_t* Header = (Arista7280_t*)(Ether + 1);

			//trace("%x Sub:%04x Version:%04x Sec:%i NSec:%i\n",	Ether->Proto, 
			//													swap16(Header->SubType), 
			//													swap16(Header->Version), 
			//													swap32(Header->Sec), 
			//													swap32(Header->NSec)
			//);
			AristaTS = ((u64)swap32(Header->Sec) * 1000000000ULL) + (u64)swap32(Header->NSec);

			// update the next protocol
			// 
			//EtherProto = swap16(Header->Proto);
		}
	}

	if (g_DecapVerbose)
	{
		s64 dTS = PCAPTS - AristaTS;
		trace("PCAPTS:%10lli AristaTS:%10lli (%10lli %12.6fsec)\n", PCAPTS, AristaTS, dTS, (float)dTS/1e9); 
	}

	// overwrite timestamp
	if (AristaTS != 0)
	{
		s_TotalTS++;
		pMetaTS[0] = AristaTS;
	}

	s_TotalPkts++;

	return EtherProto;
}
