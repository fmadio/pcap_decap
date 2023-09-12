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
// MetaMako de-encapsulation 
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

//---------------------------------------------------------------------------------------------
// protocol specific info 
typedef struct Proto_t
{
	s32		FooterDepth;		// number of metamako tages 

} Proto_t;


u8* PrettyNumber(u64 num);

//---------------------------------------------------------------------------------------------

void fDecap_Arista7130_Open(fDecap_t* D, int argc, char* argv[])
{
	Proto_t* P = (Proto_t*)D->ProtocolData;

	// by default assume a single footer
	P->FooterDepth 	= 2;
	for (int i=1; i < argc; i++)
	{
		if (strcmp(argv[i], "--arista7130") == 0)
		{
			trace("MetaMako footer\n");
			D->DecapArista7130 = true;
		}
		if (strcmp(argv[i], "--arista7130-double") == 0)
		{
			trace("MetaMako Double tagged footer\n");
			D->DecapArista7130 	= true;
			P->FooterDepth 		= 2;
		}
	}
}

void fDecap_Arista7130_Close(fDecap_t* D)
{
}

static void fDecap_Arista7130_Sample(void)
{
}

//---------------------------------------------------------------------------------------------
// metamako de-encapsulation 
//
// 1) extracts an replaces the pcap timestamp with the absolute timestamp from the metamako 
//    footer
//
// 2) strips the footer, so the orignial packet and FCS are written to the pcap
//
u16 fDecap_Arista7130_Unpack(	fDecap_t* D,	
								u64 PCAPTS,
								fEther_t** pEther, 

								u8** pPayload, 
								u32* pPayloadLength,
	
								u32* pMetaPort, 
								u64* pMetaTS, 
								u32* pMetaFCS)
{
	Proto_t* P = (Proto_t*)D->ProtocolData;

	u64 TS0;
	u64 TS1;
	u64 TS2;

	// double footer
	// grab the footer, assumption is every packet has a footer 
	MetaMakoFooter_t* Footer = (MetaMakoFooter_t*)(pPayload[0] + pPayloadLength[0] - sizeof(MetaMakoFooter_t)); 

	TS0 = (u64)swap32(Footer->Sec)*1000000000ULL + (u64)swap32(Footer->NSec);
	if (D->DecapDump)
	{
		trace(" | ");
		trace("TS: %20lli %s ", 	TS0, FormatTS(TS0)); 
		trace("%8i.%09i ", 			swap32(Footer->Sec),swap32(Footer->NSec)); 
		trace("PortID: %4i ", 		Footer->PortID); 
		trace("DevID: %04i ", 		swap16(Footer->DeviceID)); 
		trace("OrigFCS: %08x ", 	swap32(Footer->OrigFCS));	
	}

	// double tag decode
	if (P->FooterDepth == 2)
	{
		// grab the 2nd footer 
		MetaMakoFooter_t* Footer = (MetaMakoFooter_t*)(pPayload[0] + pPayloadLength[0] - sizeof(MetaMakoFooter_t) - 16); 

		u64 TS1 = (u64)swap32(Footer->Sec)*1000000000ULL + (u64)swap32(Footer->NSec);
		if (D->DecapDump)
		{
			trace("  |  ");
			trace("TS: %20lli %s ", 	TS1, FormatTS(TS1)); 
			trace("%8i.%09i ", 			swap32(Footer->Sec),swap32(Footer->NSec)); 
			trace("PortID: %4i ", 		Footer->PortID); 
			trace("DevID: %04i ", 		swap16(Footer->DeviceID)); 
			trace("OrigFCS: %08x", 		swap32(Footer->OrigFCS));	

			trace("TagDelta: %8i", 	 	TS0 - TS1);	
		}

		// by default use the inner most tag
		TS0 = TS1; 
	}

	// set new packet length (strip footer) 
	//pPayloadLength[0]	= pPayloadLength[0] - 16;

	// sanity check as maybe some random packets (e.g. ARP) are not tagged
	if ( (TS0 > (u64)946688400e9) && (TS0 < (u64)2524611600e9)) 
	{
		// overwrite the timestamp
		pMetaTS[0]			= TS0;
	}

	return 0;
}
