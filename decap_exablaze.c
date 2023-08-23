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
// Exablaze Footer de-encapsulation 
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

extern bool g_DecapVerbose;
extern bool g_DecapExablaze;
extern bool g_DecapDump;

u8* PrettyNumber(u64 num);

//---------------------------------------------------------------------------------------------

void fDecap_Exablaze_Open(int argc, char* argv[])
{
	for (int i=1; i < argc; i++)
	{
		if (strcmp(argv[i], "--cisco3550") == 0)
		{
			trace("Exablaze footer\n");
			g_DecapExablaze = true;
		}
	}
}

void fDecap_Exablaze_Close(void)
{
}

static void fDecap_Exablaze_Sample(void)
{
}

//---------------------------------------------------------------------------------------------
// Exablaze de-encapsulation 
//
// 1) extracts an replaces the pcap timestamp with the absolute timestamp from the  
//    footer
//
// 2) strips the footer, so the orignial packet and FCS are written to the pcap
//
u16 fDecap_Exablaze_Unpack(	u64 PCAPTS,
							fEther_t** pEther, 

							u8** pPayload, 
							u32* pPayloadLength,

							u32* pMetaPort, 
							u64* pMetaTS, 
							u32* pMetaFCS)
{
	// grab the footer, assumption is every packet has a footer 
	ExablazeFooter_t* Footer = (ExablazeFooter_t*)(pPayload[0] + pPayloadLength[0] - sizeof(ExablazeFooter_t)); 
	u64 TS = (u64)swap32(Footer->Sec)*1000000000ULL + (1000000000ULL*(u64)swap32(Footer->NSec)) / 0x100000000ULL;
	if (g_DecapDump)
	{
		trace("TS: %20lli %s ", TS, FormatTS(TS)); 
		trace("%8i %f %02i", swap32(Footer->Sec), swap32(Footer->NSec) / (float)0x100000000), Footer->PSec; 
		trace("PortID: %4i ", Footer->PortID); 
		trace("DevID: %4x", swap16(Footer->DeviceID)); 
		trace("\n");
	}

	// set new packet length (strip footer) 
	//pPayloadLength[0]	= pPayloadLength[0] - 16;

	// overwrite the timestamp
	pMetaTS[0]			= TS;

	return 0;
}
