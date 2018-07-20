//------------------------------------------------------------------------------------------------
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
// Arista DANZ timestamps 
//
// Timestamp format is: https://eos.arista.com/timestamping-on-the-7150-series/#Timestamp_Format 
//
// TODO: support the TS + FCS mode. currently only supports ovewriting the FCS with TS mode
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
#include <linux/tcp.h>

#include "fTypes.h"
#include "fNetwork.h"

//---------------------------------------------------------------------------------------------

extern bool g_Verbose;
extern bool g_Arista;
extern bool g_Dump;

static u64		s_KeyTS		= 0;			// last Keyframe UTC time
static u64		s_KeyTick	= 0;			// last Keyframe ASIC ticks 
static u64		s_KeyTick31	= 0;			// asic ticks only the lower 31bits
											// used to detect wraparound

static u64		s_TotalPkts = 0;			// total number of packets processed
static u64 		s_TotalTS 	= 0;			// total number of packets whose TS was updated
static u64 		s_TotalKeys	= 0;			// total number of keyframes recevied 


u8* PrettyNumber(u64 num);

//---------------------------------------------------------------------------------------------

void Arista_Open(int argc, char* argv[])
{
	for (int i=1; i < argc; i++)
	{
		if (strcmp(argv[i], "--arista") == 0)
		{
			fprintf(stderr, "Arista DANZ Timestamping Format\n");
			g_Arista = true;
		}
	}
}

void Arista_Close(void)
{
	fprintf(stderr, "Arista Timestamp\n");
	fprintf(stderr, "    Total Pkt      : %s\n", PrettyNumber(s_TotalPkts));
	fprintf(stderr, "    Total TS Update: %s\n", PrettyNumber(s_TotalTS));
	fprintf(stderr, "    Total TS Drop  : %s\n", PrettyNumber(s_TotalPkts - s_TotalTS));
	fprintf(stderr, "    Total KeyFrames: %s\n", PrettyNumber(s_TotalKeys));
}

//---------------------------------------------------------------------------------------------
// de-encapsulate a packet
u16 Arista_Unpack(	u64 PCAPTS,
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

	// assume its a normal timestamped footer

	// FCS is replaced with a 4B timestamp 
	u32* Footer  = (u32*)(Payload + PayloadLength - 8);
	u32 Footer32 = swap32(Footer[0]);

	// Arista has a weird 1 bit pad at LSB bit 8
	u64 Tick31 = (Footer32&0x7f) | ((Footer32 & 0xffffff00) >> 1);

	// check over wraparound
	if (Tick31 < s_KeyTick31)
	{
		Tick31 += 0x80000000ULL;
	}

	// arista keyframe ?
	if (EtherProto == ETHER_PROTO_IPV4)
	{
		IPv4Header_t* IPv4 = (IPv4Header_t*)( (u8*)Ether + 12 + 2);

		// keyframe
		if (IPv4->Proto == 253)
		{
			AristaKeyFrame_t* Key = (AristaKeyFrame_t*)(IPv4 + 1);

			s_KeyTS  	= swap64(Key->UTCTime);
			s_KeyTick 	= swap64(Key->ASICTick);
			s_KeyTick31 = s_KeyTick & 0x7fffffff; 

			if (g_Dump)
			{
				static u64 LastKeyTS = 0;
				fprintf(stderr, "Keyframe: ");
				fprintf(stderr, "ASIC Tick: %016llx ", s_KeyTick); 
				fprintf(stderr, "ASIC Time: %20lli ", (u64)(s_KeyTick * 20.0 / 7.0)); 
				fprintf(stderr, "UTC  Time: %20lli (%20lli)", s_KeyTS, s_KeyTS - PCAPTS); 
				fprintf(stderr, "ASIC TS: %08llx ", swap64(Key->ASICTS));
				fprintf(stderr, "EDrop: %2lli ", swap64(Key->EgressIFDrop));
				fprintf(stderr, "dKey: %lli ", s_KeyTS - LastKeyTS);
				fprintf(stderr, "\n");

				if ((s_KeyTS - LastKeyTS) > 2e9)
				{
					fprintf(stderr, "Arista likely dropped keyframe\n");
				}

				LastKeyTS = s_KeyTS;
			}

			// keyframe has no 4 byte footer
			Tick31 = swap64(Key->ASICTS) &0x7fffffff;

			// count number of keyframes seen
			s_TotalKeys++;
		}
	}

	// build the full 64b tick counter
	// combine the lower 31bits with the keyframe
	// NOTE: need to add it, as it might contain bit31 overflow
	u64 Tick64 = (s_KeyTick & 0xffffffff80000000ULL) + Tick31;

	// difference since last keyframe
	u64 dTick64 = Tick64 - s_KeyTick;

	// convert to nanos
	u64 AristaTS = s_KeyTS + (dTick64 * 20.0 / 7.0);	

	if (g_Dump)
	{
		static u64 LastArista = 0;
		static u64 LastTS = 0;

		fprintf(stderr, "P:%20lli A:%20lli (%15lli) : dPCAPTS %12lli  dArista:%12lli AristaTS: %20lli Ticks: %08llx  : %f\n", 
																			PCAPTS, 
																			AristaTS, 
																			AristaTS - PCAPTS, 

																			PCAPTS - LastTS, 
																			AristaTS - LastArista, 
																			AristaTS,
																		 	Tick31,	
																			(float)(PCAPTS - LastTS) / (float)(AristaTS - LastArista)); 

		LastTS = PCAPTS;
		LastArista = AristaTS;
	}

	// update TS only if theres a key frame to base it on
	if (s_KeyTS != 0)
	{
		pMetaTS[0]			= AristaTS;
		s_TotalTS++;
	}
	s_TotalPkts++;

	return 0;
}
