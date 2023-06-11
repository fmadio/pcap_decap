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
// Arista 7150 timestamps 
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

#include "fTypes.h"
#include "fNetwork.h"

//---------------------------------------------------------------------------------------------

extern bool g_DecapVerbose;
extern bool g_DecapDump;

static u64		s_KeyTS		= 0;			// last Keyframe UTC time
static u64		s_KeyTick	= 0;			// last Keyframe ASIC ticks 
static u64		s_KeyTick31	= 0;			// asic ticks only the lower 31bits
											// used to detect wraparound

static u64		s_TotalPkts = 0;			// total number of packets processed
static u64 		s_TotalTS 	= 0;			// total number of packets whose TS was updated
static u64 		s_TotalKeys	= 0;			// total number of keyframes recevied 

static s32		s_FooterOffset = -4;		// assume overwrite fcs

u8* PrettyNumber(u64 num);

//---------------------------------------------------------------------------------------------

void fDecap_Arista7150_Open(int argc, char* argv[])
{
	for (int i=0; i < argc; i++)
	{
		if (strcmp(argv[i], "--arista-insert") == 0)
		{
			trace("Arista DANZ Timestamping Format (insert)\n");
			s_FooterOffset = -8;
		}
		if (strcmp(argv[i], "--arista-overwrite") == 0)
		{
			trace("Arista DANZ Timestamping Format (overwrite)\n");
			s_FooterOffset = -4;
		}
	}

	s_KeyTS		= 0;
	s_KeyTick	= 0;
	s_KeyTick31	= 0;

	s_TotalPkts = 0;
	s_TotalTS 	= 0;
	s_TotalKeys	= 0;
}

void fDecap_Arista7150_Close(void)
{
	trace("Arista7150 Timestamp\n");
	trace("    Total Pkt      : %s\n", PrettyNumber(s_TotalPkts));
	trace("    Total TS Update: %s\n", PrettyNumber(s_TotalTS));
	trace("    Total TS Drop  : %s\n", PrettyNumber(s_TotalPkts - s_TotalTS));
	trace("    Total KeyFrames: %s\n", PrettyNumber(s_TotalKeys));
}

//---------------------------------------------------------------------------------------------
// decode footer 
u16 fDecap_Arista7150_Unpack(	u64 PCAPTS,
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

	// position of the fotter (insert or overwrite) 
	u32* Footer  = (u32*)(Payload + PayloadLength + s_FooterOffset);			// FCS 7150 insert
	u32 Footer32 = swap32(Footer[0]);

	// Arista has a weird 1 bit pad at LSB bit 8
	u64 Tick31 = (Footer32&0x7f) | ((Footer32 & 0xffffff00) >> 1);

	// check over wraparound
	if (Tick31 < s_KeyTick31)
	{
		Tick31 += 0x80000000ULL;
	}

	// arista TS
	u64 AristaTS = 0;

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

			if (g_DecapDump)
			{
				static u64 LastKeyTS = 0;
				trace("Keyframe: ");
				trace("ASIC Tick: %016llx %016llx ", s_KeyTick, s_KeyTick31); 
				trace("ASIC Time: %20lli ", (u64)(s_KeyTick * 20.0 / 7.0)); 
				trace("UTC  Time: %20lli (%20lli) %s ", s_KeyTS, s_KeyTS - PCAPTS, FormatTS(s_KeyTS) ); 
				trace("ASIC TS: %08llx ", swap64(Key->ASICTS));
				trace("EDrop: %2lli ", swap64(Key->EgressIFDrop));
				trace("dKey: %lli ", s_KeyTS - LastKeyTS);
				trace("\n");

				if ((s_KeyTS - LastKeyTS) > 2e9)
				{
					trace("Arista likely dropped keyframe\n");
				}

				LastKeyTS = s_KeyTS;
			}

			// keyframe has no 4 byte footer
			Tick31 = s_KeyTick31; 

			// use the keyframe timestamp
			AristaTS = s_KeyTS;

			// count number of keyframes seen
			s_TotalKeys++;
		}

		// ptp traffic from the arista does not have timestamp
		bool IsPTP = false;
		if ((IPv4->Dst.IP[0] == 224) && (IPv4->Dst.IP[1] == 0) && (IPv4->Dst.IP[2] == 1) && (IPv4->Dst.IP[3] == 129)) IsPTP = true;
		if ((IPv4->Dst.IP[0] == 224) && (IPv4->Dst.IP[1] == 0) && (IPv4->Dst.IP[2] == 1) && (IPv4->Dst.IP[3] == 130)) IsPTP = true;
		if ((IPv4->Dst.IP[0] == 224) && (IPv4->Dst.IP[1] == 0) && (IPv4->Dst.IP[2] == 1) && (IPv4->Dst.IP[3] == 131)) IsPTP = true;
		if ((IPv4->Dst.IP[0] == 224) && (IPv4->Dst.IP[1] == 0) && (IPv4->Dst.IP[2] == 1) && (IPv4->Dst.IP[3] == 132)) IsPTP = true;
		if (IsPTP)
		{
			// use the PCAP timestamp	
			AristaTS = PCAPTS;
		}
	}
	// arista STP traffic also not timestamped
	if (EtherProto == ETHER_PROTO_STP)
	{
		AristaTS = PCAPTS;
	}

	// no keyframe then use capture card 
	if (s_KeyTS == 0)
	{
		AristaTS = PCAPTS;
	}

	// not a keyframe then generate
	if (AristaTS == 0)
	{
		// build the full 64b tick counter
		// combine the lower 31bits with the keyframe
		// NOTE: need to add it, as it might contain bit31 overflow
		u64 Tick64 = (s_KeyTick & 0xffffffff80000000ULL) + Tick31;


		// difference since last keyframe
		u64 dTick64 = Tick64 - s_KeyTick;

		// convert to nanos
		AristaTS = s_KeyTS + (dTick64 * 20ULL) / 7ULL;
	}

	if (g_DecapDump)
	{
		static u64 LastArista = 0;
		static u64 LastTS = 0;

		trace("P:%20lli A:%20lli %s (%15lli) : dPCAPTS %12lli  dArista:%12lli AristaTS: %20lli Ticks: %08llx  : %f\n", 
																			PCAPTS, 
																			AristaTS, 
																			FormatTS(AristaTS),
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
