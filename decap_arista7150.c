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

#include "decap.h"

//---------------------------------------------------------------------------------------------
// protocol specific info 
typedef struct Proto_t
{
	u64		KeyTS;				// last Keyframe UTC time
	u64		KeyTick;			// last Keyframe ASIC ticks 
	u64		KeyTick31;			// asic ticks only the lower 31bits
								// used to detect wraparound

	u64		TotalPkts;			// total number of packets processed
	u64 	TotalTS;			// total number of packets whose TS was updated
	u64 	TotalKeys;			// total number of keyframes recevied 

	s32		FooterOffset;		// assume overwrite fcs

} Proto_t;

u8* PrettyNumber(u64 num);

//---------------------------------------------------------------------------------------------

void fDecap_Arista7150_Open(fDecap_t* D, int argc, char* argv[])
{
	Proto_t* P = (Proto_t*)D->ProtocolData;
	for (int i=0; i < argc; i++)
	{
		if (strcmp(argv[i], "--arista7150-insert") == 0)
		{
			fprintf(stderr, "Arista DANZ Timestamping Format (insert)\n");
			P->FooterOffset = -8;
			D->DecapArista7150Insert = 1; 
		}
		if (strcmp(argv[i], "--arista7150-overwrite") == 0)
		{
			fprintf(stderr, "Arista DANZ Timestamping Format (overwrite)\n");
			P->FooterOffset = -4;
			D->DecapArista7150Over = 1;
		}
	}

	P->KeyTS		= 0;
	P->KeyTick		= 0;
	P->KeyTick31	= 0;

	P->TotalPkts 	= 0;
	P->TotalTS 		= 0;
	P->TotalKeys	= 0;
}

void fDecap_Arista7150_Close(fDecap_t* D)
{
	Proto_t* P = (Proto_t*)D->ProtocolData;
	fprintf(stderr, "Arista7150 Timestamp\n");
	fprintf(stderr, "    Total Pkt      : %s\n", PrettyNumber(P->TotalPkts));
	fprintf(stderr, "    Total TS Update: %s\n", PrettyNumber(P->TotalTS));
	fprintf(stderr, "    Total TS Drop  : %s\n", PrettyNumber(P->TotalPkts - P->TotalTS));
	fprintf(stderr, "    Total KeyFrames: %s\n", PrettyNumber(P->TotalKeys));
}

//---------------------------------------------------------------------------------------------
// decode footer 
u16 fDecap_Arista7150_Unpack(	fDecap_t* D,	
								u64 PCAPTS,
								fEther_t** pEther, 

								u8** pPayload, 
								u32* pPayloadLength,
	
								u32* pMetaPort, 
								u64* pMetaTS, 
								u32* pMetaFCS)
{
	Proto_t* P = (Proto_t*)D->ProtocolData;

	fEther_t* Ether 	= pEther[0];
	u16 EtherProto 		= swap16(Ether->Proto);

	u8* Payload 		= pPayload[0];
	u32 PayloadLength 	= pPayloadLength[0];

	// assume its a normal timestamped footer

	// position of the fotter (insert or overwrite) 
	u32* Footer  = (u32*)(Payload + PayloadLength + P->FooterOffset);			// FCS 7150 insert
	u32 Footer32 = swap32(Footer[0]);

	// Arista has a weird 1 bit pad at LSB bit 8
	u64 Tick31 = (Footer32&0x7f) | ((Footer32 & 0xffffff00) >> 1);

	// check for 31bit tick overflow / carry
	//
	//
	//  Keyframe :  0x12340000_00001000 | ASICTick64 (0x12340000_00001000) | UTC ( 64bit epoch A)
	//
	//
	//  Packet 0 :  0x12340000_7fff0000 | PacketTick (0x7fff0000) 
	//
	//                                             PacketTick64 = { ASICTick64(0x12340000_00001000)[63:31], PacketTick(0x7fff0000)[30:0] }
	//                                                          = { 00010010_00110100_00000000_00000000_00000000_00000000_00010000_00000000[63:31],  01111111_11111111_00000000_00000000[30:0] }  
	//                                                          = { 00010010_00110100_00000000_00000000_0,  1111111_11111111_00000000_00000000 }  
	//                                                          = 00010010_00110100_00000000_00000000_01111111_11111111_00000000_00000000
	//                                                          = 0x123400007FFF0000
	//
	//
	//  Packet 1 :  0x12340000_80000000 | Packet Tick (0x00000000) 
	//
	//                                             PacketTick64 = { ASICTick64(0x12340000_00001000)[63:31], PacketTick(0x00000000)[30:0] }
	//
	//                                                         because (PacketTick[30:0] < ASICTick64[30:0]) PacketTick64 needs to += 0x80000000
	//
	//                                             PacketTick64 = { ASICTick64(0x12340000_00001000)[63:31], PacketTick(0x00000000)[30:0]} + 0x80000000 
	//                                                          = { 00010010_00110100_00000000_00000000_00000000_00000000_00010000_00000000[63:31],  00000000_00000000_00000000_00000000[30:0] } + 10000000_00000000_00000000_00000000  
	//                                                          = { 00010010_00110100_00000000_00000000_0,  0000000_00000000_00000000_00000000 }  + 10000000_00000000_00000000_00000000  
	//                                                          = 00010010_00110100_00000000_00000000_00000000_00000000_00000000_00000000 + 10000000_00000000_00000000_00000000  
	//                                                          = 00010010_00110100_00000000_00000000_10000000_00000000_00000000_00000000 
	//														    = 0x1234000080000000
	//
	//  Packet 2 :  0x12340000_80000100 | Packet Tick (0x00000100) 
	//
	//                                             PacketTick64 = { ASICTick64(0x12340000_00001000)[63:31], PacketTick(0x00000100)[30:0] }
	//
	//                                                         because (PacketTick[30:0] < ASICTick64[30:0]) PacketTick64 needs to += 0x80000000
	//
	//                                             PacketTick64 = { ASICTick64(0x12340000_00001000)[63:31], PacketTick(0x00000100)[30:0]} + 0x80000000 
	//                                                          = { 00010010_00110100_00000000_00000000_00000000_00000000_00010000_00000000[63:31],  00000000_00000000_00000001_00000000[30:0] } + 10000000_00000000_00000000_00000000  
	//                                                          = { 00010010_00110100_00000000_00000000_0,  0000000_00000000_00000001_00000000 }  + 10000000_00000000_00000000_00000000  
	//                                                          = 00010010_00110100_00000000_00000000_00000000_00000000_00000001_00000000 + 10000000_00000000_00000000_00000000  
	//                                                          = 00010010_00110100_00000000_00000000_10000000_00000000_00000001_00000000 
	//														    = 1234000080000100  
	//
	if (Tick31 < P->KeyTick31)
	{
		// add (1<<31)
		Tick31 += 0x80000000ULL;
	}

	// arista TS
	u64 AristaTS = 0;

	// IP header 
	u8* IPHeader 	= ((u8*)Ether) + 12 + 2;

	// if theres a vlan tag strip it
	if (EtherProto == ETHER_PROTO_VLAN)
	{
		VLANTag_t* Header 	= (VLANTag_t*)(Ether+1);

		u16* Proto 			= (u16*)(Header + 1);
		EtherProto 			= swap16(Proto[0]);

		IPHeader			= (u8*)(Proto + 1);
	}

	// arista keyframe ?
	if (EtherProto == ETHER_PROTO_IPV4)
	{
		IPv4Header_t* IPv4 = (IPv4Header_t*)IPHeader;

		// keyframe
		if (IPv4->Proto == 253)
		{
			u64 ASICTS = 0;

			// if there is NO Skew settings
			if (swap16(IPv4->Len) == 66)
			{
				AristaKeyFrame_t* Key = (AristaKeyFrame_t*)(IPv4 + 1);
				P->KeyTS  		= swap64(Key->UTCTime);
				P->KeyTick 		= swap64(Key->ASICTick);
				P->KeyTick31 	= P->KeyTick & 0x7fffffff; 
				ASICTS			= swap64(Key->ASICTS);
			}
			// if there is Skew settings
			else if (swap16(IPv4->Len) == 82)
			{
				AristaKeyFrameSkew_t* Key = (AristaKeyFrameSkew_t*)(IPv4 + 1);
				P->KeyTS  		= swap64(Key->UTCTime);
				P->KeyTick 		= swap64(Key->ASICTick);
				P->KeyTick31 	= P->KeyTick & 0x7fffffff; 
				ASICTS			= swap64(Key->ASICTS);
			}
			else
			{
				if (D->DecapDump) fprintf(stderr, "arista7150 ERROR unknown keyframe size ");
			}

			if (D->DecapDump)
			{
				static u64 LastKeyTS = 0;
				fprintf(stderr, "arista7150 Keyframe: ");
				fprintf(stderr, "ASIC Tick: %016llx %016llx ", P->KeyTick, P->KeyTick31); 
				fprintf(stderr, "ASIC Time: %20lli ", (u64)(P->KeyTick * 20.0 / 7.0)); 
				fprintf(stderr, "UTC  Time: %20lli (%20lli) %s ", P->KeyTS, P->KeyTS - PCAPTS, FormatTS(P->KeyTS) ); 
				fprintf(stderr, "ASIC TS: %08llx ", ASICTS);
				fprintf(stderr, "dKey: %lli ", P->KeyTS - LastKeyTS);
				fprintf(stderr, "\n");

				if ((P->KeyTS - LastKeyTS) > 2e9)
				{
					fprintf(stderr, "Arista likely dropped keyframe\n");
				}

				LastKeyTS = P->KeyTS;
			}

			// keyframe has no 4 byte footer
			Tick31 = P->KeyTick31; 

			// use the keyframe ASIC Tick (full 64bit) to calculate the actual packet TS
			//
			// NOTE: this is different to the UTCTime/ASICTick which suspect is generated
			//       way further up the pipeline. using UTCTime for this packets timestamp 
			//       would be incorrect.
			//
			//       ASICTS - beleive this is generated on egress. so calculate the 64bit epoch time
			//                the same as a 31bit tick no normal packets, except we can use the full 64bit tick value
			//                in the keyframe  structure (ASICTS)
			//
			AristaTS = P->KeyTS + (ASICTS - P->KeyTick) * 20ULL / 7ULL;
			//fprintf(stderr, "arista ASICTS:%lli ASICKey:%lli tick delta:%lli\n", swap64(Key->ASICTS), P->KeyTick, swap64(Key->ASICTS) - P->KeyTick );

			// count number of keyframes seen
			P->TotalKeys++;
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
	if (P->KeyTS == 0)
	{
		AristaTS = PCAPTS;
	}

	// not a keyframe then generate
	if (AristaTS == 0)
	{
		// build the full 64b tick counter
		// combine the lower 31bits with the keyframe
		// NOTE: need to add it, as it might contain bit31 overflow
		u64 Tick64 = (P->KeyTick & 0xffffffff80000000ULL) + Tick31;

		// difference since last keyframe
		u64 dTick64 = Tick64 - P->KeyTick;

		// difference in nanoseconds since last keyframe
		s64 dTick64_ns = (dTick64 * 20ULL) / 7ULL; 

		// convert to full Epoach wrt to the keyframe UTCTime 
		AristaTS = P->KeyTS + dTick64_ns; 

		//fprintf(stderr, "Tick64: %016llx  keyframe tick64 %016llx keyframe UTC:%016llx tickDelta:%lli tick32:%016llx\n", 
		//		Tick64,
		//		P->KeyTick,
		//		P->KeyTS,
		//		dTick64,
		//		Tick31);
	}

	if (D->DecapDump)
	{
		static u64 LastArista = 0;
		static u64 LastTS = 0;

		fprintf(stderr, "| arista7150 PCAPTS:%20lli AristaTS:%20lli %s (%15lli) : dPCAPTS %12lli  dArista:%12lli AristaTS: %20lli Ticks: %08llx  : %f\n", 
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
	if (P->KeyTS != 0)
	{
		pMetaTS[0]			= AristaTS;
		P->TotalTS++;
	}

	P->TotalPkts++;

	return 0;
}
