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
// Ixia X40 Stream  decoder. This assumes setting of replace FCS with 4B timestamp
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
typedef struct 
{
	bool TSCalib;		// first timestamp not
	s64	TSOffset;		// refernce delta from PCAP.TS - Ixia.TS 
	s64	TS0PCAPTS;		// Packet(0).PCAP.TS 
	s64	TS0IxiaTS;		// Packet(0).Ixia.TS 

} Proto_t;

//---------------------------------------------------------------------------------------------

void fDecap_Ixia_Open(fDecap_t* D, int argc, char* argv[])
{
	Proto_t* P = (Proto_t*)D->ProtocolData;
	for (int i=1; i < argc; i++)
	{
		if (strcmp(argv[i], "--ixia") == 0)
		{
			fprintf(stderr, "Ixia 4B Time footer\n");
			D->DecapIxia = true;
		}
	}

	P->TSCalib 		= false;
	P->TSOffset 		= 0;
	P->TS0PCAPTS		= 0;
	P->TS0IxiaTS		= 0;
}

void fDecap_Ixia_Close(fDecap_t* D)
{
}

static void Ixia_Sample(ERSPANv3_t* ERSpan, u32 PayloadLength, u32 SeqNo)
{
}

//---------------------------------------------------------------------------------------------
//  see the desciprion in the ERSPAN code

static bool s_TSCalib 		= false;	// first timestamp not
static s64	s_TSOffset 		= 0;		// refernce delta from PCAP.TS - ERSPAN.TS 
static s64	s_TS0PCAPTS		= 0;		// Packet(0).PCAP.TS 
static s64	s_TS0IxiaTS		= 0;		// Packet(0).ERSPAN.TS 

#define TSMODULO_BIT	31

static u64 s_TSModuloMask 	= ((1ULL <<  TSMODULO_BIT) - 1);

static u64 TSSignedModulo(u64 Value)
{
	s64 V = (Value & s_TSModuloMask); 
	V = (V << (64 - TSMODULO_BIT)) >> (64 - TSMODULO_BIT);
	return V;
}

static inline u64 TSExtract(Proto_t* P, u64 PCAPTS, u64 IxiaTS)
{
	if (!P->TSCalib)
	{
		P->TSCalib 		= true;
		P->TSOffset 		= IxiaTS - PCAPTS; 
		P->TS0PCAPTS		= PCAPTS;
		P->TS0IxiaTS		= IxiaTS;
	}

	// Packet(n).ERSPAN.TS - Packet(n).PCAP.TS
	s64 dER = IxiaTS - PCAPTS;

	// Packet(n).ERSAPN.TS - Packet(n).PCAP.TS - CalibOffset
	s64 ERWorld = dER - P->TSOffset;

	// remove any 32bit overflows 
	s64 ERNano = TSSignedModulo(ERWorld); 

	// final world time, using 32bit ESPAN timestamp
	u64 TS = PCAPTS + ERNano;

	return TS;
}

//---------------------------------------------------------------------------------------------
// de-encapsulate a packet
u16 fDecap_Ixia_Unpack(	fDecap_t* D,	
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

	// FCS is replaced with a 4B timestamp 
	u32* Footer = (u32*)(Payload + PayloadLength - 4);

	//u32 IxiaTS = (float)swap32(Footer[0]) * 2.857;			// xStream User Guide v6.75 
	u32 IxiaTS = (float)swap32(Footer[0]) * (2.857/2.0);		// testing shows it appears the clock is running at half the speed of the documentation 

	// default use the pcap TS
	u64 TS = TSExtract(P, PCAPTS, IxiaTS); 
	if (D->DecapDump)
	{
		static u32 LastIxia = 0;
		static u64 LastTS = 0;

		fprintf(stderr, " | ixia %20lli %20lli (%20lli) %20lli  %20i  %20i : %f\n", PCAPTS, TS, TS - PCAPTS, PCAPTS - LastTS, IxiaTS, IxiaTS - LastIxia, (float)(PCAPTS - LastTS) / (float)(IxiaTS - LastIxia)); 

		LastTS = PCAPTS;
		LastIxia = IxiaTS;
	}

	// update TS only
	pMetaTS[0]			= TS;

	return 0;
}
