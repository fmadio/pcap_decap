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
// erspan v3 de-encapusation 
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

u8* PrettyNumber(u64 num);

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


//---------------------------------------------------------------------------------------------
// protocol specific info 
typedef struct 
{
	// state for each possible erspan session	
	ERSPAN3Session_t ERSPAN3[1024];

	bool TSCalib;		// first timestamp not
	s64	TSEROffset;		// refernce delta from PCAP.TS - ERSPAN.TS 
	s64	TS0PCAPTS;		// Packet(0).PCAP.TS 
	s64	TS0ERTS;		// Packet(0).ERSPAN.TS 

} Proto_t;

//---------------------------------------------------------------------------------------------

void fDecap_ERSPAN3_Open(fDecap_t* D, int argc, char* argv[])
{
	Proto_t* P = (Proto_t*)D->ProtocolData;

	P->TSCalib 		= false;
	P->TSEROffset 	= 0;		// refernce delta from PCAP.TS - ERSPAN.TS 
	P->TS0PCAPTS	= 0;		// Packet(0).PCAP.TS 
	P->TS0ERTS		= 0;		// Packet(0).ERSPAN.TS 

	// reset session info
	memset(P->ERSPAN3, 0, sizeof(ERSPAN3Session_t) * (1<<10) );
}

void fDecap_ERSPAN3_Close(fDecap_t* D)
{
	Proto_t* P = (Proto_t*)D->ProtocolData;

	// list session info 
	for (int i=0; i < 1 << 10; i++)
	{
		ERSPAN3Session_t* S = &P->ERSPAN3[i];

		if (S->TotalPkt == 0) continue;

		trace("ERSPAN Session:%08x PktCnt:%s Bytes:%s Drop:%s GapCnt:%s\n",
				i, 
				PrettyNumber(S->TotalPkt), 
				PrettyNumber(S->TotalByte),
				PrettyNumber(S->TotalDrop),
				PrettyNumber(S->DropCnt) );
	}
}

static void ERSPAN3_Sample(fDecap_t* D, ERSPANv3_t* ERSpan, u32 PayloadLength, u32 SeqNo)
{
	Proto_t* P = (Proto_t*)D->ProtocolData;

	u32 Session = ERSpan->Header.Session;

	ERSPAN3Session_t* S = &P->ERSPAN3[Session];

	S->TotalPkt++;
	S->TotalByte += PayloadLength;

	// first seq no ? 
	if (S->SeqNo != 0)
	{
		// check for drops
		s64 dSeq = SeqNo - S->SeqNo;

		// check for 32bit wrap
		// Assuption is is GRE uses the full 32bits... 
		if ((SeqNo == 0) && (S->SeqNo == 0xffffffff)) dSeq = 1; 

		// check for 30bit wrap
		// Seems Cisco Nexus 3548 and probably many other devices only use 30bit seq number  
		if ((SeqNo == 0) && (S->SeqNo == 0x3fffffff)) dSeq = 1; 

		if (dSeq != 1)
		{
			// print gaps
			if (D->DecapVerbose)
			{
				trace("ERSPAN Session:%08x Drop SeqNo:%i  LastSeqNo:%i  Delta:%lli\n", Session, SeqNo, S->SeqNo, dSeq);
			}

			S->DropCnt++;	
			S->TotalDrop += abs(dSeq);
		}
	}
	S->SeqNo = SeqNo;
}

//---------------------------------------------------------------------------------------------
// erspan time expansion
//
// this is technically incorrect, as system should use the ERSPAN time marker
// however this marker may or may not be present in the capture. Also it requires
// a 2 pass algorithm to extract the time as you need to find the keyframe first
// and is unsutiable for our requirements.
//
// the assumption is the ERSPAN TS and the Capture NIC timestamps are relatively
// in sync. e.g. < 1 usec apart. If their both using PTPv2 this will be true. 
//  
// if ERSPAN TS and NIC TS are the same, we use the NIC TS for the upper 32bit part 
// of the timestamp, and use the ERSPAN TS for the lower 32bit timestamp.
//
// Keep in mind the ERSAPN TS is a *free running* 1ns counter. Its absolute 
// value is NOT the world time. 
//
// This is straight forward, however the ERSPAN TS is only 32bits and thus wraps
// around quickly, which requires some modulo arithmetic to remove any overflow
//
// The code uses the first packets PCAP TS and ERSAPN TS as the reference global time
// it then uses the time delta from Packet(0).ERSPAN.TS, and the new packet to 
// calculate the nano second world time.
//
// Packet 0 : Packet(0).PCAP.TS  : Packet(0).ERSPAN.TS
//    .
//    .
//    .
// Ignoring the modulo arithmetic the calculation is simply
//
// Packet N:
//    TS Delta = Packet(N).ERSPAN.TS - Packet(0).ERSPAN.TS
//    World TS = Packet(0).PCAP.TS + TS Delta
//
// broken out a bit
//
//   CalibOffset = Packet(0).ESAPN.TS - Packet(0).PCAP.TS
//
//   World TS = Packet(n).PCAP.TS + ((Packet(n).ERSPAN.TS - Packet(n).PCAP.TS) - CalibOffset)
//
//   World TS = Packet(n).PCAP.TS + ((Packet(n).ERSPAN.TS - Packet(n).PCAP.TS) - (Packet(0).ERSPAN.TS - Packet(0).PCAP.TS))
//
//   World TS = Packet(n).PCAP.TS + Packet(n).ERSPAN.TS - Packet(n).PCAP.TS - Packet(0).ERSPAN.TS + Packet(0).PCAP.TS
//
//   World TS = Packet(n).PCAP.TS + (Packet(n).ERSPAN.TS - Packet(0).ERSPAN.TS) - (Packet(n).PCAP.TS - Packet(0).PCAP.TS)
//
//   World TS = (Packet(n).PCAP.TS - (Packet(n).PCAP.TS - Packet(0).PCAP.TS)) + (Packet(n).ERSPAN.TS - Packet(0).ERSPAN.TS) 
//
// which is just a different way of saying:
//
//    TS Delta = Packet(N).ERSPAN.TS - Packet(0).ERSPAN.TS
//    World TS = Packet(0).PCAP.TS + TS Delta
//
// We need to use this odd approach as ERSPAN.TS is only 32bits and all these
// calculations must use modulo arithmetic. Thus the long winded approach 
//
// TODO:
//       As we`re using the NSEC of Packet(0).PCAP.TS as the reference world time
//       we should slew this value when receiving any keyframes until it
//       its using the offset from the switch
//

#define TSMODULO_BIT	32

static u64 TSSignedModulo(u64 Value)
{
	const u64 TSModuloMask 	= ((1ULL <<  TSMODULO_BIT) - 1);

	s64 V = (Value & TSModuloMask); 
	V = (V << (64 - TSMODULO_BIT)) >> (64 - TSMODULO_BIT);
	return V;
}

static inline u64 TSExtract(Proto_t* P, ERSPANv3_t* ERSPAN, u64 PCAPTS)
{
	u64 ERTS = ERSPAN->Header.TS;				// 2018/11/6: this was byteswapped, but seems should be native little endian
	if (!P->TSCalib)
	{
		P->TSCalib 		= true;
		P->TSEROffset 	= ERTS - PCAPTS; 
		P->TS0PCAPTS	= PCAPTS;
		P->TS0ERTS		= ERTS;
	}

	// Packet(n).ERSPAN.TS - Packet(n).PCAP.TS
	s64 dER = ERTS - PCAPTS;

	// Packet(n).ERSAPN.TS - Packet(n).PCAP.TS - CalibOffset
	s64 ERWorld = dER - P->TSEROffset;

	// remove any 32bit overflows 
	s64 ERNano = TSSignedModulo(ERWorld); 

	// final world time, using 32bit ESPAN timestamp
	u64 TS = PCAPTS + ERNano;

	return TS;
}

//---------------------------------------------------------------------------------------------
// de-encapsulate a packet
u16 fDecap_ERSPAN3_Unpack(	fDecap_t* 	D,	
							u64 		PCAPTS,
							fEther_t**	pEther, 

							u8** 		pPayload, 
							u32* 		pPayloadLength,

							u32* 		pMetaPort, 
							u64* 		pMetaTS, 
							u32* 		pMetaFCS)
{
	Proto_t* P = (Proto_t*)D->ProtocolData;

	fEther_t* Ether 	= pEther[0];
	u16 EtherProto 		= swap16(Ether->Proto);

	u8* Payload 		= pPayload[0];
	u32 PayloadLength 	= pPayloadLength[0];

	// default use the pcap TS
	u64 TS = PCAPTS; 

	// at this point the packet has already been qualified, so just cast it
	IPv4Header_t* IPv4Header 	= (IPv4Header_t*)Payload;
	GREHeader_t* GRE 			= (GREHeader_t*)((u8*)IPv4Header + IPv4Header->HLen*4);

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
	case GRE_PROTO_ERSPAN2:
		{
			// ERSPAN Type I flagged by 0x88be AND Version == 0 AND Seqbit == 0
			// Type I has no header, just fully encapsulated
			if (GRE->S == 0)
			{
				// Update new Ethernet header
				Ether = (fEther_t*)(GRE + 1);

				// update encapsulation
				EtherProto = swap16(Ether->Proto);

				// point to (potentially) IPv4 header
				Payload = (u8*)(Ether + 1);

				// adjust the payload size
				PayloadLength -= Payload - pPayload[0]; 
			}
			// ERSPAN Type II flagged by 0x88be AND Version == 0 AND SeqBit == 1
			// Type II has an header 
			else
			{
				ERSPANv2_t* ERSPAN = (ERSPANv2_t*)((u8*)GRE + GRELength);
				ERSPANv2_t ERSPANDecode;

				// byte swap it + non-destructive download
				ERSPANDecode.d32[0] = swap32(ERSPAN->d32[0]);
				ERSPANDecode.d32[1] = swap32(ERSPAN->d32[1]);
				ERSPANDecode.d32[2] = swap32(ERSPAN->d32[2]);

				//trace("ERSPAN Version:%i Index:%i Session:%i VLAN:%i\n", 	
				//										ERSPANDecode.Header.Version,
				//										ERSPANDecode.Header.Index,
				//										ERSPANDecode.Header.Session,
				//										ERSPANDecode.Header.VLAN);



				// Update new Ethernet header
				Ether = (fEther_t*)(ERSPAN + 1);

				// update encapsulation
				EtherProto = swap16(Ether->Proto);

				// point to (potentially) IPv4 header
				Payload = (u8*)(Ether + 1);

				// adjust the payload size
				PayloadLength -= Payload - pPayload[0]; 
			}
		}
		break;

	case GRE_PROTO_ERSPAN3:
	{
		ERSPANv3_t* ERSpan = (ERSPANv3_t*)((u8*)GRE + GRELength);
		u32 ERSpanLen = 3*4;

		// byte swap for bitfied struct  + non destructive decode
		ERSPANv3_t ERSpanDecode;
		ERSpanDecode.d32[0] = swap32(ERSpan->d32[0]);
		ERSpanDecode.d32[1] = swap32(ERSpan->d32[1]);
		ERSpanDecode.d32[2] = swap32(ERSpan->d32[2]);

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

		// remove FCS from output, as ERSPAN does not include it 
		// + keeping the orignial FCS just confuses things
		PayloadLength -= 4;

		// calculate timestamp
		TS = TSExtract(P, &ERSpanDecode, PCAPTS);

		// update stats
		ERSPAN3_Sample(D, &ERSpanDecode, PayloadLength, SeqNo);	

		if (D->DecapDump)
		{
			trace("ERSPAN Session:%08x ", ERSpanDecode.Header.Session);
			trace("SeqNo:%08x ", SeqNo);
			trace("EtherProt:%04x ", EtherProto); 
			trace("GRA:%i ", ERSpanDecode.Header.Gra); 
			trace("PCAP.TS:%lli (%s) ", PCAPTS, FormatTS(PCAPTS)); 
			trace("ERSPAN.TS:%lli (%s) ", TS, FormatTS(TS)); 
			trace("dTS:%8lli ", TS - PCAPTS); 
			trace("Ver:%i ", ERSpanDecode.Header.Version); 
			trace("\n");
		}
	}
	break;

	default:
		//trace("ERSPAN unsuported format: %x\n", GREProto);
		fDecap_Error(D, DECAP_ERROR_ERSPAN_UNSUPPORTED);
		break;
	}

	// set new Ether header (if any)
	pEther[0] 			= Ether;

	// set new IP header
	pPayload[0] 		= Payload;
	pPayloadLength[0]	= PayloadLength;

	pMetaTS[0]			= TS;

	return EtherProto;
}
