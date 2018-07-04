//---------------------------------------------------------------------------------------------
//
// Copyright (c) 2017, fmad engineering llc 
//
// Fast PCAP de-encapsulation tool. Automatically de-encapsulate PCAPs with some basic filtering
//
//---------------------------------------------------------------------------------------------

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/ioctl.h>
#include <linux/sched.h>

#include "fTypes.h"
#include "fNetwork.h"

//-------------------------------------------------------------------------------------------------

double TSC2Nano = 0;
bool g_Verbose = false;

u16 DeEncapsulate(	fEther_t** pEther, 

					u8** pPayload, 
					u32* pPayloadLength,

					u32* MetaPort, 
					u32* MetaSec, 
					u32* MetaNSec, 
					u32* MetaFCS);


void ERSPAN3Open(void);
void ERSPAN3Close(void);

//-------------------------------------------------------------------------------------------------

static void Help(void)
{
	printf("pcap_decap \n");
	printf("\n");
	printf("Command works entirely based linux input / ouput pipes.\n"); 
	printf("For example:\n");
	printf("$ cat erspan.pcap | pcap_decap > output.pcap\n");
	printf("\n");
	printf("Options:\n");
	printf("-v                 : verbose output\n");
	printf("\n");
}

//-------------------------------------------------------------------------------------------------

int main(int argc, char* argv[])
{
	for (int i=1; i < argc; i++)
	{
		if (strcmp(argv[i], "--help") == 0)
		{
			Help();
			return 0;
		}
		else if (strcmp(argv[i], "-v") == 0)
		{
			fprintf(stderr, "Verbose Output\n");
			g_Verbose = true;
		}
	}
	FILE* InFile  = stdin;
	FILE* OutFile = stdout;

	// write output pcap header 
	PCAPHeader_t		Header;
	Header.Magic		= PCAPHEADER_MAGIC_NANO;
	Header.Major		= PCAPHEADER_MAJOR;
	Header.Minor		= PCAPHEADER_MINOR;
	Header.TimeZone		= 0; 
	Header.SigFlag		= 0; 
	Header.SnapLen		= 65535; 
	Header.Link			= PCAPHEADER_LINK_ETHERNET; 
	if (fwrite(&Header, sizeof(Header), 1, OutFile) != 1)
	{
		fprintf(stderr, "Failed to write header to output\n");
		return 0;
	}

	// read the header
	PCAPHeader_t		InputHeader;
	if (fread(&InputHeader,  sizeof(InputHeader), 1, InFile) != 1)
	{
		fprintf(stderr, "Input pcap failed to read\n");
		return 0;
	}

	// what kind of pcap
	u64 TimeScale = 0; 
	if (InputHeader.Magic == PCAPHEADER_MAGIC_NANO)
	{
		fprintf(stderr, "Found PCAP Nano\n");
		TimeScale = 1;
	}
	if (InputHeader.Magic == PCAPHEADER_MAGIC_USEC)
	{
		fprintf(stderr, "Found PCAP USec\n");
		TimeScale = 1000;
	}
	if (TimeScale == 0)
	{
		fprintf(stderr, "Invalid input PCAP magic. Found: %08x Expect %08x\n",
				InputHeader.Magic, PCAPHEADER_MAGIC_NANO);
		return 0;
	}

	CycleCalibration();

	u64 TotalBytes 		= 0;
	u64 TotalPacket		= 0;
	u64 T0 				= rdtsc();

	u8* PktInput		= malloc(32*1024);
	u8* PktOutput		= malloc(32*1024);

	memset(PktInput, 0, 16*1024);

	PCAPPacket_t 	HeaderInput;	
	PCAPPacket_t 	HeaderOutput;	

	// init protocol stats
	ERSPAN3Open();

	while (true)
	{
		// read pcap header
		if (fread(&HeaderInput, sizeof(HeaderInput), 1, InFile) != 1)
		{
			break;
		}

		if (fread(PktInput, HeaderInput.LengthCapture, 1, InFile) != 1)
		{
			break;
		}
		//fprintf(stderr, "size: %i\n", HeaderInput.LengthCapture);

		fEther_t* Ether = (fEther_t*)PktInput;

		// assume payload has no de-encapsulation
		u8* Payload 		= PktInput + sizeof(fEther_t);
		u32 PayloadLength	= HeaderInput.LengthCapture - sizeof(fEther_t);

		u32 MetaPort 	= 0;
		u32 MetaSec 	= 0;
		u32 MetaNSec 	= 0;
		u32 MetaFCS 	= 0;

		u32 EtherProto = DeEncapsulate(	&Ether, 
										&Payload, 
										&PayloadLength,
										&MetaPort, 
										&MetaSec, 
										&MetaNSec, 
										&MetaFCS
									  );

		// write packet header
		HeaderOutput.Sec			= HeaderInput.Sec;
		HeaderOutput.NSec			= HeaderInput.NSec;

		HeaderOutput.LengthCapture	= PayloadLength + sizeof(fEther_t); 
		HeaderOutput.LengthWire		= HeaderInput.LengthWire; 

		fwrite(&HeaderOutput, sizeof(HeaderOutput), 1, OutFile);

		// write ether header 
		Ether->Proto				= swap16(EtherProto);
		fwrite(Ether, sizeof(fEther_t), 1, OutFile);

		// write payload
		fwrite(Payload, HeaderOutput.LengthCapture - sizeof(fEther_t), 1, OutFile);

/*
		TotalBytes += Packet->LengthCapture + sizeof(PCAPPacket_t);

		u64 T1 = rdtsc();
		if (T1 > NextPrintTSC)
		{
			NextPrintTSC = T1 + ns2tsc(1e9);

			double dT = tsc2ns(T1 - T0) / 1e9;
			double Bps = (TotalBytes * 8.0) / dT;

			double ETA = ((TotalInputBytes * 8.0) / Bps) - dT;

			printf("[%.4f %%] %.3fGB %.6fGbps Elapsed:%f Min ETA:%2.f Min | ", TotalBytes / (double)TotalInputBytes, TotalBytes / 1e9, Bps / 1e9, dT/60, ETA / 60);
			for (int i=0; i < InFileCnt; i++)
			{
				printf("%.3fGB ", InFileList[i].MapPos / 1e9);
			}
			printf("\n");
		}
*/
	}

	// print protocol stats 
	ERSPAN3Close();

	return 0;
}
