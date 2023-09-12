#ifndef ___STREAM_HTTP_DECAP_H__
#define ___STREAM_HTTP_DECAP_H__

#define DECAP_ERROR_GRE_UNSUPPORTED			1
#define DECAP_ERROR_ERSPAN_UNSUPPORTED		2
#define DECAP_ERROR_ERSPAN_TYPEII			3
#define DECAP_ERROR_MAX						4


typedef struct fDecap_t
{
	bool 	DecapDump;
	bool 	DecapVerbose;

	bool 	DecapIxia;

	bool 	DecapArista7130;					// arista 7130 timestamps (metamako)

	bool 	DecapArista7150Insert;				// 7150 insert mode
	bool 	DecapArista7150Over;				// 7150 overwrite mode

	bool 	DecapArista7280MAC48;				// 7280 mac48
	bool 	DecapArista7280ETH64;				// 7280 eth64

	bool 	DecapCisco3550;						// cisco 3550 (exablaze)

	u64		DecapErrorCnt[DECAP_ERROR_MAX];		// number of errors

	u64		GREProtoHistogram[0x10000];			// gre protocol histogram

	u8		ProtocolData[32*1024];				// protocol specific info

} fDecap_t;

struct fEther_t;

//void fDecap_Mode	(u32 Mode);

fDecap_t*  fDecap_Open(int argc, char* argv[]);
void fDecap_Close(	fDecap_t* D);

void fDecap_Error(	fDecap_t* D, u32 Index);

u16 fDecap_Packet(	fDecap_t* D, 
					u64 PCAPTS,
					struct fEther_t** pEther, 

					u8** pPayload, 
					u32* pPayloadLength,

					u32* pMetaPort, 
					u64* pMetaTS, 
					u32* pMetaFCS);

#endif
