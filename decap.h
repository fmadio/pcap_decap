#ifndef ___STREAM_HTTP_DECAP_H__
#define ___STREAM_HTTP_DECAP_H__

struct fEther_t;

void fDecap_Mode	(u32 Mode);

void fDecap_Open	(int argc, char* argv[]);
void fDecap_Close	(void);

void fDecap_Error	(u32 Index);
#define DECAP_ERROR_GRE_UNSUPPORTED			1
#define DECAP_ERROR_ERSPAN_UNSUPPORTED		2
#define DECAP_ERROR_ERSPAN_TYPEII			3
#define DECAP_ERROR_MAX						4


u16 fDecap_Packet(	u64 PCAPTS,
					struct fEther_t** pEther, 

					u8** pPayload, 
					u32* pPayloadLength,

					u32* pMetaPort, 
					u64* pMetaTS, 
					u32* pMetaFCS);

#endif
