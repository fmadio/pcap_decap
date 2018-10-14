#ifndef ___STREAM_HTTP_DECAP_H__
#define ___STREAM_HTTP_DECAP_H__

struct fEther_t;

void fDecap_Mode	(u32 Mode);

void fDecap_Open	(int argc, char* argv[]);
void fDecap_Close	(void);

u16 fDecap_Packet(	u64 PCAPTS,
					struct fEther_t** pEther, 

					u8** pPayload, 
					u32* pPayloadLength,

					u32* pMetaPort, 
					u64* pMetaTS, 
					u32* pMetaFCS);

#endif
