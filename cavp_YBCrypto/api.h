#ifndef HEADER_API_H
#define HEADER_API_H

//! BlockCIpher CAVP
void ARIA_ECB_KAT();
void ARIA_CBC_KAT();
void ARIA_CTR_KAT();

void ARIA_ECB_MMT();
void ARIA_CBC_MMT();
void ARIA_CTR_MMT();

void ARIA_ECB_MCT();
void ARIA_CBC_MCT();
void ARIA_CTR_MCT();

//! HashFunction CAVP
void SHA256_SHORT_LONG();
void SHA256_MCT();

//! HMAC CAVP
void HMAC_SHA256_KAT();

//! CTR_DRBG CAVP
void ARIA_CTR_DRBG_UDF_UPR();
void ARIA_CTR_DRBG_NDF_UPR();
void ARIA_CTR_DRBG_UDF_NPR();
void ARIA_CTR_DRBG_NDF_NPR();

//! Common API CAVP
void Count_Addition(unsigned char *count);
void print_hex( char* valName,  uint8_t* data,  int dataByteLen);
int asc2hex(uint8_t* dst, char* src);

#endif
//EOF
