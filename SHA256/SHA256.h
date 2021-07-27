#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <intrin.h>

/**************************************************/
//SHA256
//해시값 : 256bit
//내부상채 : 256bit
//블록 : 512bit
//길이한계 : (2^64 - 1)bit
//워드 : 32byte
//라운드 수 : 64round
/**************************************************/

#ifndef SHA256_H
#define SHA256_H

#ifdef  __cplusplus
extern "C" {
#endif

/*Little Endian => Big Endian*/
#undef BIG_ENDIAN
#undef LITTLE_ENDIAN

#if defined(USER_BIG_ENDIAN)
	#define BIG_ENDIAN
#elif defined(USER_LITTLE_ENDIAN)
	#define LITTLE_ENDIAN
#else
	#if 0
		#define BIG_ENDIAN
	#elif defined(_MSC_VER)
		#define LITTLE_ENDIAN
	#else
		#error
	#endif
#endif

	/*메세지의 비트길이*/
#define SHA256_DIGEST_BLOCKLEN 64 //입력값 : 512bit = 64byte / unsigned int = 32bit(4byte) / (unsinged int) * 16
#define SHA256_DIGEST_VALUELEN 32 //출력값 : 256bit = 32byte / unsinged int = 32bit(4byte) / (unsinged int) * 8

//[SHA256] : 512bit(64byte):szBuffer => 256bit(32byte):uChainVar

/*********************sha256해시함수 상태정의**************************/
//sha256의 정보를 담고있는 구조체
typedef struct {
	unsigned int uChainVar[SHA256_DIGEST_VALUELEN / 4]; //압축함수의 결과(내부상태)를 계속업데이트 하는 부분 : 32/4 = 8 => (unsigned int : 4byte) : 8*4(byte) = 32byte
	unsigned int uHighLength; //32bit data 자료형
	unsigned int uLowLength; //32bit data 자료형, bit길이
	unsigned char szBuffer[SHA256_DIGEST_BLOCKLEN]; //메세지블록을 유지하는 부분(압축함수를 적용한 메세지블록들이 저장이 되어서 처리) : 64byte
}SHA256_INFO;


/************************************************************/

void SHA256_Init(SHA256_INFO *Info);
void SHA256_Process(SHA256_INFO * Info, const unsigned char *pszMessage, unsigned int uDataLen);
void SHA256_Transform(unsigned long* Message, unsigned long* ChainVar);
void SHA256_Close(SHA256_INFO *Info, unsigned char *pszDigest);
void SHA256_Encrypt(const unsigned char *pszMessage, unsigned int uPlainTextLen, unsigned char *pszDigest);


void Short_Messages_Test();
void Long_Messages_Test();
void Pseudorandomly_Generated_Messages_Test();

#ifdef  __cplusplus
}
#endif

#endif