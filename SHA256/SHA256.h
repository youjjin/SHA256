#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <intrin.h>

/**************************************************/
//SHA256
//�ؽð� : 256bit
//���λ�ä : 256bit
//��� : 512bit
//�����Ѱ� : (2^64 - 1)bit
//���� : 32byte
//���� �� : 64round
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

	/*�޼����� ��Ʈ����*/
#define SHA256_DIGEST_BLOCKLEN 64 //�Է°� : 512bit = 64byte / unsigned int = 32bit(4byte) / (unsinged int) * 16
#define SHA256_DIGEST_VALUELEN 32 //��°� : 256bit = 32byte / unsinged int = 32bit(4byte) / (unsinged int) * 8

//[SHA256] : 512bit(64byte):szBuffer => 256bit(32byte):uChainVar

/*********************sha256�ؽ��Լ� ��������**************************/
//sha256�� ������ ����ִ� ����ü
typedef struct {
	unsigned int uChainVar[SHA256_DIGEST_VALUELEN / 4]; //�����Լ��� ���(���λ���)�� ��Ӿ�����Ʈ �ϴ� �κ� : 32/4 = 8 => (unsigned int : 4byte) : 8*4(byte) = 32byte
	unsigned int uHighLength; //32bit data �ڷ���
	unsigned int uLowLength; //32bit data �ڷ���, bit����
	unsigned char szBuffer[SHA256_DIGEST_BLOCKLEN]; //�޼�������� �����ϴ� �κ�(�����Լ��� ������ �޼�����ϵ��� ������ �Ǿ ó��) : 64byte
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