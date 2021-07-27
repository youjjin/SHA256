#include "SHA256.h"

/*압축함수에 사용되는 서브함수*/
#if defined(_MSC_VER)
#define ROTL_ULONG(x, n) _lrotl((x), (n))
#define ROTR_ULONG(x, n) _lrotr((x), (n))
#else
#define ROTL_ULONG(x, n) ((unsigned long)((x) << (n)) | (unsigned long)((x) >> (32 - (n))))
#define ROTR_ULONG(x, n) ((unsigned long)((x) >> (n)) | (unsigned long)((x) << (32 - (n))))
#endif

#define ENDIAN_REVERSE_ULONG(dwS)	( (ROTL_ULONG((dwS),  8) & 0x00ff00ff)	\
									| (ROTL_ULONG((dwS), 24) & 0xff00ff00) )

#if defined(BIG_ENDIAN)
#define BIG_B2D(B, D)		D = *(unsigned long*)(B)
#define BIG_D2B(D, B)		*(unsigned long*)(B) = (unsigned long)(D)
#define LITTLE_B2D(B, D)	D = ENDIAN_REVERSE_ULONG(*(unsigned long*)(B))
#define LITTLE_D2B(D, B)	*(unsigned long*)(B) = ENDIAN_REVERSE_ULONG(D)
#elif defined(LITTLE_ENDIAN)
#define BIG_B2D(B, D)		D = ENDIAN_REVERSE_ULONG(*(unsigned long*)(B))
#define BIG_D2B(D, B)		*(unsigned long*)(B) = ENDIAN_REVERSE_ULONG(D)
#define LITTLE_B2D(B, D)	D = *(unsigned long*)(B)
#define LITTLE_D2B(D, B)	*(unsigned long*)(B) = (unsigned long)(D)
#else
#error ERROR : Invalid DataChangeType
#endif

#define RR(x, n)		ROTR_ULONG(x, n)
#define SS(x, n)		(x >> n)

#define Ch(x, y, z)		((x & y) ^ ((~x) & z))
#define Maj(x, y, z)	((x & y) ^ (x & z) ^ (y & z))
#define Sigma0(x)		(RR(x,  2) ^ RR(x, 13) ^ RR(x, 22))
#define Sigma1(x)		(RR(x,  6) ^ RR(x, 11) ^ RR(x, 25))

#define RHO0(x)			(RR(x,  7) ^ RR(x, 18) ^ SS(x,  3))
#define RHO1(x)			(RR(x, 17) ^ RR(x, 19) ^ SS(x, 10))


//[SHA256] : 512bit(64byte):szBuffer => 256bit(32byte):uChainVar

/*압축함수에 사용되는 상수*/
unsigned int SHA256_K[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

void SHA256_Transform_op(unsigned long* Message, unsigned long* ChainVar)
{
	unsigned long a, b, c, d, e, f, g, h, T1, X[64];
	unsigned long j;

	X[0] = ENDIAN_REVERSE_ULONG(Message[0]); X[1] = ENDIAN_REVERSE_ULONG(Message[1]); X[2] = ENDIAN_REVERSE_ULONG(Message[2]); X[3] = ENDIAN_REVERSE_ULONG(Message[3]);
	X[4] = ENDIAN_REVERSE_ULONG(Message[4]); X[5] = ENDIAN_REVERSE_ULONG(Message[5]); X[6] = ENDIAN_REVERSE_ULONG(Message[6]); X[7] = ENDIAN_REVERSE_ULONG(Message[7]);
	X[8] = ENDIAN_REVERSE_ULONG(Message[8]); X[9] = ENDIAN_REVERSE_ULONG(Message[9]); X[10] = ENDIAN_REVERSE_ULONG(Message[10]); X[11] = ENDIAN_REVERSE_ULONG(Message[11]);
	X[12] = ENDIAN_REVERSE_ULONG(Message[12]); X[13] = ENDIAN_REVERSE_ULONG(Message[13]); X[14] = ENDIAN_REVERSE_ULONG(Message[14]); X[15] = ENDIAN_REVERSE_ULONG(Message[15]);

	for (j = 16; j < 64; j++)
		X[j] = RHO1(X[j - 2]) + X[j - 7] + RHO0(X[j - 15]) + X[j - 16];

	/***********************************************************************************************/

	a = ChainVar[0]; b = ChainVar[1]; c = ChainVar[2]; d = ChainVar[3];
	e = ChainVar[4]; f = ChainVar[5]; g = ChainVar[6]; h = ChainVar[7];

	/*9번의 round function*/
	for (j = 0; j < 64; j += 8)
	{
		T1 = h + Sigma1(e) + Ch(e, f, g) + SHA256_K[j] + X[j]; d += T1; h = T1 + Sigma0(a) + Maj(a, b, c);
		T1 = g + Sigma1(d) + Ch(d, e, f) + SHA256_K[j + 1] + X[j + 1]; c += T1; g = T1 + Sigma0(h) + Maj(h, a, b);
		T1 = f + Sigma1(c) + Ch(c, d, e) + SHA256_K[j + 2] + X[j + 2]; b += T1; f = T1 + Sigma0(g) + Maj(g, h, a);
		T1 = e + Sigma1(b) + Ch(b, c, d) + SHA256_K[j + 3] + X[j + 3]; a += T1; e = T1 + Sigma0(f) + Maj(f, g, h);
		T1 = d + Sigma1(a) + Ch(a, b, c) + SHA256_K[j + 4] + X[j + 4]; h += T1; d = T1 + Sigma0(e) + Maj(e, f, g);
		T1 = c + Sigma1(h) + Ch(h, a, b) + SHA256_K[j + 5] + X[j + 5]; g += T1; c = T1 + Sigma0(d) + Maj(d, e, f);
		T1 = b + Sigma1(g) + Ch(g, h, a) + SHA256_K[j + 6] + X[j + 6]; f += T1; b = T1 + Sigma0(c) + Maj(c, d, e);
		T1 = a + Sigma1(f) + Ch(f, g, h) + SHA256_K[j + 7] + X[j + 7]; e += T1; a = T1 + Sigma0(b) + Maj(b, c, d);
	}

	/*다음 압축함수에 사용되는 256bit*/
	ChainVar[0] += a; ChainVar[1] += b;
	ChainVar[2] += c; ChainVar[3] += d;
	ChainVar[4] += e; ChainVar[5] += f;
	ChainVar[6] += g; ChainVar[7] += h;

}

/*Init & Process & Close => SHA256_op*/
void SHA256_op(SHA256_INFO * Info, const unsigned char *pszMessage, unsigned int uDataLen, unsigned char *pszDigest)
{
	/*Init*/
	Info->uChainVar[0] = 0x6a09e667; Info->uChainVar[1] = 0xbb67ae85; Info->uChainVar[2] = 0x3c6ef372; Info->uChainVar[3] = 0xa54ff53a;
	Info->uChainVar[4] = 0x510e527f; Info->uChainVar[5] = 0x9b05688c; Info->uChainVar[6] = 0x1f83d9ab; Info->uChainVar[7] = 0x5be0cd19;
	Info->uHighLength = Info->uLowLength = 0;

	/*Process*/
	unsigned int temp;
	/**********************길이정보 update : bit단위로(carry를 처리)***********************/
	temp = Info->uLowLength + (uDataLen << 3);
	if (temp < Info->uLowLength)
		Info->uHighLength += 1;
	Info->uLowLength = temp;
	Info->uHighLength += (uDataLen >> 29);

	/********************************블록단위(512bit)로 hash처리*********************************/
	while (uDataLen >= SHA256_DIGEST_BLOCKLEN)
	{
		memcpy((unsigned char*)Info->szBuffer, pszMessage, (signed int)SHA256_DIGEST_BLOCKLEN);
		SHA256_Transform_op((unsigned long*)Info->szBuffer, Info->uChainVar);
		pszMessage += SHA256_DIGEST_BLOCKLEN;
		uDataLen -= SHA256_DIGEST_BLOCKLEN;
	}
	memcpy((unsigned char*)Info->szBuffer, pszMessage, uDataLen);

	/*Close*/
	unsigned long i, Index;
	/**********************************(1000......0000 padding)****************************************/
	Index = (Info->uLowLength >> 3) % SHA256_DIGEST_BLOCKLEN;
	Info->szBuffer[Index++] = 0x80;
	if (Index > 56)
	{
		memset((unsigned char*)Info->szBuffer + Index, 0, (signed int)(SHA256_DIGEST_BLOCKLEN - Index));
		SHA256_Transform_op((unsigned long*)Info->szBuffer, Info->uChainVar);
		memset((unsigned char*)Info->szBuffer, 0, (signed int)56);
	}
	else
		memset((unsigned char*)Info->szBuffer + Index, 0, (signed int)(56 - Index));

/******************************************길이정보padding*********************************************/
#if defined(LITTLE_ENDIAN)
	Info->uLowLength = ENDIAN_REVERSE_ULONG(Info->uLowLength);
	Info->uHighLength = ENDIAN_REVERSE_ULONG(Info->uHighLength);
#endif
	((unsigned long*)Info->szBuffer)[14] = Info->uHighLength; //[SHA256_DIGEST_BLOCKLEN / 4 - 2]
	((unsigned long*)Info->szBuffer)[15] = Info->uLowLength; //[SHA256_DIGEST_BLOCKLEN / 4 - 1]

	/******************************padding을 완료한 메세지블록을 가지고 압축함수를 호출********************************/
	SHA256_Transform((unsigned long*)Info->szBuffer, Info->uChainVar);

	BIG_D2B((Info->uChainVar)[0], &(pszDigest[0])); BIG_D2B((Info->uChainVar)[1], &(pszDigest[4]));
	BIG_D2B((Info->uChainVar)[2], &(pszDigest[8])); BIG_D2B((Info->uChainVar)[3], &(pszDigest[12]));
	BIG_D2B((Info->uChainVar)[4], &(pszDigest[16])); BIG_D2B((Info->uChainVar)[5], &(pszDigest[20]));
	BIG_D2B((Info->uChainVar)[6], &(pszDigest[24])); BIG_D2B((Info->uChainVar)[7], &(pszDigest[28]));
}