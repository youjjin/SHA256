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

//*********************************************************************************************************************************
// o SHA256_Transform()	: 512 비트 단위 블록의 메시지를 입력 받아 연쇄변수를 갱신하는 압축 함수로써
//						  4 라운드(64 단계)로 구성되며 8개의 연쇄변수(a, b, c, d, e, f, g, h)를 사용
// o 입력				: Message		- 입력 메시지의 포인터 변수
//						  ChainVar		- 연쇄변수의 포인터 변수
// o 출력				: 
//*********************************************************************************************************************************
void SHA256_Transform(unsigned long* Message, unsigned long* ChainVar) //Compression function : 압축함수 내부(라운드 함수)
{
	//Message : 처음받는 메세지
	//ChainVar : 출력되는 hash값

	unsigned long a, b, c, d, e, f, g, h, T1, X[64];
	unsigned long j;
	
	/************************************64개의 Working Register설정*********************************/
	//little endian으로 들어온 자료형을 big endian으로 바꿔준다.
	//나중에는 big endian형태를 little endian으로 바꿔주어야한다.
	//4Byte 단위로 Big Endian으로 변경함 (pszBuffer는 Byte단위{0x01, 0x02, 0x03, 0x04, ...}고 szBuffer는 Word단위{0x04030201, ... } -> little endian라 endian을 고려!)
	for (j = 0; j < 16; j++) //처음 16byte는 입력된 메세지..
		X[j] = ENDIAN_REVERSE_ULONG(Message[j]);

	for (j = 16; j < 64; j++)
		X[j] = RHO1(X[j - 2]) + X[j - 7] + RHO0(X[j - 15]) + X[j - 16];
	
	/***********************************************************************************************/
	
	a = ChainVar[0];
	b = ChainVar[1];
	c = ChainVar[2];
	d = ChainVar[3];
	e = ChainVar[4];
	f = ChainVar[5];
	g = ChainVar[6];
	h = ChainVar[7];

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

//*********************************************************************************************************************************
// o SHA256_Process()	: 임의의 길이를 가지는 입력 메시지를 512 비트 블록 단위로 나누어 압축함수를 호출하는 함수
// o 입력				: Info		 - SHA-256 구조체의 포인터 변수
//						  pszMessage - 입력 메시지의 포인터 변수
//						  uDataLen	 - 입력 메시지의 바이트 길이
// o 출력				: 
//*********************************************************************************************************************************
void SHA256_Process(SHA256_INFO * Info, const unsigned char *pszMessage, unsigned int uDataLen) //블록단위로 압축함수 실행
{
	Info->uChainVar[0] = 0x6a09e667;
	Info->uChainVar[1] = 0xbb67ae85;
	Info->uChainVar[2] = 0x3c6ef372;
	Info->uChainVar[3] = 0xa54ff53a;
	Info->uChainVar[4] = 0x510e527f;
	Info->uChainVar[5] = 0x9b05688c;
	Info->uChainVar[6] = 0x1f83d9ab;
	Info->uChainVar[7] = 0x5be0cd19;

	Info->uHighLength = Info->uLowLength = 0;

	unsigned int temp; //4byte (64bite인데 32bit자료형을 사용 => carry처리)

	/**********************길이정보 update : bit단위로(carry를 처리)***********************/

	temp = Info->uLowLength + (uDataLen << 3); //bit단위로 나타내어 줄것이기 때문에 byte*8을 해서 bit단위로 나타내주었다.

	if (temp < Info->uLowLength)//캐리가 발생할 경우 uHighLength에 반영
	{
		Info->uHighLength += 1;
	}

	Info->uLowLength = temp;
	Info->uHighLength += (uDataLen >> 29); //바이트당 8ibt를 곱하였을 때, 상위 32bit에 전달되는 값

	/********************************블록단위(512bit)로 hash처리*********************************/

	while (uDataLen >= SHA256_DIGEST_BLOCKLEN) //메세지의 길이가 64byte보다 크거나 같다면...
	{
		memcpy((unsigned char*)Info->szBuffer, pszMessage, (signed int)SHA256_DIGEST_BLOCKLEN); //블록사이즈만큼 Info->szBuffer에 pszMessage(실제 처리해야 할 메세지)를 copy(Byte단위)
		SHA256_Transform((unsigned long*)Info->szBuffer, Info->uChainVar);//라운드함수 szBuffer에 있는 내용이 hash되어서 uChainVar에 저장!(update)
		pszMessage += SHA256_DIGEST_BLOCKLEN; //다음 64byte(512but)만큼을 처리해주기 위해 포인터 이동
		uDataLen -= SHA256_DIGEST_BLOCKLEN; //메세지 길이도 64byte(512bit)만큼 줄여주어야한다.(512bit만큼 처리해 줬기 때문)
	}

	//uDataLen이 64byte보다 작아지면.. 마지막 남는 byte에 대해서 memcpy로 그 포인터를 받아준다.
	memcpy((unsigned char*)Info->szBuffer, pszMessage, uDataLen); //입력된 블록datad의 길이만큼  Info->szBuffer에 pszMessage를 copy(Byte단위)
}

//*********************************************************************************************************************************
// o SHA256_Close()		: 메시지 덧붙이기와 길이 덧붙이기를 수행한 후 마지막 메시지 블록을 가지고 압축함수를 호출하는 함수
// o 입력				: Info	    - SHA-256 구조체의 포인터 변수
//						  pszDigest	- SHA-256 해쉬값을 저장할 포인터 변수
// o 출력				:
//*********************************************************************************************************************************
void SHA256_Close(SHA256_INFO *Info, unsigned char *pszDigest) //패딩 수행 후, 압축함수 수행
{
	unsigned long i, Index;

	/**********************************패딩수행*********************************/
	//패딩규칙 : SHA256 => msglen + x(100000....0000) + 64 = 512*i => l+1+k = 448 (mod 512) : (512-64 = 448 - l - 1이 0의 갯수 => k는 최소의 0의 갯수가 된다.)

	/**********************************(1000......0000 padding)****************************************/
	// & : 하나라도 0이 있으면 0
	Index = (Info->uLowLength >> 3) % SHA256_DIGEST_BLOCKLEN; //(Info->uLowLength >> 3) : 메세지를 바이트 단위로 바꿔줌, & 64byte
	Info->szBuffer[Index++] = 0x80; //최상위 비트를 1로하고 0으로 채워주는 부분(x부분)

	/*k개 만큼의 0을 채워주는 부분*/
	if (Index > SHA256_DIGEST_BLOCKLEN - 8) //-8(byte)은 마지막 길이정보가 들어갈 64bit
	{
		memset((unsigned char*)Info->szBuffer + Index, 0, (signed int)(SHA256_DIGEST_BLOCKLEN - Index)); //0부분을 복사(0값을 채워주는 부분)
		SHA256_Transform((unsigned long*)Info->szBuffer, Info->uChainVar);
		memset((unsigned char*)Info->szBuffer, 0, (signed int)SHA256_DIGEST_BLOCKLEN - 8); 
	}
	else
		memset((unsigned char*)Info->szBuffer + Index, 0, (signed int)(SHA256_DIGEST_BLOCKLEN - Index - 8)); //0부분을 복사(0값을 채워주는 부분)

/******************************************길이정보padding*********************************************/

#if defined(LITTLE_ENDIAN) //최종적으로 길이에 대한 정보도 넣어줘야 한다.(endian고려)
	Info->uLowLength = ENDIAN_REVERSE_ULONG(Info->uLowLength);
	Info->uHighLength = ENDIAN_REVERSE_ULONG(Info->uHighLength);
#endif
	((unsigned long*)Info->szBuffer)[SHA256_DIGEST_BLOCKLEN / 4 - 2] = Info->uHighLength;
	((unsigned long*)Info->szBuffer)[SHA256_DIGEST_BLOCKLEN / 4 - 1] = Info->uLowLength;

	/******************************padding을 완료한 메세지블록을 가지고 압축함수를 호출********************************/
	SHA256_Transform((unsigned long*)Info->szBuffer, Info->uChainVar); //압축함수 수행

	for (i = 0; i < SHA256_DIGEST_VALUELEN; i += 4) //최종결과물 endian고려
		BIG_D2B((Info->uChainVar)[i / 4], &(pszDigest[i]));
}

void SHA256_Encrypt(const unsigned char *pszMessage, unsigned int uPlainTextLen, unsigned char *pszDigest)
{
	SHA256_INFO info;
	//SHA256_Init(&info);
	SHA256_Process(&info, pszMessage, uPlainTextLen);//바이트단위로 적용한 뒤, 512bit를 못 채우는 마지막 남는 바이트에 대해서 info의 buffer에다가 받아준다.
	SHA256_Close(&info, pszDigest);
}