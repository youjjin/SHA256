unsigned int cpucycles(void) { return __rdtsc(); }

int main(void)
{
	unsigned int uPlainTextLen = 8;
	unsigned char pszMessage[1] = { 0xED };
	unsigned char pszDigest[32] = { 0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55 };

	int i;
	unsigned long long cycles=0, cycles1, cycles2;
	unsigned int loop = 10000;

	//for loop에 들어가는 것까지 안새주려고 시간을 포루프 안에서 돌려줄것이다.
	for (i = 0; i < loop; i++)
	{
		cycles1 = cpucycles();
		SHA256_Encrypt(pszMessage, uPlainTextLen, pszDigest);
		cycles2 = cpucycles();
		cycles += (cycles2 - cycles1);
	}

	printf("\n[loop = %d]cycles : %10lld\n", loop, cycles / loop);
	cycles = 0;

	//Short_Messages_Test();
	//Long_Messages_Test();
	//Pseudorandomly_Generated_Messages_Test();
}