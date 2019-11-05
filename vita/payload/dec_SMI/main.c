/*
    mincg by SKGleba
    All Rights Reserved
*/

#include "types.h"
static volatile u32_t * const BIGMAC = (void *)0xE0050000;
static volatile u32_t * const RESULTS = (void *)0x1C000700;

void __attribute__((optimize("O0"))) _start(void) {
	int ret = 0, kdst = 0;
	u32_t flags[2];
	u32_t keyslut = 0x213;
	u32_t fw = *(u32_t *)(0xE0058000 + (0x50E * 0x20));
	u32_t (*derive_key)(unsigned int dst, unsigned int src, u32_t sz, u32_t *kslot, unsigned int iv, unsigned int flag1, unsigned int flag2, unsigned int flag3, unsigned int *flags);
	u32_t (*rsa_check)(char *a0, u32_t a1, u32_t *a2, u32_t a3, unsigned int a4, unsigned int *a5);
	u32_t (*e20_loop)();
	
	if (fw >= 0x03600000 && fw < 0x03710000) {
		derive_key = (void*)((u32_t)0x0081148c);
		rsa_check = (void*)((u32_t)0x00811b04);
		e20_loop = (void*)((u32_t)0x00811ae6);
	} else if (fw >= 0x03710000 && fw < 0x03740000) {
		derive_key = (void*)((u32_t)0x00811562);
		rsa_check = (void*)((u32_t)0x00811bda);
		e20_loop = (void*)((u32_t)0x00811bbc);
	} else {
		RESULTS[11] = 0x34;
		return;
	}
	
	if (BIGMAC[9] & 1) {
		BIGMAC[7] = 0;
		while (BIGMAC[9] & 1) {}
	}
	
	// initial pass
	BIGMAC[0] = 0x1C012100;
	BIGMAC[1] = 0x1C000100;
	BIGMAC[2] = 0x200;
	BIGMAC[3] = 0x2080 & 0xfffffff8;
	BIGMAC[7] = 1;
	while (BIGMAC[9] & 1) {}
	RESULTS[0] = BIGMAC[9];
	
	// KEY_1
	flags[0] = 1;
	flags[1] = 0x2080;
	flags[1] = (0 & 1) << 7 | flags[1] & 0xffffff7f;
	ret = derive_key(0x1C000000, 0x1C012000, 0x20, &keyslut, 0x1C012040, 1, 1, 3, &flags[0]);
	while (BIGMAC[9] & 1) {}
	RESULTS[1] = BIGMAC[9];
	RESULTS[2] = ret;
	
	// cpy key
	BIGMAC[0] = 0x1C000000;
	BIGMAC[1] = 0xE0050200;
	BIGMAC[2] = 0x20;
	BIGMAC[3] = 0x2080 & 0xfffffff8;
	BIGMAC[7] = 1;
	while (BIGMAC[9] & 1) {}
	RESULTS[3] = BIGMAC[9];
	
	// key1_dec_idst
	BIGMAC[0] = 0x1C000180;
	BIGMAC[1] = 0x1C000180;
	BIGMAC[2] = 0x180;
	BIGMAC[3] = (1 & 7) << 3 | 0x2080 & 0xfffffcc0 | 2 & 7 | (3 & 3) << 8;
	BIGMAC[4] = 0;
	BIGMAC[5] = 0x1C0120B0;
	BIGMAC[7] = 1;
	while (BIGMAC[9] & 1) {}
	RESULTS[4] = BIGMAC[9];
	
	// KEY_2
	flags[0] = 1;
	flags[1] = 0x2080;
	flags[1] = (0 & 1) << 7 | flags[1] & 0xffffff7f;
	ret = derive_key(0x1C000040, 0x1C012060, 0x20, &keyslut, 0x1C0120A0, 1, 1, 3, &flags[0]);
	while (BIGMAC[9] & 1) {}
	RESULTS[7] = BIGMAC[9];
	RESULTS[8] = ret;
	
	// cpy key
	BIGMAC[0] = 0x1C000040;
	BIGMAC[1] = 0xE0050200;
	BIGMAC[2] = 0x20;
	BIGMAC[3] = 0x2080 & 0xfffffff8;
	BIGMAC[7] = 1;
	while (BIGMAC[9] & 1) {}
	RESULTS[9] = BIGMAC[9];
	
	// key2_dec_idst
	BIGMAC[0] = 0x1C000180;
	BIGMAC[1] = 0x1C000500;
	BIGMAC[2] = 0x180;
	BIGMAC[3] = (1 & 7) << 3 | 0x2080 & 0xfffffcc0 | 2 & 7 | (3 & 3) << 8;
	BIGMAC[4] = 0;
	BIGMAC[5] = 0x1C0120C0;
	BIGMAC[7] = 1;
	while (BIGMAC[9] & 1) {}
	RESULTS[10] = BIGMAC[9];
	
	// cpy signed block
	BIGMAC[0] = 0x1C000100;
	BIGMAC[1] = 0x1C000800;
	BIGMAC[2] = 0x100;
	BIGMAC[3] = (2 & 7) << 3 | 0x2080 & 0xfffff3c0 | 3;
	BIGMAC[7] = 1;
	while (BIGMAC[9] & 1) {}
	RESULTS[5] = BIGMAC[9];
	
	// set params
	*(u32_t *)0x1C000900 = (u32_t)0x1C012400;
	*(u32_t *)0x1C000904 = (u32_t)0x40;
	*(u32_t *)0x1C000908 = (u32_t)0x1C012500;
	*(u32_t *)0x1C00090C = (u32_t)1;
	
	// rsa-check the SMI
	while (ret = rsa_check((char *)0x1C000A00, 0x1C000200, (u32_t *)0x1C000900, 0x1C000800, 4, (unsigned int *)0x1C1FD0A0), ret == -0x7ff0fff0) {
		e20_loop();
    }
	
	RESULTS[6] = ret;
	
	if (BIGMAC[9] & 1) {
		BIGMAC[7] = 0;
		while (BIGMAC[9] & 1) {}
	}
	
	if (*(u32_t *)0x1C000500 > 0x00996000 && *(u32_t *)0x1C000500 < fw) {
		RESULTS[11] = 0x69;
	} else 
		RESULTS[11] = 0x34;
	return;
}