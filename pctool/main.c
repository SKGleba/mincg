/*
    mincg_public by SKGleba
    All Rights Reserved
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdint.h>

#define SRC argv[1]

int main(int argc, char **argv){
	const char *iv_1 = "2F0AEEF98EE3965650F8485E6C0BC2C4";
	const char *iv_2 = "69D7618B7DBE7B59C04DEF5169831FBF";
	
	unsigned char syscmdc[512], cbuff[128], fw[4], gbuff[128], dbuff[128], KEY_1[65], KEY_2[65], K1BUF[32], K2BUF[32], cname[9], UNKKBUF[64];
	
	int opmode = 1, l = 0, cur = 0, found = 0;
	FILE *fp, *ft;
	if(argc < 2) {
		printf("\nusage: mincg [KEYFILE]\n");
		return -1;
	}
	
	memset((void *)KEY_1, 0, 32);
	memset((void *)KEY_2, 0, 32);
	memset((void *)K1BUF, 0, 32);
	memset((void *)K2BUF, 0, 32);
	
	ft = fopen(SRC, "rb");
	if (ft == NULL) {
		printf("ERROR: cannot open file for read (%s)\n", SRC);
		return -1;
	}
	fread(K2BUF, 32, 1, ft);
	fread(K1BUF, 32, 1, ft);
	fclose(ft);
	
	sprintf(KEY_1, "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X", K1BUF[0], K1BUF[1], K1BUF[2], K1BUF[3], K1BUF[4], K1BUF[5], K1BUF[6], K1BUF[7], K1BUF[8], K1BUF[9], K1BUF[10], K1BUF[11], K1BUF[12], K1BUF[13], K1BUF[14], K1BUF[15], K1BUF[16], K1BUF[17], K1BUF[18], K1BUF[19], K1BUF[20], K1BUF[21], K1BUF[22], K1BUF[23], K1BUF[24], K1BUF[25], K1BUF[26], K1BUF[27], K1BUF[28], K1BUF[29], K1BUF[30], K1BUF[31]);
	sprintf(KEY_2, "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X", K2BUF[0], K2BUF[1], K2BUF[2], K2BUF[3], K2BUF[4], K2BUF[5], K2BUF[6], K2BUF[7], K2BUF[8], K2BUF[9], K2BUF[10], K2BUF[11], K2BUF[12], K2BUF[13], K2BUF[14], K2BUF[15], K2BUF[16], K2BUF[17], K2BUF[18], K2BUF[19], K2BUF[20], K2BUF[21], K2BUF[22], K2BUF[23], K2BUF[24], K2BUF[25], K2BUF[26], K2BUF[27], K2BUF[28], K2BUF[29], K2BUF[30], K2BUF[31]);
	
	printf("starting loop\n");
	while (1) {
		memset((void *)syscmdc, 0, 512);
		memset((void *)cbuff, 0, 128);
		memset((void *)gbuff, 0, 128);
		memset((void *)UNKKBUF, 0, 64);
		memset((void *)fw, 0, 4);
		sprintf(gbuff, "keys/%d.SMI_KEY", cur);
		fp = fopen(gbuff, "rb");
		if (fp == NULL) {
			cur = cur + 1;
			memset((void *)gbuff, 0, 128);
			sprintf(gbuff, "keys/%d.SMI_KEY", cur);
			fp = fopen(gbuff, "rb");
			if (fp == NULL) {
				cur = cur - 1;
				printf("\nEND: no min fw lower than 03.6500.01 and higher than 00.9960.00\n");
				break;
			}
		}
		fread(UNKKBUF, 64, 1, fp);
		fclose(fp);
		sprintf(cname, "%02X%02X%02X%02X", UNKKBUF[0], UNKKBUF[1], UNKKBUF[32], UNKKBUF[33]);
		sprintf(syscmdc, "openssl enc -d -aes-256-cbc -nopad -in data/%s_SMI_NOUTER.SMI_e1 -out tmp.dec2 -K %s -iv %s", cname, KEY_1, iv_2);
		printf("\nAES256-CBC DECRYPT INNER LAYER:\n in: data/%s_SMI_NOUTER.SMI_e1\n key: %s\n iv: %s\n...", cname, KEY_1, iv_2);
		system(syscmdc);
		printf("ok!\n");
		printf("Checking resulting min fw ver... ");
		fp = fopen("tmp.dec2", "rb");
		fread(fw, 1, 4, fp);
		fclose(fp);
		unlink("tmp.dec2");
		printf("0x%08X\n", *(uint32_t *)fw);
		if (*(uint32_t *)fw < 0x03650001 && *(uint32_t *)fw > 0x00996000) {
			printf("\nEND: min fw resulting from data/%s_SMI_NOUTER.SMI_e1 (%s) is lower than 03.6500.01 ( %02X.%02X%02X.%02X )\n", cname, gbuff, fw[3], fw[2], fw[1], fw[0]);
			found = 1;
			break;
		}
		cur = cur + 1;
	}
	printf("\nloop end\n");
	if (found == 0)
		return 0;
	sprintf(syscmdc, "openssl enc -aes-256-cbc -nopad -in data/%s_SMI_NOUTER.SMI_e1 -out TSMI.rSMI -K %s -iv %s", cname, KEY_2, iv_1);
	printf("\nAES256-CBC ENCRYPT OUTER LAYER:\n in: data/%s_SMI_NOUTER.SMI_e1\n out: TSMI.rSMI\n key: %s\n iv: %s\n...", cname, KEY_2, iv_1);
	system(syscmdc);
	printf("ok!\n");
	printf("\npacking SMI data to TSMI.SMI... \n");
	sprintf(dbuff, "data/%s_SMI_HEADER.SMI_HDR", cname);
	ft = fopen(dbuff, "rb");
	if (ft == NULL) {
		printf("ERROR: cannot open file for read (%s)\n", dbuff);
		return -1;
	}
	fread(syscmdc, 0x80, 1, ft);
	fclose(ft);
	ft = fopen("TSMI.rSMI", "rb");
	if (ft == NULL) {
		printf("ERROR: cannot open file for read (TSMI.rSMI)\n");
		return -1;
	}
	fread((syscmdc + 0x80), 0x180, 1, ft);
	fclose(ft);
	fp = fopen("TSMI.SMI", "wba");
	if (fp == NULL) {
		printf("ERROR: cannot open file for write (TSMI.SMI)\n");
		return -1;
	}
	fwrite(syscmdc, 0x200, 1, fp);
	fclose(fp);
	printf("done: TSMI.SMI\n");
	return 1;
}
