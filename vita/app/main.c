/*
  Simple kplugin loader by xerpi
*/

#include <stdio.h>
#include <taihen.h>
#include <psp2/ctrl.h>
#include <psp2/io/fcntl.h>
#include "debugScreen.h"

#define MOD_PATH "ux0:app/SKGM1NCG0/mincg.skprx"
	
#define printf(...) psvDebugScreenPrintf(__VA_ARGS__)

#define BETA 0
#define DEBUG 0

static int debug_mode = DEBUG, trial = BETA;

static uint32_t nullptr;

int wait_key_press()
{
	int ret = 0x34;
	SceCtrlData pad;

	printf(" [CROSS]        DUMP SMI\n");
	printf(" [SQUARE]       VERIFY SMI\n");
	printf(" [CIRCLE]       FLASH SMI\n");
	printf(" [TRIANGLE]     EXIT\n");

	while (ret == 0x34) {
		sceCtrlPeekBufferPositive(0, &pad, 1);
		if (pad.buttons & SCE_CTRL_CROSS)
			ret = 0;
		if (pad.buttons & SCE_CTRL_TRIANGLE)
			ret = 0x34;
		if (pad.buttons & SCE_CTRL_SQUARE) {
			if (trial == 1) {
				printf("\nTRIAL MODE!\n");
			} else
				ret = 2;
		}
		if (pad.buttons & SCE_CTRL_CIRCLE) {
			if (trial == 1) {
				printf("\nTRIAL MODE!\n");
			} else
				ret = 1;
		}
		if (pad.buttons & SCE_CTRL_LTRIGGER && pad.buttons & SCE_CTRL_RTRIGGER) {
			trial = 0;
			debug_mode = 0x69;
			printf("\nDEBUGGING MODE SET\n");
		}
		sceKernelDelayThread(150 * 1000);
	}
	
	return ret;
}

int main(int argc, char *argv[])
{
	int opreq = 0;
	SceUID mod_id;
	psvDebugScreenInit();
	printf("mincg v1.0 by SKGleba\n\n");
	if (trial == 1)
		printf("TRIAL MODE!\n\n");
	opreq = wait_key_press();
	if (opreq == 0x34) {
		sceKernelExitProcess(0);
		return 0;
	}
	printf("\nWorking, please wait...");
	tai_module_args_t argg;
	argg.size = sizeof(argg);
	argg.pid = KERNEL_PID;
	argg.args = (debug_mode + opreq);
	argg.argp = &nullptr;
	argg.flags = 0;
	mod_id = taiLoadStartKernelModuleForUser(MOD_PATH, &argg);
	if (mod_id > 0 && opreq == 1) {
		taiStopUnloadKernelModuleForUser(mod_id, &argg, NULL, NULL);
		printf("\nok!, rebooting in 5s\n");
		printf("you can check ux0:data/mincg.log for more info\n");
		sceKernelDelayThread(5 * 1000 * 1000);
		scePowerRequestColdReset();
	} else if (mod_id > 0 && opreq != 1) {
		taiStopUnloadKernelModuleForUser(mod_id, &argg, NULL, NULL);
		printf("\nok!, exiting in 10s\n");
		printf("check ux0:data/ for log & dumps\n");
		if (opreq == 0)
			printf("\n\n Please consider sharing your dumps ( _SMI_ files )\n to give a downgrade chance to other users\n\n Send dumps to [ skgleba@gmail.com ]\n");
		sceKernelDelayThread(10 * 1000 * 1000);
		sceKernelExitProcess(0);
	} else {
		printf("\nerr, check log!\n");
		sceKernelDelayThread(5 * 1000 * 1000);
	}
	return 0;
}
