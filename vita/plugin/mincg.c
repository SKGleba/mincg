/*
	mincg by SKGleba
	All Rights Reserved
*/

#include <nmprunner.h>
#include "logging.h"

#define LOG_LOC "ux0:data/mincg.log"

static unsigned char enc_key_1[32] = 
{
	// FILL ME IN
};

static unsigned char enc_iv_1[16] = 
{
	// FILL ME IN
};

static unsigned char enc_key_2[32] = 
{
	// FILL ME IN
};

static unsigned char enc_iv_2[16] = 
{
	// FILL ME IN
};

static unsigned char smi_iv_1[16] = 
{
	// FILL ME IN
};

static unsigned char smi_iv_2[16] = 
{
	// FILL ME IN
};

static unsigned char rsa_key[256] = 
{
	// FILL ME IN
};
static unsigned char rsa_unk[16] = 
{
	// FILL ME IN
};
	
static char leafbuf[512], cbuff[128], keylogloc[128], cname[16];
static tai_hook_ref_t hook_ref;
static int hook = 0, debug_mode = 0;

const char *get_rfname(int field) {
	static char *rfnames[] = {
		"INIT",
		"DKEY1_B",
		"DKEY1_C",
		"CPY_KEY1",
		"DEC_1",
		"CPY_SB",
		"RSA_CHK",
		"DKEY2_B",
		"DKEY2_C",
		"CPY_KEY2",
		"DEC_2"
	};
	return rfnames[field];
}

static int hex_dump(unsigned char *addr, unsigned int size, char *name)
{
	LOG_KEY("hex_dump %s [%d]:\n ", name, size);
    unsigned int i;
    for (i = 0; i < (size >> 4); i++)
    {
        LOG_KEY("%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7], addr[8], addr[9], addr[10], addr[11], addr[12], addr[13], addr[14], addr[15]);
        addr += 0x10;
    }
	LOG_KEY("\n..ok!\n");
    return 0;
}

SceUID is_pm_patched(void *buf) {
	*(uint8_t *)buf = 4;
	return 0;
}

int siofix(void *func) {
	int ret = 0;
	int res = 0;
	int uid = 0;
	ret = uid = ksceKernelCreateThread("siofix", func, 64, 0x10000, 0, 0, 0);
	if (ret < 0){ret = -1; goto cleanup;}
	if ((ret = ksceKernelStartThread(uid, 0, NULL)) < 0) {ret = -1; goto cleanup;}
	if ((ret = ksceKernelWaitThreadEnd(uid, &res, NULL)) < 0) {ret = -1; goto cleanup;}
	ret = res;
cleanup:
	if (uid > 0) ksceKernelDeleteThread(uid);
	return ret;
}

static int getSmi() {
	int xr = ksceIdStorageReadLeaf(0x80, leafbuf, 1);
	LOG("read_leaf: 0x%X\n", xr);
	return 0;
}

static int proxy_getSmi() {
	int state = 0, ret = 0;
	ENTER_SYSCALL(state);
	ret = siofix(getSmi);
	EXIT_SYSCALL(state);
	return ret;
}

static int setSmi() {
	if (leafbuf[0] == 0x53) {
		hook = taiHookFunctionImportForKernel(KERNEL_PID, &hook_ref, "SceIdStorage", 0xF13F32F9, 0x2AC815A2, is_pm_patched);
		int xr = ksceIdStorageWriteLeaf(0x80, leafbuf, 1);
		LOG("write_leaf: 0x%X\n", xr);
		if (xr != 0)
			leafbuf[0] = 0x69;
		taiHookReleaseForKernel(hook, hook_ref);
	} else {
		LOG("bad smi!\n");
		leafbuf[0] = 0x34;
	}
	return 0;
}

static int proxy_setSmi() {
	int state = 0, ret = 0;
	ENTER_SYSCALL(state);
	ret = siofix(setSmi);
	EXIT_SYSCALL(state);
	return ret;
}

static int send_payload() {
	int ret = 0;
	
	int sysroot = ksceKernelGetSysbase();
	uint32_t fw = *(uint32_t *)(*(int *)(sysroot + 0x6c) + 4);
	
	ret = NMPexploit_init(fw);
	if (ret != 0)
		return ret;
	
	ret = NMPconfigure_stage2(fw);
	if (ret != 0)
		return (0x60 + ret);
	
	ret = NMPreserve_commem(1);
	if (ret != 0)
		return (0x10 + ret);
	
	ret = NMPcopy(&NMPstage2_payload, 0x10000, sizeof(NMPstage2_payload), 0);
	if (ret != 0)
		return (0x20 + ret);
	
	SceIoStat stat;
	int stat_ret = ksceIoGetstat("ux0:app/SKGM1NCG0/dec_SMI.nmp", &stat);
	if(stat_ret < 0){
		LOG("woold_fopread_err1\n");
		ret = 7;
	} else {
		ret = NMPfile_op("ux0:app/SKGM1NCG0/dec_SMI.nmp", 0x10100, stat.st_size, 1);
	}
	if (ret != 0)
		return (0x30 + ret);
	
	ret = NMPcopy(&leafbuf, 0x12100, sizeof(leafbuf), 0);
	if (ret == 0) ret = NMPcopy(&smi_iv_1, 0x120B0, sizeof(smi_iv_1), 0);
	if (ret == 0) ret = NMPcopy(&smi_iv_2, 0x120C0, sizeof(smi_iv_2), 0);
	if (ret == 0) ret = NMPcopy(&enc_key_1, 0x12000, sizeof(enc_key_1), 0);
	if (ret == 0) ret = NMPcopy(&enc_iv_1, 0x12040, sizeof(enc_iv_1), 0);
	if (ret == 0) ret = NMPcopy(&enc_key_2, 0x12060, sizeof(enc_key_2), 0);
	if (ret == 0) ret = NMPcopy(&enc_iv_2, 0x120A0, sizeof(enc_iv_2), 0);
	if (ret == 0) ret = NMPcopy(&rsa_key, 0x12400, sizeof(rsa_key), 0);
	if (ret == 0) ret = NMPcopy(&rsa_unk, 0x12500, sizeof(rsa_unk), 0);
	if (ret != 0)
		return (0x70 + ret);
	
	if (debug_mode == 1) {
		NMPfile_op("ux0:data/CUR_PRE_MEM.DMP", 0, 0x1FE000, 0);
	}
	
	ret = NMPfree_commem(0);
	if (ret != 0)
		return (0x50 + ret);
	
	ret = NMPf00d_jump((uint32_t)0x1C010000, fw);
	if (ret != 0)
		return (0x40 + ret);
	
	ksceSblSmCommStopSm(NMPctx, &NMPstop_res);
	return 0;
}

static int get_result() {
	int ret = 0, errc = 0;
	
	ret = NMPreserve_commem(0);
	if (ret != 0)
		return (0x10 + ret);
	
	uint32_t *RESULTS = (void *)(NMPcorridor + 0x700);
	while (errc < 11) {
		if (RESULTS[errc] != 0)
			break;
		errc = errc + 1;
	}
	
	if (errc != 11) {
		LOG("WEIRD_RET 0x%X : 0x%lX\n", errc, RESULTS[errc]);
		LOG("Aborting...\n");
		NMPfree_commem(1);
		return 0x69;
	}
	
	memset(keylogloc, 0, sizeof(keylogloc));
	memset(cname, 0, sizeof(cname));
	snprintf(cname, 9, "%02X%02X%02X%02X", *(uint8_t *)NMPcorridor, *(uint8_t *)(NMPcorridor + 1), *(uint8_t *)(NMPcorridor + 0x40), *(uint8_t *)(NMPcorridor + 0x41));
	snprintf(keylogloc, 128, "ux0:data/%s_SMI_KEYS.SMI_KEY", cname);
	LOG("dumping keys...");
	logg(NMPcorridor, 32, keylogloc, 1);
	logg((NMPcorridor + 0x40), 32, keylogloc, 2);
	LOG_KEY("\nSMI_OUT:\n");
	hex_dump(NMPcorridor, 32, "SMI_key_1");
	hex_dump((NMPcorridor + 0x40), 32, "SMI_key_2");
	hex_dump((NMPcorridor + 0x700), 64, "RESULT");
	LOG(" OK!\n");
	
	LOG("dumping SMI...");
	memset(cbuff, 0, sizeof(cbuff));
	snprintf(cbuff, 128, "ux0:data/%s_SMI_RAW.SMI_e2", cname);
	NMPfile_op(cbuff, 0x12100, 0x200, 0);
	snprintf(cbuff, 128, "ux0:data/%s_SMI_NOUTER.SMI_e1", cname);
	NMPfile_op(cbuff, 0x180, 0x180, 0);
	snprintf(cbuff, 128, "ux0:data/%s_SMI_DECRYPTED.SMI", cname);
	NMPfile_op(cbuff, 0x500, 0x180, 0);
	snprintf(cbuff, 128, "ux0:data/%s_SMI_HEADER.SMI_HDR", cname);
	NMPfile_op(cbuff, 0x12100, 0x80, 0);
	if (debug_mode == 1) {
		NMPfile_op("ux0:data/CUR_RET_MEM.DMP", 0, 0x1FE000, 0);
	}
	LOG(" OK!\n");
	
	ret = NMPfree_commem(1);
	if (ret != 0)
		return (0x50 + ret);
	
	return 0;
}

static int verify_result() {
	int ret = 0, errc = 0;
	
	ret = NMPreserve_commem(0);
	if (ret != 0)
		return (0x10 + ret);
	LOG("Results:\n");
	
	uint32_t *RESULTS = (void *)(NMPcorridor + 0x700);
	
	while (errc < 11) {
		LOG("%s: 0x%lX\n", get_rfname(errc), RESULTS[errc]);
		if (RESULTS[errc] != 0)
			break;
		errc = errc + 1;
	}
	
	if (errc != 11) {
		NMPfree_commem(1);
		LOG("%s ERR\n", get_rfname(errc));
		return 0x34;
	}
	
	LOG("FW_CHK: 0x%lX\n", *(uint32_t *)(NMPcorridor + 0x500));
	
	if (RESULTS[errc] != 0x69) {
		NMPfree_commem(1);
		LOG("FW_CHK ERR\n");
		return 0x69;
	}
	
	if (debug_mode == 1) {
		NMPfile_op("ux0:data/CUR_VER_MEM.DMP", 0, 0x1FE000, 0);
	}
	
	ret = NMPfree_commem(1);
	if (ret != 0)
		return (0x50 + ret);
	
	return 0;
}

void _start() __attribute__ ((weak, alias ("module_start")));
int module_start(SceSize argc, const void *args)
{
	LOG_START("mincg started!\n");
	LOG("fw: 0x%lX\n", *(uint32_t *)(*(int *)(ksceKernelGetSysbase() + 0x6c) + 4));
	
	int xerr = 0;
	
	LOG("OP_REQ[R]: 0x%X\n", argc);
	
	if (argc > 0x68) {\
		LOG("debugging mode [on]\n");
		debug_mode = 1;
		argc = argc - 0x69;
		LOG("OP_REQ[C]: 0x%X\n", argc);
	} else
		LOG("debugging mode [off]\n");
	
	if (argc == 0) {
		int ret;
		proxy_getSmi();
		LOG("\nDECRYPT_SMI... ");
		ret = send_payload();
		LOG("0x%X\n", ret);
		if (ret == 0) {
			ret = get_result();
			if (ret != 0)
				xerr = 1;
			LOG("\n Please consider sharing your dumps ( _SMI_ files ) to give a downgrade chance to other users\n Send dumps to [ skgleba@gmail.com ]\n");
		} else
			xerr = 1;
	} else if (argc == 1) {
		int ret;
		LOG("\nVERIFY_SMI:START\n");
		SceIoStat stat;
		int stat_ret = ksceIoGetstat("ux0:data/TSMI.SMI", &stat);
		if(stat_ret < 0 || stat.st_size != 512){
			LOG("fopread_err1\n");
			LOG("reading own leaf! (??)\n");
			proxy_getSmi();
		} else {
			int fd = ksceIoOpen("ux0:data/TSMI.SMI", SCE_O_RDONLY, 0);
			ksceIoRead(fd, leafbuf, 512);
			ksceIoClose(fd);
		}
		if (leafbuf[0] == 0x53) {
			LOG("decrypting SMI... ");
			ret = send_payload();
			LOG("0x%X\n", ret);
			if (ret == 0) {
				ret = verify_result();
				if (ret == 0) {
					LOG("VERIFY_SMI:OK!\n");
					LOG("\nWRITE_SMI:START\n");
					proxy_setSmi();
					if (leafbuf[0] == 0x53) {
						LOG("WRITE_SMI:OK!\n");
					} else {
						xerr = 1;
						LOG("WRITE_SMI_ERR 0x%X\n", leafbuf[0]);
					}
				} else {
					xerr = 1;
					LOG("VERIFY_ERR 0x%X\n", ret);
				}
			} else {
				xerr = 1;
				LOG("PAYLOAD_ERR 0x%X\n", ret);
			}
		} else {
			xerr = 1;
			LOG("FREAD_ERR\n");
		}
	} else if (argc == 2) {
		int ret;
		LOG("\nVERIFY_SMI:START\n");
		SceIoStat stat;
		int stat_ret = ksceIoGetstat("ux0:data/TSMI.SMI", &stat);
		if(stat_ret < 0 || stat.st_size != 512){
			LOG("fopread_err1\n");
			LOG("reading own leaf! (??)\n");
			proxy_getSmi();
		} else {
			int fd = ksceIoOpen("ux0:data/TSMI.SMI", SCE_O_RDONLY, 0);
			ksceIoRead(fd, leafbuf, 512);
			ksceIoClose(fd);
		}
		if (leafbuf[0] == 0x53) {
			LOG("decrypting SMI... ");
			ret = send_payload();
			LOG("0x%X\n", ret);
			if (ret == 0) {
				ret = verify_result();
				if (ret == 0) {
					LOG("VERIFY_SMI:OK!\n");
				} else {
					xerr = 1;
					LOG("VERIFY_ERR 0x%X\n", ret);
				}
			} else {
				xerr = 1;
				LOG("PAYLOAD_ERR 0x%X\n", ret);
			}
		} else {
			xerr = 1;
			LOG("FREAD_ERR\n");
		}
	} else {
		xerr = 1;
		LOG("UNKNOWN_OP_REQ\n");
	}
	
	LOG("\nmincg finished!\n");
	
	if (xerr == 1)
		return SCE_KERNEL_START_FAILED;
	
	return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize argc, const void *args)
{
	return SCE_KERNEL_STOP_SUCCESS;
}
