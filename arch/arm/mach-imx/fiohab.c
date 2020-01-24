// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2019 Foundries.IO
 */

#include <common.h>
#include <config.h>
#include <fuse.h>
#include <mapmem.h>
#include <image.h>
#include <asm/io.h>
#include <asm/system.h>
#include <asm/arch/clock.h>
#include <asm/arch/sys_proto.h>
#include <asm/mach-imx/hab.h>

#ifdef CONFIG_MX7ULP
#define SRK_FUSE_LIST								\
{ 5, 0 }, { 5, 1 }, { 5, 2}, { 5, 3 }, { 5, 4 }, { 5, 5}, { 5, 6 }, { 5 ,7 },	\
{ 6, 0 }, { 6, 1 }, { 6, 2}, { 6, 3 }, { 6, 4 }, { 6, 5}, { 6, 6 }, { 6 ,7 },
#define SECURE_FUSE_BANK	(29)
#define SECURE_FUSE_WORD	(6)
#define SECURE_FUSE_VALUE	(0x80000000)
#else
#error "SoC not supported"
#endif

static hab_rvt_report_status_t *hab_check;

static int hab_status(void)
{
	hab_check = (hab_rvt_report_status_t *) HAB_RVT_REPORT_STATUS;
	enum hab_config config = 0;
	enum hab_state state = 0;

	if (hab_check(&config, &state) != HAB_SUCCESS) {
		printf("HAB events active\n");
		return 1;
	}

	return 0;
}

/* The fuses must have been programmed and their values set in the environment.
 * The fuse read operation returns a shadow value so a board reset is required
 * after the SRK fuses have been written
 */
static int do_fiohab_close(cmd_tbl_t *cmdtp, int flag, int argc,
			   char *const argv[])
{
	struct srk_fuse {
		u32 bank;
		u32 word;
	} const srk_fuses[] = { SRK_FUSE_LIST };
	char fuse_name[20] = { '\0' };
	uint32_t fuse, fuse_env;
	int i, ret;

	if (argc != 1) {
		cmd_usage(cmdtp);
		return 1;
	}

	if (imx_hab_is_enabled()) {
		printf("secure boot already enabled\n");
		return 0;
	}

	if (hab_status())
		return 1;

	for (i = 0; i < ARRAY_SIZE(srk_fuses); i++) {
		ret = fuse_read(srk_fuses[i].bank, srk_fuses[i].word, &fuse);
		if (ret) {
			printf("Secure boot fuse read error\n");
			return 1;
		}

		sprintf(fuse_name, "srk_%d", i);
		fuse_env = (uint32_t) env_get_hex(fuse_name, 0);
		if (!fuse_env) {
			printf("%s not in environment\n", fuse_name);
			return 1;
		}

		if (fuse_env != fuse) {
			printf("%s - programmed: 0x%x != expected: 0x%x \n",
				fuse_name, fuse, fuse_env);
			return 1;
		}
	}

	ret = fuse_prog(SECURE_FUSE_BANK, SECURE_FUSE_WORD, SECURE_FUSE_VALUE);
	if (ret) {
		printf("Error writing the Secure Fuse\n");
		return 1;
	}

	return 0;
}

U_BOOT_CMD(fiohab_close, CONFIG_SYS_MAXARGS, 1, do_fiohab_close,
	   "Close the board for HAB","");

