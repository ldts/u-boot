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

#if defined(CONFIG_FIOVB) && !defined(CONFIG_SPL)
#include <fiovb.h>
static int fiovb_provisioned(void)
{
	char len_str[32] = { '\0' };
	struct fiovb_ops *sec;
	int ret;

	sec = fiovb_ops_alloc(0);
	if (!sec)
		return -EIO;

	snprintf(len_str, sizeof(len_str), "%ld", (unsigned long) 0);
	ret = sec->write_persistent_value(sec, "m4size", strlen(len_str) + 1,
					 (uint8_t *) len_str);
	fiovb_ops_free(sec);

	/* if the RPMB is accessible, then we can't close the device */
	if (ret == FIOVB_IO_RESULT_OK)
		return -1;

	return 0;
}
#else
static int fiovb_provisioned(void) { return 0; }
#endif

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
 * after the SRK fuses have been written.
 *
 * On CAAM enabled boards (imx7, imx6 and others), the board should not be closed
 * if RPMB keys have been provisioned as it would render it unavailable
 * afterwards
 */
static int do_fiohab_close(cmd_tbl_t *cmdtp, int flag, int argc,
			   char *const argv[])
{
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

	ret = fiovb_provisioned();
	if (ret) {
		printf("Error, rpmb provisioned with test keys\n");
		return 1;
	}

	return 0;
}

U_BOOT_CMD(fiohab_close, CONFIG_SYS_MAXARGS, 1, do_fiohab_close,
	   "Close the board for HAB","");

