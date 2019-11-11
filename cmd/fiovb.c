/*
 * (C) Copyright 2019, Foundries.IO
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */
#include <common.h>
#include <command.h>
#include <env.h>
#include <image.h>
#include <malloc.h>
#include <mmc.h>
#include <fiovb.h>

static struct fiovb_ops *fiovb_ops;

int do_fiovb_init(cmd_tbl_t *cmdtp, int flag, int argc, char * const argv[])
{
	unsigned long mmc_dev;

	if (argc != 2)
		return CMD_RET_USAGE;

	mmc_dev = simple_strtoul(argv[1], NULL, 16);

	if (fiovb_ops)
		fiovb_ops_free(fiovb_ops);

	fiovb_ops = fiovb_ops_alloc(mmc_dev);
	if (fiovb_ops)
		return CMD_RET_SUCCESS;

	printf("Failed to initialize fiovb\n");

	return CMD_RET_FAILURE;
}

int do_fiovb_read_rb(cmd_tbl_t *cmdtp, int flag, int argc, char * const argv[])
{
	size_t index;
	u64 rb_idx;

	if (!fiovb_ops) {
		printf("Foundries.IO Verified Boot is not initialized, run 'fiovb init' first\n");
		return CMD_RET_FAILURE;
	}

	if (argc != 2)
		return CMD_RET_USAGE;

	index = (size_t)simple_strtoul(argv[1], NULL, 16);

	if (fiovb_ops->read_rollback_index(fiovb_ops, index, &rb_idx) ==
	    FIOVB_IO_RESULT_OK) {
		printf("Rollback index: %llx\n", rb_idx);
		return CMD_RET_SUCCESS;
	}

	printf("Failed to read rollback index\n");

	return CMD_RET_FAILURE;
}

int do_fiovb_write_rb(cmd_tbl_t *cmdtp, int flag, int argc, char * const argv[])
{
	size_t index;
	u64 rb_idx;

	if (!fiovb_ops) {
		printf("Foundries.IO Verified Boot is not initialized, run 'fiovb init' first\n");
		return CMD_RET_FAILURE;
	}

	if (argc != 3)
		return CMD_RET_USAGE;

	index = (size_t)simple_strtoul(argv[1], NULL, 16);
	rb_idx = simple_strtoull(argv[2], NULL, 16);

	if (fiovb_ops->write_rollback_index(fiovb_ops, index, rb_idx) ==
	    FIOVB_IO_RESULT_OK)
		return CMD_RET_SUCCESS;

	printf("Failed to write rollback index\n");

	return CMD_RET_FAILURE;
}

int do_fiovb_read_pvalue(cmd_tbl_t *cmdtp, int flag, int argc,
		         char * const argv[])
{
	const char *name;
	size_t bytes;
	size_t bytes_read;
	void *buffer;
	char *endp;

	if (!fiovb_ops) {
		printf("Foundries.IO Verified Boot is not initialized, run 'fiovb init' first\n");
		return CMD_RET_FAILURE;
	}

	if (argc != 3)
		return CMD_RET_USAGE;

	name = argv[1];
	bytes = simple_strtoul(argv[2], &endp, 10);
	if (*endp && *endp != '\n')
		return CMD_RET_USAGE;

	buffer = malloc(bytes);
	if (!buffer)
		return CMD_RET_FAILURE;

	if (fiovb_ops->read_persistent_value(fiovb_ops, name, bytes, buffer,
					   &bytes_read) == FIOVB_IO_RESULT_OK) {
		printf("Read %zu bytes, value = %s\n", bytes_read,
		       (char *)buffer);
		free(buffer);
		return CMD_RET_SUCCESS;
	}

	printf("Failed to read persistent value\n");

	free(buffer);

	return CMD_RET_FAILURE;
}

int do_fiovb_write_pvalue(cmd_tbl_t *cmdtp, int flag, int argc,
			  char * const argv[])
{
	const char *name;
	const char *value;

	if (!fiovb_ops) {
		printf("Foundries.IO Verified Boot is not initialized, run 'fiovb init' first\n");
		return CMD_RET_FAILURE;
	}

	if (argc != 3)
		return CMD_RET_USAGE;

	name = argv[1];
	value = argv[2];

	if (fiovb_ops->write_persistent_value(fiovb_ops, name, strlen(value) + 1,
					    (const uint8_t *)value) ==
	    FIOVB_IO_RESULT_OK) {
		printf("Wrote %zu bytes\n", strlen(value) + 1);
		return CMD_RET_SUCCESS;
	}

	printf("Failed to write persistent value\n");

	return CMD_RET_FAILURE;
}

static cmd_tbl_t cmd_fiovb[] = {
	U_BOOT_CMD_MKENT(init, 2, 0, do_fiovb_init, "", ""),
	U_BOOT_CMD_MKENT(read_rb, 2, 0, do_fiovb_read_rb, "", ""),
	U_BOOT_CMD_MKENT(write_rb, 3, 0, do_fiovb_write_rb, "", ""),
	U_BOOT_CMD_MKENT(read_pvalue, 3, 0, do_fiovb_read_pvalue, "", ""),
	U_BOOT_CMD_MKENT(write_pvalue, 3, 0, do_fiovb_write_pvalue, "", ""),
};

static int do_fiovb(cmd_tbl_t *cmdtp, int flag, int argc, char * const argv[])
{
	cmd_tbl_t *cp;

	cp = find_cmd_tbl(argv[1], cmd_fiovb, ARRAY_SIZE(cmd_fiovb));

	argc--;
	argv++;

	if (!cp || argc > cp->maxargs)
		return CMD_RET_USAGE;

	if (flag == CMD_FLAG_REPEAT)
		return CMD_RET_FAILURE;

	return cp->cmd(cmdtp, flag, argc, argv);
}

U_BOOT_CMD(
	fiovb, 29, 0, do_fiovb,
	"Provides commands for testing Foundries.IO verified boot functionality",
	"init <dev> - initialize fiovb for <dev>\n"
	"fiovb read_rb <num> - read rollback index at location <num>\n"
	"fiovb write_rb <num> <rb> - write rollback index <rb> to <num>\n"
	"fiovb read_pvalue <name> <bytes> - read a persistent value <name>\n"
	"fiovb write_pvalue <name> <value> - write a persistent value <name>\n"
	);
